package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/gomoni/snug/internal/policy"
)

// dryRun is not a debugging convenience. It is the mechanism by which a human
// can trust snug at all: a sandbox you cannot read is a sandbox you are
// guessing about. It starts no process and creates no file.
//
// refusedBy is nil for a policy that can actually run. When it is not nil, p
// is a policy Validate refused (see policy.Resolve's doc comment for the
// contract) — dryRun renders it anyway, so a human can see exactly what was
// refused, but says so at the top and bottom instead of implying this is a
// runnable sandbox.
func dryRun(p *policy.Policy, args []string, cfg config, refusedBy error) {
	out := os.Stdout
	if refusedBy != nil {
		fmt.Fprintln(out, "snug — dry run of a REFUSED policy (nothing below can run; nothing was started)")
	} else {
		fmt.Fprintln(out, "snug — dry run, nothing was started")
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "TARGET   %s  %s\n", p.Target, targetAnnotation(p))
	fmt.Fprintf(out, "HOME     %s  %s\n", p.Home, homeAnnotation(p))
	fmt.Fprintf(out, "PROFILES %s\n", strings.Join(p.Selected, " "))
	if implied := p.Implied(); len(implied) > 0 {
		fmt.Fprintf(out, "         + %s  (pulled in by include; see: snug profile tree)\n",
			strings.Join(implied, " "))
	}
	describeNetwork(out, p)
	describeContainers(out, p)
	describeCommands(out, p)
	if p.NewSession {
		fmt.Fprintf(out, "TTY      --new-session (this kernel allows TIOCSTI, so the sandbox is kept\n")
		fmt.Fprintf(out, "         out of your terminal — the cost is no job control inside)\n")
	} else {
		fmt.Fprintf(out, "TTY      shared session — job control works (TIOCSTI is disabled kernel-wide)\n")
	}
	fmt.Fprintln(out)

	fmt.Fprintln(out, "FILESYSTEM  (deny-by-default; every line is a grant, there are no deny rules)")
	for _, m := range p.SortedMounts() {
		kind := m.Kind.String()
		if m.Kind == policy.KindBind {
			kind = m.Access.String()
		}
		// A KindData file with an executable permission bit is CODE, not
		// config — the podman stub is the one case of this today (see
		// podmanstub.go). Kind.String() itself stays "data" for every other
		// caller; this is a dry-run-only rendering so a human scanning the
		// FILESYSTEM block sees "this one runs" at a glance rather than
		// having to notice a permission column.
		if m.Kind == policy.KindData && m.Perms != nil && *m.Perms&0o111 != 0 {
			kind = "exec"
		}
		opt := ""
		if m.Optional {
			opt = " (optional)"
		}
		detail := m.Guest
		if m.Kind == policy.KindSymlink {
			detail = fmt.Sprintf("%s -> %s", m.Guest, m.Host)
		} else if m.Kind == policy.KindBind && m.Host != m.Guest {
			detail = fmt.Sprintf("%s (from %s)", m.Guest, m.Host)
		}
		fmt.Fprintf(out, "  %-6s %-46s %s%s\n", kind, detail, strings.Join(m.From, "+"), opt)
	}
	fmt.Fprintf(out, "  %-6s %s\n", "ro-/", "everything else is a read-only skeleton (--remount-ro /)")

	fmt.Fprintln(out)
	fmt.Fprintln(out, "  NOT GRANTED (never mounted — these read as absent, they are not hidden):")
	for _, line := range notGranted(p) {
		fmt.Fprintf(out, "    %s\n", line)
	}

	fmt.Fprintln(out)
	describeEnvironment(out, p)

	if p.Net.Mode == policy.NetEgress {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "── pasta ─────────────────────────────────────────────────────────────────")
		fmt.Fprintln(out, "pasta "+strings.Join(p.PastaArgs(0), " "))
		fmt.Fprintln(out, "  (/proc/0/... is a placeholder; the real pid is bwrap's child)")
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "── bwrap ─────────────────────────────────────────────────────────────────")
	if refusedBy != nil {
		fmt.Fprintln(out, "(this argv describes the REFUSED policy above; it is not a command you can")
		fmt.Fprintln(out, " paste and run — see the refusal below)")
	}
	fmt.Fprintln(out, formatArgs(args))

	if refusedBy != nil {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "REFUSED: %v\n", refusedBy)
	}
}

// describeEnvironment renders what the sandbox's environment will be. bwrap
// --clearenv discards the host's, so this block is the WHOLE of it — there is
// nothing inherited that does not appear here (with the one caveat CLAUDE.md
// records: a bound /etc means /etc/profile.d can still put variables back).
//
// It is a function of its own, rather than eight lines inside dryRun, because
// it is the review artifact for the environment the same way the .bwrap.txt
// goldens are for the argv: cmd/snug/testdata/env.*.txt is exactly this block,
// resolved against the REAL builtin profiles rather than a fake registry.
// The layout is §2.8's, and the PATH bands read top to bottom in RESOLUTION
// ORDER — so the rendering IS the §2.4 band diagram. If the two ever disagree,
// the renderer is lying, and a flat NAME=value list (which this replaced) could
// not disagree because it said nothing: not which verb produced a value, not
// which profile, and not what a filter dropped on the way.
func describeEnvironment(out *os.File, p *policy.Policy) {
	fmt.Fprintln(out, "ENVIRONMENT  (--clearenv, then:)")
	for _, name := range p.EnvNames() {
		v := p.Env[name]
		lines := envLines(p, v)
		if len(lines) == 0 && len(v.Dropped) == 0 {
			continue
		}
		label := name
		if len(lines) == 0 {
			// Nothing survived the filter, so the variable is UNSET rather than
			// set empty (§4.3). Say so on the screen: a variable that vanished
			// silently is exactly the failure §2.8 exists to prevent, and the
			// drops below are the whole explanation.
			fmt.Fprintf(out, "  %-16s %s\n", label, "(unset — nothing survived)")
		}
		for _, l := range lines {
			fmt.Fprintln(out, strings.TrimRight("  "+pad(label, 16)+" "+
				pad(strings.Join(l.values, " "), 31)+" "+pad(l.verb, 9)+" "+l.from+l.mark, " "))
			label = ""
		}
		// Dropped elements are NAMED, not counted. "1 of 3 kept" does not let
		// anyone check a filter, and a filter nobody can check is the exact shape
		// of failure this whole model exists to avoid.
		//
		// Grouped by REASON, one line per group, because "nothing grants that
		// path" and "only a tmpfs grants it" are materially different facts: the
		// second means the directory IS inside, is empty, and is writable, and
		// snug removed the element because keeping it would ship that shadow slot
		// pre-installed. Conflating the two into one ungrouped line is exactly
		// the ambiguity the drop's own Reason field exists to remove.
		//
		// Iterates a FIXED slice, never map order, so the rendering does not vary
		// run to run for the identical policy.
		for _, reason := range []policy.EnvDropReason{
			policy.DropNoGrant, policy.DropTmpfsOnly, policy.DropPseudoOnly,
		} {
			var vals []string
			for _, d := range v.Dropped {
				if d.Reason == reason {
					vals = append(vals, visibleValue(d.Value))
				}
			}
			if len(vals) == 0 {
				continue
			}
			word := "entries"
			if len(vals) == 1 {
				word = "entry"
			}
			fmt.Fprintf(out, "  %-16s (%d host %s dropped — %s: %s)\n",
				"", len(vals), word, reason.String(), strings.Join(vals, ", "))
		}
	}
}

// pad is %-Ns counted in RUNES rather than bytes. PS1 is snug's own and carries
// a lock emoji, so byte padding shifted every column on that one line — in the
// file a human reads to check the environment.
func pad(s string, n int) string {
	if w := utf8.RuneCountInString(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}

// envLine is one rendered row: consecutive entries that agree on verb, note and
// provenance are one line, which is what makes a band read as a band rather than
// as four unrelated rows.
type envLine struct {
	values []string
	verb   string
	from   string
	mark   string
}

func envLines(p *policy.Policy, v policy.EnvVar) []envLine {
	var out []envLine
	for _, e := range v.Entries {
		verb, from := e.Verb.String(), strings.Join(e.From, "+")
		if e.Verb == policy.VerbSnug {
			from = e.Note
		}
		mark := grantMark(p, e.Value)
		if n := len(out); n > 0 && out[n-1].verb == verb && out[n-1].from == from && out[n-1].mark == mark {
			out[n-1].values = append(out[n-1].values, visibleValue(e.Value))
			continue
		}
		out = append(out, envLine{values: []string{visibleValue(e.Value)}, verb: verb, from: from, mark: mark})
	}
	return out
}

// visibleValue renders a value so it cannot forge a line in this block.
//
// A sanitised element is HOST text — snug copies the host's value and filters
// it — and the drop line printed it verbatim. The red team put a newline in a
// host PATH element and the drop line split, the injected second line reading as
// a legitimate ENVIRONMENT row:
//
//	(2 host entries dropped — only an empty writable tmpfs is mounted there: /tmp/x/bin
//	  FORGED_VAR       fake-value                    forged-provenance, /tmp/y)
//
// --dry-run is the mechanism by which a human trusts snug, so a value that can
// author a row in it is a hole in the trust artifact even though it escapes
// nothing. internal/policy already applies exactly this guard to variable NAMES
// in its error messages (quoteVisible); the values had no equivalent.
//
// Applied to kept entries as well as dropped ones: a host element under a bind
// survives the filter, and it can carry a newline just as easily.
//
// A value with no control characters renders unchanged, so the ordinary screen —
// and every golden — is untouched.
func visibleValue(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return s
	}
	return strings.Trim(fmt.Sprintf("%q", s), `"`)
}

// grantMark is §4.2's repair, and it is a MARK rather than a refusal on purpose.
//
// snug authors HOME, PATH and SHELL unconditionally, and must keep doing so:
// there is no safe absent state for any of them (§4.3 — unset PATH and bash
// substitutes a compiled-in default ending in ".", which inside snug is the
// target). An earlier draft concluded the opposite and would have converted
// twenty minutes of confusion into a reachable hole. So the repair is to say
// which authored values name a path that is not inside this sandbox:
//
//	snug --dry-run --no-defaults -p @parent-ro .
//	  HOME, SHELL and all four PATH entries name directories that do not exist
//	  inside, and until now the screen said nothing about it.
//
// Computed against the RESOLVED MOUNTS, unlike the coupling rule in
// envcoupling.go, which is deliberately text-only. The asymmetry is the point:
// REFUSING must not depend on the host, or the same profile passes review on one
// machine and fails on another — but MARKING may, and here it must, or the mark
// is not about the sandbox that is actually going to run.
// The count of grants INSIDE an unmarked path is not decoration either. The
// predicate is "does a grant cover this path", and it must stay the one the
// sanitise filter uses (policy.GrantsGuestPath) — two implementations of "is
// this granted" eventually disagree, and the one on screen is the one a human
// trusts. But that predicate alone says "not granted" about /run/snug/bin, which
// is the directory snug creates to hold the podman stub: true in the policy's
// own vocabulary, and misleading on a line whose whole point is that a binary
// WILL be found there. Naming what is mounted inside keeps one predicate and
// stops the mark reading as a bug report — the difference between "$HOME is not
// yours to write" and "this directory holds exactly one generated file" is then
// visible without a second rule.
func grantMark(p *policy.Policy, value string) string {
	if !strings.HasPrefix(value, "/") || p.GrantsGuestPath(value) {
		return ""
	}
	inside := 0
	for _, m := range p.Mounts {
		if strings.HasPrefix(m.Guest, value+"/") {
			inside++
		}
	}
	switch inside {
	case 0:
		return "  ← not granted"
	case 1:
		return "  ← not granted (1 grant inside)"
	}
	return fmt.Sprintf("  ← not granted (%d grants inside)", inside)
}

// mountedAt finds the mount that determines what is visible at path — the
// deepest KindBind or KindTmpfs mount whose Guest is path itself or an
// ancestor of it. This mirrors the "deepest mount wins" rule Resolve itself
// applies (CLAUDE.md invariant 1): effective access at a path is a property of
// the covering set, not of any one grant, so --dry-run must compute it the
// same way rather than assuming which profile was selected.
//
// see policy.coveringMount — different question (the TARGET/HOME headline
// here vs. "is the host's content really at this path").
func mountedAt(p *policy.Policy, path string) (policy.Mount, bool) {
	var best policy.Mount
	found := false
	for _, m := range p.Mounts {
		if m.Kind != policy.KindBind && m.Kind != policy.KindTmpfs {
			continue
		}
		if m.Guest != path && !strings.HasPrefix(path, m.Guest+"/") {
			continue
		}
		if !found || len(m.Guest) > len(best.Guest) {
			best = m
			found = true
		}
	}
	return best, found
}

// targetAnnotation and homeAnnotation replace two claims that used to be
// hard-coded true — "(writable)" and "(tmpfs, ephemeral)" — and were false
// for any selection that did not include @cwd-rw / @home, the floor (no
// profile at all) most of all: neither path is mounted, so the honest
// annotation is "never granted", not "writable".
func targetAnnotation(p *policy.Policy) string {
	return pathAnnotation(p, p.Target)
}

func homeAnnotation(p *policy.Policy) string {
	return pathAnnotation(p, p.Home)
}

func pathAnnotation(p *policy.Policy, path string) string {
	m, ok := mountedAt(p, path)
	if !ok {
		return "(not mounted — never granted)"
	}
	word := accessWord(m)
	where := ""
	if m.Guest != path {
		where = fmt.Sprintf(", via %s covering %s", strings.Join(m.From, "+"), m.Guest)
	}
	return fmt.Sprintf("(%s%s%s)", word, where, writableBelow(p, path, m))
}

// writableBelow names the writable grants STRICTLY INSIDE path, so a read-only
// headline cannot hide them.
//
// REGRESSION (redteam, MVY0). The annotation above reports the DEEPEST mount
// covering the path, which is the right answer for "what is this path itself",
// and the wrong answer for "what can the sandbox write in here". Grants below it
// are invisible to that walk — and those are exactly the ones that RAISE the
// write surface. The result was `TARGET <dir>  (read-only)`, bare and
// unqualified, for the arrangement CLAUDE.md invariant 2 explicitly recommends:
//
//	ro = ["{target}"]        # grant the tree read-only...
//	rw = ["{target}/src"]    # ...and the part you want to write separately
//
// A write inside {target}/src then persisted to the host while the trust
// artifact said read-only. That is worse than the hard-coded "(writable)" this
// replaced: over-warning is a nuisance, under-warning is invariant 5.
//
// The information was never missing — the FILESYSTEM block lists every grant.
// Only the headline discarded it, and the headline is the line people read.
func writableBelow(p *policy.Policy, path string, covering policy.Mount) string {
	var inside []string
	for _, m := range p.SortedMounts() {
		// KindBind only, and that is the whole point rather than a shortcut. A
		// tmpfs below a tmpfs is not a surprise — it is ephemeral either way, and
		// listing @home's .cache/.config/.local/state under HOME would be noise
		// that trains the reader to skip the line. What must never hide is a
		// grant that PERSISTS TO THE HOST underneath a headline saying read-only
		// or ephemeral, and that is exactly a writable bind.
		if m.Kind != policy.KindBind || m.Access != policy.AccessRW {
			continue
		}
		if m.Guest == covering.Guest || !strings.HasPrefix(m.Guest, path+"/") {
			continue
		}
		inside = append(inside, m.Guest)
	}
	if len(inside) == 0 {
		return ""
	}
	// Named, not counted: "1 writable grant below" would still leave the reader
	// guessing which one, and the whole point is that they can see it.
	return fmt.Sprintf("; WRITABLE and PERSISTS below: %s", strings.Join(inside, " "))
}

func accessWord(m policy.Mount) string {
	if m.Kind == policy.KindTmpfs {
		return "tmpfs, ephemeral"
	}
	if m.Access == policy.AccessRW {
		return "writable"
	}
	return "read-only"
}

// describeContainers states where a container's network comes from, because
// today it is NOT the sandbox's and the NETWORK block immediately above is
// therefore not the whole story.
//
// This exists because of the engine-netns finding
// (.claude/design/ENGINE-NETNS.md §0): `@podman-socket` granted full egress through a
// container while `--dry-run` printed "No egress. No host loopback." The
// profile now includes `net`, so the NETWORK block is no longer false — but a
// reader still has to be told that the container and the sandbox get their
// network from two different places, or they will read the pasta guarantees
// above as covering containers. They do not.
func describeContainers(out *os.File, p *policy.Policy) {
	if p.Podman == policy.PodmanOff {
		return
	}
	fmt.Fprintf(out, "CONTAINERS  a per-sandbox engine behind a filtering proxy at %s\n",
		containerSocketGuest)
	fmt.Fprintf(out, "         INTERIM: a container runs in the ENGINE's netns, not this sandbox's,\n")
	fmt.Fprintf(out, "         so it has the engine's network — which is why this profile includes\n")
	fmt.Fprintf(out, "         '@net' rather than pretending to be offline. The pasta\n")
	fmt.Fprintf(out, "         guarantees above cover the SANDBOX; they do not cover containers.\n")
	fmt.Fprintf(out, "         Consequence: '@podman-socket' cannot currently be offline, and\n")
	fmt.Fprintf(out, "         'podman run -p N:80' is not reachable from the sandbox.\n")
	fmt.Fprintf(out, "         Planned fix: engine inside the sandbox's netns, after which the\n")
	fmt.Fprintf(out, "         '@net' include goes away and both lines above stop being true.\n")
	fmt.Fprintf(out, "         Design and feasibility: .claude/design/ENGINE-NETNS.md\n")
}

// describeCommands names snug's OWN staged executables — today, exactly one:
// the podman dispatcher stub. It exists because CONTAINERS above says a
// filtering proxy is listening, but not that a fresh `podman` command was
// placed on PATH ahead of the real one, and "there is a new executable
// running before the tool you typed" is exactly the kind of thing --dry-run
// exists to make legible rather than a human having to notice a FILESYSTEM
// line reads "exec" instead of "data".
func describeCommands(out *os.File, p *policy.Policy) {
	m, ok := p.Mounts[policy.PodmanStubDir+"/podman"]
	if !ok || !m.Authored {
		return
	}
	fmt.Fprintf(out, "COMMANDS  %s\n", m.Guest)
	fmt.Fprintf(out, "         podman on this host resolves to a shim that cannot reach the host from\n")
	fmt.Fprintf(out, "         inside a sandbox (distrobox-host-exec, host-spawn or flatpak-spawn), so\n")
	fmt.Fprintf(out, "         snug staged a dispatcher ahead of it on PATH: it forwards a fixed\n")
	fmt.Fprintf(out, "         allowlist of docker subcommands to 'docker', byte for byte, and refuses\n")
	fmt.Fprintf(out, "         everything else by name — never a flag rewrite, never a translation.\n")
	fmt.Fprintf(out, "         It is read-only (see the FILESYSTEM line above: 'exec', not writable),\n")
	fmt.Fprintf(out, "         and /usr/bin/podman is UNTOUCHED — still reachable by its absolute path,\n")
	fmt.Fprintf(out, "         just no longer first on PATH. See .claude/design/CONTAINER-CLIENT.md §8.\n")
}

// describeNetwork spells out what the sandbox can and cannot reach. The
// negative half matters more than the positive half and is stated first.
func describeNetwork(out *os.File, p *policy.Policy) {
	switch p.Net.Mode {
	case policy.NetIsolated:
		fmt.Fprintf(out, "NETWORK  isolated — private netns, loopback only, no helper process.\n")
		fmt.Fprintf(out, "         No egress. No host loopback. No abstract sockets (X11/D-Bus are\n")
		fmt.Fprintf(out, "         netns-scoped, so they are out too). Add the '@net' profile for egress.\n")
	case policy.NetEgress:
		fmt.Fprintf(out, "NETWORK  egress — private netns (one per sandbox) with a pasta helper.\n")
		fmt.Fprintf(out, "         host loopback   UNREACHABLE (--map-host-loopback none, -T none, -U none)\n")
		fmt.Fprintf(out, "         abstract unix   UNREACHABLE (netns-scoped: X11, D-Bus)\n")
		fmt.Fprintf(out, "         egress          full, IPv4 + IPv6\n")
		if p.Net.DNS {
			fmt.Fprintf(out, "         dns             169.254.1.1 -> pasta -> host resolver\n")
		}
		if len(p.Net.Publish) > 0 {
			fmt.Fprintf(out, "         host -> sandbox ports %v, on the host's 127.0.0.1 only\n", p.Net.Publish)
		} else {
			fmt.Fprintf(out, "         host -> sandbox CLOSED (publish = [3000] in a profile opens one)\n")
		}
		if p.Net.Address != "" {
			fmt.Fprintf(out, "         address         %s (synthetic; the host's LAN address is hidden)\n", p.Net.Address)
		} else {
			fmt.Fprintf(out, "         address         copied from the host — add '@net-anon' to hide it\n")
		}
	case policy.NetHost:
		fmt.Fprintf(out, "NETWORK  HOST — the sandbox SHARES your network namespace.\n")
		fmt.Fprintf(out, "         Every 127.0.0.1 service, every abstract socket (X11 keylogging and\n")
		fmt.Fprintf(out, "         screenshots included), and the LAN as you. Requires --i-know.\n")
	}
}

// notGranted probes for paths a reasonable person would expect to be there and
// confirms they are absent from the grant set. This is the only advisory part
// of explain — but it is what makes deny-by-default legible rather than
// something you take on faith.
func notGranted(p *policy.Policy) []string {
	var lines []string

	candidates := []string{
		".ssh", ".gnupg", ".aws", ".config/gh", ".kube", ".docker", ".netrc",
		".claude", ".mozilla", ".local/share/keyrings",
	}
	var absent []string
	for _, c := range candidates {
		full := filepath.Join(p.Home, c)
		if _, err := os.Stat(full); err != nil {
			continue // not on this host either; do not claim credit for it
		}
		if !covered(p, full) {
			absent = append(absent, "~/"+c)
		}
	}
	if len(absent) > 0 {
		lines = append(lines, strings.Join(absent, "  "))
	}

	// Siblings of the target, which is the property the parent-ro profile is
	// really about: the parent is readable, its other children are not.
	parent := filepath.Dir(p.Target)
	if entries, err := os.ReadDir(parent); err == nil {
		n := 0
		for _, e := range entries {
			full := filepath.Join(parent, e.Name())
			if full != p.Target && !covered(p, full) {
				n++
			}
		}
		if n > 0 {
			lines = append(lines, fmt.Sprintf("%d sibling entries under %s", n, parent))
		}
	}

	lines = append(lines, "/sys  /tmp/.X11-unix  the Wayland socket  the session D-Bus socket")
	return lines
}

// covered reports whether a host path is reachable through some grant.
func covered(p *policy.Policy, host string) bool {
	for _, m := range p.Mounts {
		if m.Kind != policy.KindBind {
			continue
		}
		if host == m.Host || strings.HasPrefix(host, m.Host+"/") {
			return true
		}
	}
	return false
}

func formatArgs(args []string) string {
	var b strings.Builder
	b.WriteString("bwrap")
	for _, a := range args {
		if strings.HasPrefix(a, "--") || a == "--" {
			b.WriteString("\n  ")
		} else {
			b.WriteString(" ")
		}
		b.WriteString(a)
	}
	return b.String()
}
