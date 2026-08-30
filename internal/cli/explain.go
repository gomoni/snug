package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// explain is --dry-run's twin for a human who has not read INDEX.md.
//
// --dry-run answers "what exactly will this do", in blocks, completely, and it
// stays the trust artifact: a human checking snug's claims reads that screen,
// and nothing here may become the thing they read instead. explain answers the
// question that comes BEFORE it — "what am I about to hand this program, and
// what am I not" — in sentences, for someone deciding whether the sandbox is
// the shape they wanted.
//
// It starts nothing, exactly as --dry-run starts nothing (issue #541), and it
// derives every sentence from the same resolved Policy. There is no host probe
// here and no second derivation: a fact that appears on both screens must
// appear because both read p, or the two will disagree and the human will
// believe whichever they read last.
//
// WHAT IS DELIBERATELY ABSENT: the mount table. Naming 40 paths in prose is
// the wall of text this flag exists to end. explain says how many, of which
// kind, and names the ones a human could be surprised by; --dry-run has the
// list, and this screen says so at the bottom rather than growing one.
func explain(env policy.Environ, out io.Writer, p *policy.Policy, args []string, cfg config, n *notes, refusedBy error) error {
	if refusedBy != nil {
		fmt.Fprintln(out, "snug — this policy was REFUSED. Nothing below can run; nothing was started.")
		fmt.Fprintf(out, "        %v\n\n", refusedBy)
	} else {
		fmt.Fprintln(out, "snug — what this sandbox would be. Nothing was started.")
		fmt.Fprintln(out)
	}

	explainWhat(out, p)
	explainFilesystem(out, p)
	explainAbsent(out, p)
	explainClaudeTrust(out, p)
	explainNetwork(out, p)
	explainEngine(out, p)
	explainCommand(out, p)
	n.render(out)

	fmt.Fprintln(out, "This is the summary. `snug --dry-run` has the complete list — every mount, every")
	fmt.Fprintln(out, "environment variable, the bwrap argv — and is the screen to read when you are")
	fmt.Fprintln(out, "checking snug rather than orienting yourself.")
	return nil
}

// explainWhat names the run: what is being sandboxed, under which profiles.
func explainWhat(out io.Writer, p *policy.Policy) {
	// Paths on their own lines rather than interpolated into a sentence: a
	// host path has no length bound, and a sentence built around one wraps at
	// whatever width the terminal happens to be. It is also the only shape
	// where a very long path cannot push the rest of the sentence off the
	// screen and take the meaning with it.
	fmt.Fprintln(out, "The project directory, writable from inside:")
	fmt.Fprintf(out, "  %s\n", visibleValue(p.Target))
	fmt.Fprintln(out, "Your home directory:")
	fmt.Fprintf(out, "  %s\n", visibleValue(p.Home))
	fmt.Fprintln(out, "Both keep the exact path they have on your host. snug never relocates a path,")
	fmt.Fprintln(out, "because a tool that prints an absolute path inside should print one that means")
	fmt.Fprintln(out, "the same thing outside.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Selected profiles:")
	fmt.Fprintf(out, "  %s\n", visibleValue(policy.JoinNames(p.Selected, " ")))
	if implied := p.Implied(); len(implied) > 0 {
		fmt.Fprintf(out, "  + %s  (pulled in by include)\n", visibleValue(policy.JoinNames(implied, " ")))
	}
	fmt.Fprintln(out, "A profile only ever GRANTS. There is no rule anywhere that takes something")
	fmt.Fprintln(out, "away, so adding a profile can only ever make the sandbox see more, and the way")
	fmt.Fprintln(out, "to see less is to select fewer.")
	fmt.Fprintln(out)
}

// explainFilesystem counts rather than lists, and names only what a human
// would be surprised by: what is WRITABLE. A read-only grant is the boring
// case; a writable one is a decision.
func explainFilesystem(out io.Writer, p *policy.Policy) {
	var rw, ro, generated int
	var writable []string
	for _, m := range p.SortedMounts() {
		if m.Kind == policy.KindData {
			generated++
			continue
		}
		if m.Access == policy.AccessRW {
			rw++
			writable = append(writable, m.Guest)
			continue
		}
		ro++
	}
	fmt.Fprintln(out, "FILESYSTEM")
	// config.go's plural, not a local one: "1 file(s)" is a screen admitting it
	// did not look at what it was saying, on the one screen whose whole job is
	// to be read as English.
	fmt.Fprintf(out, "  The root is an empty tmpfs. It has %s read-only, %d writable, and\n",
		plural(ro, "path"), rw)
	fmt.Fprintf(out, "  %s snug generates itself rather than binding from your host.\n",
		plural(generated, "file"))
	fmt.Fprintln(out, "  Everything else on this machine is not missing by a rule — it was never")
	fmt.Fprintln(out, "  granted, so there is nothing there to deny.")
	if len(writable) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "  Writable, which is the half worth reading twice:")
		sort.Strings(writable)
		for _, g := range writable {
			fmt.Fprintf(out, "    %s\n", visibleValue(g))
		}
	}
	fmt.Fprintln(out)
}

// explainAbsent is the section that has no equivalent on --dry-run, and it is
// the reason this flag is worth its code.
//
// --dry-run renders what IS. A human orienting themselves needs what is NOT,
// and on a deny-by-default model that set is not derivable by reading the
// grants — an absence leaves no row. CLAUDE.md states the rule this section
// implements: a missing capability is a feature to state plainly.
//
// EVERY SENTENCE HERE IS CONDITIONAL, and that is the correction to how this
// shipped. The first version printed four of these five as constants, so a
// profile granting `/tmp/.X11-unix` produced a screen reading "nothing inside
// can read your screen or your keystrokes" above a sandbox that could do
// exactly that — measured by the red team, with a payload opening the host X
// server through the grant. The fifth (`~/.ssh`) was conditional and still
// wrong, testing only the guest path, so `ro = ["{home}/keys"]` pointing at
// ~/.ssh read the private key under a screen saying the keys "are not in this
// filesystem at all".
//
// A screen that prints a guarantee it did not check is worse than one that
// says nothing, because the reader cannot tell which sentences were verified.
// So each line is derived, and where the capability IS granted the line
// INVERTS rather than vanishing: --explain has no environment block and lists
// only writable mounts, so a reader of this screen alone would otherwise see
// neither the grant nor the denial.
func explainAbsent(out io.Writer, p *policy.Policy) {
	fmt.Fprintln(out, "WHAT IS NOT IN HERE")

	// X11 and Wayland are a MOUNT question, not a network one — dryrun.go's
	// own note says the same about pathname sockets. $DISPLAY alone reaches
	// nothing, so the test is the socket, not the variable.
	if paths := grantedDisplaySockets(p); len(paths) > 0 {
		fmt.Fprintln(out, "  X11 or Wayland IS reachable — a profile granted the socket:")
		for _, g := range paths {
			fmt.Fprintf(out, "    %s\n", visibleValue(g))
		}
		fmt.Fprintln(out, "  Anything in this sandbox can then read your screen, read your keystrokes")
		fmt.Fprintln(out, "  and inject input into your session. That is a sandbox escape.")
	} else {
		fmt.Fprintln(out, "  No X11 and no Wayland: a GUI program will not open a window, and nothing")
		fmt.Fprintln(out, "  inside can read your screen or your keystrokes.")
	}

	if paths := grantedDBusSockets(p); len(paths) > 0 {
		fmt.Fprintln(out, "  A D-Bus socket IS granted:")
		for _, g := range paths {
			fmt.Fprintf(out, "    %s\n", visibleValue(g))
		}
		fmt.Fprintln(out, "  What that reaches depends on what is listening on your bus.")
	} else {
		fmt.Fprintln(out, "  No D-Bus, session or system. No host abstract sockets of any kind.")
	}

	// Host loopback is structural rather than derived, and stays unconditional
	// for that reason: NetIsolated has no route off loopback, and NetEgress is
	// the top of the order and starts pasta with -T none. No mode shares the
	// host's namespace, so there is no policy that makes this false — see
	// NetMode's own comment, which records that reaching one host-local port
	// is an unbuilt enumerated grant rather than a mode.
	fmt.Fprintln(out, "  No host loopback. A service you are running on 127.0.0.1 is unreachable")
	fmt.Fprintln(out, "  from inside, under every profile, including the networked ones.")

	if paths := grantedSSHPaths(p); len(paths) > 0 {
		fmt.Fprintln(out, "  ~/.ssh IS in this filesystem — a profile granted it, under:")
		for _, g := range paths {
			fmt.Fprintf(out, "    %s\n", visibleValue(g))
		}
		fmt.Fprintln(out, "  Whatever runs in here can read every private key that directory holds.")
	} else {
		fmt.Fprintln(out, "  No ~/.ssh. Your private keys are not in this filesystem at all.")
	}

	// Also structural: snug has no setuid path and every helper is a child
	// that dies with the sandbox (CLAUDE.md invariant 4).
	fmt.Fprintln(out, "  No root, no setuid, and no process snug did not start — everything here")
	fmt.Fprintln(out, "  dies with the sandbox.")
	fmt.Fprintln(out)
}

// explainClaudeTrust states the one decision snug makes on the human's behalf
// inside a @claude sandbox: Claude Code's "Quick safety check" is pre-answered
// for the target (issue #460).
//
// It is on THIS screen and not only on --dry-run because a decision taken for
// someone is the thing they most need to read first, and because the shape of
// the argument is the one --explain exists for — what is NOT here. The dialog is
// gone AND the two repo-supplied command tables it used to gate are gone with
// it; a reader who sees only the first half has been handed a downgrade
// (invariant 5).
//
// Gated on the resolved mount, like every other block here: no @claude, no
// generated ~/.claude.json, nothing to say. claudeTrustCarried reads the staged
// CONTENT rather than recomputing, so this screen and --dry-run's CLAUDE block
// cannot disagree.
func explainClaudeTrust(out io.Writer, p *policy.Policy) {
	m, ok := claudeStateMount(p)
	if !ok || !claudeTrustCarried(p, m) {
		return
	}
	fmt.Fprintln(out, "CLAUDE CODE'S SAFETY CHECK")
	fmt.Fprintln(out, "  Pre-answered by snug for the directory you named, and for no other. Claude")
	fmt.Fprintln(out, "  Code opens straight on its prompt in here, without asking whether you trust")
	fmt.Fprintln(out, "  this folder. The answer lives on this sandbox's own tmpfs and dies with the")
	fmt.Fprintln(out, "  run; your host ~/.claude.json is neither read nor written.")
	// The pay-for half, and it is derived: the projection is what makes the
	// suppression safe, so name the files that were actually reinterpreted.
	if projected := projectedTargetSettings(p); len(projected) > 0 {
		fmt.Fprintln(out, "  What that check used to gate is reinterpreted instead. These files of")
		fmt.Fprintln(out, "  this project's reach Claude Code with their hooks and MCP servers gone:")
		// One per line rather than a joined sentence: the list is one to three
		// names today and a fourth would push a joined line past 80 columns.
		for _, name := range projected {
			fmt.Fprintf(out, "    %s\n", name)
		}
	} else {
		fmt.Fprintln(out, "  This project ships no .claude/settings.json, settings.local.json or")
		fmt.Fprintln(out, "  .mcp.json, so there is nothing to reinterpret — and a NEW one written")
		fmt.Fprintln(out, "  inside is not closed.")
	}
	fmt.Fprintln(out)
}

// coversPath reports whether a mount puts target into the sandbox, in EITHER
// direction and on EITHER side.
//
// Both directions, because `ro = ["/tmp"]` grants /tmp/.X11-unix without ever
// naming it — a prefix test in one direction only would answer "no" for the
// widest grant there is. Both sides, because the guest path is a name the
// profile chose and the HOST path is what is actually being exposed:
// `ro = ["{home}/keys"]` over a symlink to ~/.ssh reads the keys under a guest
// path that says nothing about ssh, which is how the first version of this
// check missed it. --dry-run renders that host path as `(from …)`, so the
// datum was there and simply unused.
func coversPath(m policy.Mount, target string) bool {
	for _, got := range []string{m.Guest, m.Host} {
		if got == "" {
			continue
		}
		if got == target ||
			strings.HasPrefix(target, got+"/") ||
			strings.HasPrefix(got, target+"/") {
			return true
		}
	}
	return false
}

// hostExposingMounts are the mounts that can put HOST content in reach: a bind
// of a host path, or a symlink whose target is one.
//
// The other kinds are excluded because they carry nothing of the host's, and
// excluding them is load-bearing rather than tidy — coversPath deliberately
// matches an ANCESTOR grant, so without this filter the tmpfs $HOME that
// @home mounts would "cover" $HOME/.ssh and the tmpfs /tmp would "cover"
// /tmp/.X11-unix. Both were measured saying so on the plain defaults, which
// would have replaced one false sentence with another: a fresh empty tmpfs at
// a path is the opposite of the host's directory being there. KindData is
// snug's own generated content — the identity files it writes under ~/.ssh
// among them — for the same reason.
func hostExposingMounts(p *policy.Policy) []policy.Mount {
	var out []policy.Mount
	for _, m := range p.SortedMounts() {
		if m.Kind != policy.KindBind && m.Kind != policy.KindSymlink {
			continue
		}
		out = append(out, m)
	}
	return out
}

// grantedDisplaySockets names the grants that put an X11 or Wayland socket in
// reach. The X11 directory is matched by path; Wayland sockets are matched by
// name because their directory is $XDG_RUNTIME_DIR, which the pure policy
// package does not resolve.
func grantedDisplaySockets(p *policy.Policy) []string {
	var out []string
	for _, m := range hostExposingMounts(p) {
		hit := coversPath(m, "/tmp/.X11-unix")
		if !hit {
			for _, got := range []string{m.Guest, m.Host} {
				if got == "" {
					continue
				}
				base := got[strings.LastIndex(got, "/")+1:]
				if strings.HasPrefix(base, "wayland-") || strings.Contains(got, "/.X11-unix/") {
					hit = true
					break
				}
			}
		}
		if hit {
			out = append(out, m.Guest)
		}
	}
	return out
}

// grantedDBusSockets names the grants that reach a D-Bus socket. The session
// bus is $XDG_RUNTIME_DIR/bus and the system bus is a fixed path.
func grantedDBusSockets(p *policy.Policy) []string {
	var out []string
	for _, m := range hostExposingMounts(p) {
		hit := coversPath(m, "/run/dbus/system_bus_socket") ||
			coversPath(m, "/var/run/dbus/system_bus_socket")
		if !hit {
			for _, got := range []string{m.Guest, m.Host} {
				if got == "" {
					continue
				}
				base := got[strings.LastIndex(got, "/")+1:]
				if base == "bus" || strings.Contains(got, "dbus") {
					hit = true
					break
				}
			}
		}
		if hit {
			out = append(out, m.Guest)
		}
	}
	return out
}

// grantedSSHPaths names the grants that put the user's ~/.ssh into the
// sandbox, under whatever guest name the profile chose.
func grantedSSHPaths(p *policy.Policy) []string {
	var out []string
	for _, m := range hostExposingMounts(p) {
		if coversPath(m, p.Home+"/.ssh") {
			out = append(out, m.Guest)
		}
	}
	return out
}

func explainNetwork(out io.Writer, p *policy.Policy) {
	fmt.Fprintln(out, "NETWORK")
	switch p.Net.Mode {
	case policy.NetIsolated:
		fmt.Fprintln(out, "  None. The sandbox has its own empty network namespace with nothing in it")
		fmt.Fprintln(out, "  but loopback, and no helper process to carry packets anywhere. This is")
		fmt.Fprintln(out, "  the absence of a network profile rather than a setting, so it cannot be")
		fmt.Fprintln(out, "  switched back on by accident.")
	default:
		fmt.Fprintln(out, "  Full outbound internet, through a pasta helper in a namespace of its own.")
		fmt.Fprintln(out, "  Host loopback stays unreachable — pasta is started with -T none, so a")
		fmt.Fprintln(out, "  port on your own machine is not a port from in here.")
		if p.Net.DNS {
			if r := p.Net.Resolver(); len(r.Servers) > 0 {
				fmt.Fprintf(out, "  DNS: %d resolver(s), in a /etc/resolv.conf snug generates.\n", len(r.Servers))
			} else {
				fmt.Fprintln(out, "  DNS: none — a profile asked for it and this host names no usable")
				fmt.Fprintln(out, "  resolver, so lookups inside will fail immediately rather than stall.")
			}
		}
	}
	if len(p.ListenNames) > 0 {
		fmt.Fprintf(out, "  HTTP door(s) declared: %s. Nothing is reachable until you run `snug proxy`,\n",
			visibleValue(strings.Join(p.ListenNames, " ")))
		fmt.Fprintln(out, "  and opening one serves the sandbox into your own browser on an origin the")
		fmt.Fprintln(out, "  browser trusts as local. That is a sandbox escape and snug does not bound it.")
	}
	fmt.Fprintln(out)
}

func explainEngine(out io.Writer, p *policy.Policy) {
	if p.Podman == policy.PodmanOff {
		return
	}
	fmt.Fprintln(out, "CONTAINERS")
	fmt.Fprintln(out, "  There is a real container engine for this run, and it is snug's own — a")
	fmt.Fprintln(out, "  sibling process, not the host's podman and not something inside the sandbox.")
	fmt.Fprintln(out, "  What the sandbox talks to is a filtering proxy: a request that would change")
	fmt.Fprintln(out, "  state and that the filter has not read is refused rather than forwarded.")
	fmt.Fprintln(out, "  The engine sees a view DERIVED from this policy, not your host tree.")
	fmt.Fprintln(out, "  This run therefore starts a stage process even with no network profile: the")
	fmt.Fprintln(out, "  engine needs the stage for its user namespace, not for the network.")
	if p.Net.Mode == policy.NetIsolated {
		fmt.Fprintln(out, "  A container gets the sandbox's network, which here is no network. It also")
		fmt.Fprintln(out, "  means `podman run -p 8080:80` publishes nothing your host can reach.")
	} else {
		fmt.Fprintln(out, "  A container gets the SANDBOX'S network — the same egress, not a bridge of")
		fmt.Fprintln(out, "  its own — so it reaches the internet and `podman run -p` publishes nothing")
		fmt.Fprintln(out, "  your host can reach.")
	}
	fmt.Fprintln(out)
}

func explainCommand(out io.Writer, p *policy.Policy) {
	if len(p.Command) == 0 {
		return
	}
	fmt.Fprintln(out, "COMMAND")
	fmt.Fprintf(out, "  %s\n", visibleValue(strings.Join(p.Command, " ")))
	fmt.Fprintln(out)
}
