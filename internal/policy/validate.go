package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// Validate runs before any argv is emitted, so that a mistake surfaces as a
// readable error here rather than as a bwrap abort with no provenance.
func (p *Policy) Validate(env Environ) error {
	if p.Target == "" {
		return fmt.Errorf("no target")
	}

	// Topology is derived, never set independently, so a policy whose Topology
	// disagrees with what its own Net/Podman would produce did not come through
	// Resolve. This closes the zero-value hazard on hand-built policies: several
	// unit tests construct &Policy{...} directly, and a zero Topology silently
	// read as NetnsSandbox/SubuidNone even for a policy whose Net.Mode or
	// Podman would derive something higher.
	if want := deriveTopology(p.Net.Mode, p.Podman); p.Topology != want {
		return fmt.Errorf("policy.Topology (%s) does not match what Net.Mode=%s and Podman=%s derive "+
			"(%s): build the fixture through Resolve, or set Topology with deriveTopology",
			p.Topology, p.Net.Mode, p.Podman, want)
	}

	// Report the whole picture at once. Someone who selected an empty or
	// near-empty profile set has a concept problem, not a missing flag, and
	// telling them one gap at a time makes them fix it one gap at a time.
	hasRuntime := false
	for g := range p.Mounts {
		if g == "/usr" || g == "/bin" {
			hasRuntime = true
		}
	}
	// The target must be REACHABLE, not necessarily writable. A read-only view
	// of a project is a legitimate sandbox — it is what `sys parent-ro` gives
	// you — so requiring rw here would forbid a perfectly good configuration.
	hasTarget := false
	for _, m := range p.Mounts {
		if m.Kind != KindBind {
			continue
		}
		if p.Target == m.Guest || strings.HasPrefix(p.Target, m.Guest+"/") {
			hasTarget = true
			break
		}
	}

	switch {
	case !hasRuntime && !hasTarget && len(p.Profiles) == 0:
		// Nothing was selected AT ALL — not "a profile that happens to grant
		// nothing", there is no such profile any more (see @null's removal).
		// This is the lattice floor: /proc, /dev, /tmp and
		// /etc/resolv.conf, and no KindBind anywhere. It is the correct result
		// of resolving an empty selection, and it is also --no-defaults's exact
		// destination — say so, since that is the flag whoever got here typed
		// (or the one their config.toml's `defaults = []` reaches silently).
		return fmt.Errorf("no profile selected: this is the floor of the lattice — an empty tmpfs "+
			"root, no OS runtime, no target — and nothing can run in it.\n"+
			"       This is what --no-defaults selects.\n"+
			"       Try:  snug %s          (uses the default profile selection)\n"+
			"       See:  snug profile list", p.Target)
	case !hasRuntime && !hasTarget:
		return fmt.Errorf("the selected profiles (%s) grant nothing: no OS runtime to execute, "+
			"and no writable target.\n"+
			"       This is the empty sandbox — it is the correct floor of the model, but nothing can run in it.\n"+
			"       Try:  snug %s          (uses the default profile selection)\n"+
			"       See:  snug profile list",
			JoinNames(p.Profiles, " "), p.Target)
	case !hasRuntime:
		return fmt.Errorf("no OS runtime granted: neither /usr nor /bin is readable, so nothing can execute " +
			"(add the 'sys' profile)")
	case !hasTarget:
		return fmt.Errorf("target %s is not visible inside the sandbox: no profile grants it.\n"+
			"       Add 'target-rw' to make it writable, or 'parent-ro' to see it read-only.", p.Target)
	}

	// Build the sandbox's own symlink map so we can resolve guest paths through
	// the links snug itself creates.
	links := map[string]string{}
	for _, m := range p.Mounts {
		if m.Kind == KindSymlink {
			t := m.Host
			if !filepath.IsAbs(t) {
				t = filepath.Join(filepath.Dir(m.Guest), t)
			}
			links[m.Guest] = filepath.Clean(t)
		}
	}

	// Read once: RULE 5 asks the same table of every bind, and a run has dozens.
	// A table snug cannot read is not a refusal — see kernelTreeAt.
	hostMounts, err := env.HostMounts()
	if err != nil {
		hostMounts = nil
	}

	guests := make([]string, 0, len(p.Mounts))
	for g := range p.Mounts {
		guests = append(guests, g)
	}
	sort.Strings(guests)

	for _, g := range guests {
		m := p.Mounts[g]
		// KindGraft and KindCgroup2 belong ONLY in p.Grafts, installed by
		// Policy.Graft — never in p.Mounts, which is the PAYLOAD's mount set.
		// There is no legitimate way for either to arrive here (no TOML key
		// produces a Graft, and Policy.Graft never writes p.Mounts), so this
		// refuses a bug rather than a real configuration. It exists because
		// bwrap.go's switch has no case for either Kind and never will (a
		// graft, or the engine's own cgroup2 mount, is unreachable from the
		// bwrap argv by design — bwrap 0.11.2 has no flag that can express
		// either): without this check, one landing in p.Mounts would either
		// vanish from the argv silently (the --seccomp-after-`--` shape) or, if
		// BwrapFlags were ever changed to fall through on an unrecognised Kind,
		// would emit a real mount into the PAYLOAD's namespace of a subtree
		// meant for the engine alone — exactly the leak ENGINE-NETNS.md §5.1
		// step 3 exists to prevent. (KindProc is deliberately not in this list:
		// it legitimately appears in p.Mounts already, for the sandbox's own
		// /proc — see bwrap.go's default arm.)
		if m.Kind == KindGraft || m.Kind == KindCgroup2 {
			name := "KindGraft"
			if m.Kind == KindCgroup2 {
				name = "KindCgroup2"
			}
			return fmt.Errorf("mount %q (from %s) is a %s in p.Mounts: a %s mount belongs only in\n"+
				"       p.Grafts, installed by Policy.Graft — it must never reach the payload's own\n"+
				"       mount set. Remove it from p.Mounts; if the intent was to expose this path to\n"+
				"       the ENGINE's derived view, call Policy.Graft after Resolve instead.",
				g, provenance(m), name, m.Kind)
		}
		if err := checkPathHygiene("grant", g, provenance(m), "INSIDE the sandbox"); err != nil {
			return err
		}
		// The root is snug's, whatever the kind. This used to refuse only a BIND
		// at /, which left `tmpfs = ["/"]` accepted — and inert, but only by
		// accident: nearestCovering stops before / and never returns it, so the
		// masking rule cannot see anything nested under a root grant. What saved
		// it was SortedMounts emitting / first, so every sibling landed on top.
		// That makes the invariant depend on mount ORDER rather than on the
		// check, which is precisely the shape that breaks quietly the day the
		// ordering is tuned for an unrelated reason. Refuse the whole path
		// instead: bwrap's root is already a tmpfs, so a profile has nothing to
		// gain here, and an invariant with no exception can be checked by
		// grepping for one. (redteam.)
		if g == "/" && !m.Authored {
			return fmt.Errorf("profile %s puts %s at /, but the sandbox root is snug's own:\n"+
				"       it is already an empty tmpfs, and the masking rule cannot see inside a grant\n"+
				"       at / — nothing above it can be judged. Grant the paths you meant instead.",
				provenance(m), describeNode(m))
		}
		// RULE 4: /proc, /dev and the staging directory belong to snug, and a
		// profile may not take them — nor anything CONTAINING them.
		//
		// snug authors /proc and /dev AFTER the profile fold and yields to whatever
		// is already there (Resolve step 4), so a profile grant at either path
		// silently DISPLACED snug's — `ro = ["/proc"]` handed the sandbox the
		// host's procfs instead of one bound to its own pid namespace, and a bind
		// at /dev would substitute the host's device tree for bwrap's synthetic
		// minimal set. Neither is a hole a profile gets to open. The yield is what
		// lets this refusal name the profile that did it; /tmp yields for real,
		// because a profile replacing the private tmpfs with a host directory
		// it names is the intended use.
		//
		// COVERING, not just AT, and that distinction is the whole of issue #22.
		// The check was an exact map lookup, so a grant AT the staging directory
		// was refused and a grant one directory up was accepted — the identical
		// hole. Measured, with @podman-socket to put the directory on PATH:
		// WROTE-OK, `command -v git` resolved to it, and the shadowed git RAN.
		// (The paths in that measurement were the pre-#206 ones under /run/snug;
		// the shape is unchanged, one namespace over.) --remount-ro / does
		// not reach either, because the profile's tmpfs is a separate mount and the
		// staging directory is then created inside it.
		//
		// /proc and /dev did NOT have the same hole, and only by luck of depth:
		// their one strict ancestor is /, which the check above refuses for every
		// kind. Measured — `tmpfs = ["/"]` and `rw = ["/tmp:/"]` both refused. They
		// go through the same predicate now so the property does not depend on a
		// path happening to sit at depth 1.
		if at, own, ours := snugsOwnCovered(g); ours && !m.Authored {
			if at == g {
				// "displaces it" was the whole sentence here, and it was written
				// for /proc and /dev, where snug really does author a node a
				// profile would replace. It is inaccurate for SnugDir and
				// StagedBinDir, where snug mounts NOTHING and the hazard is the
				// opposite shape: a profile's mount is a separate mount that
				// `--remount-ro /` does not reach inside, so the directory that
				// was unwritable becomes writable.
				return fmt.Errorf("profile %s puts %s at %s, but %s is snug's own: %s\n"+
					"       Whatever a profile puts there takes it over — by displacing the node snug\n"+
					"       authors, or, where snug mounts nothing at all, by being a separate mount that\n"+
					"       --remount-ro / does not reach inside. Either way it is a hole no profile may\n"+
					"       open.\n"+
					"       %s",
					provenance(m), describeNode(m), g, g, own.why, own.instead)
			}
			return fmt.Errorf("profile %s puts %s at %s, which CONTAINS %s — and %s is snug's own: %s\n"+
				"       A grant at an ancestor takes the descendant with it: %s ends up inside that\n"+
				"       mount instead of where snug put it, and the property snug relies on there\n"+
				"       stops holding. Naming the parent is not a narrower grant than naming the child.\n"+
				"       %s",
				provenance(m), describeNode(m), g, at, at, own.why, at, own.instead)
		}
		// RULE 4b: SnugDir is snug's own NAMESPACE, and that is the difference
		// between this rule and the one above (issue #206).
		//
		// Rule 4 is a LIST, and it had to grow every time snug acquired a path.
		// The reason it gave for the staging directory — a profile's mount is a
		// SEPARATE mount, so `--remount-ro /` does not reach inside it and the
		// directory snug relied on being unwritable becomes writable — applies
		// word for word to every path snug will ever own; Tier C (#125) alone
		// would have added four. So this one is stated over the namespace rather
		// than over its current members, and a path snug adds next is protected
		// the day it exists rather than the day someone remembers the entry.
		//
		// It asks a DIFFERENT question from rule 4 and does not repeat it. Rule 4
		// asks "does this grant swallow a node snug placed" — an ancestor test,
		// over a map of specific paths. This one asks "is this grant inside
		// snug's namespace at all", which catches the paths snug has not placed
		// yet: /snug/engine (issue #125's graft destinations) is refused here on
		// the day the name is chosen, not on the day someone remembers to add a
		// map entry. Between them there is no gap and no overlap.
		if !m.Authored && insideSnugDir(g) && !stagedFileUnderSnugDir(g, m) {
			return fmt.Errorf("profile %s puts %s at %s, inside snug's own namespace %s:\n"+
				"       the ONE thing a profile may do there is stage a single executable read-only\n"+
				"       under %s, which is what that directory exists for. Anything else — a tmpfs, a\n"+
				"       writable bind, or a mount AT one of the directories snug creates — either\n"+
				"       displaces something snug put there or escapes --remount-ro / and becomes a\n"+
				"       writable directory ahead of /usr/bin on the PATH snug hands over.\n"+
				"       Stage the FILE, never the directory:\n"+
				"         ro = [\"/host/path/tool:%s/tool\"]",
				provenance(m), describeNode(m), g, SnugDir, StagedBinDir, StagedBinDir)
		}
		// RULE 5: no profile may bind FROM /proc, /dev or /sys, at any access.
		// The abuse each one carries is in kernelTrees, below.
		//
		// The HOST end, because the guest end says nothing about it: a redteam
		// round broke a guest-only version with `rw = ["/sys/fs/cgroup:/mnt/cg"]`,
		// measured inside the sandbox as cgroup2 rw with `mkdir
		// /mnt/cg/snugpwn_redteam` succeeding.
		if t, under, ok := kernelTreeAt(hostMounts, m); ok {
			what := fmt.Sprintf("That is %s, one of the kernel's own trees, and no profile may\n"+
				"       bind from one at any access.", t.path)
			instead := t.instead
			if under != "" {
				what = fmt.Sprintf("%s is mounted BENEATH it, and bwrap's bind is RECURSIVE, so\n"+
					"       %s — one of the kernel's own trees — comes too. No profile may bind from\n"+
					"       one at any access.", VisibleText(under), t.path)
				instead = "Grant the parts of that directory you meant instead. Naming the parent is not\n" +
					"       a narrower grant than naming the child, and nothing on screen says what a\n" +
					"       recursive bind brought with it."
			}
			return fmt.Errorf("profile %s binds the host's %s at %s.\n"+
				"       %s\n"+
				"       %s\n"+
				"       Read-only is not a bound here, so `ro` is refused too.\n"+
				"       %s",
				provenance(m), VisibleText(m.Host), VisibleText(g), what, t.abuse, instead)
		}
		// RULE 5b: the GUEST end, /sys only. Nothing judges a Mount against
		// EngineMountpoints, so a profile mount there collides with the
		// engine's --dir entries and the cgroup2 graft, and argv order decides.
		//
		// /proc and /dev are NOT here on purpose. Their guest end is closed at
		// and above by RULE 4 and strictly inside by checkNesting, which runs
		// from rejectMasking AFTER this loop — an arm here would preempt it and
		// replace a message naming the outer pseudo-filesystem with this one.
		if !m.Authored {
			if t, ok := namesKernelTree(g); ok && t.path == "/sys" {
				return fmt.Errorf("profile %s puts %s at %s, but /sys inside the sandbox is snug's own:\n"+
					"       snug creates /sys, /sys/fs and /sys/fs/cgroup for a container engine run and\n"+
					"       grafts a fresh cgroup2 at the last of them, and a mount at or under /sys\n"+
					"       collides with those — which one survives is decided by argv order.\n"+
					"       There is nothing to grant: a sandbox has no /sys unless an engine run needs\n"+
					"       one, and that one is snug's.",
					provenance(m), describeNode(m), VisibleText(g))
			}
		}
		// A TOMBSTONE, and it is deliberately a refusal rather than silence.
		//
		// snug's own paths moved out of legacySnugDir in issue #206. A profile
		// on this host that still names the old location would otherwise keep
		// validating and quietly stop doing what its author meant: the staging
		// grant would stage into an ordinary directory that is not on PATH, and
		// nothing on screen would say so. That is the failure mode a rename owes
		// its users a refusal for.
		//
		// The cost is stated rather than hidden: legacySnugDir stays reserved,
		// so a profile that wants a runtime directory there for reasons of its
		// own cannot have that exact path any more. That is a smaller price than
		// a grant that looks fine and does nothing, and it is the only way the
		// old name can say where the new one is.
		if !m.Authored && namesLegacySnugDir(g) {
			return fmt.Errorf("profile %s puts %s at %s, but snug's own paths moved from %s to %s\n"+
				"       (issue #206), and %s is kept refused so this grant cannot silently stop\n"+
				"       working. A staging grant there would still validate, stage into a directory\n"+
				"       that is no longer on PATH, and say nothing.\n"+
				"       Stage into the new location instead:\n"+
				"         ro = [\"/host/path/tool:%s/tool\"]\n"+
				"       If you wanted an unrelated runtime directory rather than snug's, pick a path\n"+
				"       outside %s — that name is a tombstone now, not a feature.",
				provenance(m), describeNode(m), g, legacySnugDir, SnugDir, legacySnugDir,
				StagedBinDir, legacySnugDir)
		}
		// bwrap cannot create a mountpoint at a symlink destination. Catch the
		// case where a grant's guest path traverses a symlink snug itself
		// created — this is the failure that cost the previous generation a day
		// (.claude/design/INDEX.md §3.3).
		if m.Kind != KindSymlink {
			if via, resolved := resolveViaDeepest(links, g); via != "" {
				return fmt.Errorf("grant %s (from %s) resolves through the symlink %s -> %s, landing at %s; "+
					"bwrap cannot create a mountpoint at a symlink destination — grant %s instead",
					g, strings.Join(m.From, "+"), via, links[via], resolved, resolved)
			}
		}
	}

	// Grafts are p.Grafts, not p.Mounts, so the loop above never sees one — but
	// Policy.Graft is the only writer in the shipped code path, and a hand-built
	// Policy (a test, or a future caller) can write directly into p.Grafts and
	// skip its checks entirely (issue #55). Re-run G1-G5 here so that door is
	// closed structurally rather than by convention: nothing that reaches
	// bwrap.go or --dry-run can have skipped them, whichever path it came in by.
	//
	// This is the one re-check in this whole function. Every other grant is
	// checked exactly once, at fold time, because p.Mounts has one writer
	// sequence (Resolve, then Replace) that Validate always runs after. Grafts
	// are the same shape in the shipped path (Policy.Graft) but nothing forces a
	// hand-built Policy through it, so Validate is the backstop.
	grafts := make([]string, 0, len(p.Grafts))
	for g := range p.Grafts {
		grafts = append(grafts, g)
	}
	sort.Strings(grafts)
	for _, g := range grafts {
		if err := p.checkGraft(env, p.Grafts[g]); err != nil {
			return err
		}
	}

	if err := p.rejectGeneratedOntoHost(env); err != nil {
		return err
	}

	if err := p.rejectHostHomeBind(); err != nil {
		return err
	}

	if err := p.rejectEndpointSource(env); err != nil {
		return err
	}

	if err := p.rejectTargetInAnEphemeralDirectory(); err != nil {
		return err
	}

	if err := p.rejectUnboundedTmpfs(); err != nil {
		return err
	}

	if err := p.rejectRelocatedGrant(env); err != nil {
		return err
	}

	return p.rejectMasking(env)
}

// sortedGuests returns the guest paths in a stable order.
//
// Extracted when a second refusal needed it (issues #220, #179), and it is not
// tidiness: a refusal that walks a Go map reports a DIFFERENT one of several
// eligible mounts between runs, so the same policy fails with two different
// messages. That is the shape the note on snugsOwnCovered records the model
// being bitten by before.
func sortedGuests(mounts map[string]Mount) []string {
	out := make([]string, 0, len(mounts))
	for g := range mounts {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// rejectHostHomeBind refuses a policy in which a bind covers the host's $HOME.
//
// WHY THIS IS A REFUSAL AND NOT A WARNING (issue #220). snug is deliberately
// permissive about foot-guns — it will not stop you writing a typo in a profile
// variable name, and that is right for a tool whose whole model is "you name the
// holes". A bind of the home directory is a different kind of thing: it is the
// single largest grant snug can emit, and it is reachable with builtins alone.
//
//	snug --no-defaults -p @sys -p @parent-ro ~/myproject
//
// `@parent-ro` grants {target_parent}; for a target sitting directly in the home
// directory that parent IS $HOME. That started fine before this check, and
// --dry-run rendered it as one unremarkable line, visually identical to
// `ro /etc/passwd`.
//
// MEASURED through it, against a scratch home: an ssh private key read, .netrc
// read, .aws read, a git alias from the host's ~/.gitconfig EXECUTED, ~/.bashrc
// executed by an interactive shell, and — issue #219 — a host ssh-agent
// enumerated and used for a signature through the socket in ~/.ssh, which is what
// identity.ssh.agent = "proxy" (one pinned key, no enumeration) exists to prevent.
//
// Three rules this project already holds fail at once here: the command-table
// rule (read-only SUPPLIES every program the file names), the socket rule
// (#219), and what identity.ssh.agent = "proxy" exists to prevent. The working
// agreement's own test settles it — write the abuse sentence: "a hostile process inside the
// sandbox can use this to read every credential you own, execute your shell rc
// files, and sign with your ssh agent." If you cannot write it, the grant is not
// ready; this one writes itself and the answer is no.
//
// NO OVERRIDE FLAG, deliberately, on #191's reasoning in the hook's own words:
// an override is a thing an agent talks itself into.
//
// SCOPE, kept narrow on purpose. Only KindBind, and only at $HOME or an ancestor
// of it:
//
//   - a TMPFS at {home} is @home working correctly, and is in fact what makes a
//     bind there unrepresentable in the default selection;
//   - generated KindData under the home is snug's own writing;
//   - `ro {home}/src` is a perfectly good grant and stays legal — enumerating is
//     invariant 2's sanctioned answer to "X but not Y".
//
// An ancestor counts because `ro /home` exposes this home and everyone else's.
func (p *Policy) rejectHostHomeBind() error {
	if p.Home == "" {
		return nil
	}
	for _, g := range sortedGuests(p.Mounts) {
		m := p.Mounts[g]
		if m.Kind != KindBind {
			continue
		}
		// covers(), not a hand-rolled HasPrefix: the root is the case a
		// hand-rolled one gets wrong, because m.Guest+"/" is "//" and no path
		// starts with that. Found by the /-bind fixture in the test beside this.
		//
		// BOTH SIDES, and the host side is the half issue #220's rule missed
		// for a milestone (issue #601). add() canonicalises the HOST path and
		// leaves the GUEST as the profile wrote it, so one colon moves the
		// guest out from under {home} while the grant stays exactly as large:
		// `ro = ["/home/u:/mnt/h"]` bound the whole home and started without a
		// word — measured, the payload read $HOME/.secret and exited 0. The
		// direct spelling was refused on that host by the @home tmpfs
		// collision, which is a different rule and one the translated spelling
		// sidesteps for the same reason.
		//
		// Comparing the CANONICAL host against p.Home (itself EvalSymlinks of
		// $HOME) also closes the ancestor spelling a symlinked home gives for
		// free: `ro = ["/home"]` on a /home -> /var/home layout.
		// hostCovers is spelled out rather than inlined because covers("", x)
		// is TRUE — the empty outer trims to "" and every absolute path starts
		// with the "/" that leaves. add() always sets Host for a KindBind, so
		// this is unreachable from a profile; a hand-built Policy in a test is
		// what would otherwise get a refusal naming an empty path.
		hostCovers := m.Host != "" && covers(m.Host, p.Home)
		guestCovers := covers(m.Guest, p.Home)
		if !guestCovers && !hostCovers {
			continue
		}
		coveredBy := m.Guest
		if !guestCovers {
			coveredBy = m.Host
		}
		what := "your home directory"
		if coveredBy != p.Home {
			what = "an ancestor of your home directory"
		}
		// Name BOTH ends when they differ. A message quoting only the guest
		// would print "/mnt/h, which is your home directory", which reads as a
		// bug in snug rather than as the grant the profile wrote.
		where := VisibleText(m.Guest)
		if m.Host != "" && m.Host != m.Guest {
			where = fmt.Sprintf("the host's %s at %s", VisibleText(m.Host), VisibleText(m.Guest))
		}
		// TWO BODIES, because only one of the two shapes is the credential
		// disaster below and a refusal that says otherwise is a false claim on
		// the one screen a human reads to decide whether to trust snug.
		//
		// `ro = ["/etc:{home}"]` covers the home on its GUEST side and is
		// refused — correctly, {home} is not a profile's to claim — but it
		// exposes nothing of the host's home, so "every credential under it is
		// readable" is simply untrue of it. The round that graded issue #601
		// found the sentence already wrong for this input before the change and
		// newly explicit about it after, because `where` now names /etc out
		// loud.
		if !hostCovers {
			return fmt.Errorf("profile %s binds %s, which is %s (%s).\n"+
				"       Nothing of your home is handed to the sandbox by this one — its source\n"+
				"       is elsewhere — but {home} inside is snug's own: @home puts an ephemeral\n"+
				"       tmpfs there, and the generated .gitconfig, .ssh/config and .claude files\n"+
				"       are written into it. A bind at that path takes it from them.\n"+
				"       Pick a guest path that is not your home or above it, e.g.\n"+
				"       ro = [\"%s:/mnt/...\"] in your own profile.",
				provenance(m), where, what, m.Access, VisibleText(m.Host))
		}
		return fmt.Errorf("profile %s binds %s, which is %s (%s).\n"+
			"       That is the largest grant snug can emit: every credential under it is\n"+
			"       readable by the sandbox, ~/.bashrc and ~/.gitconfig are COMMAND TABLES a\n"+
			"       read-only bind SUPPLIES rather than restrains, and any agent socket in it\n"+
			"       can be used unfiltered — which is what identity.ssh.agent = \"proxy\" (one pinned\n"+
			"       key, no enumeration) exists to prevent, defeated by a mount.\n"+
			"       There is no flag to allow it. Grant the part you meant instead, e.g.\n"+
			"       ro = [\"{home}/src\"] in your own profile. If the target sits directly in\n"+
			"       your home directory, @parent-ro's \"the target's parent\" IS $HOME — move\n"+
			"       the project one level down (~/src/myproject) or select without it.",
			provenance(m), where, what, m.Access)
	}
	return nil
}

// endpointNoun names, for the refusal message, what kind of endpoint a
// mode was found to be. Kept to exactly the two modes rejectEndpointSource
// tests for — anything else is a caller bug, not a case this needs to render.
func endpointNoun(mode fs.FileMode) string {
	switch {
	case mode&fs.ModeSocket != 0:
		return "unix SOCKET"
	case mode&fs.ModeNamedPipe != 0:
		return "FIFO (a named pipe)"
	}
	return "endpoint"
}

// maxGeneratedDestLinks bounds the walk below the way the kernel bounds its own
// resolution (ELOOP at 40), so a cycle of host symlinks ends in a refusal
// rather than in a loop inside Validate.
const maxGeneratedDestLinks = 40

// linkLanding reads the host symlink at hostAt and returns where it lands in
// GUEST terms: absolute text against the sandbox's root, relative text against
// the directory the link sits in. It is the single step bwrap's resolution and
// snug's destination walks have in common, and it is here rather than copied
// because the namespace is the part that was got wrong once (#580):
// EvalSymlinks resolves against HOST components, bwrap against GUEST ones, and
// a path-translating grant makes those different places.
//
// Takes HostLinks rather than the wider Environ — Readlink is all it reads —
// so envresolve.go's walkLinks can share this exact step without needing the
// rest of Environ's host-canonicalisation surface. Every existing Environ
// value still satisfies HostLinks, so no caller here changes.
func linkLanding(env HostLinks, guestAt, hostAt string) (landing, text string, err error) {
	text, err = env.Readlink(hostAt)
	if err != nil {
		return "", "", err
	}
	landing = text
	if !filepath.IsAbs(text) {
		landing = filepath.Join(filepath.Dir(guestAt), text)
	}
	return filepath.Clean(landing), text, nil
}

// followToDestination walks from the covering grant's root down to the
// generated file, resolving every symlink the way BWRAP will — against GUEST
// components, inside the sandbox's namespace — and returns the host path bwrap
// would really touch, plus whether that path's parent directory exists on the
// host.
//
// It refuses when a link takes the destination OUT of the grant that covers it:
// there the file lands wherever the sandbox has that path, which is another
// grant's host tree or nothing at all, and neither is where the policy says the
// generated file goes.
//
// The FINAL component is never followed. bwrap opens the destination without
// following it (measured: `Can't mount on symlink destination …`), so a symlink
// there is a shape for bwrapAtDestination to answer about, not a redirection.
func (p *Policy) followToDestination(env Environ, m, outer Mount, at, host string) (hostDest string, parentExists bool, err error) {
	rest := strings.Trim(strings.TrimPrefix(m.Guest, at), "/")
	if rest == "" {
		return host, true, nil // the generated file IS the grant, which has no ancestors to walk
	}
	comps := strings.Split(rest, "/")
	last, pending := comps[len(comps)-1], comps[:len(comps)-1]

	guestAt, hostAt, links := at, host, 0

	// step resolves whatever is AT the current position, following a CHAIN of
	// symlinks until it reaches something that is not one. Following only the
	// first link was an escape of its own: the walk remapped to the link's
	// landing and moved on to the next component, so a link AT that landing —
	// the generated file's own parent, reached through an in-grant first hop —
	// was never read, and the Lstat of the finished hostDest then followed it in
	// the HOST namespace while bwrap followed it in the sandbox's. MEASURED with
	// bwrap 0.12.0 alone: `--ro-bind $cover $g --bind $realhost $wtarget` plus
	// `$cover/d -> inner` and `$cover/inner -> $wtarget`, mounting at
	// $g/d/gen.conf, exits 0 and leaves a 0444 $realhost/gen.conf on the host
	// while the literal $wtarget/gen.conf is untouched.
	//
	// It returns false when the position does not exist, which ends the walk:
	// nothing under an absent directory can be a link.
	step := func() (exists bool, err error) {
		for {
			fi, lerr := env.Lstat(hostAt)
			if errors.Is(lerr, fs.ErrNotExist) {
				return false, nil
			}
			if lerr != nil {
				return false, fmt.Errorf("profile %s grants %s on %s (the host's %s), and snug generates %s\n"+
					"       inside it, but the host path %s cannot be examined: %v.\n"+
					"       snug cannot tell where this destination lands, so it refuses rather than guess.",
					provenance(outer), outer.Access, at, VisibleText(host), m.Guest,
					VisibleText(hostAt), lerr)
			}
			if fi.Mode()&fs.ModeSymlink == 0 {
				return true, nil
			}

			if links++; links > maxGeneratedDestLinks {
				return false, fmt.Errorf("profile %s grants %s on %s (the host's %s), and snug generates %s\n"+
					"       inside it, but resolving the host symlinks between them took more than %d steps.\n"+
					"       snug cannot tell where this destination lands, so it refuses rather than guess.",
					provenance(outer), outer.Access, at, VisibleText(host), m.Guest, maxGeneratedDestLinks)
			}
			landing, text, rerr := linkLanding(env, guestAt, hostAt)
			if rerr != nil {
				return false, fmt.Errorf("profile %s grants %s on %s (the host's %s), and snug generates %s\n"+
					"       inside it, but the host symlink %s cannot be read: %v.\n"+
					"       snug cannot tell where this destination lands, so it refuses rather than guess.",
					provenance(outer), outer.Access, at, VisibleText(host), m.Guest,
					VisibleText(hostAt), rerr)
			}

			if landing != at && !strings.HasPrefix(landing, at+"/") {
				return false, fmt.Errorf("profile %s grants %s on %s (the host's %s), and snug generates %s inside it —\n"+
					"       but %s on the host is a symlink to %q, and the SANDBOX resolves that to %s,\n"+
					"       which is OUTSIDE that grant. bwrap follows it when it creates the mountpoint, so the\n"+
					"       generated file lands wherever the sandbox has that path: on the host tree of whatever\n"+
					"       grant covers it there (measured: a 0444 settings.json appeared under an unrelated rw\n"+
					"       grant, snug exit 0, before the payload ran), or, where nothing in the sandbox has that\n"+
					"       path, the run dies on bwrap's own `Can't mkdir parents for %s: No such file or directory`.\n"+
					"       A generated file is meant to land where the grant covering it says it lands.\n"+
					"       Fix: drop the %s grant on %s, or deselect %s, which generates at %s.",
					provenance(outer), outer.Access, at, VisibleText(host), m.Guest,
					VisibleText(hostAt), VisibleText(text), VisibleText(landing),
					VisibleText(m.Guest),
					outer.Access, at, provenance(m), m.Guest)
			}

			// Inside the grant: carry on from where the link points, on both
			// sides, so the rest of the path is read from the same place bwrap
			// reads it — and look again, because the landing can be a link too.
			guestAt = landing
			hostAt = filepath.Join(host, strings.TrimPrefix(landing, at))
		}
	}

	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		guestAt, hostAt = filepath.Join(guestAt, c), filepath.Join(hostAt, c)

		exists, err := step()
		if err != nil {
			return "", false, err
		}
		if !exists {
			// Not created yet. Nothing below an absent directory can be a
			// symlink, so there is no escape left to find — and the parent of
			// the destination does not exist, which is a different bwrap
			// sentence than an absent file in a directory that does.
			return filepath.Join(append([]string{hostAt}, append(pending, last)...)...), false, nil
		}
	}

	if fi, lerr := env.Lstat(hostAt); lerr != nil || !fi.IsDir() {
		// The parent is absent, or is not a directory — bwrap says "Can't mkdir
		// parents for …" rather than "Can't create file …" for both.
		return filepath.Join(hostAt, last), false, nil
	}
	return filepath.Join(hostAt, last), true, nil
}

// bwrapAtDestination is what bubblewrap does with a generated file at a
// destination of this shape, and it is the whole of rejectGeneratedOntoHost's
// second question. said is the sentence bwrap prints when it will NOT mount
// there, empty when it mounts. writes says what bwrap does to the HOST when it
// DOES mount — "creates" a mountpoint where nothing was, "overwrites" a file
// that was — and is empty for an overmount, which leaves the host alone. Both
// empty is the one accepting case.
//
// MEASURED, bubblewrap 0.12.0, every row run: fd 9 carries the content, the
// destination sits inside the cover, and the host tree was read afterwards.
//
//	destination     --ro-bind-data (AccessRO)            --file (AccessRW)
//	regular file    exit 0, host unchanged               under --bind: exit 0, HOST FILE OVERWRITTEN
//	                                                     under --ro-bind: Can't create file …: Read-only file system
//	absent          under --bind: exit 0, a 0444 file    same as --ro-bind-data
//	                CREATED on the host; under
//	                --ro-bind: Can't create file …:
//	                Read-only file system
//	symlink         Can't mount on symlink destination … Can't create file …: Too many levels of symbolic links
//	dangling link   same                                 same
//	directory       Destination is not a file …          Can't create file …: Is a directory
//	FIFO            exit 0, host unchanged               BLOCKS in the open and never returns; killed at 10s
//	socket          exit 0, host unchanged               Can't create file …: No such device or address
//
// The FIFO and socket rows are why this is a table and not an IsRegular test:
// bwrap binds over both and writes nothing, so refusing them would deny a
// policy bubblewrap runs. The symlink rows are why it is Lstat and not Stat —
// CVE-2026-87766's fix is what makes them refusals, and the bubblewrap before
// it followed the link and wrote the host at the link's target instead.
type bwrapVerdict struct {
	// said is the sentence bwrap prints when it will NOT mount there, empty
	// when it mounts.
	said string
	// writes is what bwrap does to the HOST when it DOES mount: "creates" a
	// mountpoint where nothing was, "overwrites" a file that was already
	// there. Empty for an overmount, which leaves the host alone.
	writes string
	// why says, in snug's own words, what bwrap objected to. fix is which
	// extra way out the refusal should offer besides dropping the grant:
	// "regular" (the destination is the wrong shape) or "rw" (the cover is
	// read-only and the generated file is not). Both empty when bwrap mounts.
	why, fix string
}

// ok reports the one accepting case: bwrap mounts, and the host is untouched.
func (v bwrapVerdict) ok() bool { return v.said == "" && v.writes == "" }

func bwrapAtDestination(dest string, fi fs.FileInfo, parentExists bool, access Access, coverWritable bool) bwrapVerdict {
	cannot := func(why string) string { return "bwrap: Can't create file " + dest + ": " + why }

	if fi == nil { // nothing at the name, so bwrap has to make the mountpoint
		if !parentExists {
			// A missing DIRECTORY above it is a different sentence and, under a
			// writable cover, a bigger footprint: bwrap makes the directories
			// too (measured: a 0700 sub/ as well as the 0444 file).
			if coverWritable {
				return bwrapVerdict{writes: "creates, along with every directory above it,"}
			}
			return bwrapVerdict{
				said: "bwrap: Can't mkdir parents for " + dest + ": Read-only file system",
				why: "nothing exists at " + dest + " on the host, nor the directory above it,\n" +
					"       so bwrap would have to CREATE both inside a read-only mount",
			}
		}
		if coverWritable {
			return bwrapVerdict{writes: "creates"}
		}
		return bwrapVerdict{
			said: cannot("Read-only file system"),
			why: "nothing exists at " + dest + " on the host, so bwrap would have to\n" +
				"       CREATE that file inside a read-only mount",
		}
	}

	shape := func(said, why string) bwrapVerdict {
		return bwrapVerdict{
			said: said,
			why:  dest + " on the host is " + fileShape(fi.Mode()) + ",\n       and " + why,
			fix:  "regular",
		}
	}

	switch mode := fi.Mode(); {
	case mode&fs.ModeSymlink != 0:
		if access == AccessRW {
			return shape(cannot("Too many levels of symbolic links"), "bwrap does not follow the name")
		}
		return shape("bwrap: Can't mount on symlink destination "+dest, "bwrap does not follow the name")
	case mode.IsDir():
		if access == AccessRW {
			return shape(cannot("Is a directory"), "a directory is not a file to copy onto")
		}
		return shape("bwrap: Destination is not a file "+dest, "a directory is not a file to mount onto")
	case mode&fs.ModeNamedPipe != 0:
		if access != AccessRW {
			return bwrapVerdict{} // bwrap binds over it and writes nothing
		}
		return shape("bwrap: (no message at all — it blocks opening the FIFO and never returns; "+
			"measured, killed after 10s)", "--file OPENS its destination, and opening a FIFO with "+
			"no reader blocks forever")
	case mode&fs.ModeSocket != 0:
		if access != AccessRW {
			return bwrapVerdict{} // likewise
		}
		return shape(cannot("No such device or address"), "--file opens its destination, and a "+
			"socket cannot be opened that way")
	}

	// --ro-bind-data binds over a regular file, and over a device node, and
	// writes nothing to either.
	if access != AccessRW {
		return bwrapVerdict{}
	}
	if fi.Mode()&fs.ModeDevice != 0 {
		// --file OPENS its destination, and bwrap mounts /dev nodev, so the open
		// is EACCES rather than a write (measured, --file onto /dev/null inside
		// a --bind of /dev).
		return shape(cannot("Permission denied"), "--file opens its destination, and bwrap "+
			"cannot open a device node there")
	}
	if coverWritable {
		return bwrapVerdict{writes: "overwrites"}
	}
	return bwrapVerdict{
		said: cannot("Read-only file system"),
		why: "snug generates there WRITABLE, which it delivers with bwrap's --file,\n" +
			"       and --file COPIES onto its destination instead of binding over it — a\n" +
			"       read-only cover refuses that however present " + dest + " is",
		fix: "rw",
	}
}

// fileShape names what is at a path, for a refusal that has to tell a human
// which shape bwrap tripped over. It is endpointNoun's wider sibling: that one
// renders the two kinds rejectEndpointSource tests for, this one renders every
// kind a generated file's destination can be found to be, because the shape is
// what decides which of bwrap's three sentences the run would have died on.
// internal/cli has the same function for the same decision one layer up
// (projectableTargetFile); neither package may import the other's.
func fileShape(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "a symlink"
	case m.IsDir():
		return "a directory"
	case m&fs.ModeNamedPipe != 0:
		return "a FIFO"
	case m&fs.ModeSocket != 0:
		return "a socket"
	case m&fs.ModeDevice != 0:
		return "a device node"
	}
	return "not a regular file"
}

// rejectEndpointSource refuses a bind whose SOURCE is a unix socket or a FIFO
// (issues #219, #287).
//
// An inode that is an ENDPOINT to a process rather than a container of bytes is
// one for which the read-only bit means nothing: may_open() clears MAY_WRITE for
// S_IFSOCK and S_IFIFO before MNT_READONLY is consulted, so `ro` guards the
// filesystem and not the process on the other end. Measured both ways — a
// payload wrote through a read-only FIFO and a host process received the bytes
// (#287), and a payload enumerated the host's ssh-agent and signed with it
// through a read-only bind after re-deriving the path `--clearenv` had stripped
// (#219).
//
// Devices are out of scope because bwrap's `nosuid,nodev` on every bind already
// closes them; there is no MS_NOFIFO and no MS_NOSOCK. That argument depends on
// snug never emitting `--dev-bind`, pinned separately.
//
// Detected by stat through the injected Environ, never by a path list: a stat
// does not care how a path was spelled, so this is not the catalogue shape #207
// deleted.
//
// AUTHORED MOUNTS ARE EXEMPT and a profile cannot borrow the exemption. snug's
// own proxy sockets are sockets deliberately — the ssh-agent proxy exposes one
// pinned key, the container proxy filters every request — and they are the
// narrower alternatives this refusal stops a mount from replacing. Three writers
// set Authored: Policy.Replace (nothing a profile expresses reaches it),
// Policy.Graft (writes p.Grafts, a different map this loop never reads), and
// Policy.yieldTo (installs base mounts only at an unclaimed guest, leaving a
// profile's grant unauthored so RULE 4 can still name it).
//
// RESIDUAL, and it is the larger half: a stat sees only endpoints that exist at
// resolve time, so a grant of a DIRECTORY still covers every socket and FIFO
// created in it afterwards. `ro {home}/.ssh` is accepted today and is a hole the
// moment an agent starts there; #287's headline measurement went through that
// door under @parent-ro alone. Scanning granted directories at resolve time was
// rejected rather than skipped: it makes acceptance depend on host state that
// changes underneath it, it is unbounded work, and it loses to anything creating
// a node after resolve returns. Two bounds keep it below critical — the payload
// cannot create the endpoint inside a read-only grant (measured: `mkfifo: cannot
// create fifo '/tmp/rodir/newfifo': Read-only file system`), so it can only
// speak to one a host process already holds open; and no mount flag would close
// it, so this is a kernel residual rather than laziness.
func (p *Policy) rejectEndpointSource(env Environ) error {
	for _, g := range sortedGuests(p.Mounts) {
		m := p.Mounts[g]
		if m.Kind != KindBind || m.Authored {
			continue
		}
		fi, err := env.Stat(m.Host)
		if err != nil {
			// Absent is not this check's business: an optional grant that does
			// not exist is legal, and a required one that does not exist is
			// refused by the existence check with a better message.
			continue
		}
		if fi.Mode()&(fs.ModeSocket|fs.ModeNamedPipe) == 0 {
			continue
		}
		noun := endpointNoun(fi.Mode())
		return fmt.Errorf("profile %s binds %s, whose source is a %s.\n"+
			"       Read-only does not restrain an endpoint. `ro` stops the sandbox REPLACING the\n"+
			"       node and does nothing about SPEAKING THROUGH it: the kernel clears MAY_WRITE\n"+
			"       for a socket, a FIFO and a device node before it ever consults the read-only\n"+
			"       bit, so MNT_READONLY guards the filesystem, not the process on the other end.\n"+
			"       Measured on a read-only bind: a payload wrote through a FIFO and a host process\n"+
			"       received the bytes, while `touch` on a regular file in the same bind got EROFS\n"+
			"       (issue #287). A socket got the host's ssh-agent enumerated and used for a\n"+
			"       signature through exactly this shape (issue #219). The private network\n"+
			"       namespace does not help either — a unix socket is filesystem, not network.\n"+
			"       If you want the sandbox to sign with ONE key, do not mount an agent socket.\n"+
			"       Put an identity block in your own profile and select it with -p:\n"+
			"           [profile.work.identity.ssh]\n"+
			"           key   = \"{home}/.ssh/id_ed25519.pub\"   # the PUBLIC half\n"+
			"           agent = \"proxy\"\n"+
			"       snug then runs a proxy that offers that one key, enumerates nothing, and needs\n"+
			"       no mount. If you want a container engine, select '@podman-socket', whose\n"+
			"       socket is a filtering proxy rather than the engine itself.\n"+
			"       NOTE THE LIMIT of this refusal: it sees the node a grant NAMES, and only if it\n"+
			"       exists now. Granting a DIRECTORY still grants every socket and every FIFO\n"+
			"       anyone puts in it later, and nothing checks that — it is how issue #287 was\n"+
			"       measured, through @parent-ro alone.\n",
			provenance(m), VisibleText(m.Guest), noun)
	}
	return nil
}

// rejectGeneratedOntoHost refuses a policy in which snug's own generated content
// would be written onto the HOST instead of into the sandbox.
//
// THE PROPERTY: for every resolved policy, no KindData mount's guest path
// resolves through a writable host bind.
//
// Why it is a refusal and not a mark. bwrap renders a writable KindData mount as
// `--file FD DEST`, and `--file` COPIES the descriptor onto DEST — creat(DEST,
// 0666) plus copy_file_data, a real write to whatever DEST resolves to. DEST
// normally lands in @home's tmpfs, where the write is harmless and dies with the
// run. A profile granting rw on a host path that COVERS DEST makes DEST resolve
// through that bind, and snug's own setup then overwrites the host's file. That
// is issue #186, and it destroyed a real ~/.claude: settings.json replaced by the
// allowlist output, .credentials.json replaced by the staged copy with the
// refreshToken gone, and CLAUDE.md created on the host at 0 bytes.
//
// Nothing escaped and no grant was exceeded — the profile asked for rw on that
// tree and got it. The writer is snug, on the way in, before the payload exists.
// Which is why no mitigation aimed at the sandboxed process reaches it, and why
// the answer is to refuse the policy rather than to warn about it: no profile
// author means "overwrite my host credentials", so there is nothing to disclose
// and nothing to negotiate. Demoting the grant to ro instead would be a
// restriction operation, which invariant 1 does not have.
//
// It is NOT @claude-shaped, and the test set says so: KindData also carries
// /etc/resolv.conf and the identity files ({home}/.gitconfig, {home}/.ssh/config,
// {home}/.ssh/known_hosts), so a profile granting rw over {home}/.ssh plus an
// identity is the same defect writing snug's generated config onto the host's.
//
// Two neighbouring cases, deliberately not refused here:
//
//   - A READ-ONLY bind covering a generated path, WHEN THE DESTINATION STAYS
//     INSIDE IT. bwrap then fails loudly and by itself: `Can't create file …:
//     Read-only file system`, which is the error that identified this mechanism
//     in the first place. That sentence used to be written without its first
//     clause and was false: a HOST symlink at a directory component inside the
//     bind takes the destination OUT of the read-only mount, bwrap's
//     mkdir_with_parents follows it, and the file is created on the host with
//     no error at all. Measured, bwrap 0.12.0 — `ro {home}/.config` plus a host
//     `~/.config/git -> ~/proj/sub/dotfiles-git` produced a 0-byte
//     `-r--r--r--` allowed_signers on the host, snug exit 0. That is what the
//     containment arm below exists for, and it is why that arm does not consult
//     Access.
//   - A tmpfs covering a generated path. That is the normal case and the whole
//     point: everything snug generates into the ephemeral $HOME sits inside
//     @home's tmpfs.
//
// This is the corner invariant 1 already names as monotonicity's thin spot,
// approached from the direction its comment does not cover. rejectMasking exempts
// snug's own authored mounts by Mount.Authored, justified — correctly — by the
// fact that nothing a profile writes can reach Policy.Replace. That still holds:
// the profile here never PRODUCES a KindData grant, it only makes one LAND on a
// writable host path. An exemption's own reach is the thing to re-read whenever a
// grant can steer where the exempted mount goes.
func (p *Policy) rejectGeneratedOntoHost(env Environ) error {
	for _, m := range p.SortedMounts() {
		if m.Kind != KindData {
			continue
		}
		// The DEEPEST mount containing the generated path is the one that
		// supplies it, the same "effective access is the deepest mount covering
		// it" rule join is keyed on. A tmpfs nested inside a writable bind
		// therefore protects the file, and correctly reports no finding.
		outer, at, ok := p.nearestCovering(m.Guest)
		if !ok || outer.Kind != KindBind {
			continue
		}
		// A bind with no host source is not a shape any profile produces, and
		// the check refuses it rather than waving it through: "I cannot tell
		// where this resolves" and "it resolves onto the host" have to give the
		// same answer, or the guard fails open on exactly the input nobody
		// anticipated. An earlier version skipped it, and the only thing that
		// exposed the branch was that no mutation of it could be made to fail.
		host := outer.Host
		if host == "" {
			host = at
		}
		// ARM 1 — CONTAINMENT, asked in the SANDBOX's namespace, because that is
		// the one bwrap resolves the destination in.
		//
		// This is the host's half of a rule Validate already applies to the
		// symlinks SNUG creates: resolveViaDeepest refuses a grant whose guest path
		// traverses a link snug itself made. Host symlinks inside a bound directory
		// cannot be enumerated lexically, so the walk costs one Lstat per component
		// between the grant's root and the file — the default selection has one.
		//
		// THE NAMESPACE IS THE POINT, and asking in the wrong one was a host write.
		// The arm used to call EvalSymlinks on the HOST path, which resolves the
		// link against host components. bwrap resolves the same link against GUEST
		// components, and a path-translating grant (`ro = ["$H:$G"]`) makes those
		// different places: a relative `../cover/real` under $H stays inside the
		// grant host-side and lands in a DIFFERENT GRANT guest-side. MEASURED, with
		// `ro = ["$S/h/cover:$S/proj"]` plus `rw = ["$S/data:$S/cover"]` and a host
		// `$S/h/cover/.claude -> ../cover/real`: snug exit 0, the payload ran, and
		// afterwards $S/data/real/settings.json existed on the HOST — 0444, created
		// before the sandbox did, named by no line of --dry-run.
		//
		// So the walk reads each link's TEXT and resolves it the way bwrap will,
		// against the guest path, then maps the landing back through the grant to
		// keep walking. hostDest comes out of it: the host path bwrap really
		// touches, which is what ARM 3 then asks about.
		//
		// NOT ATOMIC, and this says so rather than implying otherwise: Validate
		// resolves here and bwrap resolves again milliseconds later. This run's
		// payload cannot race it — the sandbox does not exist yet — but a PREVIOUS
		// run holding rw on the directory can plant the link for the next one, the
		// same residual anchor.go already states for renames.
		hostDest, parentExists, err := p.followToDestination(env, m, outer, at, host)
		if err != nil {
			return err
		}

		// ARMS 2 AND 3 — ONE QUESTION, of ONE path: what does bwrap do at
		// hostDest with a mount of this Access, inside a cover of that one?
		// bwrapAtDestination carries the measured answer, and the accept case is
		// exactly the one where bwrap mounts and the host is not touched.
		//
		// IT ASKS Lstat(hostDest) RATHER THAN READING Mount.HostDestExists, and
		// that is a fix rather than a preference. HostDestExists is set by the CLI
		// from an os.Lstat of the mount's GUEST path; hostDest is that path
		// translated through the covering grant, and the grant language has a
		// translating form (`rw = ["/host/dir:/guest/dir"]` — @claude itself uses
		// one for the staged binary). With such a cover the two are different
		// paths, and the exemption answered for the wrong one. MEASURED: @claude
		// plus `rw = ["$S/out:$S/target"]`, snug exit 0 with no refusal and nothing
		// on --dry-run, and afterwards $S/out held a 0444 .mcp.json, a .claude/ and
		// a .claude/settings.json that snug had created ON THE HOST before the
		// payload existed — issue #186's own mechanism, reached through the
		// exemption meant to prevent it.
		fi, lerr := env.Lstat(hostDest)
		if lerr != nil && !errors.Is(lerr, fs.ErrNotExist) {
			return fmt.Errorf("profile %s grants %s on %s (the host's %s), and snug generates %s\n"+
				"       inside it, but the host path %s cannot be examined: %v.\n"+
				"       snug cannot tell what bwrap would do there, so it refuses rather than guess.",
				provenance(outer), outer.Access, at, VisibleText(host), m.Guest,
				VisibleText(hostDest), lerr)
		}
		if lerr != nil {
			fi = nil // absent, which is a shape of its own below
		}

		v := bwrapAtDestination(VisibleText(hostDest), fi, parentExists, m.Access, outer.Access == AccessRW)
		if v.ok() {
			continue // bwrap mounts over an inode already there, and writes nothing
		}

		if v.writes != "" {
			// The #186 family: bwrap succeeds and the HOST is changed on the way in.
			// "creates" is a mountpoint made where nothing was; "overwrites" is
			// --file copying onto a file that was already there.
			return fmt.Errorf("profile %s grants %s on %s (the host's %s), and snug generates %s inside it.\n"+
				"       bwrap %s %s on the HOST on its way in — outside the sandbox, with no undo,\n"+
				"       and surviving teardown.\n"+
				"       A generated file is meant to land on the sandbox's own tmpfs and die with the run.\n"+
				"       Fix: drop the %s grant on %s, or deselect %s, which generates at %s.",
				provenance(outer), outer.Access, at, VisibleText(host), m.Guest,
				v.writes, VisibleText(hostDest),
				outer.Access, at, provenance(m), m.Guest)
		}

		// The other family: bwrap will not mount there at all, so the run dies on
		// ITS message, which names neither snug nor the profile nor a fix. snug
		// prints the same sentence first, and says whose grant produced it.
		fix := fmt.Sprintf("drop the %s grant on %s", outer.Access, at)
		switch v.fix {
		case "regular":
			fix = fmt.Sprintf("make %s a regular file, or %s", VisibleText(hostDest), fix)
		case "rw":
			fix = "grant rw on " + at
		}
		return fmt.Errorf("profile %s grants %s on %s (the host's %s), and snug generates %s inside it —\n"+
			"       but %s.\n"+
			"       The run dies on bwrap's own message, which names neither snug nor this profile:\n"+
			"           %s\n"+
			"       Fix: %s, or deselect %s,\n"+
			"       which generates at %s.",
			provenance(outer), outer.Access, at, VisibleText(host), m.Guest,
			v.why, v.said,
			fix, provenance(m), m.Guest)
	}
	return nil
}

// checkPathHygiene applies the two checks every path snug accepts into the
// model must pass — absolute and clean, and free of a rune that could forge a
// second line on the screen that renders it — factored out of Validate's own
// per-grant loop so a graft's Guest AND Host can run the identical checks
// (issue #55, G5) rather than a fourth hand-rolled copy. "Assert the set, not
// the site."
//
// noun names what kind of path this is for the message ("grant" for a mount's
// Guest, "graft destination" / "graft source" for a Graft's two paths); who is
// the provenance to blame; where names the screen a forged line would land on,
// since a mount's Guest lands on the FILESYSTEM block and a graft's two paths
// land on the ENGINE VIEW block, in two different namespaces.
//
// A control character is refused, not merely escaped, next to the clean-path
// check, because it is the same kind of rule — a property of the text — and
// because filepath.Clean does not touch one. The reason is the screen, not the
// kernel: --dry-run renders one row per line in fixed columns, so a newline
// inside a path prints as TWO rows, and the second can be spelled to look like
// a row nobody wrote — a lie in the artifact CLAUDE.md calls the mechanism by
// which a human can trust snug. The renderer (visibleValue/VisibleText)
// escapes these too; this refusal is what keeps a caller from putting one
// there in the first place. It asks the one predicate every sink asks
// (IsForgingRune), which is what keeps this in step with checkEnvValue and the
// renderer rather than becoming a third copy that drifts (the fate the guest-
// path check itself once had against the ASCII-only version of this rule).
func checkPathHygiene(noun, path, who, where string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s %q (from %s) is not an absolute clean path", noun, path, who)
	}
	if i := strings.IndexFunc(path, IsForgingRune); i >= 0 {
		r := []rune(path[i:])[0]
		return fmt.Errorf("%s %q (from %s) has %q in its path %s, and "+
			"%s.\n"+
			"       Every line of `snug --dry-run` is one row, so a path that spans two lines "+
			"can forge\n"+
			"       a row that does not otherwise exist. No mountpoint needs one; write the "+
			"path you meant.",
			noun, path, who, r, where, forgingRuneReason(r))
	}
	return nil
}

// ownedPath is one of the paths only snug may put a node at: why it is snug's,
// and what a profile author who reached for it should write instead.
//
// The second field is not decoration. A profile that wrote `tmpfs = ["/run"]`
// wrote it for a reason — something inside wanted a writable runtime directory
// and the root tmpfs is read-only — and a refusal that names no alternative gets
// answered by deleting the refusal, not the grant.
type ownedPath struct {
	why     string
	instead string
}

// snugsOwn are the paths only snug may put a node at, with the reason. A grant
// AT one of them is refused, and so is a grant at any ANCESTOR of one — see
// snugsOwnCovered. /tmp is deliberately NOT here: a profile replacing the
// private tmpfs with a host directory it names is the intended use of the
// yield (Resolve step 4).
var snugsOwn = map[string]ownedPath{
	"/proc": {
		why: "it must be a fresh procfs bound to the sandbox's OWN pid namespace, " +
			"or the sandbox reads the host's process table.",
		instead: "Remove the grant. snug mounts a procfs at /proc in every sandbox, so there\n" +
			"       is nothing a profile needs to add there.",
	},
	"/dev": {
		why: "it must be bwrap's synthetic minimal device set, never a bind of the host's " +
			"(which hands over every block device and every input device).",
		instead: "Remove the grant. snug mounts bwrap's device tree at /dev in every sandbox;\n" +
			"       one more device node is a change to snug, not a grant a profile can make.",
	},

	// SnugDir and StagedBinDir are here for a different reason from the other
	// two, and the difference is the point. /proc and /dev are refused because a
	// profile grant DISPLACES snug's own node. Nothing is mounted at these two
	// at all — they are plain directories on the root tmpfs, and that is
	// precisely what makes them unwritable, because `--remount-ro /` covers
	// them. A profile mounting ANYTHING there — a tmpfs, or a rw bind — is a
	// separate mount, is not covered by that remount, and turns the directory
	// writable.
	//
	// What that buys the profile is not its own writable directory. It is
	// SNUG's PATH band: HasStagedBin sees the staged executable, snug puts
	// StagedBinDir first on PATH in `(snug)` provenance, and the payload then
	// writes `git` into a directory that runs ahead of /usr/bin.
	//
	// COVERING, not just AT, and that distinction is the whole of issue #22.
	// The check was an exact map lookup, so a grant AT the staging directory was
	// refused and a grant one directory up was accepted — the identical hole.
	// Measured, with @podman-socket to put the directory on PATH: WROTE-OK,
	// `command -v git` resolved to it, and the shadowed git RAN.
	//
	// BOTH entries, not just the outer one, and the reason is `covers`'s
	// direction: a grant AT StagedBinDir does not cover SnugDir, so the outer
	// entry alone would miss exactly the case issue #22 is about. This map
	// answers "does this grant swallow a node snug placed"; rule 4b answers "is
	// this grant inside snug's namespace at all". Two questions, no overlap —
	// which is why both exist and why rule 4b does not repeat the ancestor test.
	//
	// Note what is NOT refused, and must not be: a grant at a path INSIDE the
	// staging directory. The predicate is a path-ANCESTOR test, so @claude's
	// `{home}/.local/bin/claude:/snug/bin/claude` is untouched — staging one
	// executable is the whole purpose of the directory. Nor is a sibling that
	// merely shares a string prefix: /snug/binaries is not an ancestor of
	// /snug/bin (it is refused, but by rule 4b, for being in the namespace).
	// The `why` names StagedBinDir on purpose, even though this entry is about
	// the whole namespace. A refusal that says only "/snug is snug's own" tells
	// the reader they may not have it without telling them what is at stake, and
	// the thing at stake is concrete: this grant takes the directory snug puts
	// FIRST on PATH down with it. Every refusal in this family names the thing
	// at risk, and the integration test asserts it does.
	SnugDir: {
		why: "it is the namespace snug reserves for everything it needs a path for inside " +
			"a sandbox — " + StagedBinDir + " among them — and those paths are unwritable " +
			"only because they are plain directories on the root tmpfs that --remount-ro / " +
			"covers. A mount here takes " + StagedBinDir + " with it, and snug puts that " +
			"directory FIRST on PATH.",
		instead: "Grant the path you actually meant — any path that neither is nor contains\n" +
			"       " + SnugDir + ". Nothing a profile needs lives there; it is snug's own.",
	},
	StagedBinDir: {
		why: "it is a plain directory on the root tmpfs, which is what makes it " +
			"unwritable once / is remounted read-only, and snug puts it FIRST on PATH. " +
			"A mount at or above it is not covered by that remount, so it would hand the " +
			"payload a writable directory ahead of /usr/bin.",
		instead: "Stage the FILE, never the directory:\n" +
			"         ro = [\"/host/path/tool:" + StagedBinDir + "/tool\"]\n" +
			"       If you named an ancestor because something inside needs a writable runtime\n" +
			"       directory, grant THAT directory — any path that neither is nor contains\n" +
			"       " + StagedBinDir + ".",
	},
}

// covers reports whether a node at guest path outer contains inner: the same
// path, or inner strictly beneath it. It is the same lexical relation
// nearestCovering and coveringMount walk upwards to find, asked in the other
// direction — those two search the resolved mount set for what supplies a path,
// while this one asks whether one path swallows another, which is what a
// per-grant check needs.
//
// Both arguments must be absolute and filepath.Clean. Validate has already
// refused any grant that is not, and the profile layer cleans upstream anyway —
// measured, `tmpfs = ["/run/"]` reaches Validate as /run. The TrimSuffix covers
// the one clean path that ends in a slash, "/", where a naive outer+"/" would
// build "//" and match nothing.
//
// It is a path-ancestor test and NOT a string-prefix test, in both directions:
// /snug/binaries does not cover /snug/bin, and /snug/bin/claude does
// not cover /snug/bin. The first is what a bare strings.HasPrefix gets
// wrong; the second is the grant the staging directory EXISTS for, and refusing
// it would break @claude on every run.
func covers(outer, inner string) bool {
	return outer == inner || strings.HasPrefix(inner, strings.TrimSuffix(outer, "/")+"/")
}

// snugsOwnCovered reports which of snug's own paths a grant at guest would take
// over — that path itself, or any ancestor of it.
//
// The keys are sorted, so a grant covering more than one reports the same one on
// every run. Nothing reachable covers two today (the only common ancestor of
// /proc, /dev, /snug and /snug/bin is /, refused before this by its own rule), but
// a security verdict that depends on Go's map iteration order is one that
// changes between runs, and the model has been bitten by exactly that before —
// see the note on resolveViaDeepest.
// snugsOwnAncestorOf is snugsOwnCovered's mirror: the deepest of snug's own
// paths that STRICTLY CONTAINS guest, rather than the one guest contains.
// Both directions are refused for a graft, and they need separate messages —
// "you named the parent" and "you named something inside it" are different
// mistakes with different fixes.
func snugsOwnAncestorOf(guest string) (at string, own ownedPath, ok bool) {
	keys := make([]string, 0, len(snugsOwn))
	for k := range snugsOwn {
		keys = append(keys, k)
	}
	// Deepest first, so a message names the closest owner rather than the
	// alphabetically first one.
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	for _, k := range keys {
		if k != guest && covers(k, guest) {
			return k, snugsOwn[k], true
		}
	}
	return "", ownedPath{}, false
}

func snugsOwnCovered(guest string) (at string, own ownedPath, ok bool) {
	keys := make([]string, 0, len(snugsOwn))
	for k := range snugsOwn {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if covers(guest, k) {
			return k, snugsOwn[k], true
		}
	}
	return "", ownedPath{}, false
}

// rejectMasking closes the ways the grant language could still express
// subtraction. Anything mounted on top of a path a bind already exposes hides
// what was underneath, which is a `mask` rule wearing a different hat.
//
// It is tempting to allow, because hiding feels like the safe direction. Two
// reasons not to:
//
//   - It breaks the property that makes profiles composable: that adding one
//     never makes anything worse. Once a profile can hide, you cannot reason
//     about a profile set without reading every profile in it.
//   - Hiding is not reliably safe. Mask /etc/ssl and TLS clients lose their
//     trust store; mask /etc/nsswitch.conf and name lookup changes behaviour.
//     "More hidden" and "more secure" are not the same axis.
//
// The one nesting that is legitimate is re-granting the SAME underlying host
// tree at a stronger access — which is exactly what the default does, with
// `target-rw` laying rw {target} over `parent-ro`'s ro {target_parent}. That exposes a
// superset, not a subset. So a nested grant is allowed only when it is a bind
// whose host source is the corresponding subpath of the outer bind's host.
//
// An earlier version of this check looked only at KindTmpfs, and the redteam
// agent walked straight through it with a bind of an empty directory over
// /usr/share/misc: three entries became zero, with no error. Hence the check is
// now on every kind.
//
// When you want "X but not Y", the honest reading is that X was too coarse a
// grant. Grant the parts of X you meant — or grant X read-only and the parts
// you want to write separately, which the Access join already handles.
//
// RULE 2 — nesting is judged on the OUTER mount's content, because that is what
// decides whether there was anything to hide:
//
//	outer          inner allowed?
//	KindTmpfs      YES — a fresh tmpfs exposes nothing, so nothing can be hidden
//	KindBind of H  YES iff the inner is a bind of H/rel; otherwise it substitutes
//	KindProc/Dev   NO  — populated by the kernel and by bwrap, not snug's to carve
//	KindData       NO  — a grant beneath a FILE is meaningless
//	anything       YES if the inner is snug's own authored replacement (RULE 3)
//
// The KindTmpfs row is not a convenience. Everything snug puts into the
// ephemeral $HOME sits inside @home's tmpfs — @claude's read-only binds of
// {home}/.claude/skills and {home}/.claude/plugins, and every generated
// KindData file (the identity files, {home}/.gitconfig,
// {home}/.claude/settings.json) — so treating a tmpfs as maskable would break
// those profiles on the first invocation. The principled statement is the same
// one: masking requires the outer mount to HAVE content at the inner path.
//
// Two names left this sentence stale before anyone re-read it, which is worth
// noting because the row itself is load-bearing: @git's .gitconfig was cited
// here as a BIND long after @git stopped binding anything (it extracts and
// generates — .claude/design/GIT-CONFIG.md), and @claude's settings.json went
// the same way in issue #17. Both are still covered by this row; they are just
// covered as generated content rather than as binds.
//
// This function compares guest paths lexically, which is only honest because
// rejectRelocatedGrant runs first and refuses every non-Authored mount whose
// destination lands anywhere other than its own guest path (issue #588): by
// the time this runs, m.Guest IS the landing for every mount it sees, so the
// lexical comparison below is the landing comparison.
func (p *Policy) rejectMasking(env Environ) error {
	for _, m := range p.SortedMounts() {
		// RULE 3 — authorship, as a field rather than a convention. These are
		// snug's own mounts: /etc/resolv.conf, the generated identity files, the
		// staged Claude credentials, the proxy sockets. They deliberately sit on
		// top of whatever a profile exposed, and that is a REPLACEMENT, not a
		// mask: the sandbox still sees a node at that path, just a truthful one,
		// and Policy.Replace records what it displaced so --dry-run says so.
		//
		// This used to exempt Kind == KindData, justified by "no TOML key
		// produces a KindData grant". True, but a proxy for the property that
		// actually matters — WHO WROTE IT — and one that a future TOML key would
		// have inherited for free.
		//
		// THE SAME FALSE SENTENCE STOOD IN TWO PLACES, which is this project's
		// most-repeated shape: this comment and rejectEndpointSource's both said
		// "Mount.Authored is set only by Policy.Replace". It is not — there are
		// three production writers, and the claim is the one carrying "a
		// profile cannot borrow the exemption" in BOTH rules:
		//
		//   Policy.Replace   snug's own post-resolve writes. A profile cannot
		//                    express one.
		//   Policy.Graft     writes p.GRAFTS, a different map — irrelevant to
		//                    this loop and to rejectEndpointSource, which both
		//                    read only p.Mounts, but not because a graft goes
		//                    unchecked: a graft is judged by G1-G6 in
		//                    checkGraft, which Validate re-runs over every
		//                    installed graft (validate.go:326, in Validate
		//                    itself, before this function runs).
		//   Policy.yieldTo   installs snug's base mounts (/proc, /dev, /tmp)
		//                    ONLY when the guest is unclaimed. A profile's
		//                    grant at the same path is left UNauthored, which
		//                    is precisely what lets RULE 4 refuse it BY NAME.
		//
		// So the exemption holds, for a reason that has to be stated per
		// writer rather than by naming one of them.
		if m.Authored {
			continue
		}
		// THE PSEUDO-FILESYSTEM ANCESTOR IS ASKED FIRST, and it is not the same
		// question as "what is the nearest covering mount".
		//
		// nearestCovering answers "who supplies the content at this path", which
		// is the right question when the answer is a profile's bind. It is the
		// WRONG question the moment snug itself authors a mount inside /proc or
		// /dev: issue #29 put a read-only bind of /proc/sys at /proc/sys, and
		// `ro = ["/proc/sys/kernel"]` from a profile then became LEGAL — the
		// nearest covering mount was a KindBind of the same tree, so the KindBind
		// row's re-grant clause admitted it, and the KindProc row that had
		// refused every grant under /proc never ran. Measured: the suite's own
		// TestGrantStrictlyInsideProcIsFatal went red the moment that mount
		// existed, which is what this clause restores.
		//
		// The rule is stated over the REGION rather than over the nearest mount:
		// anything a profile puts strictly inside snug's procfs or device tree
		// substitutes host content for kernel content, however many snug-authored
		// mounts happen to sit between the two. A future snug-authored mount
		// under /proc or /dev therefore cannot re-open this by accident, which is
		// the property the previous spelling lacked.
		if outer, at, ok := p.pseudoAncestor(m.Guest); ok {
			return checkNesting(env, outer, at, m)
		}
		outer, at, ok := p.nearestCovering(m.Guest)
		if !ok {
			continue
		}
		if err := checkNesting(env, outer, at, m); err != nil {
			return err
		}
	}
	return nil
}

// pseudoAncestor returns the deepest KindProc or KindDev mount that strictly
// contains guest, if any. Unlike nearestCovering it looks past whatever sits
// between: the two answers differ exactly when snug has authored a mount inside
// one of those regions, which is the case that made the caller's own comment
// necessary.
func (p *Policy) pseudoAncestor(guest string) (Mount, string, bool) {
	for d := filepath.Dir(guest); d != "/" && d != "."; d = filepath.Dir(d) {
		m, ok := p.Mounts[d]
		if !ok {
			continue
		}
		if m.Kind == KindProc || m.Kind == KindDev {
			return m, d, true
		}
	}
	return Mount{}, "", false
}

// nearestCovering returns the deepest mount that strictly contains guest. The
// NEAREST one is the only one that decides: it is what actually supplies the
// content at that path, and anything further up was already judged when it was
// itself the inner mount (SortedMounts is depth-ascending, so an ancestor is
// always checked before its descendants).
func (p *Policy) nearestCovering(guest string) (Mount, string, bool) {
	for d := filepath.Dir(guest); d != "/" && d != "."; d = filepath.Dir(d) {
		if m, ok := p.Mounts[d]; ok {
			return m, d, true
		}
	}
	return Mount{}, "", false
}

func checkNesting(env Environ, outer Mount, at string, inner Mount) error {
	switch outer.Kind {
	case KindTmpfs:
		// A fresh tmpfs is empty. There is nothing underneath to hide.
		return nil

	case KindBind:
		if inner.Kind == KindBind && sameUnderlyingTree(env, outer, inner, at) {
			return nil // re-granting the same tree, e.g. target-rw over parent-ro
		}
		return fmt.Errorf("profile %s puts %s at %s, which is inside %s from profile %s.\n"+
			"       That hides what %s already exposes there, and profiles may only ever grant.\n"+
			"       Grant the parts of %s you meant instead of masking the parts you did not.",
			provenance(inner), describeNode(inner), inner.Guest, at, provenance(outer), at, at)

	case KindProc, KindDev:
		return fmt.Errorf("profile %s puts %s at %s, which is inside %s — a pseudo-filesystem the "+
			"kernel and bwrap populate, not a grant any profile made.\n"+
			"       That hides what %s already exposes there, and substitutes host content for kernel\n"+
			"       content: %s\n"+
			"       Remove the grant at %s.",
			provenance(inner), describeNode(inner), inner.Guest, at, at, snugsOwn[at].why, inner.Guest)

	case KindData:
		return fmt.Errorf("profile %s puts %s at %s, which is inside %s — a generated FILE (from %s).\n"+
			"       A grant beneath a file is meaningless: nothing can be mounted inside a regular file.\n"+
			"       Remove the grant at %s.",
			provenance(inner), describeNode(inner), inner.Guest, at, provenance(outer), inner.Guest)
	}
	// KindSymlink: unreachable here — Validate already refuses any grant whose
	// guest path traverses one of snug's own symlinks, with a better message
	// (bwrap cannot create a mountpoint at a symlink destination, §3.3).
	return nil
}

// describeNode names what a grant puts at its guest path, for a refusal.
// The message used to read "an empty tmpfs" for every kind that was not a bind,
// so a symlink conflict was reported as a tmpfs.
//
// THE HOST PATH GOES THROUGH VisibleText, because a refusal is a screen. Six
// masking refusals are built from this one function, and every one of them was
// rendering a host path verbatim — measured on this branch: a bind of a
// directory whose name carries U+202E printed escaped in the FILESYSTEM block
// and in the --ro-bind line, and RAW in the refusal that stopped the run. A host
// path cannot be REFUSED for its characters (a file on this machine may legally
// be named that way, and Validate says so), so rendering is the only guard there
// is, and it has to be at every sink rather than at the two that were tested.
func describeNode(m Mount) string {
	switch m.Kind {
	case KindBind:
		return fmt.Sprintf("a bind of %s", VisibleText(m.Host))
	case KindTmpfs:
		return "an empty tmpfs"
	case KindSymlink:
		return fmt.Sprintf("a symlink to %s", VisibleText(m.Host))
	case KindData:
		return "generated file content"
	case KindProc:
		return "a procfs"
	case KindDev:
		return "a device tree"
	}
	return m.Kind.String()
}

// sameUnderlyingTree reports whether inner re-grants the very subpath of outer
// that it sits on, rather than substituting unrelated content for it.
func sameUnderlyingTree(env Environ, outer, inner Mount, outerGuest string) bool {
	rel := strings.TrimPrefix(inner.Guest, outerGuest+"/")
	expected := filepath.Join(outer.Host, rel)
	if inner.Host == expected {
		return true
	}
	// The grant's host was canonicalised at resolve time; the path we just built
	// by joining may still contain symlinks. Compare canonical forms before
	// calling it a mask, so a symlinked /usr/share does not trip the check.
	if real, err := env.EvalSymlinks(expected); err == nil && real == inner.Host {
		return true
	}
	return false
}

// One symlink map, TWO entry points, because two different questions are asked
// of it and a single function answering both would have to hide the difference
// behind a bool. They are deliberately not folded together: the comment on each
// has to be able to say which question it answers.
//
// Both pick the DEEPEST matching link. The single function these replace
// returned the first match Go's map iteration happened to produce, which is
// nondeterministic the moment one link prefixes another — /lib and /lib64 on a
// usr-merged host is the shipped case — and a security tool whose verdict flips
// between runs is worse than one that is wrong reproducibly.

// resolveViaDeepest reports whether guest path g passes THROUGH one of our own
// symlinks, and where a mountpoint at g would actually land.
//
// g == link is SKIPPED, and that is right for a MOUNTPOINT: a grant at the link
// path is the link itself, and there is nothing being diverted. bwrap's failure
// is about creating a mountpoint at a symlink DESTINATION (.claude/design/INDEX.md
// §3.3), which only arises for a path below the link.
func resolveViaDeepest(links map[string]string, g string) (via, resolved string) {
	for link, target := range links {
		if g == link || !strings.HasPrefix(g, link+"/") {
			continue
		}
		if len(link) <= len(via) {
			continue
		}
		via, resolved = link, filepath.Join(target, strings.TrimPrefix(g, link+"/"))
	}
	return via, resolved
}

// resolveLinkForEnv rewrites a guest path through one of our own symlinks, so a
// path a profile WROTE into the environment can be compared against the paths
// that profile granted.
//
// g == link is MATCHED, and that is the difference: an environment value can be
// literally /bin, and on a usr-merged host /bin is a symlink to usr/bin rather
// than a grant. Judging it unrewritten would refuse a profile that granted /usr
// and named the path the sandbox will actually see. It returns g unchanged when
// no link applies, so the caller has one path to compare either way.
func resolveLinkForEnv(links map[string]string, g string) string {
	via, resolved := "", g
	for link, target := range links {
		if g != link && !strings.HasPrefix(g, link+"/") {
			continue
		}
		if len(link) <= len(via) {
			continue
		}
		via = link
		if g == link {
			resolved = target
			continue
		}
		resolved = filepath.Join(target, strings.TrimPrefix(g, link+"/"))
	}
	return resolved
}

// rejectTargetInAnEphemeralDirectory refuses a target that sits directly in — or
// IS — a directory some profile provides as an ephemeral tmpfs rooted at $HOME.
//
// THE CASE (issue #179). `mkdir ~/proj && snug ~/proj`: @home wants a tmpfs at
// {home}, and for a home-child target that tmpfs IS the target's parent.
//
// IT IS A USABILITY RULE AND THE MESSAGE MUST NOT DRESS IT AS A CONFLICT.
// MEASURED, with this check lifted and the default selection of the day
// (@sys @home @target-rw, since issue #550 dropped @parent-ro): `snug ~/proj`
// resolves and runs correctly — the target is read-write, $HOME is the empty
// tmpfs holding only the XDG directories and the target, ~/.ssh is absent.
// There is no mount collision to report, so reporting one would be a false
// reason for a true refusal. The maintainer's call is that a project living
// directly in the directory snug replaces with an empty tmpfs is the wrong
// thing to sandbox, and one answer beats a fork somebody guesses at.
//
// A COLLISION DOES EXIST for `-p @parent-ro`, which grants "the target's
// parent" — the tmpfs itself for a home-child target, and there is no join
// between a tmpfs and a bind (invariant 1). That is a second, real reason in
// exactly one selection, and the message names it as such rather than as the
// reason for the refusal.
//
// NOT KEYED ON $HOME, and that is the part measured before it was written.
// @home provides FIVE tmpfs paths — {home} and the four XDG directories — so
// `~/.cache/build` and `~/.config/nvim` produce the identical conflict at a
// different path. A rule written against `p.Home` would have been wrong on day
// one. It walks the resolved mounts instead, so it covers whatever the selected
// profiles actually made ephemeral.
//
// AND NOT ANY TMPFS: only one rooted at $HOME. snug's own /tmp is a tmpfs too,
// and `snug /tmp/proj` is ordinary — `mktemp -d` targets are how
// the whole integration suite build theirs. Refusing those would break snug's own
// workflow, and what happens there instead is issue #223's annotation.
//
// TWO SHAPES, and they need different sentences, because one of them has no
// working answer at all:
//
//   - the target sits IN an ephemeral directory (`~/proj`). Moving it one level
//     down works.
//   - the target IS one (`snug ~`, `snug ~/.config`). Measured: no builtin
//     selection sandboxes those at all — @target-rw includes @home, so the bind and
//     the tmpfs collide however you select. "Move it" is the only answer, and
//     saying "select differently" there would be advice that cannot be followed.
func (p *Policy) rejectTargetInAnEphemeralDirectory() error {
	if p.Home == "" || p.Target == "" {
		return nil
	}
	parent := filepath.Dir(p.Target)
	for _, g := range sortedGuests(p.Mounts) {
		m := p.Mounts[g]
		if m.Kind != KindTmpfs {
			continue
		}
		// An anchor is not what this rule is about, and without this arm every
		// home-rooted target below the first level would be refused: the anchor
		// at the target's parent (anchor.go, issue #553) would equal `parent`
		// on every default run. An anchor is placed ONLY where the deepest cover
		// is ALREADY a tmpfs, so it never converts a persistent parent into an
		// ephemeral one — the parent was ephemeral before the anchor and is
		// ephemeral after it, and whichever grant made it so is still in this
		// loop under its own name. This rule asks whether a PROFILE provides the
		// target's parent as an empty tmpfs, which is what its message says
		// ("which %s provides") and what the fix it prints acts on.
		if m.Anchor {
			continue
		}
		// Only ephemeral directories rooted at the home. snug's own /tmp is a
		// tmpfs and a /tmp target must keep working.
		if !covers(p.Home, m.Guest) {
			continue
		}
		if p.Target == m.Guest || parent == m.Guest {
			// A resolved policy cannot hold a bind AND a tmpfs at one guest —
			// Mounts is keyed by guest and join would have reported the kind
			// conflict — so the collision the pre-fold half can see is
			// unrepresentable here.
			return ephemeralTargetError(p.Target, parent, m.Guest, p.Home, provenance(m), false)
		}
	}
	return nil
}

// ephemeralTargetError is the one author of issue #179's refusal, shared by the
// pre-fold check in Resolve and the post-fold one in Validate. Two authors for
// one message is how the two halves of a rule drift apart — the shape CLAUDE.md
// names — so there is one.
//
// TWO SHAPES, because one of them has no working answer at all:
//
//   - the target sits IN an ephemeral directory (`~/proj`). Moving it one level
//     down works, and the message says exactly which command.
//   - the target IS one (`snug ~`, `snug ~/.config`). MEASURED: no builtin
//     selection sandboxes those — @target-rw includes @home, so a bind of the target
//     and the tmpfs collide however you select. Telling that user to "select
//     differently" would be advice that cannot be followed.
func ephemeralTargetError(target, parent, ephemeral, home, from string, collides bool) error {
	if target == ephemeral {
		return fmt.Errorf("refusing to sandbox %s: it IS a directory %s provides as an empty, "+
			"ephemeral tmpfs.\n"+
			"       No selection sandboxes this path — a profile must bind the target to make it\n"+
			"       visible, and that collides with the tmpfs however you choose. Sandbox a\n"+
			"       project directory instead:\n"+
			"           mkdir -p %s/src/myproject && snug %s/src/myproject",
			VisibleText(target), from, VisibleText(home), VisibleText(home))
	}
	why := "This selection RESOLVES — nothing collides — and snug refuses the shape\n" +
		"       anyway: a project living directly in the directory snug replaces with an\n" +
		"       empty tmpfs is the wrong thing to sandbox, and one answer beats a fork\n" +
		"       somebody guesses at. (Add -p @parent-ro and it collides too: that grant's\n" +
		"       \"the target's parent\" IS the tmpfs.)"
	if collides {
		why = "This selection ALSO COLLIDES — a grant in it binds the same path the tmpfs\n" +
			"       claims — and the shape is refused either way: a project living directly in\n" +
			"       the directory snug replaces with an empty tmpfs is the wrong thing to\n" +
			"       sandbox, and one answer beats a fork somebody guesses at."
	}
	return fmt.Errorf("refusing to sandbox %s: it sits directly in %s, which %s provides as an "+
		"empty, ephemeral tmpfs.\n"+
		"       Move the project one level down:\n"+
		"           mv %s %s/src/ && snug %s/src/%s\n"+
		"       %s",
		VisibleText(target), VisibleText(ephemeral), from,
		VisibleText(target), VisibleText(home), VisibleText(home),
		VisibleText(filepath.Base(target)), why)
}

// rejectUnboundedTmpfs refuses a policy that would emit a tmpfs with no
// bound. It is an internal-consistency check, not a judgement on a profile:
// Resolve always sets the field, so reaching this means a Policy was built
// by hand and would hand the payload a mount defaulting to half of host RAM
// (issue #281). Named rather than defaulted, because a default here would be
// a second copy of DefaultTmpfsSize living where nobody looks for it.
func (p *Policy) rejectUnboundedTmpfs() error {
	if p.TmpfsSizeBytes != 0 {
		return nil
	}
	for _, g := range sortedGuests(p.Mounts) {
		m := p.Mounts[g]
		if m.Kind != KindTmpfs {
			continue
		}
		return fmt.Errorf("tmpfs at %s has no size bound, so bwrap would default it to half of host RAM.\n"+
			"       Every KindTmpfs mount is bounded by Policy.TmpfsSizeBytes, which Resolve always\n"+
			"       sets. A policy that reaches here was not built by Resolve: set the field, or set\n"+
			"       tmpfs_size in ~/.config/snug/config.toml and resolve again.",
			VisibleText(m.Guest))
	}
	return nil
}

// mountEmittedAfter reports whether a is emitted strictly after b in bwrap
// argv order — SortedMounts' own comparator (types.go:600-606): depth
// ascending, then guest path lexically.
func mountEmittedAfter(a, b Mount) bool {
	da, db := depth(a.Guest), depth(b.Guest)
	if da != db {
		return da > db
	}
	return a.Guest > b.Guest
}

// afterMeError explains a walk that would have to read a mount emitted after
// the one being judged: at is the guest position the walk had reached, and
// supplier is the mount that would put content there. bwrap has not created it
// yet when it creates m's mountpoint, so anything read through it describes a
// sandbox that does not exist at that moment.
func afterMeError(m, supplier Mount, at string) error {
	return fmt.Errorf("profile %s puts %s at %s, and resolving where it lands passes through %s,\n"+
		"       which profile %s's own mount would supply — but that mount is emitted AFTER this one,\n"+
		"       so it does not exist yet when bwrap creates this mountpoint.\n"+
		"       snug cannot tell where this destination lands, so it refuses rather than guess.",
		provenance(m), describeNode(m), m.Guest, VisibleText(at), provenance(supplier))
}

// guestLanding answers, for a mount snug is about to hand bwrap, where bwrap
// will really create the mountpoint — in GUEST terms.
//
// bwrap resolves a destination path inside the SANDBOX, one component at a
// time, against whatever is mounted there at that moment. A covering bind
// supplies host content for those components, so a host symlink inside a bound
// tree diverts the mountpoint to wherever the SANDBOX has the link's text —
// which is another grant's tree, or nothing at all. MEASURED in #588 on
// bubblewrap 0.12.0: a second profile's `--ro-bind $S/w/mnt $S/G/sub/mnt`, with
// a host `$S/cover/sub -> $S/w` inside the cover bound at $S/G, landed on
// $S/w/mnt and turned the first profile's rw grant read-only, exit 0, no
// refusal, and --dry-run rendered the row at $S/G/sub/mnt.
//
// via is the guest path of the FIRST symlink that diverted the walk, and text
// is that link's text, both for the refusal. landing == m.Guest and via == ""
// is the straight case, which is every mount in the shipped profile set today.
func (p *Policy) guestLanding(env Environ, m Mount) (landing, via, text string, err error) {
	comps := strings.Split(strings.Trim(m.Guest, "/"), "/")
	last, pending := comps[len(comps)-1], comps[:len(comps)-1]

	cur, links := "/", 0

	for _, c := range pending {
		cur = filepath.Join(cur, c)

		// Re-examine the same position after every jump: a landing can itself
		// be a link, and following only the first one was the chain bug
		// followToDestination's own step() records above.
		for {
			if mm, ok := p.Mounts[cur]; ok {
				if mountEmittedAfter(mm, m) {
					return "", via, text, afterMeError(m, mm, cur)
				}
				break // bwrap made cur a directory already; nothing is followed.
			}

			outer, _, ok := p.nearestCovering(cur)
			if !ok || outer.Kind != KindBind {
				break // no host content at this position: a tmpfs is empty, /proc and /dev are kernel's.
			}

			// The same question the arm above asks, for the mount that SUPPLIES
			// the host content rather than the one that occupies the position.
			// A jump can leave the walk under a cover emitted after m, whose
			// content bwrap does not have yet when it creates this mountpoint,
			// so reading it here would answer for a sandbox that does not exist
			// at that moment. Every constructed case is already refused because
			// the landing differs from m.Guest anyway; this arm is what makes
			// that a property of the walk rather than a coincidence of the
			// cases somebody thought of.
			if mountEmittedAfter(outer, m) {
				return "", via, text, afterMeError(m, outer, cur)
			}
			host := outer.Host
			if host == "" {
				host = outer.Guest
			}
			hostAt := filepath.Join(host, strings.TrimPrefix(cur, outer.Guest))

			fi, lerr := env.Lstat(hostAt)
			if errors.Is(lerr, fs.ErrNotExist) {
				break
			}
			if lerr != nil {
				return "", via, text, fmt.Errorf("profile %s puts %s at %s, and resolving where it "+
					"lands reaches the host path\n"+
					"       %s, which cannot be examined: %v.\n"+
					"       snug cannot tell where this destination lands, so it refuses rather than guess.",
					provenance(m), describeNode(m), m.Guest, VisibleText(hostAt), lerr)
			}
			if fi.Mode()&fs.ModeSymlink == 0 {
				break
			}

			landingHere, linkText, rerr := linkLanding(env, cur, hostAt)
			if rerr != nil {
				return "", via, text, fmt.Errorf("profile %s puts %s at %s, and resolving where it "+
					"lands reaches the host symlink\n"+
					"       %s, which cannot be read: %v.\n"+
					"       snug cannot tell where this destination lands, so it refuses rather than guess.",
					provenance(m), describeNode(m), m.Guest, VisibleText(hostAt), rerr)
			}
			if via == "" {
				via, text = cur, linkText
			}
			if links++; links > maxGeneratedDestLinks {
				return "", via, text, fmt.Errorf("profile %s puts %s at %s, and resolving where it "+
					"lands took more than %d steps\n"+
					"       through host symlinks.\n"+
					"       snug cannot tell where this destination lands, so it refuses rather than guess.",
					provenance(m), describeNode(m), m.Guest, maxGeneratedDestLinks)
			}
			cur = landingHere
		}
	}

	// The final component is never followed: bwrap opens the destination
	// without following it (measured: `Can't mount on symlink destination
	// …`; INDEX §3.3), so a symlink there is not a redirection.
	return filepath.Join(cur, last), via, text, nil
}

// relocatedError explains a non-Authored mount whose guest path is not where
// bwrap really creates the mountpoint (issue #588): a host symlink inside a
// covering bind diverted the walk. via is the guest path of the symlink that
// did it and text is the link's own, unresolved text; landing is where the
// walk actually ends.
func relocatedError(p *Policy, m Mount, via, text, landing string) error {
	outer, at, _ := p.nearestCovering(via)
	host := outer.Host
	if host == "" {
		host = outer.Guest
	}
	hostVia := filepath.Join(host, strings.TrimPrefix(via, at))

	tail := "on top of whatever grant has that path, named by no line of --dry-run.\n" +
		"       Measured that way (issue #588): a second profile's rw grant became read-only, snug\n" +
		"       exit 0, no refusal."
	_, exact := p.Mounts[landing]
	cover, _, covered := p.nearestCovering(landing)
	switch {
	case !exact && !covered:
		tail = fmt.Sprintf("and nothing in the sandbox has that path, so the run dies on bwrap's own\n"+
			"       \"Can't mkdir parents for %s: No such file or directory\", which names neither snug\n"+
			"       nor this profile.", VisibleText(landing))
	case !exact && cover.Kind == KindTmpfs:
		// Say what it IS rather than the downgrade sentence above, which would
		// be a measurement this policy does not carry: a tmpfs exposes nothing
		// and dies with the sandbox, so nothing is shadowed and no access
		// changes. The grant simply takes effect nowhere a profile named.
		tail = fmt.Sprintf("inside %s, an ephemeral tmpfs that dies with the sandbox — so\n"+
			"       the grant takes effect at no path any profile named, and nothing says so.",
			VisibleText(cover.Guest))
	}

	return fmt.Errorf("profile %s puts %s at %s, but that is\n"+
		"       not where it lands.\n"+
		"       profile %s grants %s on %s (the host's %s), and %s on the host\n"+
		"       is a symlink to %q. bwrap resolves a mount destination INSIDE the sandbox, so it\n"+
		"       creates the mountpoint at\n"+
		"       %s instead — %s\n"+
		"       Fix: grant %s — the path the sandbox really has.",
		provenance(m), describeNode(m), VisibleText(m.Guest),
		provenance(outer), outer.Access, at, VisibleText(host),
		VisibleText(hostVia), VisibleText(text),
		VisibleText(landing), tail,
		VisibleText(landing))
}

// rejectRelocatedGrant refuses a non-Authored mount whose guest destination,
// resolved the way bwrap resolves it — component by component, inside the
// sandbox, through the host symlinks a covering bind carries — lands anywhere
// other than its own guest path (issue #588). Without it, a second profile
// can steer a third grant's mountpoint through a host symlink inside its own
// bound tree and land it on top of an earlier profile's grant, changing that
// grant's access with no refusal and no line of --dry-run naming it.
//
// It is the precondition rejectMasking's own doc comment now names: once
// every non-Authored mount has passed here or been refused, m.Guest IS the
// landing for every mount rejectMasking, nearestCovering and checkNesting
// see, so their lexical comparison of guest paths is the landing comparison.
//
// Authored mounts are snug's own writing, judged by rejectGeneratedOntoHost's
// own walk instead.
func (p *Policy) rejectRelocatedGrant(env Environ) error {
	for _, m := range p.SortedMounts() {
		if m.Authored {
			continue
		}
		landing, via, text, err := p.guestLanding(env, m)
		if err != nil {
			return err
		}
		if landing == m.Guest {
			continue
		}
		return relocatedError(p, m, via, text, landing)
	}
	return nil
}

// kernelTree is one of the kernel's own pseudo-filesystems a profile may not
// bind from: the ABUSE a bind of the host's copy carries, and what to write
// instead.
type kernelTree struct {
	path    string
	abuse   string
	instead string
}

var kernelTrees = []kernelTree{
	{
		path: "/proc",
		abuse: "it is the host's process table. /proc/PID/environ and /proc/PID/cmdline are\n" +
			"       readable for every host process this user owns, and a token passed in an\n" +
			"       environment variable or on a command line is exactly the host secret snug\n" +
			"       exists to keep out. /proc/PID/root, /proc/PID/cwd and /proc/PID/fd/* are\n" +
			"       worse still: the kernel resolves them to that process's own root, cwd and\n" +
			"       open files, so they land in the HOST's mount tree and read-only bounds\n" +
			"       nothing — the file reached through the symlink is in the host's mount, not\n" +
			"       in this one.",
		instead: "Remove the grant. snug mounts a procfs bound to the sandbox's OWN pid namespace\n" +
			"       at /proc in every sandbox, and that is the only procfs a sandbox may have.",
	},
	{
		path: "/dev",
		abuse: "it is the host's device tree, every block device and every input device,\n" +
			"       and read-only does not restrain a device node: the kernel clears MAY_WRITE\n" +
			"       for one before it consults MNT_READONLY (issue #287).",
		instead: "Remove the grant. snug mounts bwrap's synthetic minimal device set at /dev in\n" +
			"       every sandbox; one more device node is a change to snug, not a grant a profile\n" +
			"       can make.",
	},
	{
		path: "/sys",
		abuse: "it is the kernel's own write surface, and /sys/fs/cgroup is cgroup\n" +
			"       delegation: a delegated cgroup's cgroup.procs and cgroup.freeze reach\n" +
			"       processes OUTSIDE the sandbox.",
		instead: "Remove the grant. Nothing a profile needs lives there; a sandbox that must read a\n" +
			"       kernel attribute is a change to snug, not a grant a profile can make.",
	},
}

// kernelFSTypes recognises the kernel's own trees by FILESYSTEM rather than by
// name, mapped to the kernelTrees entry whose abuse they carry. Both halves are
// load-bearing, and each was measured breaking the other's absence:
//
//   - by name only: `ro = ["/run/host/proc:/mnt/p"]` resolved and ran — /mnt/p
//     listed the host's process table and /mnt/p/self/root listed the HOST ROOT.
//     /run/host/proc is a procfs wherever a toolbox container runs.
//   - by the grant root only: `ro = ["/run/host:/host"]` resolved and ran, and
//     /host/proc came up type proc with the host's pid 1 cmdline, /host/sys
//     type sysfs, /host/dev/dm-0 a real block device. bwrap's bind is
//     RECURSIVE, so every pseudo-filesystem BENEATH a granted regular directory
//     rides in as a submount. (redteam.)
var kernelFSTypes = map[string]string{
	"proc":        "/proc",
	"nsfs":        "/proc",
	"devtmpfs":    "/dev",
	"devpts":      "/dev",
	"sysfs":       "/sys",
	"cgroup":      "/sys",
	"cgroup2":     "/sys",
	"debugfs":     "/sys",
	"tracefs":     "/sys",
	"bpf":         "/sys",
	"securityfs":  "/sys",
	"pstore":      "/sys",
	"efivarfs":    "/sys",
	"binfmt_misc": "/sys",
	"configfs":    "/sys",
	"fusectl":     "/sys",
	"selinuxfs":   "/sys",
}

// kernelTreeAt reports which of the kernel's own trees a mount binds FROM: by
// path, by the filesystem under its host path, and by anything of that kind
// mounted beneath it. The second return is the submount that decided, empty
// when the grant root itself is the hit.
//
// KindBind is load-bearing: Mount.Host is a bind's host path and a SYMLINK's
// link target (types.go), so without it a profile symlink to /proc/self/fd —
// the sandbox's own procfs — is refused for naming a host path it does not
// name. A mount table snug could not read leaves only the path half, which is
// the pre-existing behaviour rather than a new hole.
func kernelTreeAt(mounts []HostMount, m Mount) (kernelTree, string, bool) {
	if m.Authored || m.Kind != KindBind {
		return kernelTree{}, "", false
	}
	if t, ok := namesKernelTree(m.Host); ok {
		return t, "", true
	}
	var under HostMount
	for _, hm := range mounts {
		root, ok := kernelFSTypes[hm.FSType]
		if !ok {
			continue
		}
		if strings.HasPrefix(hm.Path, strings.TrimSuffix(m.Host, "/")+"/") {
			return treeNamed(root), hm.Path, true
		}
		// The deepest kernel filesystem covering the grant root is the one it
		// is actually on; a shallower one is a tree it merely sits inside.
		if covers(hm.Path, m.Host) && len(hm.Path) > len(under.Path) {
			under = hm
		}
	}
	if root, ok := kernelFSTypes[under.FSType]; ok {
		return treeNamed(root), "", true
	}
	return kernelTree{}, "", false
}

func treeNamed(path string) kernelTree {
	for _, t := range kernelTrees {
		if t.path == path {
			return t
		}
	}
	return kernelTree{}
}

// namesKernelTree reports which of the kernel's own trees a path names — the
// tree itself or anything under it.
//
// A path COMPONENT, never a string prefix: /system, /sysroot, /devel and
// /procedures are ordinary paths. Paths are canonical here — splitSpec runs
// filepath.Clean over each — so this compares rather than re-normalises.
func namesKernelTree(p string) (kernelTree, bool) {
	for _, t := range kernelTrees {
		if p == t.path || strings.HasPrefix(p, t.path+"/") {
			return t, true
		}
	}
	return kernelTree{}, false
}
