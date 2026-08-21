package policy

import (
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
	// read as NetnsSandbox/SubuidNone even for a policy whose Net.Mode
	// is NetHost.
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
			"       Add 'cwd-rw' to make it writable, or 'parent-ro' to see it read-only.", p.Target)
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
		// because @tmp-shared replacing the private tmpfs is the intended use.
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
	// THE NETWORK VALUES ARE PROFILE TEXT AND THEY REACH TWO SCREENS.
	//
	// `address`/`gateway`/`address6`/`gateway6` are the only profile-supplied
	// scalars typed as netip rather than string (net.go's NetPolicy). The
	// parse a Prefix goes through is a SUPERSET of the old forging refusal for
	// that half of the pair — ParsePrefix refuses a v6 ZONE outright and
	// refuses trailing junk after the prefix, both measured — so the loop that
	// used to run IsForgingRune over these two raw strings is retired for
	// prefixes.
	//
	// It is NOT retired for gateways, and this is the one place the netip
	// claim above was wrong: a ZONE is arbitrary text on a netip.Addr, and
	// Addr.String() re-emits it verbatim wherever the value is later shown —
	// the NETWORK block and the pasta argv four lines below it, including the
	// `host loopback UNREACHABLE` row directly above. A red team round
	// demonstrated the pre-netip version of this exact hazard (an ESC/CR
	// payload in a raw `address` string), and the run stayed HEALTHY while the
	// screen lied: pasta's `-n` parser tolerated the trailing junk, so the
	// forged profile launched and worked, which removed the one signal that
	// would otherwise give it away. checkAddressPair's V7 is what closes the
	// zone half, and it has to run here too, not only in Resolve's own parse:
	// a hand-built Policy can hold a Gateway built directly from
	// netip.MustParseAddr("fe80::1%<payload>") — or an Address built from
	// netip.PrefixFrom(zonedAddr, bits) — without ever going through the
	// parse that would have refused it.
	//
	// One body (net.go's checkAddressPair) for both call sites, invoked here
	// with a nil owner map — Validate has no fold to attribute a value to —
	// because two spellings of the pair-and-zone rule are exactly what a
	// reader would have to diff to trust either. The renderers escape as well
	// (visibleValue), and that belt-and-braces is the same pairing
	// checkEnvValue and VisibleText already have: refusing what a profile may
	// CONTAIN and escaping what a screen may SHOW are two guarantees, not one
	// done twice.
	if err := p.Net.checkAddressPair(nil); err != nil {
		return err
	}

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

	if err := p.rejectGeneratedOntoHost(); err != nil {
		return err
	}

	if err := p.rejectHostHomeBind(); err != nil {
		return err
	}

	if err := p.rejectSocketSource(env); err != nil {
		return err
	}

	if err := p.rejectTargetInAnEphemeralDirectory(); err != nil {
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
// enumerated and used for a signature through the socket in ~/.ssh, which is the
// whole @ssh-agent filtering-proxy design defeated by a mount.
//
// Three rules this project already holds fail at once here: the command-table
// rule (read-only SUPPLIES every program the file names), the socket rule
// (#219), and @ssh-agent's one-pinned-key design. The working agreement's own
// test settles it — write the abuse sentence: "a hostile process inside the
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
		if !covers(m.Guest, p.Home) {
			continue
		}
		what := "your home directory"
		if m.Guest != p.Home {
			what = "an ancestor of your home directory"
		}
		return fmt.Errorf("profile %s binds %s, which is %s (%s).\n"+
			"       That is the largest grant snug can emit: every credential under it is\n"+
			"       readable by the sandbox, ~/.bashrc and ~/.gitconfig are COMMAND TABLES a\n"+
			"       read-only bind SUPPLIES rather than restrains, and any agent socket in it\n"+
			"       can be used unfiltered — which is the @ssh-agent proxy's one-pinned-key\n"+
			"       design defeated by a mount.\n"+
			"       There is no flag to allow it. Grant the part you meant instead, e.g.\n"+
			"       ro = [\"{home}/src\"] in your own profile. If the target sits directly in\n"+
			"       your home directory, @parent-ro's \"the target's parent\" IS $HOME — move\n"+
			"       the project one level down (~/src/myproject) or select without it.",
			provenance(m), VisibleText(m.Guest), what, m.Access)
	}
	return nil
}

// rejectSocketSource refuses a bind whose SOURCE is a unix socket (issue #219).
//
// A socket is the third noun, after the file a tool reads and the config file a
// tool INTERPRETS, and `ro` restrains it least of all: read-only stops the
// sandbox REPLACING the socket and does nothing about SPEAKING to whatever
// listens on it. The private netns does not help either — a unix socket is
// filesystem, not network.
//
// MEASURED (issue #219, found by redteam attacking #179): from a sandbox
// holding a read-only bind of a home directory, a payload enumerated the host's
// ssh-agent and signed with it. `--clearenv` had correctly stripped
// SSH_AUTH_SOCK and the payload simply re-derived the path. That is
// @ssh-agent's filtering proxy — one pinned key, no enumeration, the entire
// reason that profile exists — defeated by a mount.
//
// DETECTED BY stat, NEVER BY A PATH LIST, and that distinction is the whole
// reason this is not the catalogue shape #207 deleted. That catalogue was a
// maintained list of path strings, and #189 proved a list of strings is
// defeated by spelling one path five ways with three going unmarked. A stat
// does not care how a path was spelled, there is nothing to keep in sync with
// a third party's layout, and there is no normalisation gap. This is the
// NUL-check shape: a structural property of a VALUE, refused wherever it
// appears.
//
// internal/policy stays pure: the stat goes through the injected Environ, the
// same way every other host lookup in this package does.
//
// AUTHORED MOUNTS ARE EXEMPT, and this is not a loophole — it is the whole
// point of the rule. snug's own proxy sockets ARE sockets, deliberately: the
// ssh-agent proxy at AgentSocketGuest exposes one pinned key and enumerates
// nothing, and the container proxy filters every request. Those are the
// narrower alternatives this refusal exists to stop a mount from replacing.
// Mount.Authored is set only by Policy.Replace, which nothing a profile can
// write reaches, so a profile cannot borrow the exemption.
//
// WHAT THIS DOES NOT COVER, and it must be read as part of the rule rather
// than discovered later:
//
//   - A stat at resolve time sees only sockets that EXIST THEN. A grant of a
//     DIRECTORY is a grant of every socket anyone puts in it afterwards, and
//     that case passes this check. `ro {home}/.ssh` with no socket in it today
//     is accepted, and is a hole the moment an agent is started there.
//   - So this closes the spelled-out case and ratchets the accidental one. It
//     is not a complete answer to "a grant of a directory is a grant of every
//     socket in it", which remains the rule CLAUDE.md states and which nothing
//     mechanically enforces.
//
// A check that silently covers half its rule is this project's most-repeated
// defect — five recorded instances — so the refusal text says the same thing
// to whoever reads it.
func (p *Policy) rejectSocketSource(env Environ) error {
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
		if fi.Mode()&fs.ModeSocket == 0 {
			continue
		}
		return fmt.Errorf("profile %s binds %s, whose source is a unix SOCKET.\n"+
			"       Read-only does not restrain a socket: `ro` stops the sandbox replacing it\n"+
			"       and does nothing about speaking to whatever is listening. The private\n"+
			"       network namespace does not help either — a unix socket is filesystem, not\n"+
			"       network. Measured: a payload enumerated the host's ssh-agent and signed\n"+
			"       with it through exactly this shape (issue #219).\n"+
			"       If you want the sandbox to sign with ONE key, select '@ssh-agent', which\n"+
			"       proxies a single pinned key and enumerates nothing. If you want a\n"+
			"       container engine, select '@podman-socket', whose socket is a filtering\n"+
			"       proxy rather than the engine itself.\n"+
			"       NOTE THE LIMIT of this refusal: it sees sockets that exist NOW. Granting\n"+
			"       a DIRECTORY still grants every socket anyone puts in it later, and that\n"+
			"       case is not checked by anything.\n",
			provenance(m), VisibleText(m.Guest))
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
//   - A READ-ONLY bind covering a generated path. bwrap fails loudly and by
//     itself: `Can't create file …: Read-only file system`, which is the error
//     that identified this mechanism in the first place. Loud is correct, and a
//     second refusal here would be a rule with no failure left to prevent.
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
func (p *Policy) rejectGeneratedOntoHost() error {
	for _, m := range p.SortedMounts() {
		if m.Kind != KindData {
			continue
		}
		// The DEEPEST mount containing the generated path is the one that
		// supplies it, the same "effective access is the deepest mount covering
		// it" rule join is keyed on. A tmpfs nested inside a writable bind
		// therefore protects the file, and correctly reports no finding.
		outer, at, ok := p.nearestCovering(m.Guest)
		if !ok || outer.Kind != KindBind || outer.Access != AccessRW {
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
		return fmt.Errorf("profile %s grants rw on %s (the host's %s), and snug generates %s inside it.\n"+
			"       snug writes generated content with bwrap's --file, which COPIES onto its destination,\n"+
			"       so this policy would overwrite %s on the HOST — outside the sandbox, with no undo.\n"+
			"       A generated file is meant to land on the sandbox's own tmpfs and die with the run.\n"+
			"       Fix: drop the rw grant on %s, or deselect %s, which generates at %s.",
			provenance(outer), at, VisibleText(host), m.Guest,
			VisibleText(filepath.Join(host, strings.TrimPrefix(m.Guest, at))),
			at, provenance(m), m.Guest)
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
// snugsOwnCovered. /tmp is deliberately NOT here: @tmp-shared replacing the
// private tmpfs with a host directory is the intended use of the yield (Resolve
// step 4).
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
// `cwd-rw` laying rw {target} over `parent-ro`'s ro {target_parent}. That exposes a
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
// noting because the row itself is load-bearing: @git-ro's .gitconfig was cited
// here as a BIND long after @git-ro stopped binding anything (it extracts and
// generates — .claude/design/GIT-CONFIG.md), and @claude's settings.json went
// the same way in issue #17. Both are still covered by this row; they are just
// covered as generated content rather than as binds.
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
		// have inherited for free. Mount.Authored is set only by Policy.Replace,
		// which nothing a profile can write reaches.
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
			return nil // re-granting the same tree, e.g. cwd-rw over parent-ro
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
// THE CASE (issue #179). `mkdir ~/proj && snug ~/proj` was refused by the default
// selection with a conflict: @home wants a tmpfs at {home}, @parent-ro wants a
// read-only bind of the target's parent, and for a home-child target that parent
// IS $HOME. The refusal was correct — there is no join between a tmpfs and a
// bind, and inventing one is what invariant 1 forbids — but it named no working
// command, and ~/myproject is an extremely common layout.
//
// WHY THIS REFUSES RATHER THAN SUGGESTING. A selection without @parent-ro does
// resolve, and it is a perfectly good sandbox. The maintainer's call is that a
// project directly in the home directory is the wrong thing to sandbox in the
// first place, so snug refuses it outright and says to move the project — one
// answer rather than a fork, and nobody can reach for the other branch by
// mistake. The other branch used to be lethal; #220 closed it, so this is now a
// usability rule rather than a security one, and the message says so plainly
// instead of implying no working selection exists.
//
// NOT KEYED ON $HOME, and that is the part measured before it was written.
// @home provides FIVE tmpfs paths — {home} and the four XDG directories — so
// `~/.cache/build` and `~/.config/nvim` produce the identical conflict at a
// different path. A rule written against `p.Home` would have been wrong on day
// one. It walks the resolved mounts instead, so it covers whatever the selected
// profiles actually made ephemeral.
//
// AND NOT ANY TMPFS: only one rooted at $HOME. snug's own /tmp is a tmpfs too,
// and `snug /tmp/proj` is ordinary — `mktemp -d` targets are how VERIFY.md and
// the whole integration suite build theirs. Refusing those would break snug's own
// workflow, and what happens there instead is issue #223's annotation.
//
// TWO SHAPES, and they need different sentences, because one of them has no
// working answer at all:
//
//   - the target sits IN an ephemeral directory (`~/proj`). Moving it one level
//     down works.
//   - the target IS one (`snug ~`, `snug ~/.config`). Measured: no builtin
//     selection sandboxes those at all — @cwd-rw includes @home, so the bind and
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
		// Only ephemeral directories rooted at the home. snug's own /tmp is a
		// tmpfs and a /tmp target must keep working.
		if !covers(p.Home, m.Guest) {
			continue
		}
		if p.Target == m.Guest || parent == m.Guest {
			return ephemeralTargetError(p.Target, parent, m.Guest, p.Home, provenance(m))
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
//     selection sandboxes those — @cwd-rw includes @home, so a bind of the target
//     and the tmpfs collide however you select. Telling that user to "select
//     differently" would be advice that cannot be followed.
func ephemeralTargetError(target, parent, ephemeral, home, from string) error {
	if target == ephemeral {
		return fmt.Errorf("refusing to sandbox %s: it IS a directory %s provides as an empty, "+
			"ephemeral tmpfs.\n"+
			"       No selection sandboxes this path — a profile must bind the target to make it\n"+
			"       visible, and that collides with the tmpfs however you choose. Sandbox a\n"+
			"       project directory instead:\n"+
			"           mkdir -p %s/src/myproject && snug %s/src/myproject",
			VisibleText(target), from, VisibleText(home), VisibleText(home))
	}
	return fmt.Errorf("refusing to sandbox %s: it sits directly in %s, which %s provides as an "+
		"empty, ephemeral tmpfs.\n"+
		"       So the parent snug would grant IS that directory, and a read-only bind of it\n"+
		"       cannot coexist with the tmpfs. Move the project one level down:\n"+
		"           mv %s %s/src/ && snug %s/src/%s\n"+
		"       A selection without @parent-ro does resolve; snug does not offer it here. A\n"+
		"       project sitting directly in an ephemeral directory is the wrong thing to\n"+
		"       sandbox, and one answer beats a fork somebody guesses at.",
		VisibleText(target), VisibleText(ephemeral), from,
		VisibleText(target), VisibleText(home), VisibleText(home), filepath.Base(target))
}
