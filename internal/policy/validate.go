package policy

import (
	"fmt"
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
		// The check was an exact map lookup, so `tmpfs = ["/run/snug/bin"]` was
		// refused and `tmpfs = ["/run"]` was accepted — the identical hole one
		// directory up. Measured, with @podman-socket to put the directory on PATH:
		// WROTE-OK /run/snug/bin/git, `command -v git` resolved to it, and the
		// shadowed git RAN. Same at `tmpfs = ["/run/snug"]`. --remount-ro / does
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
				return fmt.Errorf("profile %s puts %s at %s, but %s is snug's own: %s\n"+
					"       Whatever a profile puts there displaces it, so this is a hole no profile may\n"+
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

	return p.rejectMasking(env)
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

	// StagedBinDir is here for a different reason from the other two, and the
	// difference is the point. /proc and /dev are refused because a profile grant
	// DISPLACES snug's own node. Nothing is mounted at StagedBinDir at all — it is
	// a plain directory on the root tmpfs, and that is precisely what makes it
	// unwritable, because `--remount-ro /` covers it. A profile mounting ANYTHING
	// there — a tmpfs, or a rw bind — is a separate mount, is not covered by that
	// remount, and turns the directory writable.
	//
	// What that buys the profile is not its own writable directory. It is
	// SNUG's PATH band: HasStagedBin sees the staged executable, snug puts
	// StagedBinDir first on PATH in `(snug)` provenance, and the payload then
	// writes `git` into a directory that runs ahead of /usr/bin. Measured, with
	// `tmpfs = ["/run/snug/bin"]` plus one staged bind: WROTE-OK, and the
	// shadowed git ran. The rw-bind spelling is worse — the shadowed command
	// persists to the host directory.
	//
	// This is the case the staging rule in CLAUDE.md says cannot happen ("a
	// profile cannot pick a writable directory by accident, because it does not
	// pick one at all"), and it is not the accepted residual class either: the
	// profile writes no PATH declaration, so no human ever read a line saying a
	// writable directory would go on PATH.
	//
	// Note what is NOT refused, and must not be: a grant at a path INSIDE the
	// directory. The predicate is a path-ANCESTOR test, so @claude's
	// `{home}/.local/bin/claude:/run/snug/bin/claude` is untouched — staging one
	// executable is the whole purpose of the directory. Nor is a sibling that
	// merely shares a string prefix: /run/snug/binaries is not an ancestor of
	// /run/snug/bin and stays legal.
	//
	// What IS refused, since issue #22, is any ancestor: /run/snug, /run, /. The
	// exact-key version of this rule shipped, and `tmpfs = ["/run"]` walked
	// straight past it.
	StagedBinDir: {
		why: "it is a plain directory on the root tmpfs, which is what makes it " +
			"unwritable once / is remounted read-only, and snug puts it FIRST on PATH. " +
			"A mount at or above it is not covered by that remount, so it would hand the " +
			"payload a writable directory ahead of /usr/bin.",
		instead: "Stage the FILE, never the directory:\n" +
			"         ro = [\"/host/path/tool:" + StagedBinDir + "/tool\"]\n" +
			"       If you named an ancestor (`tmpfs = [\"/run\"]`) because something inside needs\n" +
			"       a writable runtime directory, grant THAT directory — `tmpfs = [\"/run/myapp\"]`,\n" +
			"       any path that neither is nor contains " + StagedBinDir + ".",
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
// /run/snug/binaries does not cover /run/snug/bin, and /run/snug/bin/claude does
// not cover /run/snug/bin. The first is what a bare strings.HasPrefix gets
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
// /proc, /dev and /run/snug/bin is /, refused before this by its own rule), but
// a security verdict that depends on Go's map iteration order is one that
// changes between runs, and the model has been bitten by exactly that before —
// see the note on resolveViaDeepest.
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
