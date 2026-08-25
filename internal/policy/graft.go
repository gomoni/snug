package policy

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Graft installs one mount into the ENGINE's derived view. It is the ONLY
// writer of p.Grafts — the same device as Policy.Replace for p.Mounts and
// deriveTopology for p.Topology (TestOnlyGraftWritesGrafts).
//
// A second graft at the same Guest is an ERROR, not a join: there is exactly
// one author, so two grafts at one destination is a bug in that author, and a
// join would silently pick a winner. Symmetric message naming both.
//
// It is NOT reached through join, and NOT the KindData late-assignment path
// either (Policy.Replace) — that distinction is load-bearing, not incidental.
// join merges two grants at one Guest IN ONE NAMESPACE; a graft and a bind at
// the same Guest are in TWO DIFFERENT mount namespaces, so joining them would
// compute an effective access no kernel ever computes. Replace is invariant 1's
// one carve-out because it displaces a profile's grant at the same path in the
// same namespace — the sandbox's view really changes and a profile's grant
// really vanishes. A graft does neither: it lands in a namespace no profile can
// name, no TOML key produces one so there is nothing to displace, and it is not
// in p.Mounts so it cannot overwrite an entry there. So grafts are OUTSIDE
// invariant 1 rather than an exception to it, and that stays true structurally
// — one writer, no TOML key — not by convention. Do not read "a graft is
// snug's own writing, like KindData" as license to fold it into Replace; that
// is the plausible-and-wrong reading that would widen the KindData carve-out
// by analogy (issue #55).
//
// Called by Tier C from internal/cli AFTER Resolve returns, for the same
// reason BindSocket is: the store and runroot paths are host artefacts snug
// creates for the run, and Resolve itself authors none. Runs the graft-specific
// rules (G1-G5) inline and returns the error, so a graft can never be installed
// unvalidated — this mirrors nothing existing on purpose: Replace is
// unvalidated today, and issue #55 is a report about an unchecked writer.
func (p *Policy) Graft(env Environ, g Graft) error {
	if _, exists := p.Grafts[g.Guest]; exists {
		return fmt.Errorf("cannot graft %s: already grafted (from %s).\n"+
			"       Policy.Graft is the only writer of p.Grafts, so two attempts at the same\n"+
			"       destination is a bug in the caller, not a disagreement to resolve — a join\n"+
			"       here would silently pick a winner between two grafts nobody compared.",
			g.Guest, strings.Join(p.Grafts[g.Guest].From, "+"))
	}

	g.Authored = true

	// Resolve BEFORE any rule looks at Host, and store the resolved path,
	// because the stage passes g.Host to open_tree(2) and open_tree FOLLOWS a
	// final symlink (measured, issue #55 F6). Checking the literal and storing
	// the literal would leave `ln -s ~/.ssh $TARGET/link` passing G4 lexically
	// while the kernel opened ~/.ssh — the identical hole a previous redteam
	// round found in the container bind filter (dockerproxy/create.go:319).
	//
	// A resolution FAILURE is not a refusal and must not become one. Nothing
	// exists at a path that does not exist, so there is no symlink to defeat;
	// and making existence a policy input would let a payload flip which
	// refusal a human sees by creating or deleting a directory. Fall back to
	// the lexical form and let G4 — a rule over the grant set, which the
	// payload cannot touch — be the one that speaks.
	//
	// Skipped entirely for a Kind the stage MOUNTS rather than clones. Both
	// arms below end in filepath.Clean, and Clean("") is ".", so normalising a
	// kind that has no Host manufactures one: checkGraft's refusal then reads
	// `Host is "."` and the ENGINE VIEW block would render `from .` for a fresh
	// procfs. The normalisation is only meaningful for the path open_tree(2)
	// will be handed, so it runs only for the kinds that have one — and
	// checkGraft refuses a non-empty Host on the others, so "no Host" is
	// enforced rather than assumed (issue #125).
	if graftKindRules[g.Kind].hasHost {
		if real, err := ResolveExistingHostPath(env, g.Host); err == nil {
			if real != filepath.Clean(g.Host) {
				g.HostAsked = g.Host
			}
			g.Host = real
		} else {
			g.Host = filepath.Clean(g.Host)
		}
	}

	if err := p.checkGraft(env, g); err != nil {
		return err
	}

	if p.Grafts == nil {
		p.Grafts = map[string]Graft{}
	}
	p.Grafts[g.Guest] = g
	return nil
}

// OwnEngineHostPath records one host path snug itself created for THIS run —
// the container store, the runroot, a socket directory — as visible to a
// graft under G4's second disjunct, without requiring the SANDBOX's own
// grants to expose it. It is the ONLY writer of p.EngineOwnedHostPaths, the
// same device Policy.Graft is for p.Grafts (TestOnlyOneWriterOfEngineOwnedHostPaths).
//
// Before this existed the map had no writer at all: a caller could set
// p.EngineOwnedHostPaths directly, with no hygiene check, and any string
// placed in it passed G4 unconditionally — the "a rule written once and
// applied to one of its two halves" shape (CLAUDE.md), on G4's own two
// disjuncts, found by the redteam (issue #55, finding F2). checkPathHygiene
// is the same check Policy.Graft runs on a graft's own Guest and Host; this
// is what brings the wider, unbounded-by-any-grant half of G4 up to the
// standard the narrower half (HostPathVisible) already met.
//
// The argument goes through ResolveExistingHostPath with the same
// fallback-to-lexical Policy.Graft uses, for the same reason F6 fixed the
// OTHER half of G4's `if`: G4's second disjunct is EXACT membership
// (types.go, "never a pattern, never a prefix match"), so if a graft's Host
// is normalised and this set is not, a legitimate Tier C graft fails
// membership for a reason nobody wrote down (issue #55, F6 §2d — the same
// "rule applied to one of its two halves" shape, on the two halves of one
// if).
func (p *Policy) OwnEngineHostPath(env Environ, path string) error {
	if real, err := ResolveExistingHostPath(env, path); err == nil {
		path = real
	} else {
		path = filepath.Clean(path)
	}
	if err := checkPathHygiene("engine-owned host path", path, "(snug)", "the ENGINE VIEW block"); err != nil {
		return err
	}
	if p.EngineOwnedHostPaths == nil {
		p.EngineOwnedHostPaths = map[string]bool{}
	}
	p.EngineOwnedHostPaths[path] = true
	return nil
}

// JudgeEngineToolchain returns the resolved engine toolchain root, or the
// refusal EngineToolchain would return for the same string. It RECORDS NOTHING,
// so --dry-run can reach the run's verdict without becoming a writer.
//
// Split out for issue #422: report.go called CheckEngineToolchainTree on the
// raw $SNUG_PODMAN_ROOT and cleared a symlinked root the run refuses, because
// resolution, hygiene and the selection arm all lived one level up. There is
// now no second copy of the judgement to leave a caller behind.
//
// Resolution and hygiene are OwnEngineHostPath's, for its reasons: the stage
// hands this path to open_tree(2), which follows a final symlink, and G4 is
// exact membership — a root recorded unresolved while a graft's Host is
// resolved fails membership for a reason nobody wrote down (#55, F6 §2d).
//
// "" is a REFUSAL, not a no-op that clears the field, and the returned path is
// "" on every error — a path beside a non-nil error is a value a careless
// caller renders as though it had been approved.
func (p *Policy) JudgeEngineToolchain(env Environ, root string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("cannot record the engine's toolchain root: the path is empty.\n" +
			"       A caller with no toolchain root to record must not call this — an empty\n" +
			"       value here would silently clear one already recorded.")
	}
	// The spelling the caller handed over, kept because the resolution below
	// REPLACES root, and the selection arm at the end of this function asks the
	// one question that only has an answer BEFORE resolution (issue #369).
	//
	// Cleaned lexically and only lexically: filepath.Clean follows no symlink,
	// so it discards nothing the selection arm needs, and a trailing slash in
	// $SNUG_PODMAN_ROOT is an ordinary human spelling that checkPathHygiene
	// would otherwise refuse as non-clean.
	asGiven := filepath.Clean(root)
	// One operation, two policies, worth stating rather than leaving for a
	// reader to discover by diffing this against Resolve's own resolution
	// (resolve.go:177): on an EvalSymlinks error, Resolve HARD-FAILS a
	// non-Optional grant, while this degrades to a bare filepath.Clean. Not a
	// defect and not unified here — a caller here has no Optional to
	// consult, and the fallback is unreachable for the one
	// production caller anyway (preflightToolchainRoot's os.Stat+IsDir already
	// requires the root to exist, so ResolveExistingHostPath's own "not even /
	// resolves" failure mode never fires against a real filesystem). Named so
	// the next reader finds it stated instead of re-deriving it.
	if real, err := ResolveExistingHostPath(env, root); err == nil {
		root = real
	} else {
		root = filepath.Clean(root)
	}
	if err := checkPathHygiene("engine toolchain root", root, "(snug)", "the ENGINE VIEW block"); err != nil {
		return "", err
	}
	// The as-given spelling reaches a REFUSAL a human reads (the selection arm
	// at the end of this function), so it is a SINK and gets the same check the
	// resolved form just got — invariant 7's rule that a value's guard belongs
	// at every sink it can reach, not at the site where it was noticed. This
	// mirrors Policy.Graft's own treatment of g.HostAsked ("graft source
	// (asked)", above). Skipped when the two strings are identical, which is
	// the ordinary case: the check has already run on it.
	if asGiven != root {
		if err := checkPathHygiene("engine toolchain root (asked)", asGiven, "(snug)", "the ENGINE VIEW block"); err != nil {
			return "", err
		}
	}
	// Issue #405, first half through this door: G4b (checkGraft, below) only
	// ever runs when a graft of this root is actually installed, which never
	// happens while $SNUG_PODMAN_ROOT is unset. Asking on the path to the one
	// writer of p.EngineToolchainRoot means a root the sandbox's own grants (or
	// a grant strictly inside it) already make writable is refused before it is
	// ever recorded — not left to wait for a graft that, on the common
	// unset-env path, is never attempted at all.
	if err := p.CheckEngineToolchainTree(root); err != nil {
		return "", err
	}
	// Issue #369's second door: this function used to judge the root only
	// AFTER resolving it, so $SNUG_PODMAN_ROOT=$TARGET/bundle — a symlink the
	// payload can rewrite, pointing at a host-owned tree — chose which
	// directory the engine executes out of while every check above saw only
	// where it pointed. DERIVED BY READING, not measured: the engine-binary
	// door above is the one a redteam round measured; this is the same shape
	// one field over.
	//
	// Arm order is load-bearing, and the first version of this block got it
	// backwards: it sat BEFORE the resolution and CheckEngineToolchainTree,
	// so a plain, non-symlinked, payload-writable root printed this arm's
	// "the directory at the end of that chain is not writable" clause while
	// that directory was precisely what was writable
	// (TestCheckEngineToolchainTree's B1 case caught it). The endpoint arm
	// must run first: the payload WRITING the toolchain is the worse fact,
	// and a message may only assert what the code above it already
	// established. Once CheckEngineToolchainTree has cleared, the chain's
	// last prefix can no longer fire writableNameOnChain's canonical arm on
	// the same string, so anything reported here is either an ancestor on
	// the way to the root or the root's own spelling diverging from what it
	// resolves to.
	//
	// checkGraft's G4b deliberately has no equivalent door; the reason is the
	// theorem in writableNameOnChain's own comment (engineexec.go).
	if name, asked, found := p.writableNameOnChain(env, asGiven); found {
		return "", fmt.Errorf("%s cannot be this run's engine toolchain root: %s\n"+
			"       The directory at the end of that chain is not writable, and neither is anything\n"+
			"       inside it — snug checked both of those first. So this is not the payload EDITING\n"+
			"       the toolchain; it is the payload CHOOSING it. The engine resolves conmon, crun,\n"+
			"       netavark and fuse-overlayfs out of the recorded root as uid 0 in this sandbox's\n"+
			"       user namespace, so a name the payload can rewrite is the payload deciding what\n"+
			"       the engine executes as root.\n"+
			"       Grafting it read-only does not help: `ro` restrains the ENGINE, and the payload\n"+
			"       rewrites the same host name through its own rw grant.\n"+
			"       Fix: point $SNUG_PODMAN_ROOT at the installation directory itself, or drop the rw\n"+
			"       grant that covers the name above.", asGiven, selectionClause(name, asked))
	}
	return root, nil
}

// EngineToolchain records the ONE host directory the container engine's own
// program files live in, as G4's third source — see the field's doc comment
// (types.go) for what it is for and why it is exact, single and read-only.
// It is the ONLY writer of p.EngineToolchainRoot
// (TestOnlyOneWriterOfEngineToolchainRoot), the same device Policy.Graft is
// for p.Grafts and OwnEngineHostPath is for p.EngineOwnedHostPaths.
//
// Everything it JUDGES is JudgeEngineToolchain's, so the run and --dry-run
// cannot reach different verdicts about one string (issue #422). What is left
// here is the RECORD.
//
// Written ONCE. A second call with a DIFFERENT value is an error rather than
// a replacement: there is one engine per run, so two toolchain roots is a bug
// in the caller, and silently keeping either one would decide, without saying
// so, which host directory the engine may execute out of. A repeat of the
// SAME value is accepted.
//
// Write-once now runs AFTER the judgement, so a second, different, WRITABLE
// root reports the writability refusal where it used to report this one. Both
// refuse and the writability fact is graver; no production caller reaches the
// pair anyway (container.go calls this once per run).
func (p *Policy) EngineToolchain(env Environ, root string) error {
	resolved, err := p.JudgeEngineToolchain(env, root)
	if err != nil {
		return err
	}
	if p.EngineToolchainRoot != "" && p.EngineToolchainRoot != resolved {
		return fmt.Errorf("cannot record %s as the engine's toolchain root: this run already\n"+
			"       recorded %s. There is one engine per run, so a second, different root is a\n"+
			"       bug in the caller rather than a disagreement to resolve — and choosing\n"+
			"       between them here would decide which host directory the engine may execute\n"+
			"       out of without saying so.", resolved, p.EngineToolchainRoot)
	}
	p.EngineToolchainRoot = resolved
	return nil
}

// ResolveExistingHostPath canonicalises as much of a host path as exists, then
// rejoins the remainder lexically.
//
// Plain EvalSymlinks fails outright on a path that is not there yet, and both
// callers legitimately name one: `-v ./build:/out` where ./build does not exist
// is ordinary (the engine creates it), and Tier C may record a host artefact's
// path before creating it. Resolving the longest existing prefix keeps that
// working while still defeating a symlink planted anywhere along the part that
// DOES exist — which is the whole point, because a symlink an attacker planted
// must EXIST to be followed, so it is always inside the prefix this resolves.
//
// This is the SECOND half of "can the sandbox see this host path", and it moved
// here for the same reason HostPathVisible did (invariant 6, issue #55 finding
// F6): the first half moved and this one did not, leaving one author of half a
// rule. dockerproxy.resolveExisting is now a one-line call to this.
//
// It takes an Environ rather than calling filepath.EvalSymlinks so that
// internal/policy stays pure and the graft tests can plant a symlink in a fake
// host layout with no privileges.
func ResolveExistingHostPath(env Environ, path string) (string, error) {
	path = filepath.Clean(path)
	rest := ""
	for cur := path; ; {
		real, err := env.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(real, rest), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", fmt.Errorf("no existing ancestor")
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// graftKindRule is one row of graftKindRules: everything checkGraft needs to
// know about a Kind to decide which of its Host-shaped rules make sense.
type graftKindRule struct {
	// hasHost is false for a graft the STAGE builds itself — a fresh procfs,
	// a fresh cgroup2 mount — rather than one it clones from an existing host
	// path with open_tree(2). There is no Host to resolve, no Host to visit,
	// and no "is this visible to the sandbox" question to ask about it.
	hasHost bool
}

// graftKindRules is the allowlist for Graft.Kind, written as a TABLE rather
// than a scattered `if g.Kind == ...` for the reason CLAUDE.md names
// directly: "a rule written once and applied to one of its two halves is the
// shape to watch for" — checkEnvName's NUL check, refused on the name and
// forgotten on the value, is the worked example. G4 and the two Host hygiene
// checks below are ONE RULE ("a graft's source must be a real, visible host
// path") that has a Host half and a no-Host half, and every Kind has to say
// which half applies to it rather than the code silently having an `if` that
// covers only the Kind whoever wrote it was thinking about.
//
//	Kind         hasHost  what it skips, and why
//	KindGraft    true     nothing — an open_tree(2) clone of a HOST directory
//	                      (issue #125's four grafts: the container store, the
//	                      runroot, the socket directory, the config
//	                      directory). Every rule below runs.
//	KindProc     false    the two Host hygiene checks (checkPathHygiene on
//	                      Host and HostAsked) and G4 (the source-visibility
//	                      rule) — there is no source: the stage MOUNTS a
//	                      fresh procfs owned by the engine's own pid
//	                      namespace (`mount("proc", "/proc", "proc", 0,
//	                      "")`), the same way the sandbox's own /proc is a
//	                      fresh procfs and not a bind of anything.
//	KindCgroup2  false    identical reasoning to KindProc: the stage MOUNTS a
//	                      fresh cgroup2 (`mount("cgroup2", "/sys/fs/cgroup",
//	                      "cgroup2", 0, "")`), never open_tree(2) of a host
//	                      path.
//	KindTmpfs    false    the engine's own /run (`mount("tmpfs", "/run",
//	                      "tmpfs", 0, "")`). Same "the stage mounts it" half
//	                      as the two above, and the same reuse of an existing
//	                      Kind as KindProc: a fresh empty tmpfs is a fresh
//	                      empty tmpfs, and which namespace it lands in is
//	                      decided by which map it lives in, not by a second
//	                      name for one idea (issue #125's design pass §9.2).
//
// Every OTHER rule — G1 (no graft may cover snug's own paths), G2 (no graft
// may cover or be covered by another graft), G3 (the destination must exist
// in the sandbox's own view), and G5's remaining checks (Access, Optional,
// Why, From, and Guest's own hygiene) — runs for every Kind unconditionally.
// None of those ask about Host.
var graftKindRules = map[Kind]graftKindRule{
	KindGraft:   {hasHost: true},
	KindProc:    {hasHost: false},
	KindCgroup2: {hasHost: false},
	KindTmpfs:   {hasHost: false},
}

// checkGraft runs G1-G5 over one graft WITHOUT installing it, so Policy.Graft
// and Validate's re-check (issue #55) share exactly one implementation of the
// rules rather than the two that would otherwise drift.
//
// The exact-duplicate half of G2 ("two grafts at one Guest") is NOT checked
// here — it is checked by Policy.Graft before this runs, against the map
// lookup, because by the time Validate calls this over an ALREADY-INSTALLED
// graft, that graft IS the map entry at its own Guest, and comparing it to
// itself would refuse every graft that ever validated successfully. What this
// checks instead is a DIFFERENT graft covering or covered by this one, which a
// hand-built Policy can still produce and which the map's own uniqueness
// cannot catch.
func (p *Policy) checkGraft(env Environ, g Graft) error {
	// G5, structural half — a bug in the caller, not a configuration choice, so
	// checked first and unconditionally. The allowlist is graftKindRules, not
	// a flat `!= KindGraft`: a graft may also be the engine's own procfs or
	// cgroup2 mount (issue #125's design pass §1), and both of those still
	// have to be REFUSED as a payload-namespace Kind exactly as a stray
	// KindGraft is (see BwrapFlags's default panic arm and Validate's
	// KindGraft-in-p.Mounts check, which now also names KindCgroup2).
	rules, allowed := graftKindRules[g.Kind]
	if !allowed {
		return fmt.Errorf("cannot graft %s: Kind is %q, and a graft's Kind must be one the engine's\n"+
			"       derived view actually builds — KindGraft (an open_tree(2) clone of a host path),\n"+
			"       or KindProc, KindCgroup2 or KindTmpfs (a fresh mount the stage makes itself). A\n"+
			"       caller building a Graft with any other Kind is a bug in that caller, not a policy\n"+
			"       this can accept.",
			g.Guest, g.Kind)
	}
	if g.Access != AccessRO && g.Access != AccessRW {
		return fmt.Errorf("cannot graft %s: Access is %q, and a graft must be ro or rw — Access is a\n"+
			"       REQUIREMENT enforced by mount_setattr before move_mount (§5.1), and \"none\"\n"+
			"       describes nothing the stage can build. Set AccessRO or AccessRW.", g.Guest, g.Access)
	}
	if g.Optional {
		return fmt.Errorf("cannot graft %s: Optional is not permitted on a graft.\n"+
			"       -try semantics mean \"silently do less\", and under Tier C the derived view IS\n"+
			"       the enforcement boundary — a graft that silently did not happen would leave the\n"+
			"       engine with a different confinement from the one --dry-run described\n"+
			"       (invariant 5). Make the host path exist, or do not graft it.", g.Guest)
	}
	if g.Why == "" {
		return fmt.Errorf("cannot graft %s: Why is empty.\n"+
			"       Every graft carries the abuse sentence — \"a hostile process inside the sandbox\n"+
			"       can use this to ___\" — because a graft is the one grant a profile can never\n"+
			"       write, so a Graft literal is the only place left for a human to read it. Set Why\n"+
			"       before calling Policy.Graft.", g.Guest)
	}
	// G5 also requires From to be EXACTLY snug's own provenance — not merely
	// "not one of this run's resolved profiles". Comparing only against
	// p.Profiles let From: []string{"@podman-socket"} through on any
	// selection that did not happen to include @podman-socket: Validate
	// returned nil and the ENGINE VIEW block rendered the @ sigil next to a
	// row the block's own header says no profile could have authored — the
	// one guarantee the sigil exists to make (CLAUDE.md, "@ marks a profile
	// snug ships, and the mark is derived, not written"), forged by a Graft
	// literal (issue #55, finding F8). No profile — selected or not, builtin
	// or user-defined — may ever author a graft, so the only From this
	// accepts is the literal sentinel every other snug-generated mount
	// already uses for the same fact ("(snug)": /proc, /dev, /tmp, the
	// identity KindData mounts).
	if len(g.From) != 1 || g.From[0] != "(snug)" {
		return fmt.Errorf("cannot graft %s: From is %q, and a graft's From must be exactly\n"+
			"       []string{\"(snug)\"}.\n"+
			"       No profile may author a graft — there is no TOML key that produces one, and\n"+
			"       Policy.Graft is the only writer of p.Grafts — so any other From, including the\n"+
			"       name of a builtin this run never selected, means the caller copied provenance\n"+
			"       from somewhere else instead of writing the graft's own. Set From to\n"+
			"       []string{\"(snug)\"}.", g.Guest, g.From)
	}

	// Guest goes through the SAME check a mount's Guest already does
	// (validate.go), rather than a fourth hand-rolled copy — unconditionally,
	// for every Kind: the destination is always a real path in the derived
	// view and always reaches the ENGINE VIEW block, whether or not this Kind
	// has a Host.
	if err := checkPathHygiene("graft destination", g.Guest, strings.Join(g.From, "+"), "the ENGINE VIEW block"); err != nil {
		return err
	}
	// A kind with hasHost=false must not merely SKIP the Host rules — it must
	// have no Host to skip them for. Gating alone was the first shape of this
	// code and it is the wrong one: a KindProc graft carrying
	// Host: "/home/u/.ssh" passed every check (they are all gated), was stored
	// verbatim, and describeGrafts printed `from /home/u/.ssh` under a row the
	// stage builds from a fresh mount and never opens that path for. Nothing
	// was reachable — the stage ignores Host for KindProc — but --dry-run is
	// the mechanism by which a human trusts snug at all, and a line there that
	// names a host path nothing reads is a lie in the one artifact that may not
	// contain one. Refuse the field instead of ignoring it, so the skip in
	// graftKindRules means "this kind has no source", not "this kind's source
	// goes unchecked".
	if !rules.hasHost && (g.Host != "" || g.HostAsked != "") {
		return fmt.Errorf("cannot graft %s: Kind is %q, which the stage builds as a FRESH mount,\n"+
			"       but Host is %q — a path nothing will ever open.\n"+
			"       A fresh procfs or cgroup2 has no source: the stage mounts it, it does not clone\n"+
			"       a host subtree with open_tree(2). Leaving the field set would put `from %s` on\n"+
			"       the ENGINE VIEW block for a mount that reads nothing there. Clear Host (and\n"+
			"       HostAsked), or use KindGraft if you meant to clone that path.",
			g.Guest, g.Kind, g.Host, g.Host)
	}
	// Host and HostAsked are the two checks graftKindRules.hasHost gates —
	// there is nothing here to sanitise for KindProc/KindCgroup2, because
	// there is no Host (see graftKindRules's own doc comment, and the refusal
	// directly above, which is what makes "there is no Host" true rather than
	// merely assumed). HostAsked runs through the same check when set — it
	// reaches --dry-run too (issue #55, F6 §2c) — and this order matters:
	// hygiene on Guest and Host first, so a forging rune never reaches a
	// screen.
	if rules.hasHost {
		if err := checkPathHygiene("graft source", g.Host, strings.Join(g.From, "+"), "the ENGINE VIEW block"); err != nil {
			return err
		}
		if g.HostAsked != "" {
			if err := checkPathHygiene("graft source (asked)", g.HostAsked, strings.Join(g.From, "+"), "the ENGINE VIEW block"); err != nil {
				return err
			}
		}
	}

	// G4, resolution half. Host is a FIXED POINT of ResolveExistingHostPath by
	// the time it is stored, because Policy.Graft normalises it. Validate
	// re-runs this over an already-installed graft, so a hand-built Policy that
	// wrote straight into p.Grafts with an unresolved Host is refused here —
	// the same door the rest of this function is the backstop for (issue #55
	// F3a). It also re-samples the host, so a link created between Policy.Graft
	// and Validate is caught; a link created AFTER Validate is not, and cannot
	// be (the TOCTOU paragraph in the G4 comment below).
	//
	// Gated by rules.hasHost for the same reason the two hygiene checks above
	// are: there is no Host to be a fixed point of anything for KindProc or
	// KindCgroup2.
	if rules.hasHost {
		if real, err := ResolveExistingHostPath(env, g.Host); err == nil && real != g.Host {
			return fmt.Errorf("cannot graft %s: its source %s is not the path it resolves to (%s).\n"+
				"       open_tree(2) FOLLOWS a symlink, so a graft installed with an unresolved source\n"+
				"       opens whatever the link points at — and the sandbox's writable target is\n"+
				"       attacker-controlled, so that is a choice the payload gets to make. Policy.Graft\n"+
				"       resolves before it checks; a graft whose stored source is unresolved did not go\n"+
				"       through it. Install grafts with Policy.Graft.",
				g.Guest, g.Host, real)
		}
	}

	// G1 — a graft may not cover one of snug's own paths, in EITHER namespace.
	//
	// THE TRAP, stated so it cannot be copied wrong: validate.go's mount-level
	// check reads `if at, own, ours := snugsOwnCovered(g); ours && !m.Authored`.
	// Every graft is Authored by construction (set two lines above, in
	// Policy.Graft). Copying that clause here would make this check a
	// PERMANENT NO-OP. The `!Authored` clause exists on the mount-level check
	// because snug legitimately replaces /proc and /etc/resolv.conf in the
	// PAYLOAD's namespace; nothing legitimately covers StagedBinDir in ANY
	// namespace, so there is no analogous exemption to carry over here. It is
	// deliberately absent below. (TestGraftCoveringStagedBinDirIsRefused fails
	// if it is reintroduced.)
	//
	// No new relation is needed to find the /run-covers-StagedBinDir case —
	// covers/snugsOwnCovered is already a depth rule, asked of the SAME guest
	// path a mount-level grant would be asked of. It is not extended across
	// namespaces to do this: this is one graft's own Guest, judged on its own,
	// never compared against another namespace's containment.
	//
	// ONE hard-coded admission: (/proc, KindProc). /proc is in snugsOwn
	// because a profile grant there would displace the sandbox's OWN procfs
	// with the host's — but this graft, when its Kind is KindProc, IS the
	// engine's own procfs, replacing snug's placeholder /proc entry in the
	// ENGINE's derived view exactly as legitimately as the sandbox's own
	// procfs replaces it in the payload's (validate.go's mount-level check,
	// `ours && !m.Authored`). Written as an EXACT (Guest, Kind) match, not as
	// an `Authored` predicate: the doc comment on this function's own trap,
	// three paragraphs up, says copying `!m.Authored` here makes G1 a
	// PERMANENT NO-OP, because Policy.Graft sets Authored on every graft
	// unconditionally — that trap applies word for word to a predicate
	// spelled any other way that is also true of every graft. Nothing else
	// gets this admission: a KindGraft (a host-tree clone) at /proc is still
	// refused below, unchanged — it would hand the engine /proc/<pid>/root
	// and /proc/<pid>/cwd for every host process, the exact complete
	// filesystem bypass G1 exists to prevent (issue #125's design pass §1).
	if g.Guest == "/proc" && g.Kind == KindProc {
		// admitted — fall through to G2/G3 below, which still apply.
	} else if at, own, ours := snugsOwnCovered(g.Guest); ours {
		if at == g.Guest {
			return fmt.Errorf("cannot graft %s into the engine's view: %s is snug's own: %s\n"+
				"       A graft at that path would displace it in the ENGINE's mount namespace\n"+
				"       exactly as a profile's grant would displace it in the sandbox's — this is a\n"+
				"       hole no graft may open, snug's own code included. Graft a destination that\n"+
				"       is neither %s nor an ancestor of it.",
				g.Guest, g.Guest, own.why, g.Guest)
		}
		return fmt.Errorf("cannot graft %s into the engine's view: it CONTAINS %s, and %s is snug's\n"+
			"       own: %s\n"+
			"       A graft at an ancestor takes the descendant with it in the engine's mount\n"+
			"       namespace, exactly as it would in the sandbox's — naming the parent is not a\n"+
			"       narrower graft than naming the child. Graft a destination that is neither %s\n"+
			"       nor an ancestor of it.",
			g.Guest, at, at, own.why, at)
	} else if at, own, inside := snugsOwnAncestorOf(g.Guest); inside && !insideSnugDir(g.Guest) {
		// STRICTLY INSIDE, which the two clauses above do not cover: they ask
		// whether the graft is AT one of snug's own paths or CONTAINS one.
		//
		// Nothing refused a graft at /proc/sys until issue #29, and what
		// refused it then was an accident of arithmetic rather than a rule:
		// G3 requires the destination to exist in the sandbox's view, and
		// nothing mounted anything under /proc, so the case never arose. #29's
		// read-only /proc/sys made that path exist — and (/proc/sys, KindProc)
		// was ACCEPTED, which TestG1AdmitsExactlyProcAsKindProc caught on the
		// first run after the mount appeared.
		//
		// A graft inside /proc or /dev substitutes host content for kernel
		// content in the ENGINE's namespace, which is the hole G1 exists to
		// refuse one level up. Stated over the region, so the next mount snug
		// authors inside one of those trees cannot re-open it.
		//
		// SnugDir is excluded because it is not that shape: /snug is a
		// NAMESPACE with a legal subtree (/snug/engine), and G1b below is the
		// rule that admits it. Swallowing it here would refuse every engine
		// graft — measured, TestGraftInsideSnugDirIsRefusedExceptUnderTheEngine\
		// Subtree went red the first time this clause did not exclude it.
		return fmt.Errorf("cannot graft %s into the engine's view: it is INSIDE %s, and %s is\n"+
			"       snug's own: %s\n"+
			"       A graft there substitutes host content for kernel content in the engine's\n"+
			"       mount namespace, exactly as a profile's grant would in the sandbox's. Graft a\n"+
			"       destination outside %s.",
			g.Guest, at, at, own.why, at)
	}

	// G1b — SnugDir is snug's own namespace for GRAFTS too, and only the
	// engine's own subtree inside it may be grafted onto.
	//
	// G1 above is a LIST (snugsOwn), and a list is what left this half open:
	// it held SnugDir and StagedBinDir and not the two proxy socket paths, so
	// the namespace rule was total for the payload's mounts (validate.go's rule
	// 4b) and partial for grafts. MEASURED before this existed: an AccessRW
	// graft at ContainerSocketGuest, with a source G4 admits, was ACCEPTED —
	// G1 saw it cover nothing in the map, G2 found no sibling graft, and G3 was
	// satisfied because the socket IS a mount. That puts an arbitrary writable
	// host tree where the engine expects the container proxy's socket.
	//
	// Adding the sockets to snugsOwn would have closed that and kept the shape.
	// This closes the shape: graftAllowedInSnugDir names the ONE subtree a graft
	// may use, so anything snug puts under SnugDir next is protected the day it
	// is named rather than the day someone remembers an entry.
	//
	// Note what this does NOT rely on: G3 refusing a destination that does not
	// exist. /snug/engine is refused by G3 today only because nothing creates
	// that directory yet, and that is a coincidence of Tier C not having landed
	// — the day it does, G3 stops refusing and this rule is what remains.
	if insideSnugDir(g.Guest) && !graftAllowedInSnugDir(g.Guest) {
		return fmt.Errorf("cannot graft %s into the engine's view: it is inside snug's own\n"+
			"       namespace %s, and the only part of it a graft may land in is the engine's own\n"+
			"       subtree under %s/.\n"+
			"       Everything else there belongs to the PAYLOAD — the staging directory and the\n"+
			"       proxy sockets — and a graft at one of those replaces it in the engine's mount\n"+
			"       namespace with whatever this graft's source is.",
			g.Guest, SnugDir, EngineDir)
	}

	// G1c — the pre-#206 location is a tombstone for grafts as well as for
	// profile grants. Neither should be able to name it; a rule that refuses it
	// on one side only is the same half-applied shape G1b exists to close.
	if namesLegacySnugDir(g.Guest) {
		return fmt.Errorf("cannot graft %s into the engine's view: snug's own paths moved from\n"+
			"       %s to %s (issue #206), and the old location is kept refused so that nothing\n"+
			"       names it by habit. The engine's own destinations are under %s/.",
			g.Guest, legacySnugDir, SnugDir, EngineDir)
	}

	// G2 — a graft may not cover, or be covered by, another graft. The
	// exact-Guest case is skipped here (see the doc comment above): it is
	// handled by Policy.Graft before this runs, and when Validate re-checks an
	// already-installed graft, "existing" at that exact Guest IS g itself.
	for _, existing := range p.Grafts {
		if existing.Guest == g.Guest {
			continue
		}
		if covers(g.Guest, existing.Guest) {
			return fmt.Errorf("cannot graft %s into the engine's view: it would CONTAIN the graft\n"+
				"       already at %s (from %s).\n"+
				"       A graft at an ancestor takes the descendant's destination with it in the\n"+
				"       engine's mount namespace — the same containment rule the sandbox's own\n"+
				"       grants follow. Graft a destination that neither is nor contains %s.",
				g.Guest, existing.Guest, strings.Join(existing.From, "+"), existing.Guest)
		}
		if covers(existing.Guest, g.Guest) {
			return fmt.Errorf("cannot graft %s into the engine's view: the graft already at %s\n"+
				"       (from %s) CONTAINS it.\n"+
				"       A graft at an ancestor takes the descendant's destination with it in the\n"+
				"       engine's mount namespace — the same containment rule the sandbox's own\n"+
				"       grants follow. Graft a destination that is not inside %s.",
				g.Guest, existing.Guest, strings.Join(existing.From, "+"), existing.Guest)
		}
	}

	// G3 — the destination must already exist in the SANDBOX's own view.
	// existsInSandbox names the fix and is measured against ENGINE-NETNS.md
	// §5.1's four rows; see its own doc comment for the soundness caveat on its
	// third disjunct.
	if !existsInSandbox(p, g.Guest) {
		return fmt.Errorf("snug cannot graft %s into the engine's view: nothing in this policy\n"+
			"       creates that directory inside the sandbox, and the sandbox root is read-only, so\n"+
			"       the mkdir that a graft needs fails with EROFS (measured, ENGINE-NETNS.md §5.1).\n"+
			"       Graft a destination that already exists — a path some grant mounts, an ancestor\n"+
			"       of one, or a path inside a writable grant.", g.Guest)
	}

	// G4 — the source must be something the sandbox can ALREADY see
	// (HostPathVisible), OR a host path snug itself created for this run
	// (EngineOwnedHostPaths, written only by OwnEngineHostPath). This is
	// invariant 6 expressed as a predicate: the engine's view is DERIVED from
	// the sandbox's, never a second, wider window onto the host.
	//
	// Gated by rules.hasHost, same as the two checks above: there is no
	// source to ask this about for KindProc or KindCgroup2 — the stage MOUNTS
	// those itself, it does not open_tree(2) anything the sandbox would have
	// to have already exposed.
	//
	// The two disjuncts are asking DIFFERENT questions and neither one alone
	// is "G4". HostPathVisible refuses /run/user/<uid> — the host's
	// ssh-agent, session D-Bus, Wayland and rootless podman socket — because
	// no grant exposes it: that is a fact about the FIRST disjunct only. It
	// is not a fact about EngineOwnedHostPaths, which is bounded by nothing
	// the sandbox's own policy granted — its only defence is that
	// OwnEngineHostPath is its one writer, called exclusively by snug's own
	// Tier C code for artefacts snug itself created (the container store,
	// the runroot, a socket directory), never by anything a profile or the
	// payload can reach. A doc comment claiming "/run/user/<uid> is refused
	// by G4, full stop" is true of HostPathVisible and silent about this
	// disjunct beside it — do not write that sentence again without naming
	// both halves (issue #55, finding F2).
	//
	// TOCTOU — what the resolution above (both here and in Policy.Graft)
	// closes and what it does not (issue #55, F6 §4; refined by issue #125's
	// design pass §5, which is what corrects the paragraph this replaces).
	//
	// STALE CLAIM CORRECTED. This paragraph used to say the window was wide
	// because "ensureEngine starts the engine LAZILY, on first proxy use,
	// i.e. after the payload has been running and has already been able to
	// write to the target" — that was already false when it was written
	// (issue #125's design pass, §0(a)): since Tier B, internal/cli/container.go
	// passes nil for ensureEngine ("the engine is EAGER now, forked and
	// confirmed well before StartSandbox ever forks the payload"), and
	// internal/sandbox/exec.go runs StartEngine + OnEngineReady strictly
	// BEFORE StartSandbox. THIS run's payload has never executed when
	// Policy.Graft or Validate run, full stop — there is no "payload has
	// already been able to write to the target" window today, and there
	// never was under the code that actually shipped.
	//
	// Closed: G4 now judges, and the stage will open, the SAME tree —
	// $TARGET/link -> ~/.ssh is refused because ~/.ssh is exposed by no
	// grant. That is the whole of F6's defect.
	//
	// NOT closed, and the residual is stated precisely rather than loosely
	// (issue #125's design pass §5): *the descriptor is the object the graft
	// is built from, so nothing observed between the openat2 and the graft
	// can redirect IT* — not "the graft cannot be redirected" in general. The
	// remaining window is between ResolveExistingHostPath (above, in
	// Policy.Graft) and the openat2(AT_FDCWD, g.Host,
	// {O_PATH|O_DIRECTORY|O_CLOEXEC, RESOLVE_NO_SYMLINKS}) that re-walks the
	// same path — and THAT WINDOW IS NOT SMALL. This paragraph said "a few
	// lines later, in the SAME function, in P0 — one process, no process
	// boundary", and that a fd travelled "P0 -> P1 -> the engine child by
	// ExtraFiles" so "nothing after the openat2 can be raced". Every clause of
	// that is false as shipped, verified by grep rather than argued:
	//
	//   - the whole family lives in internal/stage's __inengine — openat2 at
	//     inengine.go:246, open_tree at :251, move_mount at :313 — a DIFFERENT
	//     PROCESS, reached after the stage, the netns and bwrap all exist;
	//   - the resolved Host travels there as an ARGV STRING and is RE-WALKED.
	//     This comment was the sole mention of ExtraFiles in internal/policy,
	//     naming a transport that does not exist.
	//
	// The fd claim was not fantasy, it was MISPLACED, and the corrected
	// version is the useful one: a descriptor IS held across a gap, but the gap
	// is inside __inengine — open_tree(:251) clones from the openat2 fd, and
	// move_mount(:313) attaches from THAT fd in a second loop. So nothing
	// between the openat2 and the move_mount can redirect the graft. What the
	// old text got backwards is WHICH SIDE the window is on: the walk that
	// produces the descriptor happens in __inengine, from a string, after
	// everything exists — so the exposure is BEFORE the openat2, not after it.
	//
	// So the window spans the whole stage/netns/bwrap startup, across a
	// process boundary. WHAT CLOSES THE RACE IS THE FLAG, NOT THE WINDOW:
	// RESOLVE_NO_SYMLINKS refuses a symlink at ANY depth, final or not, and
	// ELOOP is fatal with no fallback to the path form (below). That is
	// payload-independent, which is why it holds over a window this long.
	//
	// Read the difference before touching either site: a reader who believed
	// the old text would judge the window a few instructions in one process
	// and could relax RESOLVE_NO_SYMLINKS thinking the window had closed the
	// race. It has not. The flag is doing all of the work.
	//
	// The residual actors, because THIS run's payload cannot be one of them,
	// are (a) a PREVIOUS run's payload — the container store persists across
	// runs of the same TARGET DIRECTORY, whatever profiles either run
	// selected, and so does /tmp under @tmp-shared, so a symlink an earlier
	// sandbox planted is still there to win the race —
	// and (b) another same-uid HOST process, which is OUTSIDE snug's threat
	// model: it already has, without any of this, every capability U-namespace
	// confinement does not remove.
	//
	// Two decisions this closing carries, made by #125's design pass. They
	// were written forward-looking — "not to be re-derived differently when
	// the openat2 call itself lands" — and it HAS landed, at
	// internal/stage/inengine.go:246. Read them as describing that site
	// (issue #125, C2):
	//   - ELOOP from the openat2 is FATAL, with NO fallback to the path form.
	//     A component becoming a symlink between ResolveExistingHostPath and
	//     the openat2 — a window spanning a process boundary and the whole
	//     stage/netns/bwrap startup, NOT "a few instructions later" as this
	//     said — IS the attack this closing exists to catch, not a host
	//     layout snug should route around —
	//     falling back to open_tree(2) on the path would silently reopen
	//     exactly the F6 hole this paragraph says is closed.
	//   - RESOLVE_NO_XDEV is deliberately NOT set. All four host grafts (the
	//     container store, the runroot, the socket directory, the config
	//     directory) plausibly cross a mount boundary on an ordinary host —
	//     $HOME on its own filesystem, /tmp as tmpfs, the store on a separate
	//     subvolume — so RESOLVE_NO_XDEV would fail EXDEV on an unremarkable
	//     layout, not on an attack. open_tree(2)'s AT_RECURSIVE cloning the
	//     crossed submounts is the INTENT here, not a hazard to fence off.
	//
	// THE THIRD DISJUNCT, added by Tier C's toolchain graft (issue #125): the
	// engine's own program files. It is the narrowest of the three and is
	// written as MEMBERSHIP rather than as a question — `g.Host ==
	// p.EngineToolchainRoot`, one value, exact, never a prefix — deliberately,
	// because the alternative shape was to ask "did the path preflight
	// accept this?" and preflight answers a DIFFERENT question ("is this a
	// host-escape shim?"). Two questions that will drift, where a later
	// relaxation of preflight would widen what may be grafted with nothing
	// named G4 noticing. So preflight writes one resolved value into one
	// field through one writer, and G4 checks membership in it.
	//
	// AccessRO only, checked here rather than left to the caller: the two
	// other sources have an owner who can say a write is intended — the
	// sandbox's own grants say so for the first, snug created the artefact
	// for the second — and this one is the host user's own installation,
	// where a writable graft is a host-write channel out of the engine.
	if rules.hasHost {
		toolchain := p.EngineToolchainRoot != "" &&
			g.Host == p.EngineToolchainRoot &&
			g.Access == AccessRO

		// G4b, issue #390, and its second half (issue #405): the toolchain
		// disjunct above admits a path the sandbox's own grants do NOT
		// expose — that is the whole point of it — and AccessRO was treated
		// as making that safe. It does not, because READ-ONLY RESTRAINS THE
		// WRONG PARTY, and not only at the root: the engine resolves conmon,
		// crun, netavark and fuse-overlayfs out of the WHOLE tree as root in
		// this sandbox's user namespace, so a writable directory anywhere
		// inside it — not just AT it — is the payload choosing what the
		// engine executes as root. This is CLAUDE.md's socket/FIFO lesson
		// with a third noun: `ro` says nothing about who else holds the path.
		//
		// Delegated to CheckEngineToolchainTree rather than asked here twice
		// (once for the root, once for the tree): the question and its
		// wording are authored ONCE in internal/policy/engineexec.go, and
		// KEPT here rather than folded into Policy.Graft's own B1 check
		// because Policy.Graft is a boundary check over a possibly hand-built
		// Policy — TestOnlyOneWriterOfEngineToolchainRoot's source sweep
		// excludes _test.go — and Validate re-runs checkGraft over every
		// already-installed graft, so B1 going stale (a mount added after it
		// ran) is still caught here.
		if toolchain {
			if err := p.CheckEngineToolchainTree(g.Host); err != nil {
				// Guest only in the prefix: the delegated message already
				// names the host, which for a toolchain graft IS the root it
				// judges. Naming it in both read "cannot graft X (host Y) ...:
				// Y cannot be ..." — the same path three times in one
				// sentence.
				return fmt.Errorf("cannot graft %s into the engine's view: %w", g.Guest, err)
			}
		}

		if !p.HostPathVisible(g.Host, g.Access == AccessRW) && !p.EngineOwnedHostPaths[g.Host] && !toolchain {
			needWrite := ""
			if g.Access == AccessRW {
				needWrite = ", writable"
			}
			msg := fmt.Sprintf("cannot graft %s (host %s%s) into the engine's view: the sandbox's own\n"+
				"       policy does not expose this host path, and snug did not create it for this run.\n"+
				"       A graft may only reach a host path the sandbox's OWN grants already expose — the\n"+
				"       engine's view is DERIVED from the sandbox's, never a second, wider window onto\n"+
				"       the host — or a path snug itself created (the container store, the runroot, a\n"+
				"       socket directory), or this run's recorded engine toolchain root, read-only.\n"+
				"       Grant it to the sandbox first, or graft a path snug owns.",
				g.Guest, g.Host, needWrite)
			// Said separately from the sentence above, because "the root is
			// recorded and you asked for it WRITABLE" is a different mistake
			// from "the root is not recorded", and one message covering both
			// would name neither.
			if p.EngineToolchainRoot != "" && g.Host == p.EngineToolchainRoot && g.Access == AccessRW {
				msg += "\n       That path IS this run's engine toolchain root, but it may only be grafted\n" +
					"       READ-ONLY: it is the host user's own installation, not something snug created\n" +
					"       for this run, so a writable graft of it is a host-write channel out of the engine."
			}
			// Appended ONLY when HostAsked is set — i.e. only when resolution
			// actually changed the source — so the ordinary (non-symlink) refusal
			// stays byte-identical to what it read before this fix (issue #55, F6).
			if g.HostAsked != "" {
				msg += fmt.Sprintf("\n       The source was named as %s, which is a SYMLINK on the host;\n"+
					"       snug judges what it resolves to, because open_tree(2) follows it (measured, issue #55).",
					g.HostAsked)
			}
			return fmt.Errorf("%s", msg)
		}
	}

	// G6 — a graft's SOURCE must be a DIRECTORY (issue #290).
	//
	// A POSITIVE PREDICATE, deliberately, not a mode blacklist mirroring §1's
	// socket-plus-FIFO check in validate.go: there is nothing to exempt and
	// nothing a future inode kind can be forgotten from. G3 already requires
	// the graft's DESTINATION to be a directory the sandbox created; this is
	// its other half — a graft moves a directory TREE onto a directory, and
	// relaxing either end without the other is the shape to watch. G3 and G6
	// are one sentence, not two rules that happen to sit near each other.
	//
	// COVERS SOCKET, FIFO AND DEVICE IN ONE CLAUSE, and that breadth matters
	// here in a way it does not for the mount-level check: the graft path is
	// open_tree(OPEN_TREE_CLONE) followed by move_mount (internal/stage's
	// engine-side stager), which CLONES the source mount and carries its
	// existing mount flags forward, adding only MOUNT_ATTR_RDONLY. bwrap's
	// `nosuid,nodev` on the sandbox's own binds does NOT travel with it — that
	// flag belongs to the bind bwrap created, not to the underlying mount
	// open_tree clones from — so the device exclusion validate.go's
	// rejectEndpointSource comment explains would be UNSOUND if copied here.
	// A positive "must be a directory" predicate sidesteps the question
	// entirely: it needs no device flag to lean on, because a device node is
	// not a directory either.
	//
	// ABSENT SOURCE IS NOT THIS RULE'S BUSINESS: skip silently on a Stat
	// error. GraftPathsInto runs at a point where the run directory a caller
	// is about to graft may not exist yet — issue #125's design pass measured
	// this — and refusing here would make --dry-run fail on host state
	// instead of on policy, which is a different function's job (G4's "source
	// must be visible" question, not this one's "source must be a
	// directory").
	//
	// NO Authored EXEMPTION, and none may be added. Policy.Graft marks every
	// graft's Authored field true a few lines into this file, BEFORE
	// checkGraft ever runs (see the doc comment on Graft above) — so `if
	// g.Authored { continue }` here would be unconditionally true for every
	// graft this package ever builds, the exact "documented but not
	// implemented" shape CLAUDE.md names. If snug ever needs the engine to
	// see a socket, the fix is to graft the DIRECTORY CONTAINING it and let
	// the engine bind the socket itself — which is what EngineSockGuest
	// already does. That sentence is what stops the next author reaching for
	// an exemption here instead.
	//
	// All five shipped graft sources are directories today (the container
	// store, the runroot, the socket directory, the config directory, and
	// EngineToolchainRoot), so nothing shipped starts failing.
	if rules.hasHost {
		if fi, err := env.Stat(g.Host); err == nil && !fi.IsDir() {
			return fmt.Errorf("cannot graft %s: its source %s is not a directory (mode %s).\n"+
				"       A graft is an open_tree(2) clone of the source moved onto the destination —\n"+
				"       G3 already requires the destination to be a directory the sandbox created, and\n"+
				"       this is that rule's other half: a graft moves a directory TREE, never a single\n"+
				"       socket, FIFO or device node. bwrap's `nosuid,nodev` does not travel with the\n"+
				"       clone into the engine's view, so a device node here would be a real hole, not a\n"+
				"       cosmetic one. If you need the engine to see a socket, graft the DIRECTORY\n"+
				"       containing it and let the engine bind the socket itself.",
				g.Guest, g.Host, fi.Mode())
		}
	}

	return nil
}

// EngineMountpoints are the guest paths BwrapFlags pre-creates (`--perms
// 0755 --dir`) so a container graft has somewhere to land, when
// p.Podman != PodmanOff (issue #125's design pass §1, "two engine-view
// mounts that are not grafts of a host path").
//
// /proc is deliberately NOT here. Every resolved policy already mounts a
// procfs at /proc — p.Mounts["/proc"] exists on every Policy Resolve
// produces — so a graft at /proc (Kind KindProc, the engine's own procfs)
// already passes existsInSandbox's FIRST disjunct with nothing extra to add.
// This list exists only for the paths nothing else in a resolved policy ever
// creates: no builtin profile grants /sys (@sys binds fourteen individual
// /etc entries and the OS runtime, never /sys), so without pre-creating it
// there is nowhere for the engine's cgroup2 mount (Guest /sys/fs/cgroup,
// Kind KindCgroup2) to land.
//
// The five under /snug/engine are Tier C's own destinations, and /snug and
// /snug/engine are listed above them for the same depth-ascending reason the
// /sys chain is: --dir creates no ancestors, and the root is read-only by the
// time anything else could. Listing /snug is not a second author of that
// directory — skeletonDirs already creates it whenever a profile stages a
// binary — it is what makes the destinations reachable on a container run that
// stages nothing, where nothing else would have created it.
//
// MEASURED, and it is why G3 insists the destination exist rather than trying
// to create it: mkdir on the sandbox's read-only root fails EROFS, while
// move_mount ONTO a directory that is already there succeeds — a mountpoint
// needs no write access to the filesystem beneath it (issue #125, the
// derived-view measurement).
//
// /var/tmp is here for a reason the design pass predicted and this
// implementation measured twice. containers/image hardcodes /var/tmp as the
// scratch space for the COMMIT step of a build — `TemporaryDirectoryForBigFiles`
// on Linux, which no environment variable reaches — so a build through the
// proxy returned 500 with `stat /var/tmp: no such file or directory` and kept
// doing so after containers.conf's image_copy_tmp_dir and $TMPDIR were both
// pointed somewhere the engine can write. The remaining consumer cannot be
// configured, so it gets a mountpoint and a fresh tmpfs, exactly like /run.
//
// It is NOT a graft of the host's /var/tmp, which is what §6 of the design
// ruled out: nothing of the host's is in it.
//
// /run is here for the same reason and a different mount: the engine needs a
// WRITABLE /run of its own — podman, seeing itself as root-like with the full
// delegated subuid range, does not self-mount one and fails outright on `mkdir
// /run/libpod` — and since issue #206 moved snug's own paths to /snug, a
// sandbox no longer creates /run at all. Under the derived view the engine's
// /run is whatever the SANDBOX's view has at /run, so without this entry there
// is no directory for the engine's tmpfs to land on and the mount fails ENOENT.
//
// What that costs the payload is one empty directory on the read-only root, and
// only on a run that selects a container engine. It grants nothing: the tmpfs
// itself is mounted in the ENGINE's namespace (Kind KindTmpfs in p.Grafts,
// which is why it is modelled rather than unmodelled — issue #125's design pass
// §9.2), and the payload sees the empty mountpoint, never the tmpfs.
//
// All THREE of /sys, /sys/fs and /sys/fs/cgroup are listed, not just the
// leaf: bwrap's --dir does not create ancestors implicitly the way a bind's
// auto-created mountpoint parents do (skeletonDirs, bwrap.go), and the
// sandbox root is read-only after --remount-ro / — the LAST filesystem
// operation BwrapFlags performs — so nothing later in the run can create
// what was not pre-created here. Order matters for the same reason
// skeletonDirs is depth-ascending: /sys/fs/cgroup needs /sys/fs to already
// be a directory, which needs /sys.
var EngineMountpoints = []string{
	"/run",
	"/snug", "/snug/engine",
	EngineStoreGuest, EngineRunrootGuest, EngineSockGuest, EngineConfGuest, EngineToolchainGuest,
	"/sys", "/sys/fs", "/sys/fs/cgroup",
	"/var/tmp",
}

// existsInSandbox is G3: a graft's destination must already be a directory
// inside the SANDBOX's own mount namespace before move_mount(2) can land
// anything on it. ENGINE-NETNS.md §5.1 measured mkdir failing with EROFS on
// the read-only root tmpfs, and succeeding (EEXIST) wherever the directory
// already existed — so the discriminator is the directory, not the mount.
//
// Four ways a destination can already exist, only the THIRD of which is a
// guess:
//
//   - it is itself a mountpoint (a Guest key in p.Mounts);
//   - it is a strict ANCESTOR of one — bwrap auto-creates a mount's parent
//     directories (--dir), so the directory is there even though nothing is
//     mounted AT it;
//   - it sits inside a writable grant (KindBind rw, or KindTmpfs) — the STAGE
//     can mkdir it there before move_mount runs;
//   - it is one of EngineMountpoints, AND this run selects a container
//     engine (p.Podman != PodmanOff) — BwrapFlags pre-creates exactly this
//     list, under exactly this condition, so the fourth disjunct has to
//     match the same condition or it would accept a graft destination
//     nothing in THIS run's argv actually creates.
//
// THE THIRD DISJUNCT IS A SOUNDNESS APPROXIMATION, NOT A FACT, and must be
// read as one: "the stage can create this" is not the same claim as "this
// exists", and this function cannot run mkdir to find out (internal/policy
// stays pure — no filesystem, no exec). A destination this disjunct accepts
// that some unmodelled interaction has already turned into a file rather than
// a directory still fails at runtime — which is exactly why §6 makes the
// runtime open_tree/mount_setattr/mkdir/move_mount failure FATAL rather than
// treating this check as the last word. The two are not redundant: this is
// where an approximation that guessed wrong surfaces. The FOURTH disjunct is
// not this kind of approximation — EngineMountpoints and BwrapFlags's
// emission of it are the SAME list, so this is a fact about the argv this
// run will actually produce, not a guess about the filesystem.
//
// Checked against ENGINE-NETNS.md §5.1's four measured rows: /etc/containers
// and /var/tmp match none of the three (@sys binds fourteen individual /etc
// entries, never /etc itself) -> refused, matching the measurement. /run is a
// strict ancestor of /snug/bin/claude under @claude -> passes this, then
// is refused by G1 — also matching. A destination inside an AccessRW bind ->
// accepted by the third disjunct, matching "onto a writable grant".
func existsInSandbox(p *Policy, guest string) bool {
	if _, ok := p.Mounts[guest]; ok {
		return true
	}
	for _, m := range p.Mounts {
		if m.Guest != guest && covers(guest, m.Guest) {
			return true
		}
	}
	if m, ok := p.SandboxView().coveringMount(guest); ok {
		if (m.Kind == KindBind || m.Kind == KindTmpfs) && m.Access == AccessRW {
			return true
		}
	}
	if p.Podman != PodmanOff {
		for _, mp := range EngineMountpoints {
			if mp == guest {
				return true
			}
		}
	}
	return false
}

// HostPathVisible reports whether the SANDBOX can itself see a host path at the
// given access. It is G4's first disjunct and the same rule
// internal/dockerproxy's bind filter enforces for a container's own `-v`
// requests — invariant 6: one author of "can the sandbox see this host path",
// not two implementations that eventually disagree.
//
// IT IS PURELY LEXICAL, AND THAT IS A CONTRACT ON ITS CALLERS RATHER THAN AN
// OVERSIGHT. It compares strings against p.Mounts; it touches no filesystem and
// takes no Environ, so it cannot tell a directory from a symlink pointing out of
// every grant this policy makes. Measured (issue #55, F6): open_tree(2) FOLLOWS
// a final symlink, and podman resolves a `-v` source on the host. A caller that
// asks this about a literal string the payload can influence is asking about a
// NAME, not about a TREE, and `ln -s ~/.ssh $TARGET/link` then passes.
//
// Every caller therefore owes it a path already put through
// ResolveExistingHostPath, and must USE the resolved path afterwards rather than
// the one it asked about — resolving and then passing the literal onward moves
// the hole instead of closing it. There are exactly FIVE non-test callers,
// and every one either discharges the obligation immediately before calling,
// or is reading a value some OTHER caller already discharged it for:
//
//   - dockerproxy.(*Proxy).checkOne — resolves, audits a divergence, and
//     forwards the RESOLVED Source to the engine (create.go).
//   - policy.(*Policy).checkGraft — G4, over a Graft whose Host Policy.Graft has
//     already rewritten, and which checkGraft additionally requires to be a
//     fixed point of the same resolution, so a hand-built Policy cannot install
//     an unresolved one either.
//   - internal/cli's describeGrafts (dryrun.go) — NOT a decision, a RENDER.
//     It asks only whether an already-installed graft's stored Host is
//     visible through the sandbox's own grants, so it can print the "owned:"
//     provenance line when the answer is no (issue #55, finding F2). The
//     Host it asks about was already resolved by Policy.Graft before this
//     ever runs — the obligation was discharged at write time, not here — so
//     this caller owes nothing further; it would be wrong for it to resolve
//     a SECOND time and risk printing a provenance line about a different
//     sample of the host than the one that was actually judged.
//   - policy.(*Policy).CheckEngineBinary and policy.(*Policy).
//     CheckEngineToolchainTree (engineexec.go, issue #405) — both ask about a
//     value the CALLER resolved before handing it here: CheckEngineBinary's
//     path is preflightPodmanBinary's return, resolved at
//     containerpreflight.go's own two return sites; CheckEngineToolchainTree's
//     root is JudgeEngineToolchain's argument, already put through
//     ResolveExistingHostPath a few lines above where it calls this file's B1
//     check, or (from checkGraft's G4b) a Graft.Host Policy.Graft already
//     resolved — the same fixed point checkGraft's own entry above relies on.
//   - policy.(*Policy).writableNameOnChain (engineexec.go) — the one caller
//     that deliberately asks about UNRESOLVED and INTERMEDIATE spellings. It
//     is asking "can the payload rewrite this NAME", which only has an
//     answer BEFORE resolution, not "can the sandbox see this object", so it
//     owes this function nothing; do not "fix" it by resolving its argument
//     first — that is precisely the defect it exists to close.
//
// TestHostPathVisibleCallersAreInventoried fails when a SIXTH caller
// appears. Adding one means writing its resolution obligation (or its reason
// for owing none, as describeGrafts's entry does) into this list: a tripwire
// on the SET is the only enforceable form of an obligation that cannot be
// checked at the call itself.
//
// It walks only KindBind mounts, matching a host path against a mount's Host
// by exact match or path-ancestor — never a string prefix — and, for a
// writable request, requiring AccessRW. A snug-GENERATED KindData grant (the
// identity files, /etc/resolv.conf) is invisible to this on purpose: it has no
// host path to match against, and inventing one would be a second, guessed
// answer to "what does this correspond to on the host".
func (p *Policy) HostPathVisible(host string, needWrite bool) bool {
	host = filepath.Clean(host)
	for _, m := range p.Mounts {
		if m.Kind != KindBind {
			continue
		}
		if host != m.Host && !strings.HasPrefix(host, m.Host+"/") {
			continue
		}
		if needWrite && m.Access != AccessRW {
			continue
		}
		return true
	}
	return false
}

// EngineGuestPath maps a HOST path to the path the ENGINE sees it at, or
// reports that the engine cannot see it at all.
//
// It exists because the engine's view is DERIVED from the sandbox's rather than
// being a copy of the host tree, which means every host path snug hands the
// engine — its argv, its environment, and the absolute paths inside
// the configuration files snug generates for it — stops meaning what it said.
// A store at /home/u/.local/share/snug/engines/<key>/storage is
// /snug/engine/store from inside; a podman inside a pinned bundle is under
// /snug/engine/toolchain; a podman in /usr/bin is still /usr/bin, because the
// sandbox's own @sys grant already exposes it and the engine's view inherits
// that.
//
// THE THREE CASES ARE THE WHOLE RULE, and the third one is why this returns a
// bool rather than a string:
//
//   - a GRAFT's Host covers it — the deepest such graft wins, and the answer is
//     that graft's Guest plus the remainder;
//   - failing that, a KindBind MOUNT's Host covers it — the sandbox's own view,
//     which the engine's is derived from, so the same path with the same
//     remainder;
//   - failing both, THE ENGINE CANNOT SEE IT. Callers must treat that as a
//     refusal and say so (invariant 5): handing the engine a path it cannot
//     resolve produces podman's own error several layers down, about a file
//     rather than about a boundary.
//
// WHAT THIS IS NOT (issue #371). This answers "where does the engine see this
// host CONTENT", which is a WIRING question: internal/engine asks it about
// paths SNUG owns, to write them into the engine's argv, environment and
// generated configuration. It is not "what does the engine find at this NAME",
// and it must never be asked about a payload-supplied string — its first arm
// matches a GRAFT by Graft.Host and so answers "visible at /snug/engine/store"
// for exactly the engine-owned host paths HostPathVisible refuses (the hole
// issue #251 closed), and its graft-first tie-break returns the graft's name
// even where the sandbox's own mount still exposes the same content at its own
// name — a live over-refusal wherever $SNUG_PODMAN_ROOT sits inside a grant,
// which containerpreflight.go permits ("usually" outside, not "always"). The
// security question is Policy.CheckEngineForwardedPath. Callers: internal/engine
// only — TestEngineGuestPathIsAskedOnlyByTheEngineWiring.
//
// A mount-derived answer is discarded when a graft's Guest covers it. Grafts
// are installed ON TOP of the sandbox's view, so the mount that would have
// answered is shadowed in the engine's namespace and its path now names the
// graft's content instead — a different tree with the same name, which is the
// one answer worse than "cannot see it".
//
// Purely lexical, like HostPathVisible and for the same reason: internal/policy
// touches no filesystem. Callers owe it a path already put through
// ResolveExistingHostPath — Policy.Graft has already done that for every
// graft's own Host, so the SET this matches against is resolved even when the
// question is not.
func (p *Policy) EngineGuestPath(host string) (string, bool) {
	host = filepath.Clean(host)

	best, bestGuest := "", ""
	for _, g := range p.Grafts {
		if !graftKindRules[g.Kind].hasHost || g.Host == "" {
			continue
		}
		if !covers(g.Host, host) {
			continue
		}
		if len(g.Host) > len(best) {
			best, bestGuest = g.Host, g.Guest
		}
	}
	if best != "" {
		return joinRemainder(bestGuest, best, host), true
	}

	for _, m := range p.Mounts {
		if m.Kind != KindBind || m.Host == "" {
			continue
		}
		if !covers(m.Host, host) {
			continue
		}
		if len(m.Host) > len(best) {
			best, bestGuest = m.Host, m.Guest
		}
	}
	if best == "" {
		return "", false
	}
	guest := joinRemainder(bestGuest, best, host)
	for _, g := range p.Grafts {
		if covers(g.Guest, guest) {
			return "", false
		}
	}
	return guest, true
}

// joinRemainder is the "same remainder" half of EngineGuestPath: the part of
// host below root, appended to guest. Split out so the two arms cannot drift.
func joinRemainder(guest, root, host string) string {
	if host == root {
		return guest
	}
	return filepath.Join(guest, strings.TrimPrefix(host, root+"/"))
}
