package policy

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// writableNameOnChain returns the FIRST name the resolution of asGiven
// passes through that a writable grant of this sandbox covers. Root-first,
// so the SHALLOWEST offender is reported — that is the one a human fixes,
// and it is usually a directory rather than the leaf.
//
// THE QUESTION IS PROVENANCE, NOT CONTENT, and that is why it exists
// beside HostPathVisible rather than inside it. HostPathVisible answers
// "can the payload write the object at this path"; this answers "can the
// payload decide which object that path names". They are the same question
// for a regular file and different questions for a symlink, which is the
// whole of the defect.
//
// TWO ARMS PER PREFIX, and NEITHER IMPLIES THE OTHER:
//
//   - the SPELLING q — the payload can replace that name outright. This is
//     the arm the measured defect needed: $TARGET/podman is inside
//     @cwd-rw's grant while /usr/bin/true, what it pointed at, is inside no
//     writable grant at all.
//   - q's CANONICAL form — the payload can write through that path, or
//     plant a name under it. This is the arm that catches a PATH entry
//     symlinked into the sandboxed tree: $PATH holds /opt/tools,
//     /opt/tools -> $TARGET/bin, and neither endpoint of the walk is
//     covered by a writable grant.
//
// A grant's Host is CANONICAL by the time it reaches p.Mounts (Resolve,
// resolve.go:177), which is what makes the pair a partition rather than a
// belt-and-braces duplicate: the first arm fires when a canonical grant
// covers a SPELLING, the second when one covers a RESOLUTION. Neither can
// be dropped.
//
// The `real != cur` guard keeps that partition clean: where a prefix is
// already canonical the second arm would re-ask the identical question the
// first just answered, and a hit would not be attributable to an arm.
//
// A prefix that does not exist is skipped, not refused, for the reason
// Policy.Graft states at graft.go:55 — nothing exists at a path that does
// not exist, so there is no symlink to rewrite, and making existence a
// policy input would let a payload choose which refusal a human sees.
//
// asked is "" when the SPELLING arm fired, and the prefix as spelled when
// the CANONICAL arm did, so a caller's message can name the link AND where
// it points.
//
// IT ADDS NOTHING ON A CANONICAL PATH, WHICH IS WHY ONLY TWO SITES CALL IT.
// Feed it a fixed point of ResolveExistingHostPath and it degenerates,
// provably, into HostPathVisible(path, true):
//
//   - the SPELLING arm walks ancestor prefixes, and HostPathVisible already
//     matches a grant at ANY ancestor of the leaf — so an ancestor hit here is
//     a hit there, and vice versa;
//   - the CANONICAL arm is dead, because every prefix of a symlink-free path is
//     itself symlink-free, so `real != cur` is false at every step.
//
// The selection question therefore only has CONTENT for a non-canonical input,
// and the only sites that ever see one are the two writers that accept a
// HUMAN'S RAW STRING: ResolveEngineBinary ($SNUG_PODMAN or exec.LookPath's
// answer) and EngineToolchain ($SNUG_PODMAN_ROOT).
//
// checkGraft's G4b is the site a reader will ask about. It judges g.Host, which
// for the toolchain disjunct must EQUAL p.EngineToolchainRoot — a value only
// EngineToolchain can write (TestOnlyOneWriterOfEngineToolchainRoot), which
// EngineToolchain resolved and which checkGraft additionally requires to be a
// fixed point of ResolveExistingHostPath (G4's resolution half). So G4b's input
// is canonical by two independent mechanisms, the theorem above applies, and
// adding this call there would be a second author of a question
// CheckEngineToolchainTree's ancestor arm already answers identically. The
// asymmetry is not a gap: the raw spelling never reaches G4b, and there is
// nothing left there to ask the question OF.
//
// The two doors are ordered in TIME, not competing: a root refused here is
// never recorded, so p.EngineToolchainRoot stays empty, the toolchain
// disjunct's `g.Host == p.EngineToolchainRoot` cannot be satisfied, and the
// graft is never attempted.
func (p *Policy) writableNameOnChain(env Environ, asGiven string) (name, asked string, found bool) {
	cur := "/"
	for _, comp := range strings.Split(strings.TrimPrefix(filepath.Clean(asGiven), "/"), "/") {
		if comp == "" {
			continue
		}
		cur = filepath.Join(cur, comp)
		if p.HostPathVisible(cur, true) {
			return cur, "", true
		}
		real, err := ResolveExistingHostPath(env, cur)
		if err != nil {
			continue
		}
		if real != cur && p.HostPathVisible(real, true) {
			return real, cur, true
		}
	}
	return "", "", false
}

// ResolveEngineBinary resolves the host path snug will exec as this run's
// container engine and refuses it when this sandbox's own grants let the
// PAYLOAD choose it — by writing the BYTES (CheckEngineBinary's arm) or by
// rewriting a NAME the resolution passes through (writableNameOnChain's).
//
// asGiven is the path AS NAMED: $SNUG_PODMAN's value, or exec.LookPath's
// answer. NEVER a path a caller resolved first. That inversion is the fix:
// resolution and judgement now happen in one function over ONE sample of
// the host, so there is no call-site precondition left for a later change
// to move, and no window in which the value judged and the value exec'd
// could be two different samples.
//
// ABSOLUTE, refused rather than accommodated. exec.LookPath fails closed on
// a relative PATH entry (MEASURED: it returns "bin/podman" together with
// ErrDot, "cannot run executable found relative to current directory",
// which preflightPodmanBinary already treats as an error), but $SNUG_PODMAN
// is only os.Stat'd. A relative value there makes every lexical check on
// this path VACUOUS, not wrong-answered: HostPathVisible compares against
// canonical, absolute grant Hosts, so "bin/podman" matches nothing and is
// accepted, and DetectHostShim's own LookPath fails closed and silently
// does not run either. helperBesideEngine (internal/engine/engine.go:1389)
// already refuses a relative engine, one layer downstream and with a
// different message; refusing here is what stops the SECURITY check from
// answering a question about a string that means nothing.
//
// Arm order is load-bearing. CheckEngineBinary runs FIRST so a hit at the
// BYTES keeps its own wording and its own golden section byte-identical
// (refusals.txt, engine_binary_inside_a_writable_grant): the payload
// writing the engine is strictly the worse fact and must not be
// re-described as a naming problem. Once it clears, the chain's last prefix
// can no longer fire its canonical arm — same string, same predicate — so
// the two verdicts partition rather than overlap.
func (p *Policy) ResolveEngineBinary(env Environ, asGiven string) (string, error) {
	if !filepath.IsAbs(asGiven) {
		return "", fmt.Errorf("%s cannot be this run's container engine: it is not an absolute path.\n"+
			"       Every check snug makes on the engine binary compares it against this sandbox's\n"+
			"       grants, which are absolute and canonical — a relative name matches none of them,\n"+
			"       so it would be ACCEPTED without being judged, and then exec'd relative to snug's\n"+
			"       own working directory rather than to anything --dry-run described.\n"+
			"       Fix: set $SNUG_PODMAN to an absolute path.", asGiven)
	}
	asGiven = filepath.Clean(asGiven)
	// asGiven reaches a refusal a human reads, twice, below. Same sink rule as
	// EngineToolchain's "(asked)" check: guard the value at every sink, not at
	// the site where the need was noticed.
	if err := checkPathHygiene("container engine binary", asGiven, "(snug)", "the CONTAINERS block"); err != nil {
		return "", err
	}
	resolved, err := ResolveExistingHostPath(env, asGiven)
	if err != nil {
		resolved = filepath.Clean(asGiven)
	}
	if err := p.CheckEngineBinary(resolved); err != nil {
		return "", err
	}
	if name, asked, found := p.writableNameOnChain(env, asGiven); found {
		return "", fmt.Errorf("%s cannot be this run's container engine: %s\n"+
			"       The bytes at the end of that chain (%s) are not writable, so this is not the\n"+
			"       payload EDITING the engine — it is the payload CHOOSING it. snug execs whatever\n"+
			"       this name resolves to as uid 0, pid 1 of the engine's pid namespace, with\n"+
			"       CAP_SYS_ADMIN in this sandbox's user namespace and the whole delegated subuid\n"+
			"       range, so a name the payload can rewrite is the payload deciding what runs as\n"+
			"       root — and every other filter on the container path is moot, because the payload\n"+
			"       picked the engine.\n"+
			"       Read-only would not help: `ro` restrains the ENGINE, and the payload rewrites the\n"+
			"       same host name through its own rw grant.\n"+
			"       Fix: name the engine by a path no rw grant covers — point $SNUG_PODMAN at the\n"+
			"       binary itself (%s), take the writable directory off $PATH, or drop the rw grant.\n"+
			"       `snug --dry-run` lists every grant this sandbox makes; the one to look for is\n"+
			"       whichever covers the name above.",
			asGiven, selectionClause(name, asked), resolved, resolved)
	}
	return resolved, nil
}

// selectionClause renders the one sentence that differs between
// writableNameOnChain's two arms, so each SUBJECT (the engine binary, the
// toolchain root) has one message rather than two near-copies — and so the
// arms stay distinguishable in refusals.txt, which is where a human reads
// them.
func selectionClause(name, asked string) string {
	if asked == "" {
		return "a grant of this sandbox makes that NAME writable."
	}
	return fmt.Sprintf("resolving it goes through %s (%s points there), and a grant of\n"+
		"       this sandbox makes THAT writable.", name, asked)
}

// CheckEngineBinary refuses to hand a container engine a host binary this
// sandbox's own grants let the PAYLOAD write.
//
// path names a regular FILE — the engine binary snug is about to exec,
// resolved by preflightPodmanBinary either from $SNUG_PODMAN or from PATH —
// never a directory: preflightPodmanBinary refuses a $SNUG_PODMAN naming one
// (fi.IsDir(), containerpreflight.go), and exec.LookPath never returns one
// either. A regular file has nothing strictly BELOW it, so only the ANCESTOR
// direction — "does a writable grant cover this path, or an ancestor of it" —
// can ever apply, and that is exactly what HostPathVisible answers. That is
// the whole argument for two predicates instead of one widened one:
// file -> ancestor only; tree -> ancestor plus descendants
// (CheckEngineToolchainTree, below, is the tree half).
//
// WHY THIS MATTERS. snug execs this file as uid 0, pid 1 of the engine's pid
// namespace, with EngineCapBounding's twelve capabilities (CAP_SYS_ADMIN among
// them) and the whole delegated subuid range. A binary the payload can write
// is therefore the payload choosing what runs as root, and every OTHER filter
// on the container path — the proxy, the private netns, the capability drop —
// is moot, because the payload has become the engine before any of them ever
// run. Nothing gated this before: $SNUG_PODMAN and the PATH lookup both land
// in the single containerPreflight.Podman field, and G4b guards only the
// toolchain GRAFT, which is not installed at all when $SNUG_PODMAN_ROOT is
// unset — the default.
//
// Deliberately does not name the offending grant: doing so needs a SECOND
// enumeration of the ancestor direction — a second author for a question
// HostPathVisible already answers. The message names the path judged and
// points at --dry-run, which already lists every grant.
//
// PRECONDITIONS. This is a purely lexical comparison, so it is only as sound as
// the strings it compares. CANONICALISATION APPEARS TWICE BELOW WITH OPPOSITE
// SIGNS, and merging the two is how this defect happened — read the signs, not
// the word:
//
//   - CANONICALISING THE GRANT SIDE **CLOSES** AN EVASION, and is required.
//     Discharged by Resolve (resolve.go:177), which runs every KindBind grant's
//     Host through env.EvalSymlinks before it ever reaches p.Mounts. A grant
//     spelled /proj/link, where link points at the real toolchain directory,
//     therefore CANNOT hide a writable grant from this check: m.Host is already
//     the resolved target by the time this reads it, never the spelling a
//     profile wrote. More grants match after canonicalisation than before, so
//     the operation is monotone in the refusing direction.
//
//   - CANONICALISING THE JUDGED PATH **OPENS** ONE, and this function no longer
//     asks for it. It used to: the precondition read "requires path itself to be
//     CANONICAL", discharged by a ResolveExistingHostPath call at
//     preflightPodmanBinary's two return sites, and it was documented,
//     deliberate, and the defeat. MEASURED: a payload-writable symlink at
//     $TARGET/podman -> /usr/bin/true was resolved before this ran, so this
//     judged /usr/bin/true — read-only, correctly accepted — and snug exec'd the
//     binary the payload had chosen. Fewer names match after canonicalisation
//     than before, so the operation is monotone in the ACCEPTING direction,
//     which is the opposite sign from the grant side.
//
//     What this function may therefore assume is not "canonical" but "FINAL":
//     path is the byte sequence snug is about to exec, and this function takes
//     NO view on how that path was named. "Could the payload choose this name"
//     is a different question with a different answer shape, and
//     ResolveEngineBinary (above) owns it, resolving and judging in one call so
//     that no call site is left holding an obligation it can silently drop.
//
//   - Requires path to name a regular FILE, which is what makes "ancestor only,
//     no descendant arm" correct rather than a simplification. Discharged twice,
//     once per source: preflightPodmanBinary's own fi.IsDir() refusal of a
//     $SNUG_PODMAN naming a directory (containerpreflight.go), and, for the PATH
//     lookup, os/exec's own requirement that a candidate not be a directory
//     before LookPath returns it.
func (p *Policy) CheckEngineBinary(path string) error {
	path = filepath.Clean(path)
	if !p.HostPathVisible(path, true) {
		return nil
	}
	return fmt.Errorf("%s cannot be this run's container engine: a grant of this sandbox makes it\n"+
		"       WRITABLE.\n"+
		"       snug execs this file as uid 0, pid 1 of the engine's pid namespace, with\n"+
		"       CAP_SYS_ADMIN in this sandbox's user namespace and the whole delegated subuid\n"+
		"       range — so an engine binary the payload can write is the payload choosing what\n"+
		"       runs as root, and every other filter on the container path is moot because the\n"+
		"       payload IS the engine.\n"+
		"       Read-only would not help: `ro` restrains the ENGINE, and the payload writes the\n"+
		"       same host inode through its own rw grant.\n"+
		"       Fix: install the engine somewhere no rw grant covers, or point $SNUG_PODMAN at\n"+
		"       one, or drop the rw grant. `snug --dry-run` lists every grant this sandbox makes;\n"+
		"       the one to look for is whichever covers this path.", path)
}

// writableGrantsBelow returns the sorted, deduplicated Host of every writable
// KindBind mount STRICTLY below root — never root itself, which is
// HostPathVisible's arm, not this one.
//
// STRICT so the two directions PARTITION the question: for any grant G and any
// root R, exactly one of — G is R or an ancestor of it (HostPathVisible's
// arm), G is strictly below R (this arm), or the two are disjoint — ever
// holds. Overlapping arms would make the composed answer depend on the order
// the two are asked in; a partition makes CheckEngineToolchainTree's "ask
// both" provably total, and it means neither arm can be dropped without a
// named test failing.
//
// Reuses covers (validate.go) rather than a hand-rolled strings.HasPrefix, for
// the reason every other caller in this package does: a bare prefix test
// accepts a SIBLING whose name happens to extend root's ("/proj/sub-other"
// against a root of "/proj/sub"), which is exactly the off-by-one this
// question's matrix is built to catch.
//
// UNEXPORTED on purpose: asked alone it silently misses the equal case, which
// is the arm G4b already had before this existed, and a caller composing the
// two predicates by hand is precisely how one of them gets forgotten a second
// time (CheckEngineToolchainTree is the one caller allowed to compose them).
//
// Host space, KindBind only, Mounts only — never Guest (a divergent bind is
// judged by the host inode the payload actually writes, not by where the
// sandbox displays it) and never Grafts (those are the ENGINE's own derived
// view; this question is about the PAYLOAD's grants).
func (p *Policy) writableGrantsBelow(root string) []string {
	root = filepath.Clean(root)
	seen := map[string]bool{}
	for _, m := range p.Mounts {
		if m.Kind != KindBind || m.Host == "" || m.Access != AccessRW {
			continue
		}
		h := filepath.Clean(m.Host)
		if h == root || !covers(root, h) {
			continue // STRICT: equality excluded, disjoint excluded
		}
		seen[h] = true
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// CheckEngineToolchainTree refuses to adopt root as this run's engine
// toolchain root when this sandbox's own grants make root ITSELF writable, or
// make anything inside the tree BELOW it writable.
//
// Two arms, asked in this order so a grant AT the root keeps issue #390's
// original wording: the ancestor arm (HostPathVisible) runs first, and only
// once it clears does the tree arm (writableGrantsBelow) run — this time
// NAMING every offending path, because here the enumeration IS the verdict:
// no other function in this package answers "what, below this root, is
// writable", so listing them costs no second author of the question.
//
// WHY THE TREE ARM EXISTS AT ALL (issue #405, second half). G4b's
// HostPathVisible check is directional: it matches a writable grant AT OR
// ABOVE root, never one strictly inside it. A grant at
// $ROOT/usr/local/lib/podman — the directory holding conmon, crun, netavark —
// or at $ROOT/usr/local/bin — holding the engine binary itself, this ticket's
// FIRST half through a different door — passed G4b silently. The engine
// resolves those helpers out of the recorded root as uid 0 in this sandbox's
// user namespace (helper_binaries_dir and the toolchain graft exist precisely
// so it can), so a writable directory ANYWHERE inside the tree is the payload
// choosing what the engine executes as root, even on a root whose top level
// holds no podman at all.
//
// PRECONDITIONS, named with where each is discharged rather than assumed —
// both arms are purely lexical, so an unresolved string on either side of the
// comparison makes the answer meaningless:
//
//   - Requires every grant's Host to be CANONICAL. Discharged by Resolve
//     (resolve.go:177) for the same reason and in the same place
//     CheckEngineBinary's matching precondition names — a symlinked grant
//     cannot hide a writable path from either arm, because m.Host is already
//     resolved by the time this walks p.Mounts.
//   - Requires root to be CANONICAL. Discharged at both call sites, never by
//     this function itself: at B1, EngineToolchain resolves its argument via
//     ResolveExistingHostPath (graft.go:162-166) BEFORE checkPathHygiene and
//     therefore before it calls this check — CONDITIONALLY: that call falls
//     back to a bare filepath.Clean when ResolveExistingHostPath errors, which
//     it does only when not even "/" resolves through the injected Environ, an
//     outcome preflightToolchainRoot's own os.Stat+IsDir on the root already
//     excludes for the one production caller (containerpreflight.go), so the
//     fallback is reachable only from a test-supplied Environ built to error
//     unconditionally. At B2, Policy.Graft (graft.go:69-77) resolves g.Host
//     through the SAME two-armed call and assigns the result back to g.Host
//     before calling checkGraft — Policy.Graft's own fallback IS reachable in
//     production for other grafts (its comment there: a resolution failure is
//     not a refusal, because a path snug itself is about to create, like the
//     store, legitimately does not exist yet), but not for the TOOLCHAIN
//     disjunct specifically: g.Host there must equal p.EngineToolchainRoot,
//     which preflightToolchainRoot already required to exist (os.Stat) before
//     it was ever recorded, so the happy (fully-resolved) arm is what runs.
//     Either way, the graft-time caller of this function is judging the
//     identical fixed point checkGraft's other G4 disjuncts already rely on.
func (p *Policy) CheckEngineToolchainTree(root string) error {
	root = filepath.Clean(root)
	if p.HostPathVisible(root, true) {
		return fmt.Errorf("%s cannot be this run's engine toolchain root: a grant of this sandbox makes it\n"+
			"       WRITABLE.\n"+
			"       Grafting it read-only does not help, because read-only restrains the wrong\n"+
			"       party: it stops the ENGINE writing and does nothing about the payload, which\n"+
			"       writes the same host directory through its own rw grant so the new bytes\n"+
			"       appear under the engine's read-only graft. The engine resolves conmon, crun\n"+
			"       and netavark out of that directory as root in this sandbox's user namespace,\n"+
			"       so a directory the payload can write is the payload choosing what the engine\n"+
			"       executes as root.\n"+
			"       Fix: put the engine somewhere no rw grant covers, or drop the rw grant.", root)
	}

	below := p.writableGrantsBelow(root)
	if len(below) == 0 {
		return nil
	}
	var listed strings.Builder
	for _, h := range below {
		listed.WriteString("             " + h + "\n")
	}
	return fmt.Errorf("%s cannot be this run's engine toolchain root: the root itself is not\n"+
		"       writable, but a grant of this sandbox makes part of the TREE below it writable:\n"+
		"%s"+
		"       The engine resolves conmon, crun, netavark and fuse-overlayfs out of that tree as\n"+
		"       uid 0 in this sandbox's user namespace, and helper_binaries_dir plus the toolchain\n"+
		"       graft exist precisely so it can — so one writable directory anywhere inside is the\n"+
		"       payload choosing what the engine executes as root, even when it holds no podman.\n"+
		"       Grafting the root read-only does not help: `ro` restrains the ENGINE, while the\n"+
		"       payload writes the same host inode through its own rw grant and the bytes appear\n"+
		"       under the graft.\n"+
		"       Fix: put the engine's installation outside every rw grant, or drop the grant(s)\n"+
		"       listed above.", root, listed.String())
}
