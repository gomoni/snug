package policy

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

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
// PRECONDITIONS. This is a purely lexical comparison, so it is only as sound
// as the strings it compares — each is required, and named here with where it
// is actually discharged, not merely assumed:
//
//   - Requires every grant's Host to be CANONICAL, not merely as a profile
//     spelled it. Discharged by Resolve (resolve.go:177), which runs every
//     KindBind grant's Host through env.EvalSymlinks before it ever reaches
//     p.Mounts — the same comment there names why ("a symlink planted inside
//     the sandbox later cannot retroactively widen a grant resolved here").
//     This is what stops an obvious-looking evasion from working: a grant
//     spelled at /proj/link, where link -> the real toolchain directory, does
//     NOT let a writable grant hide from this check, because m.Host is
//     already the RESOLVED target by the time this reads it, never the
//     spelling a profile wrote.
//   - Requires path itself to be CANONICAL. Unlike the grant side, this one is
//     NOT inherited from an existing invariant — it exists only because this
//     change adds it: preflightPodmanBinary (containerpreflight.go) now runs
//     its return value through policy.ResolveExistingHostPath immediately
//     before every return. If a later change moves or drops that call, this
//     predicate starts silently comparing an unresolved spelling instead of
//     refusing to compile or panicking — nothing here can detect that, which
//     is why the call is also documented at the resolution site itself.
//   - Requires path to name a regular FILE, which is what makes "ancestor
//     only, no descendant arm" correct rather than a simplification.
//     Discharged twice, once per source: preflightPodmanBinary's own
//     fi.IsDir() refusal of a $SNUG_PODMAN naming a directory
//     (containerpreflight.go), and, for the PATH lookup, os/exec's own
//     requirement that a candidate not be a directory before it is returned
//     from LookPath.
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
