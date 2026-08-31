package policy

import (
	"fmt"
	"path/filepath"
	"strings"
)

// CheckEngineBindSource reports whether a guest path is safe to forward to the
// container engine as a bind mount SOURCE. nil means every name on the path is
// anchored: nothing this sandbox holds — no rename, no capability, no other
// grant — can re-point what that name resolves to between this check and the
// container engine's own start-time resolution of it.
//
// # Why a second check exists at all (issue #284)
//
// checkOne already resolves and vets a bind source once, at container CREATE.
// The engine (crun, via libpod) re-resolves the same path string a second
// time, from a SEPARATE process, at container START — a distinct client
// request with an attacker-controlled gap in between. Path-string forwarding
// cannot be made safe against that by resolving harder: resolving finds the
// inode a name pointed at ONCE, and forwards the NAME, not the inode. If any
// component of that name sits in a directory this sandbox can still write
// AFTER the check, the payload renames a symlink into that slot in the gap
// and the engine's own resolution follows it — into, among other places,
// `/snug/engine/store`: this sandbox's read-write, host-backed, cross-run
// container store (measured, issue #284: `mkdir realdir; podman create -v
// realdir:/x; rmdir realdir; ln -s /snug/engine/store realdir; podman start`
// mounted the store read-write into the container, with the payload's own
// `/snug/engine/store` still empty — the store is not in the sandbox's own
// namespace at all).
//
// # The rule (the "anchored source rule")
//
// For guest, walk its component paths C_1 = "/", C_2, ..., C_n = guest. For
// each C_i with parent P = C_(i-1):
//
//  1. P is not payload-writable at C_i's depth -> C_i is anchored; the walk
//     continues to the next component.
//  2. P IS payload-writable and C_i is NOT itself a mount root -> C_i is a
//     plain name in a directory this sandbox can write: SWAPPABLE. Refused,
//     naming C_i (M2, the #284 primitive itself; M5, the same shape one level
//     up when the writable ancestor is a tmpfs rather than a bind — e.g. a
//     target living under /tmp).
//  3. P IS payload-writable and C_i IS a mount root -> C_i cannot be renamed
//     onto FROM WITHIN THIS SANDBOX's OWN mount namespace: `mv` onto a live
//     mountpoint returns EBUSY (measured, M1) and the payload holds no
//     capability that changes that (CapEff is the empty set inside every
//     snug sandbox, measured, M3) — so C_i itself looks anchored. But the
//     engine resolves the source in a SEPARATE mount namespace that does not
//     contain this sandbox's mount at C_i, so if the SAME parent P is also
//     reachable there as an ordinary writable directory — which is exactly
//     what a read-write KindBind mount covering P means, since a bind's
//     Guest is required to equal its Host by the caller (see checkOne) — the
//     payload can still rename the underlying entry from that OTHER route,
//     invisibly to the mount at C_i, and the engine will resolve the swapped
//     name at start (M4). So: refused, naming C_i, iff some KindBind mount
//     with Access == AccessRW covers P; otherwise C_i is anchored and the
//     walk continues.
//
// # Anchors satisfy case 3, and they satisfy it MORE than an ordinary bind
//
// An anchor (anchor.go, issue #553) is a KindTmpfs snug mounts at an ancestor
// of another mount, so it is a mount root and case 2 stops firing for a name
// underneath it. That is the removal of a statement that has BECOME FALSE, not
// a loosening: case 2's message says the name can be replaced with a symlink
// after this check, and with the anchor in place mv and ln -s onto it return
// EBUSY. Printing it anyway would be a refusal whose stated reason is wrong.
//
// Case 3 then decides, and for an anchor its residual worry is structurally
// absent. M4 is about a SECOND ROUTE to the same underlying directory entry —
// a host directory reachable both through this sandbox's mount and through a
// read-write bind of the same tree. An anchor's dentry lives in a tmpfs snug
// created for this run; there is no host filesystem behind it and no other
// route to it. rwBindCovers still guards the parent, which is the conservative
// direction and is what keeps a source under @tmp-shared's rw /tmp refused.
//
// This rule reads the engine's view as DERIVED from the sandbox's, and an
// anchor is in it: the engine's mount namespace is built by open_tree on the
// host path, setns into THIS sandbox's mount namespace, then unshare
// (ENGINE-NETNS.md §5.1, measured — "the rest of the host tree is not there;
// the sandbox's own grants are"). An anchor is therefore a boundary over there
// too, and not a name that means one thing here and the host's directory there.
//
// Two premises this rule depends on, both measured rather than assumed:
//
//   - the root of the sandbox is a plain tmpfs that nothing granted covers,
//     and --remount-ro / is bwrap's LAST filesystem operation (non-recursive,
//     so it does not reach an rw grant nested under it) — so "no mount covers
//     this path" means NOT WRITABLE, never "writable because it's the root".
//   - the payload holds zero capabilities in its own user namespace — CapEff
//     is empty — so there is no capability-shaped escape from case 3's EBUSY
//     that this rule needs to account for separately.
//
// Separately, and checked over every C_i regardless of writability: if any
// C_i is covered by a GRAFT's Guest, guest is refused outright. A graft
// installs a completely different tree in the ENGINE's derived view at that
// path (ENGINE-NETNS.md §5.1) — so a name underneath it does not mean what
// this sandbox's own check judged, independent of who can write to it.
//
// # What decides "payload-writable at X"
//
// The deepest mount in p.Mounts whose Guest covers X (validate.go's covers,
// asked exactly as nearestCovering/coveringMount ask it):
//
//	deepest cover           writable
//	none (root tmpfs)        NO   — see the first premise above
//	KindBind                 iff Access == AccessRW
//	KindTmpfs/KindDev/       YES  — KindProc and KindData are the
//	  KindProc/KindData             conservative two: treated as writable
//	                                 even where that overstates the payload's
//	                                 actual reach, because understating it is
//	                                 the direction that reopens #284.
//	KindSymlink               not a mount: skipped entirely, both as a
//	                                 cover and as a mount root (below) — it
//	                                 names bwrap's own --symlink content, not
//	                                 a namespace boundary of any kind.
//
// "C_i is a mount root" means p.Mounts[C_i] exists with Kind in {KindBind,
// KindTmpfs, KindProc, KindDev} — KindData is deliberately excluded: a
// generated file lands via --ro-bind-data over an EXISTING path (issue #73)
// and is never a renameable anchor a symlink could be swapped in for, so
// counting it here would invent a boundary the kernel does not draw.
//
// This is a PURE, LEXICAL check, like policy.HostPathVisible and
// policy.EngineGuestPath beside it: no filesystem, no Environ, so it runs
// unprivileged in CI. Its correctness depends on its caller having already
// established that guest is BOTH the resolved host source AND the path the
// engine will see it at (Policy.CheckEngineForwardedPath, issue #284 §3.3) —
// this function does not re-derive that; it only judges whether guest, once
// it is that path, can still be re-pointed.
//
// Both current callers now discharge that precondition immediately before
// calling: create.go's checkOne, and build.go's checkSeccompProfile, which did
// NOT until issue #371 — it passed a host path to a parameter named `guest`,
// every predicate here having walked Mount.Guest all along. This function's own
// graft-component clause is therefore redundant by contract, and is kept as the
// backstop for a caller that forgets.
func (p *Policy) CheckEngineBindSource(guest string) error {
	guest = filepath.Clean(guest)
	components := pathComponents(guest)

	for _, c := range components {
		for _, g := range p.Grafts {
			if covers(g.Guest, c) {
				return fmt.Errorf("mount source %s cannot be forwarded to the container engine:\n"+
					"       %s is inside %s, which is one of snug's own grafts in the engine's derived\n"+
					"       view (issue #284) — the engine sees different content there than this sandbox\n"+
					"       does, so a source under it can never mean what this check just judged.\n"+
					"       Fix: bind a source outside %s.",
					guest, c, g.Guest, g.Guest)
			}
		}
	}

	for i := 1; i < len(components); i++ {
		parent, child := components[i-1], components[i]

		if !payloadWritable(p.Mounts, parent) {
			continue // anchored: nothing in this sandbox can rename child
		}

		if !isMountRoot(p.Mounts, child) {
			return fmt.Errorf("mount source %s cannot be forwarded to the container engine:\n"+
				"       the name %q sits in %s, which this sandbox can write, so it can\n"+
				"       be replaced with a symlink after this check and before the container starts —\n"+
				"       the engine resolves the source at START, in a namespace that also contains\n"+
				"       snug's own /snug/engine grafts (issue #284).\n"+
				"       The rule: a source is forwarded only if EVERY component from it up to / is\n"+
				"       anchored. A name whose parent this sandbox can write is re-pointable; a mount\n"+
				"       root is not.\n"+
				"%s",
				guest, filepath.Base(child), parent, swappableFix(p.Mounts, parent, p.Target))
		}

		if rwBindCovers(p.Mounts, parent) {
			return fmt.Errorf("mount source %s cannot be forwarded to the container engine:\n"+
				"       %s is itself a mount, so this sandbox cannot rename onto it directly (EBUSY) —\n"+
				"       but %s, which contains it, is also covered by a read-write bind, so this\n"+
				"       sandbox can still rewrite the underlying directory ENTRY at %s from that other\n"+
				"       route, invisibly to the mount at %s, and the engine resolves the source fresh at\n"+
				"       START, in a namespace that does not contain this sandbox's mount either\n"+
				"       (issue #284).\n"+
				"       The rule: a source is forwarded only if EVERY component from it up to / is\n"+
				"       anchored, and a mount root is only anchored while no other route reaches the\n"+
				"       same directory entry.\n"+
				"       Fix: bind an ancestor no read-write grant covers.",
				guest, child, parent, child, child)
		}
		// child is a mount root and no rw bind covers parent: anchored (M1/M3).
	}

	return nil
}

// swappableFix writes the last paragraph of the case-2 refusal: what, if
// anything, the caller can do instead.
//
// The walk in CheckEngineBindSource returns at the FIRST swappable component,
// so every shallower component already passed the identical walk — which makes
// `parent` exactly the DEEPEST ancestor of the source that this rule accepts.
// That is a fact about the predicate, not a guess.
//
// But "accepted" is not the same as "a useful substitute", and saying so would
// be the message implying a workaround that does not exist. The distinction is
// the parent's own Kind:
//
//   - a KindBind parent is a real HOST tree that CONTAINS the source, so
//     binding it and addressing the subdirectory inside the container mounts
//     the same bytes the caller asked for. A genuine mitigation, and the
//     common case: a source one level inside the sandbox's target.
//   - anything else covering the parent is a tmpfs (or /dev, or procfs) that
//     snug created for this run. The caller's files are not in it — they are
//     behind further mounts stacked on top — so offering it as "the fix" would
//     send someone to mount an ephemeral empty directory and wonder why their
//     project is not in it. This is the case that fires once the target sits
//     three or more levels below $HOME, where the deepest anchored ancestor is
//     the $HOME tmpfs itself. Both arms now end at the same place: the target
//     graft (issue #376) makes the target itself forwardable regardless of
//     depth, so the fix is to bind the target and address the subdirectory
//     inside the container — checkOne never reaches this rule at all for the
//     target itself; it is caught by the graft first.
func swappableFix(mounts map[string]Mount, parent, target string) string {
	if m, ok := deepestNonSymlinkCover(mounts, parent); ok && m.Kind == KindBind {
		return "       Fix: bind " + parent + " — the deepest ancestor of this source whose whole\n" +
			"       path this sandbox cannot rewrite — and address the subdirectory inside the\n" +
			"       container."
	}
	return "       The deepest ancestor this rule accepts is " + parent + ", which is not a bind of a\n" +
		"       host directory — it is a filesystem snug created for this run, so binding it would\n" +
		"       not mount what you asked for.\n" +
		"       Fix: bind " + target + " — snug hands the engine a mount it cloned itself, so that\n" +
		"       source has no re-pointable name on it — and address the subdirectory inside the\n" +
		"       container."
}

// pathComponents returns the cumulative absolute paths from "/" up to and
// including clean itself — clean("/a/b") -> ["/", "/a", "/a/b"] — so
// CheckEngineBindSource can walk parent/child pairs without re-deriving the
// split at every step. clean must already be filepath.Clean'd and absolute;
// CheckEngineBindSource is the only caller and guarantees that.
func pathComponents(clean string) []string {
	if clean == "/" {
		return []string{"/"}
	}
	rest := strings.TrimPrefix(clean, "/")
	parts := strings.Split(rest, "/")
	out := make([]string, 0, len(parts)+1)
	out = append(out, "/")
	cur := "/"
	for _, part := range parts {
		cur = filepath.Join(cur, part)
		out = append(out, cur)
	}
	return out
}

// payloadWritable answers CheckEngineBindSource's first question for one path:
// can THIS sandbox write at x, judged by the deepest mount whose Guest covers
// it (skipping KindSymlink, which is not a mount) — see the table in
// CheckEngineBindSource's own doc comment for what each Kind means here and
// why. No cover at all means the plain root tmpfs, which is read-only because
// --remount-ro / is bwrap's last, non-recursive filesystem operation.
func payloadWritable(mounts map[string]Mount, x string) bool {
	m, ok := deepestNonSymlinkCover(mounts, x)
	if !ok {
		return false
	}
	switch m.Kind {
	case KindBind:
		return m.Access == AccessRW
	case KindTmpfs, KindDev, KindProc, KindData:
		return true
	default:
		return false
	}
}

// deepestNonSymlinkCover finds the mount in mounts whose Guest covers x and is
// nested deepest — the same "deepest cover decides" rule the rest of the
// resolver uses (invariant 1's "effective access at a path is that of the
// deepest mount covering it"), restricted to the Kinds that are mounts at
// all. KindSymlink is excluded: it names bwrap's own --symlink content, not a
// namespace boundary, and CheckEngineBindSource's doc comment states this
// exclusion applies both here and in isMountRoot.
func deepestNonSymlinkCover(mounts map[string]Mount, x string) (Mount, bool) {
	var best Mount
	found := false
	for _, m := range mounts {
		if m.Kind == KindSymlink {
			continue
		}
		if !covers(m.Guest, x) {
			continue
		}
		if !found || len(m.Guest) > len(best.Guest) {
			best, found = m, true
		}
	}
	return best, found
}

// isMountRoot reports whether x is exactly the Guest of a mount that is a
// real namespace boundary — KindBind, KindTmpfs, KindProc or KindDev.
// KindData is excluded on purpose (a generated file overmounts an existing
// path via --ro-bind-data and is never a renameable anchor, issue #73) and so
// is KindSymlink (not a mount at all) — see CheckEngineBindSource's doc
// comment for both exclusions stated together.
func isMountRoot(mounts map[string]Mount, x string) bool {
	m, ok := mounts[x]
	if !ok {
		return false
	}
	switch m.Kind {
	case KindBind, KindTmpfs, KindProc, KindDev:
		return true
	default:
		return false
	}
}

// rwBindCovers reports whether some read-write KindBind mount's Guest covers
// x — CheckEngineBindSource's case 3, the M4 clause: a mount root is EBUSY
// against a rename from inside THIS sandbox's own mount namespace, but a
// separate rw bind covering the same parent gives the payload another route
// to the same underlying directory entry, one the engine's own start-time
// resolution — running in a namespace that does not contain this sandbox's
// mount either — cannot tell apart from the anchored case.
func rwBindCovers(mounts map[string]Mount, x string) bool {
	for _, m := range mounts {
		if m.Kind == KindBind && m.Access == AccessRW && covers(m.Guest, x) {
			return true
		}
	}
	return false
}
