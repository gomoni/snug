package policy

import (
	"path/filepath"
	"sort"
)

// anchorFrom is the provenance an anchor appears under in --dry-run. It is not
// a profile name and deliberately does not look like one: no profile can
// express an anchor, and a reader asking "who granted this" deserves the
// answer "nobody, snug put it there" rather than a name they could go and
// unselect.
const anchorFrom = "(snug anchor)"

// AnchorNote is what --dry-run's FILESYSTEM block says about anchor rows. It
// lives here, next to the rule it describes, because a screen that explains a
// mount from a different file is how the explanation and the mount come to
// disagree.
const AnchorNote = "(snug anchor) rows are snug's own empty tmpfs at an ancestor of a grant. " +
	"They hold nothing and grant nothing — the payload could already write that path through " +
	"the tmpfs covering it — and they exist so it cannot rename the path out from under a " +
	"mount (issue #553)."

// InstallAnchors mounts an empty tmpfs at every ancestor of a mount that a
// payload could otherwise rename out from under it (issue #553).
//
// # The hole
//
// rename(2) refuses only when the dentry BEING RENAMED is itself a mount
// point. Renaming a directory that merely CONTAINS one is allowed, and the
// mount travels with it — which frees the original name for the payload to
// recreate. Measured in #553 on the default selection: a payload renamed the
// target's parent, recreated $SNUG_TARGET as an ordinary directory in the
// covering tmpfs, and everything a later reader touched at that path — a
// human's `snug attach` included — was payload-authored content, while every
// screen went on printing the real project path and the work "saved" there
// evaporated at teardown. The host was untouched: this is deception, not an
// escape, which is why it is a mount-generation bug and not a containment one.
//
// The same mechanism reaches snug's own generated files one directory up:
// {home}/.ssh is covered by @home's tmpfs and is not a mount root, so
// `mv ~/.ssh ~/.sshOLD; mkdir ~/.ssh` strands the generated read-only
// ~/.ssh/config behind the renamed directory and lets the payload author its
// own — with a ProxyCommand in it. Anchoring is therefore stated over EVERY
// mount's ancestor chain rather than over the target's: the class is not
// target-specific, and a target-only rule would close the reported instance
// while leaving the identity files open.
//
// # The rule
//
// A path is anchored iff it is a proper ancestor of some mount, is not itself
// a mount of any kind, and its deepest covering mount is a KindTmpfs.
//
// # Why the cover must be a tmpfs and not merely payload-writable
//
// #553 proposes payloadWritable, which is the predicate CheckEngineBindSource
// uses, and it is the wrong one HERE. payloadWritable is true of a read-write
// KindBind — a real host directory with real entries in it — and an empty
// tmpfs on top of one hides every entry that is not separately granted. That
// is subtraction, invariant 1's whole subject, and nothing would refuse it:
// an anchor is Authored, so rejectMasking skips it (validate.go, RULE 3).
// The exemption is what makes the narrower predicate mandatory rather than
// merely tidy.
//
// A tmpfs cover has nothing underneath by construction. The only things that
// have ever existed under an anchored path in the covering tmpfs are the
// mountpoint skeleton directories bwrap auto-creates for deeper mounts, and
// every one of those is strictly deeper and is re-created inside the anchor.
//
// # The residual, stated rather than papered over
//
// An ancestor covered by a read-write bind is still renameable. The reason is
// the masking one above, and the second reason is that an rw grant of a host
// tree IS a grant of the right to rename inside it — the rename lands on the
// host, where the human said writes may land.
//
// Measured on this branch, with a user profile granting rw over a directory
// containing the target (`rw = ["/var/tmp/X/data"]`, target
// /var/tmp/X/data/proj/sub): `mv proj hidden` succeeded, the payload recreated
// the target path, and the host tree really was renamed — `ls` showed `hidden`
// and a fresh `proj`. NO SHIPPED BUILTIN REACHES THIS SHAPE: @tmp-shared looks
// like it should (rw {host_tmpdir}:/tmp) and does not, because a target under
// /tmp then makes @cwd-rw's bind nest inside @tmp-shared's and rejectMasking
// refuses the whole selection — measured, `snug -p @tmp-shared /tmp/X/proj/sub`
// exits on "which is inside /tmp from profile @tmp-shared".
//
// CheckEngineBindSource already refuses to forward a source under that shape
// (its case 3, rwBindCovers), and `snug attach` is covered separately.
//
// # Ordering, which is what keeps every grant visible
//
// SortedMounts is depth-ascending and bwrap applies mounts in argv order, so
// an anchor — a proper ancestor by construction — is emitted strictly before
// everything it covers. A sibling grant deeper than the anchor is mounted
// INTO it and keeps its content: @home tmpfs at /home/u, anchors at
// /home/u/src and /home/u/src/proj, and a bind at /home/u/src/other still
// binds, inside the anchor, with the same host path and access.
//
// It is idempotent: an anchor is placed only where the cover is already a
// KindTmpfs and is itself a KindTmpfs, so re-running cannot change any
// verdict. That is what lets internal/cli call it a second time after its own
// post-Resolve mounts.
func (p *Policy) InstallAnchors() {
	seen := map[string]bool{}
	for g := range p.Mounts {
		for d := filepath.Dir(g); d != "/" && d != "."; d = filepath.Dir(d) {
			seen[d] = true
		}
	}
	candidates := make([]string, 0, len(seen))
	for d := range seen {
		candidates = append(candidates, d)
	}
	sort.Strings(candidates)

	install := make([]string, 0, len(candidates))
	for _, d := range candidates {
		// ANY kind counts as taken, KindSymlink and KindData included. A
		// symlink is not a mountpoint bwrap can create one at (INDEX §3.3) and
		// mounting over one would mask a profile's grant; a KindData file has
		// nothing to anchor. Both are already mounts as far as this rule is
		// concerned: there is a node at that name that the payload cannot
		// rename away.
		if _, taken := p.Mounts[d]; taken {
			continue
		}
		// NEVER at or under snug's own paths. Condition 3 below already
		// excludes them today — /proc and /dev are KindProc/KindDev, and
		// SnugDir and StagedBinDir sit on the root tmpfs that --remount-ro
		// covers, so neither has a tmpfs cover — but the failure this guards
		// against is silent and in the wrong direction: a tmpfs AT
		// StagedBinDir is a WRITABLE directory snug then puts first on PATH in
		// its own provenance, which is issue #22's hole arrived at from a new
		// side. Two independent guards, so a future cover kind cannot open it.
		if _, _, ok := snugsOwnCovered(d); ok {
			continue
		}
		if _, _, ok := snugsOwnAncestorOf(d); ok {
			continue
		}
		m, ok := deepestNonSymlinkCover(p.Mounts, d)
		if !ok || m.Kind != KindTmpfs {
			continue
		}
		install = append(install, d)
	}

	for _, d := range install {
		// Replace, not join: this is snug's own write, like the generated
		// identity files and /etc/resolv.conf. The check above guarantees
		// nothing is displaced, so Replace's "replaces:" provenance branch is
		// unreachable from here — asserted by the test rather than assumed.
		p.Replace(Mount{
			Guest:  d,
			Kind:   KindTmpfs,
			Access: AccessRW,
			Anchor: true,
			From:   []string{anchorFrom},
		})
	}
}
