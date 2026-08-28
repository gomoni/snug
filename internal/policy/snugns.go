package policy

import "strings"

// SnugDir is the guest-path namespace snug reserves for itself: everything snug
// needs a path for INSIDE a sandbox lives under it, and nothing else may mount
// there.
//
// It replaces a list with a rule, and that is the whole of issue #206. Before
// it, each path snug owned was a separate entry in snugsOwn — /proc, /dev, and
// the staging directory — and the third one's reason applies unchanged to every
// path snug will ever add: a profile mounting ANYTHING at a path snug owns
// escapes `--remount-ro /`, because the profile's mount is a separate mount and
// the remount does not reach inside it, and the directory snug relied on being
// unwritable is writable. Tier C alone (#125) would have added four more
// entries for the engine's graft destinations. A list that grows once per
// feature is a rule written somewhere it can be forgotten; this is the same
// rule written once.
//
// /proc and /dev stay in snugsOwn, and deliberately. They are refused for a
// DIFFERENT reason — a profile grant there DISPLACES a node snug authors, the
// host's procfs for the sandbox's own and the host's device tree for bwrap's
// synthetic one — and they are FHS paths a profile could reasonably think it
// may name. This namespace is refused because it is snug's, which is a claim
// only a name nobody else has can make.
//
// WHY A NEW TOP-LEVEL NAME AND NOT /opt/snug. /opt is a real FHS location for
// add-on software, so a profile could legitimately want to grant something
// under it — and reserving a subtree of a path other people have a claim to is
// a weaker reservation than reserving a name nobody claims. /snug is not in the
// FHS; the reservation is total and needs no exceptions. It is also short,
// which it earns: it appears in PATH, in CONTAINER_HOST, on the --dry-run
// screen and in every refusal message quoting a path.
//
// Nothing on the HOST is touched. These are guest paths, no profile binds /,
// and snug creates the directory on the sandbox's own root tmpfs.
const SnugDir = "/snug"

// StagedBinDir is the ONE directory snug puts executables in, and the only
// directory of snug's own making that ever goes on PATH.
//
// It is under SnugDir, alongside the container proxy socket and the ssh-agent
// proxy socket — all snug's own, all unwritable from inside once --remount-ro /
// has run (constraint 1, CONTAINER-CLIENT.md §8: measured — the staging
// directory refuses `touch` and `echo >` with EROFS), and all gone with the
// sandbox.
//
// UNWRITABLE IS THE WHOLE POINT, and it is why there is one directory rather
// than a per-caller choice. A writable directory ahead of /usr/bin on PATH is a
// SHADOW SLOT: the payload writes a file called `git` into it and the next `git`
// a human or another agent runs inside the sandbox is that file. The payload can
// always rewrite its own PATH and nothing stops it — what this rule buys is that
// the environment SNUG ITSELF hands over does not ship the slot pre-installed.
//
// It gets its read-only property from being a plain directory on the ROOT tmpfs,
// which --remount-ro / covers. A `tmpfs` grant at this path would be a separate
// mount, would NOT be covered, and would quietly undo it — which is what
// insideSnugDir refuses, now for every path under SnugDir rather than for this
// one by name.
const StagedBinDir = SnugDir + "/bin"

// ContainerSocketGuest and AgentSocketGuest are the two sockets snug publishes
// inside the sandbox. They are here rather than beside their callers so that
// every guest path snug owns is declared in one file — the property SnugDir
// exists to make checkable is easier to keep when the set is visible.
const (
	ContainerSocketGuest = SnugDir + "/podman.sock"
	AgentSocketGuest     = SnugDir + "/ssh-agent.sock"
)

// EngineDir is the ONE place inside SnugDir a GRAFT may land: the engine's own
// derived-view mountpoints (issue #125's store, runroot, socket and config
// directories).
//
// Everything else snug puts under SnugDir belongs to the PAYLOAD — the staging
// directory, the container proxy socket, the ssh-agent proxy socket — and a
// graft landing on one of those replaces it in the engine's view with whatever
// the graft's source is. Measured before this rule existed: an AccessRW graft
// at /snug/podman.sock, with a source G4 admits, was ACCEPTED, which puts an
// arbitrary writable host tree where the engine expects the container proxy's
// socket.
//
// A graft AT EngineDir itself is refused along with the rest, for the reason a
// mount at StagedBinDir is: a grant of the whole directory rather than of one
// thing in it.
const EngineDir = SnugDir + "/engine"

// The four destinations under EngineDir, and the toolchain's, named here
// rather than built by string concatenation at their call sites — the same
// reason ContainerSocketGuest and AgentSocketGuest are here: every guest path
// snug owns is declared in one file, because the property SnugDir exists to
// make checkable is easier to keep when the set is visible.
//
// These are what the ENGINE sees. The host paths behind them belong to
// internal/engine (the store, the runroot, the run directory's sock/ and
// conf/ halves) and to the host user (the toolchain), and the mapping between
// the two is the graft. The engine is handed ONLY these: a host path in the
// engine's argv or environment is a path it cannot see once its view is
// derived from the sandbox's.
const (
	EngineStoreGuest     = EngineDir + "/store"
	EngineRunrootGuest   = EngineDir + "/runroot"
	EngineSockGuest      = EngineDir + "/sock"
	EngineConfGuest      = EngineDir + "/conf"
	EngineToolchainGuest = EngineDir + "/toolchain"
)

// EngineBindsDir is the ONE place a profile's `engine_binds` declaration lands
// in the engine's view: one directory under it per declared host path, each
// holding an open_tree(2) clone of that path.
//
// It is not in the const block above because those five are snug's own
// artefacts — the store, the runroot, the two halves of the run directory, the
// toolchain — and there is exactly one of each. This one names a DIRECTORY
// whose children are decided by the selected profiles, so the paths under it
// are per-run and are derived by EngineBindGuest rather than declared here.
//
// Why a subdirectory rather than /snug/engine/<name> directly: G1b admits a
// graft anywhere under EngineDir, so a declared bind called `store` would
// otherwise collide with EngineStoreGuest and Policy.Graft would refuse the
// second — a profile's own choice of directory name deciding whether snug's
// engine wiring resolves. Under a name of snug's own, the two sets cannot meet.
const EngineBindsDir = EngineDir + "/binds"

// graftAllowedInSnugDir reports whether a graft may land at this guest path,
// for the half of the namespace rule that applies to p.Grafts.
//
// WHY THIS EXISTS AS A RULE AND NOT AS MORE snugsOwn ENTRIES. Validate's rule 4b
// covers the payload's mount set; G1 covers grafts through snugsOwn, which is a
// LIST. Before this, that list held SnugDir and StagedBinDir and not the two
// socket paths, so the namespace was total for mounts and partial for grafts —
// CLAUDE.md's "a rule written once and applied to one of its two halves",
// committed in the change that quotes it. Adding the sockets to the list would
// have closed today's hole and left the shape: the next path snug puts under
// SnugDir would need remembering again.
//
// Stated this way it does not grow. Anything snug adds under SnugDir is
// protected from a graft the day it is named, and the engine's own subtree is
// the single exception, which is what Tier C actually needs.
func graftAllowedInSnugDir(guest string) bool {
	return strings.HasPrefix(guest, EngineDir+"/")
}

// legacySnugDir is where all of the above lived before issue #206.
//
// It is kept for ONE purpose: a profile on this host that still names it gets a
// refusal that says where the path went, instead of a grant that silently
// stops doing what its author meant. A rename whose old name merely stops
// working is a trap; a rename whose old name says the new one is a rename.
//
// It is NOT an alias and must never become one. Accepting both would mean two
// paths meaning one thing, which is the "no second noun for the same concept"
// rule applied to a path, and would leave the namespace rule below with an
// exception carved through it.
const legacySnugDir = "/run/snug"

// insideSnugDir reports whether a guest path is inside snug's reserved
// namespace — at SnugDir itself, or anywhere beneath it.
//
// A path-ancestor test and NOT a string-prefix test: /snugly is not inside
// /snug. This is the same distinction `covers` documents, and getting it wrong
// in this direction refuses grants that are none of snug's business.
func insideSnugDir(guest string) bool {
	return guest == SnugDir || strings.HasPrefix(guest, SnugDir+"/")
}

// namesLegacySnugDir reports whether a guest path is at or under the pre-#206
// location, so Validate can name the replacement rather than let the grant
// quietly miss.
func namesLegacySnugDir(guest string) bool {
	return guest == legacySnugDir || strings.HasPrefix(guest, legacySnugDir+"/")
}

// stagedFileUnderSnugDir reports whether a mount inside SnugDir is the ONE
// shape that is legitimate there: a profile staging a single executable
// read-only into the staging directory, which is what that directory exists for
// (@claude's `{home}/.local/bin/claude:/snug/bin/claude`).
//
// The allowance is deliberately the narrowest thing that keeps @claude working
// — a read-only bind STRICTLY BELOW StagedBinDir — rather than "anything
// read-only under SnugDir". The wider version would let a profile bind at
// /snug/engine, displacing a destination the engine's derived view is about to
// graft onto (#125), and the whole point of a namespace is that snug's paths
// are snug's whether or not the rule's author had that particular path in mind.
//
// Each exclusion is a measured defect rather than defensive coding:
//
//   - a mount AT SnugDir, or at one of the directories snug creates under it, is
//     a grant of the whole directory rather than of one executable in it — and
//     if it is a tmpfs or a writable bind it is a shadow slot `--remount-ro /`
//     cannot reach (issue #22, measured: WROTE-OK, `command -v git` resolved to
//     it, and the shadowed git RAN);
//   - AccessRW anywhere inside is the same hole one path deeper;
//   - a KindTmpfs is the same hole with no host path at all.
//
// What it does NOT decide is whether the host side is a file or a directory.
// internal/policy is pure — no filesystem — so it cannot know.
//
// AND READ-ONLY HERE IS NOT THE SAME AS IMMUTABLE, which an earlier version of
// this comment got wrong by calling it "no writable slot". A read-only bind is
// read-only THROUGH THIS MOUNT; if the same host path is also reachable through
// a writable grant — `ro = ["{target}/tool:/snug/bin/tool"]`, with the target
// writable, which is the ordinary case — the payload rewrites the inode through
// the other path and the rewritten file is first on PATH. That is pre-existing
// and not something this rule introduced, but it must not be described as safe.
// Closing it needs a host lookup and belongs in the layer that has one.
func stagedFileUnderSnugDir(guest string, m Mount) bool {
	return strings.HasPrefix(guest, StagedBinDir+"/") &&
		m.Kind == KindBind && m.Access == AccessRO
}
