// Package targetkey is the ONE place a target directory becomes a derived
// name.
//
// Three sites turn a target's canonical path into a name snug puts on disk.
// Before this package existed they each ran their own sha256 and their own
// truncation, and nothing declared the algorithm or the length in a way a
// second site could copy:
//
//   - internal/engine/paths.go's engineKey/KeyForTarget — the engine store
//     and runroot directory name.
//   - internal/cli/targetlock.go's targetKeyPrefix — "target-" + the hash,
//     the per-target lock file and run-state JSON.
//   - internal/cli/tmpdir.go's hostTmpDirPath — "snug-<uid>-" + the hash,
//     @tmp-shared's host directory.
//
// targetlock.go's own doc comment already made this argument for its first
// two consumers before this package existed: "One function so the two can
// never drift onto different hashes of the same path — a drift that would
// not fail loudly, it would simply mean [a reader] looked up a [name] no run
// had written." This package extends that guarantee to all three.
//
// ALL THREE USE THE FULL, UNTRUNCATED DIGEST — maintainer ruling: a truncated
// hash is an unlabelled lossy transform. A reader holding the target path
// cannot verify a `[:12]` or `[:16]` name against it without already knowing
// it was truncated and by how much, and nothing in the name says so. Two of
// the three consumers used to truncate (engineKey to 16 hex chars,
// hostTmpDirPath to 12); both now use the same full form targetKeyPrefix
// already did, rather than inventing a fourth length. Path lengths are
// comfortable — "target-sha256_<64hex>.lock" is 83 characters and has never
// been a problem.
//
// THE NAME ALSO CARRIES ITS ALGORITHM (issue #349): Hash returns
// "sha256_<64hex>", not a bare digest. A name built from a bare hex string
// says nothing about what produced it; a reader — or a future second
// algorithm — can now tell a sha256 key apart from any other kind on sight,
// rather than every consumer having to already know which transform this
// package happens to run today.
//
// THE PAYOFF: with every key identical, the relationship issue #308's
// garbage collector needs between a store's key and its per-target lock
// stops being a prefix coincidence between two independently-truncated
// hashes and becomes an IDENTITY — the lock file for a store whose
// breadcrumb names target T is named from exactly the same string this
// package returns for T, with nothing to compare a prefix against and
// nothing to drift.
//
// A second `sha256.Sum256` over a target-shaped string anywhere outside this
// file is exactly the drift the paragraph above describes, and it would not
// fail loudly. There is no AST sweep asserting that directly: the module
// already has an unrelated sha256.Sum256 (internal/sandbox's FilterDigest,
// hashing a seccomp BPF program, not a target), and a name-only match cannot
// tell the two apart without a type checker this package does not carry.
// Instead each of the three consumers asserts, in its own package, that its
// output IS Hash applied to the same string — see
// internal/engine's TestEngineKeyAgreesWithTargetkey and internal/cli's
// TestTargetLockAndTmpDirAgreeWithTargetkey. That is a narrower guarantee
// than a sweep (it only catches a consumer this package already knows about
// disagreeing, not an unknown fourth site appearing), and it is the one this
// package can make without a false positive on day one.
package targetkey

import (
	"crypto/sha256"
	"encoding/hex"
)

// Hash is "sha256_" followed by the full hex sha256 digest of the target's
// canonical path. Every on-disk name snug derives from a target starts here;
// a consumer may prefix this value further (targetKeyPrefix adds "target-")
// but must not truncate it — see the package doc comment for why a
// truncation is a lossy transform nothing else can detect, and for why the
// algorithm name is now part of the value rather than left for a consumer to
// add or, worse, to omit.
//
// target must already be canonical — EvalSymlinks'd, as policy.Resolve
// leaves pol.Target and lockTarget leaves the realpath it hashes. This
// function does no canonicalisation of its own: doing it here as well as at
// the caller would only create two supposedly-identical forms of the same
// string (see internal/engine's engineKey doc comment on why that residual
// is not reopened casually).
func Hash(target string) string {
	sum := sha256.Sum256([]byte(target))
	return "sha256_" + hex.EncodeToString(sum[:])
}
