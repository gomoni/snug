package policy

import "fmt"

// DefaultTmpfsSize is the bound applied to every snug-controlled tmpfs when
// the user's config names none. 1 GiB per mount, which on the default
// selection is six mounts — five from base.toml's [profile.home] plus /tmp —
// so a worst case near 6 GiB of pinned page cache. Read the count from
// internal/profile/profiles/base.toml, never from this comment.
const DefaultTmpfsSize uint64 = 1 << 30

// tmpfsSize substitutes DefaultTmpfsSize for an unset (zero) preference. It is
// the ONLY place that substitution happens — Resolve calls it once, in the
// Policy literal, so a caller inspecting a resolved Policy never has to ask
// whether TmpfsSizeBytes is "zero meaning default" or "zero meaning zero".
func tmpfsSize(n uint64) uint64 {
	if n == 0 {
		return DefaultTmpfsSize
	}
	return n
}

// DefaultEngineScratchSize bounds the engine's own /var/tmp tmpfs — the
// mount(2) call in internal/stage/inengine.go, not a payload tmpfs. It is a
// fixed constant, not DefaultTmpfsSize, because the consumer is fixed too:
// containers/image hardcodes /var/tmp for TemporaryDirectoryForBigFiles, the
// scratch space it unpacks a whole image layer into while committing, so the
// cap has to clear the biggest base image a user pulls rather than track
// whatever a profile author sized a build's own tmpfs at. Coupling it to
// DefaultTmpfsSize would make an ordinary `podman pull` fail mid-pull because
// somebody tuned tmpfs_size_mib down. Changing this number is a policy
// decision — it sets how much host RAM one sandbox's engine can pin — so
// there is deliberately no config key for it (issue #281).
const DefaultEngineScratchSize uint64 = 8 << 30

// EngineTmpfsSize returns the bound for one of the engine's own tmpfs
// mounts, keyed by its guest path: "/run" tracks tmpfsSizeBytes (the same
// number a payload's tmpfs use, so tmpfs_size_mib moves it too — podman
// writes /run/libpod state, locks and sockets there, kilobytes at most),
// "/var/tmp" is always DefaultEngineScratchSize. Any other guest returns
// (0, false): a new engine tmpfs must be given a bound here deliberately
// before it ships, and a default for the unknown case is exactly how a third
// one would ship unbounded (invariant 5, in the small).
func EngineTmpfsSize(guest string, tmpfsSizeBytes uint64) (uint64, bool) {
	switch guest {
	case "/run":
		return tmpfsSizeBytes, true
	case "/var/tmp":
		return DefaultEngineScratchSize, true
	default:
		return 0, false
	}
}

// FormatBytes renders a byte count the way a human reading --dry-run or
// `snug config` wants to see it: "1 GiB", "512 MiB". Total, cannot fail.
//
// The value always arrives as a whole number of MiB (the config key is in
// MiB, the default a power of two), so the last arm is unreachable in
// practice and exists so this function cannot fail to answer.
func FormatBytes(n uint64) string {
	const (
		mib uint64 = 1 << 20
		gib uint64 = 1 << 30
	)
	switch {
	case n != 0 && n%gib == 0:
		return fmt.Sprintf("%d GiB", n/gib)
	case n != 0 && n%mib == 0:
		return fmt.Sprintf("%d MiB", n/mib)
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
