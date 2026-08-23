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
