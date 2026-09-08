package policy

import (
	"fmt"
	"math"
	"strings"
)

// Size is a count of bytes carrying its unit in the VALUE rather than in the
// name of the key that holds it: `100 MiB`, `128 mb`, `4 GiB`. time.Duration's
// shape and for time.Duration's reason — a key that spells its unit
// (`tmpfs_size_mib`) can only ever mean that one unit, so the human writing
// 512 has to do the conversion the program is better at, and the program
// cannot tell 512 MiB from a typo for 512 bytes because both are the integer
// 512.
//
// Underlying uint64 and no MarshalText, deliberately: encoding/json therefore
// renders a Size as the NUMBER it is, which is what the --dry-run facts
// document already publishes as mounts[].size_bytes. A MarshalText here would
// silently turn that field into a string.
//
// Size is the config surface's type — the parsed preference and everything
// rendered for a human. The resolved Policy still carries plain uint64 bytes
// (Policy.TmpfsSizeBytes), because that is what reaches bwrap's `--size` and
// the JSON facts, and both want the number.
type Size uint64

// The two families, kept apart because they ARE apart: kB is 1000 bytes and
// KiB is 1024, and every reader of a config file already knows which one they
// meant. Kubernetes draws the line in the same place (`Ki`/`Mi`/`Gi` binary,
// `k`/`M`/`G` decimal); Docker does not, and reads a bare `m` as 1024² — see
// sizeUnits for what that costs the bare spellings.
const (
	Kilobyte Size = 1000
	Megabyte Size = 1000 * Kilobyte
	Gigabyte Size = 1000 * Megabyte
	Terabyte Size = 1000 * Gigabyte

	Kibibyte Size = 1 << 10
	Mebibyte Size = 1 << 20
	Gibibyte Size = 1 << 30
	Tebibyte Size = 1 << 40
)

// sizeUnits is the accepted set, keyed by the lower-cased suffix, so `MiB`,
// `mib` and `MIB` are one unit. Case cannot be load-bearing here the way it is
// in Kubernetes (where `m` is milli and `M` is mega): a config file is written
// by hand and `100 mib` is not a different quantity from `100 MiB`.
//
// The BARE magnitude letters — `k`, `m`, `g`, `t` — are deliberately absent.
// Docker reads `-m 512m` as 512 MiB and Kubernetes reads `512M` as 512
// megabytes, so a bare letter is the one spelling whose meaning depends on
// which tool the author had in mind. Refusing it is CLAUDE.md's rule about an
// unrecognised value never being read as the nearest thing it resembles; the
// error names `MB` and `MiB` and the author says which they meant.
var sizeUnits = map[string]Size{
	"b":     1,
	"byte":  1,
	"bytes": 1,

	"kb": Kilobyte,
	"mb": Megabyte,
	"gb": Gigabyte,
	"tb": Terabyte,

	"ki":  Kibibyte,
	"mi":  Mebibyte,
	"gi":  Gibibyte,
	"ti":  Tebibyte,
	"kib": Kibibyte,
	"mib": Mebibyte,
	"gib": Gibibyte,
	"tib": Tebibyte,
}

// sizeUnitAdvice is the tail every ParseSize error ends with. One string, so a
// unit added above cannot leave half the messages naming the old set.
const sizeUnitAdvice = `write a number and a unit, as in "512 MiB": ` +
	`B, kB, MB, GB, TB (1000-based) or KiB, MiB, GiB, TiB (1024-based)`

// sizeRender is the descending list String() picks from: the largest unit that
// divides the value exactly, whichever family it belongs to. That is what
// makes String() the inverse of ParseSize for anything ParseSize accepted —
// 128 MB renders "128 MB" rather than "125000 KiB", which is the same number
// and not the same sentence.
var sizeRender = []struct {
	unit Size
	name string
}{
	{Tebibyte, "TiB"},
	{Terabyte, "TB"},
	{Gibibyte, "GiB"},
	{Gigabyte, "GB"},
	{Mebibyte, "MiB"},
	{Megabyte, "MB"},
	{Kibibyte, "KiB"},
	{Kilobyte, "kB"},
}

// ParseSize reads the value half of `tmpfs_size = "100 MiB"`. Whitespace
// around the number and between number and unit is optional; the unit is not.
//
// A bare number is REFUSED rather than read as bytes. `tmpfs_size = "512"` from
// somebody who had `tmpfs_size_mib = 512` in the file yesterday would otherwise
// resolve to a 512-BYTE tmpfs — a value a million times smaller than what they
// wrote, arriving as a mount that fails at runtime rather than as an error at
// parse time. Same reasoning refuses a sign and a fraction: `-1` and `1.5` are
// each a thing a human means something by, and neither has one obvious reading
// in bytes.
func ParseSize(s string) (Size, error) {
	text := strings.TrimSpace(s)
	if text == "" {
		return 0, fmt.Errorf("empty size; %s", sizeUnitAdvice)
	}

	digits := 0
	for digits < len(text) && text[digits] >= '0' && text[digits] <= '9' {
		digits++
	}
	if digits == 0 {
		return 0, fmt.Errorf("%q does not begin with a number; %s", text, sizeUnitAdvice)
	}

	unit := strings.TrimSpace(text[digits:])
	if unit == "" {
		return 0, fmt.Errorf("%q has no unit; %s", text, sizeUnitAdvice)
	}
	if unit[0] == '.' || unit[0] == ',' {
		// "1.5 GiB" is a quantity, and the reason it is refused is not that it
		// is hard to parse: rounding it would put a bound in the sandbox that
		// no line of the config file spells.
		return 0, fmt.Errorf("%q is a fraction; write it as a whole number of a "+
			"smaller unit, as in \"1536 MiB\"", text)
	}
	mult, ok := sizeUnits[strings.ToLower(unit)]
	if !ok {
		return 0, fmt.Errorf("unknown unit %q in %q; %s", unit, text, sizeUnitAdvice)
	}

	// Accumulate by hand rather than through strconv: the digit run can be
	// arbitrarily long, and a uint64 that has already overflowed cannot be
	// told apart from a legitimate value once strconv has wrapped it.
	var n Size
	for i := 0; i < digits; i++ {
		d := Size(text[i] - '0')
		if n > (math.MaxUint64-d)/10 {
			return 0, fmt.Errorf("%q overflows a 64-bit byte count", text)
		}
		n = n*10 + d
	}
	if n != 0 && mult != 1 && n > math.MaxUint64/mult {
		return 0, fmt.Errorf("%q overflows a 64-bit byte count", text)
	}
	return n * mult, nil
}

// UnmarshalText is the ONLY door a decoded Size comes through, which is what
// makes it safe where policy.ProfileName is not (internal/cli/config.go says
// why a decoded field may not be a ProfileName): go-toml writes a plain
// struct field by reflection, but a TextUnmarshaler it must call.
//
// go-toml hands over the raw scalar text for a non-string TOML value too, so
// `tmpfs_size = 512` arrives here as "512" and `tmpfs_size = true` as "true".
// Both meet ParseSize's refusal and its advice, instead of a decoder message
// about Go types.
func (s *Size) UnmarshalText(b []byte) error {
	v, err := ParseSize(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// RoundUpTo raises s to the next multiple of granule, and is how a byte count
// snug PUBLISHES comes to be the byte count the kernel DELIVERS. tmpfs rounds
// its size up to a whole page, so `tmpfs_size = "1 B"` mounts 4096 bytes while
// --dry-run, the JSON facts and the bwrap argv all said 1 — three copies of a
// number snug does not deliver, on the one screen whose entire job is being
// trustable. Not reachable before the unit moved into the value: every
// tmpfs_size_mib was a whole number of MiB and so already page-aligned.
//
// granule 0 or 1 is the identity. Total: a value near MaxUint64 that cannot be
// raised without wrapping stays where it is rather than becoming a small
// number, which is the only failure mode that would matter.
func (s Size) RoundUpTo(granule Size) Size {
	if granule <= 1 {
		return s
	}
	rem := s % granule
	if rem == 0 {
		return s
	}
	add := granule - rem
	if s > math.MaxUint64-add {
		return s
	}
	return s + add
}

// String renders a Size the way a human reading --dry-run or `snug config`
// wants to see it, and the way ParseSize would read back: "1 GiB", "512 MiB",
// "128 MB". Total, cannot fail.
func (s Size) String() string {
	for _, r := range sizeRender {
		if s != 0 && s%r.unit == 0 {
			return fmt.Sprintf("%d %s", s/r.unit, r.name)
		}
	}
	return fmt.Sprintf("%d B", uint64(s))
}
