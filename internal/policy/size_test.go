package policy

import (
	"math"
	"strings"
	"testing"
)

// TestParseSizeAccepts is the accepted set, spelled out. Both families and
// both spellings of each, because "128 mb" and "128 MiB" differing by 6217728
// bytes is the whole reason the unit lives in the value.
func TestParseSizeAccepts(t *testing.T) {
	cases := []struct {
		in   string
		want Size
	}{
		{"100 MiB", 100 << 20},
		{"128 mb", 128_000_000},
		{"128MB", 128_000_000},
		{"128 MB", 128_000_000},
		{"1 GiB", 1 << 30},
		{"1gib", 1 << 30},
		{"1 GIB", 1 << 30},
		{"1 Gi", 1 << 30},
		{"1 gb", 1_000_000_000},
		{"512 KiB", 512 << 10},
		{"512 kB", 512_000},
		{"2 TiB", 2 << 40},
		{"2 tb", 2_000_000_000_000},
		{"4096 B", 4096},
		{"4096 bytes", 4096},
		{"1 byte", 1},
		{"  512   MiB  ", 512 << 20},
		{"0 MiB", 0},
	}
	for _, tc := range cases {
		got, err := ParseSize(tc.in)
		if err != nil {
			t.Errorf("ParseSize(%q) = error %v, want %d", tc.in, err, tc.want)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseSize(%q) = %d, want %d", tc.in, uint64(got), uint64(tc.want))
		}
	}
}

// TestParseSizeRefuses is the negative, and it is the half that matters: every
// input here is something a human plausibly writes, and reading any of them as
// the nearest accepted thing hands them a bound they did not ask for.
func TestParseSizeRefuses(t *testing.T) {
	cases := []struct {
		in   string
		why  string
		want string // a substring the message must carry
	}{
		{"512", "a bare number is 512 BYTES if it is anything, which is not what the writer of tmpfs_size_mib = 512 meant", "no unit"},
		{"", "an empty string is not zero", "empty size"},
		{"   ", "nor is whitespace", "empty size"},
		{"MiB", "a unit with no number", "does not begin with a number"},
		{"-1 MiB", "a sign; the old key took an int64 and this one does not", "does not begin with a number"},
		{"1.5 GiB", "a fraction rounds, and the rounding is invisible in the file", "is a fraction"},
		{"512 m", "docker reads a bare m as 1024², Kubernetes reads M as 1000²", "unknown unit"},
		{"512 g", "same ambiguity one magnitude up", "unknown unit"},
		{"512 MiBB", "a typo one character past a real unit", "unknown unit"},
		{"true", "what go-toml hands UnmarshalText for tmpfs_size = true", "does not begin with a number"},
	}
	for _, tc := range cases {
		got, err := ParseSize(tc.in)
		if err == nil {
			t.Errorf("ParseSize(%q) = %d with no error; %s", tc.in, uint64(got), tc.why)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseSize(%q) = error %q, want it to carry %q", tc.in, err.Error(), tc.want)
		}
	}
}

// TestParseSizeRefusesOverflow covers both places the arithmetic can wrap: the
// digit run itself, and the multiply by the unit. A wrapped value is not a
// parse failure the caller can see — it is a small, valid-looking bound that
// nothing downstream would question.
func TestParseSizeRefusesOverflow(t *testing.T) {
	for _, in := range []string{
		"99999999999999999999999 B",
		"18446744073709551616 B", // MaxUint64 + 1
		"18446744073709551615 KiB",
		"17592186044417 MiB", // one MiB past MaxUint64
	} {
		if got, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) = %d with no error, want an overflow refusal", in, uint64(got))
		}
	}
	// The largest value that still fits, so the refusals above are not a
	// blanket "anything big fails".
	if got, err := ParseSize("18446744073709551615 B"); err != nil || uint64(got) != math.MaxUint64 {
		t.Errorf("ParseSize(MaxUint64 bytes) = (%d, %v), want (%d, nil)", uint64(got), err, uint64(math.MaxUint64))
	}
}

// TestSizeString guards the string that reaches --dry-run and `snug config`:
// a change here is a change to what a human reads as the sandbox's own
// disclosure of its writable surface's bound.
func TestSizeString(t *testing.T) {
	cases := []struct {
		n    Size
		want string
	}{
		{1 << 30, "1 GiB"},
		{512 << 20, "512 MiB"},
		{6 << 30, "6 GiB"},
		// A decimal value renders in its own family rather than as the
		// 125000 KiB it also exactly is.
		{128_000_000, "128 MB"},
		{1_000, "1 kB"},
		{1 << 10, "1 KiB"},
		{1 << 40, "1 TiB"},
		{1, "1 B"},
		{0, "0 B"},
		{4097, "4097 B"},
	}
	for _, tc := range cases {
		if got := tc.n.String(); got != tc.want {
			t.Errorf("Size(%d).String() = %q, want %q", uint64(tc.n), got, tc.want)
		}
	}
}

// TestSizeStringRoundTrips is the property the two tables above only sample:
// what String writes, ParseSize reads back as the same number. `snug config`
// prints a value a user copies into config.toml, and a rendering that will not
// parse turns that copy into an error.
func TestSizeStringRoundTrips(t *testing.T) {
	sizes := []Size{
		0, 1, 4097, 1000, 1 << 10, 1 << 20, 1 << 30, 1 << 40,
		Size(DefaultTmpfsSize), Size(DefaultEngineScratchSize),
		128_000_000, 512 << 20, 6 << 30, math.MaxUint64,
	}
	for _, s := range sizes {
		got, err := ParseSize(s.String())
		if err != nil {
			t.Errorf("ParseSize(Size(%d).String() = %q) = error %v", uint64(s), s.String(), err)
			continue
		}
		if got != s {
			t.Errorf("Size(%d).String() = %q, which parses back as %d", uint64(s), s.String(), uint64(got))
		}
	}
}

// TestSizeUnmarshalTextIsParseSize asserts the decoder door is the parser and
// not a second, laxer copy of it. go-toml writes an ordinary struct field by
// reflection; a TextUnmarshaler it must call, which is what makes this the one
// way a decoded Size can be built.
func TestSizeUnmarshalTextIsParseSize(t *testing.T) {
	var s Size
	if err := s.UnmarshalText([]byte("100 MiB")); err != nil || s != 100<<20 {
		t.Fatalf("UnmarshalText(\"100 MiB\") = (%d, %v), want (%d, nil)", uint64(s), err, uint64(100<<20))
	}
	s = 7
	if err := s.UnmarshalText([]byte("512")); err == nil {
		t.Fatal("UnmarshalText(\"512\") was accepted; a bare number has no unit")
	} else if s != 7 {
		t.Errorf("a refused UnmarshalText wrote %d into the receiver; it must leave it alone", uint64(s))
	}
}

// TestSizeRoundUpTo covers the arithmetic behind the one number a human is
// asked to trust: tmpfs sizes itself in whole pages, so a bound snug prints
// that is not page-aligned is a bound the kernel does not deliver.
func TestSizeRoundUpTo(t *testing.T) {
	const page Size = 4096
	cases := []struct {
		in      Size
		granule Size
		want    Size
	}{
		{0, page, 0},
		{1, page, 4096},
		{3000, page, 4096}, // "3 kB"
		{4096, page, 4096}, // already whole
		{4097, page, 8192},
		{100_000_000, page, 100_003_840}, // "100 MB"
		{1 << 20, page, 1 << 20},
		{1 << 30, page, 1 << 30},
		// granule 0 and 1 are the identity, so a caller that cannot ask the
		// host for a page size does not get a wrong answer.
		{4097, 0, 4097},
		{4097, 1, 4097},
		// A 64 KiB page, which is a real host (ppc64le), not a hypothetical.
		{4097, 1 << 16, 1 << 16},
		// Total at the top: raising this would wrap, so it does not move.
		{math.MaxUint64, page, math.MaxUint64},
		{math.MaxUint64 - 1, page, math.MaxUint64 - 1},
	}
	for _, tc := range cases {
		if got := tc.in.RoundUpTo(tc.granule); got != tc.want {
			t.Errorf("Size(%d).RoundUpTo(%d) = %d, want %d",
				uint64(tc.in), uint64(tc.granule), uint64(got), uint64(tc.want))
		}
	}
	// The property the table samples: the result is a multiple of the granule
	// and never below the input.
	for n := Size(0); n < 20000; n += 7 {
		got := n.RoundUpTo(4096)
		if got < n || got%4096 != 0 || got-n >= 4096 {
			t.Fatalf("Size(%d).RoundUpTo(4096) = %d", uint64(n), uint64(got))
		}
	}
}
