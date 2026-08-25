package policy

import (
	"strconv"
	"testing"
)

// TestProfileAuthoredTmpfsCarriesTheSizeBound fails if a KindTmpfs mount that
// originates from a PROFILE's `tmpfs = [...]` grant (resolve.go's prof.Tmpfs
// loop) ever reaches the bwrap argv with its `--tmpfs` unpaired with the
// `--size <TmpfsSizeBytes>` that must immediately precede it.
//
// A redteam round against #394 (the --size-on-every-tmpfs change) enumerated
// this path on its own and found it uncovered: TestOnlyResolveSetsTmpfsSizeBytes
// (tmpfssizewriter_test.go) sweeps for a second Go WRITER of the field, not for
// what the argv does with the one writer that exists; rejectUnboundedTmpfs
// (validate.go) refuses a KindTmpfs mount with TmpfsSizeBytes unset entirely,
// not a mispairing in the argv; the config-boundary integration tests
// (test/integration/tmpfssize_test.go) exercise /tmp and @home's XDG tmpfs
// mounts, never a profile's own `tmpfs` key. bwrap.go's KindTmpfs arm emits
// `--size` and `--tmpfs` in one `append`, which is why no profile-tmpfs path
// can route around the bound today — this pins that fact for the profile path
// specifically, the one none of the above happens to reach.
func TestProfileAuthoredTmpfsCarriesTheSizeBound(t *testing.T) {
	ctx := testCtx()
	// Distinct from DefaultTmpfsSize (1 GiB): if the assertion below matched
	// on the default regardless of what the policy actually carried, it would
	// not be testing the pairing at all.
	ctx.TmpfsSizeBytes = 8 << 20

	reg := testRegistry()
	// A profile whose ONLY grant is `tmpfs`, so every one of these three guest
	// paths in the argv is attributable to this profile's grant alone, not to
	// @home's tmpfs list or to yieldTo's /tmp.
	reg["tmpsy"] = &Profile{Name: "tmpsy", Tmpfs: []string{"/t1", "/t2", "/t3"}}

	p, err := Resolve(reg, []ProfileName{"runtime-bin", "@cwd-rw", "tmpsy"}, ctx, newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.TmpfsSizeBytes != ctx.TmpfsSizeBytes {
		t.Fatalf("resolved policy carries TmpfsSizeBytes=%d, want the context's %d", p.TmpfsSizeBytes, ctx.TmpfsSizeBytes)
	}
	wantSize := strconv.FormatUint(p.TmpfsSizeBytes, 10)

	args := p.BwrapArgs(1000, 1000)

	// POSITIVE CONTROL: the three guest paths this profile granted must
	// actually surface as --tmpfs in the argv, or the pairing loop below
	// would pass vacuously on a selection whose grant never reached bwrap at
	// all.
	seen := map[string]bool{"/t1": false, "/t2": false, "/t3": false}
	for i, a := range args {
		if a != "--tmpfs" {
			continue
		}
		guest := args[i+1]
		if _, ours := seen[guest]; !ours {
			continue
		}
		seen[guest] = true

		// The assertion this test exists for: --size <bound> must be the pair
		// immediately preceding this --tmpfs (bwrap.go's KindTmpfs comment: it
		// sets the size of the NEXT argument and bwrap refuses it anywhere
		// else). Counting --size and --tmpfs occurrences instead would pass on
		// a mispairing as long as the totals matched.
		if i < 2 || args[i-2] != "--size" || args[i-1] != wantSize {
			lo := i - 2
			if lo < 0 {
				lo = 0
			}
			t.Errorf("profile-granted --tmpfs %s is not immediately preceded by \"--size %s\"; argv around it: %v",
				guest, wantSize, args[lo:i+1])
		}
	}
	for guest, ok := range seen {
		if !ok {
			t.Fatalf("positive control failed: profile's tmpfs grant at %s never appeared as --tmpfs in the argv at all", guest)
		}
	}
}
