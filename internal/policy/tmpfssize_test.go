package policy

import (
	"strconv"
	"strings"
	"testing"
)

// tmpfsSelections is the set of selections these tests scan for a size on
// every emitted tmpfs. It reuses TestGoldenBwrapArgs's own table (bwrap_test.go)
// rather than re-typing a parallel list of profile names: every one of those
// selections already resolves through @cwd-rw's Include of @home, so each
// carries the full five-tmpfs @home block plus /tmp.
func tmpfsSelections(t *testing.T) map[string]*Policy {
	t.Helper()
	cases := map[string][]ProfileName{
		"sys":                  {"@sys", "@cwd-rw"},
		"defaults":             testDefaults,
		"parent-ro":            {"@sys", "@cwd-rw", "@parent-ro"},
		"podman-socket":        {"@sys", "@cwd-rw", "@podman-socket"},
		"system-ssh-uncovered": {"@home", "@cwd-rw", "@parent-ro", "runtime-bin"},
	}
	out := make(map[string]*Policy, len(cases))
	for name, sel := range cases {
		out[name] = mustResolve(t, sel...)
	}
	// The floor: no profiles at all. Resolve still returns a policy (Validate
	// refuses it, but BwrapArgs is still a pure function of it), and its base
	// topology alone carries a tmpfs at /tmp.
	floor, _ := Resolve(testRegistry(), nil, testCtx(), newFakeEnv())
	if floor == nil {
		t.Fatal("Resolve(nil) returned no policy at all; the floor case cannot be built")
	}
	out["floor"] = floor
	return out
}

// TestEveryTmpfsInTheArgvCarriesASize is the set assertion that matters: for
// every selection this suite resolves, every "--tmpfs" token in BwrapArgs is
// immediately preceded by "--size" and the resolved Policy's own
// TmpfsSizeBytes, spelled out as a base-10 string.
//
// The positive control comes FIRST and is mandatory: if a selection resolved
// with no KindTmpfs mount at all, the loop below would range over zero
// "--tmpfs" tokens and pass having checked nothing. Asserting count > 0 before
// the scan is what stops that — every selection here is chosen precisely
// because it carries @home (five tmpfs mounts) or the base topology's /tmp (at
// least one), so the count really can be, and is, nonzero.
func TestEveryTmpfsInTheArgvCarriesASize(t *testing.T) {
	for name, p := range tmpfsSelections(t) {
		t.Run(name, func(t *testing.T) {
			args := p.BwrapArgs(1000, 1000)

			count := 0
			for _, a := range args {
				if a == "--tmpfs" {
					count++
				}
			}
			// MANDATORY POSITIVE CONTROL: without this, a selection that
			// happened to carry no tmpfs mount at all would make every
			// assertion below vacuously true.
			if count == 0 {
				t.Fatalf("selection %q emits no --tmpfs token at all, so this test cannot fail "+
					"and proves nothing about it", name)
			}

			want := strconv.FormatUint(p.TmpfsSizeBytes, 10)
			if want == "0" {
				t.Fatalf("policy.TmpfsSizeBytes is 0 for selection %q; Resolve is supposed to "+
					"substitute DefaultTmpfsSize for an unset preference", name)
			}

			seen := 0
			for i, a := range args {
				if a != "--tmpfs" {
					continue
				}
				seen++
				if i < 2 {
					t.Fatalf("--tmpfs at index %d has no room for a preceding --size pair", i)
				}
				if args[i-2] != "--size" {
					t.Errorf("--tmpfs %s at index %d is not preceded by --size two tokens back "+
						"(got %q); bwrap defaults an unsized tmpfs to half of host RAM", args[i-1], i, args[i-2])
				}
				if args[i-1] != want {
					t.Errorf("--tmpfs %s at index %d carries size %q, want %q (p.TmpfsSizeBytes)",
						args[i-1], i, args[i-1], want)
				}
			}
			if seen != count {
				t.Fatalf("counted %d --tmpfs tokens up front and %d in the scan; the two loops disagree", count, seen)
			}
		})
	}
}

// TestSizeAppearsOnlyImmediatelyBeforeATmpfs is the negative half: no --size
// token anywhere in BwrapFlags may be followed by anything other than --tmpfs
// two tokens later. bwrap does not treat a misplaced --size as inert — it
// exits 1 with "bwrap: --size must be followed by --tmpfs" (measured, bwrap
// 0.11.2) — so this test is protecting against a HARD FAILURE of the whole
// sandbox launch, not a silently-missing feature the way most of this
// project's negative tests are.
func TestSizeAppearsOnlyImmediatelyBeforeATmpfs(t *testing.T) {
	for name, p := range tmpfsSelections(t) {
		t.Run(name, func(t *testing.T) {
			flags := p.BwrapFlags(1000, 1000, func(string) int { return 9 })

			found := false
			for i, a := range flags {
				if a != "--size" {
					continue
				}
				found = true
				if i+2 >= len(flags) {
					t.Fatalf("--size at index %d has no room for a following --tmpfs; bwrap would "+
						"exit 1 with \"bwrap: --size must be followed by --tmpfs\"", i)
				}
				if flags[i+2] != "--tmpfs" {
					t.Errorf("--size at index %d is followed by %q two tokens later, not --tmpfs; "+
						"bwrap would refuse this argv outright with exit 1", i, flags[i+2])
				}
			}
			// Every selection here carries at least one tmpfs (see
			// TestEveryTmpfsInTheArgvCarriesASize's positive control), so a
			// --size token must actually have been found, or this test is
			// checking a property of an empty set.
			if !found {
				t.Fatalf("selection %q emits no --size token at all, so this test cannot fail", name)
			}
		})
	}
}

// TestResolveUsesTheContextTmpfsBound: a caller's non-zero preference reaches
// the resolved Policy unchanged.
func TestResolveUsesTheContextTmpfsBound(t *testing.T) {
	ctx := testCtx()
	ctx.TmpfsSizeBytes = 512 << 20
	p, err := Resolve(testRegistry(), testDefaults, ctx, newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.TmpfsSizeBytes != 512<<20 {
		t.Errorf("p.TmpfsSizeBytes = %d, want %d (the context's preference)", p.TmpfsSizeBytes, uint64(512<<20))
	}
}

// TestResolveDefaultsTheTmpfsBoundWhenContextIsZero: an absent (zero)
// preference becomes DefaultTmpfsSize, never a bare zero — a zero
// Policy.TmpfsSizeBytes reaching bwrap would mean an unbounded tmpfs
// (rejectUnboundedTmpfs's whole reason to exist).
func TestResolveDefaultsTheTmpfsBoundWhenContextIsZero(t *testing.T) {
	ctx := testCtx()
	ctx.TmpfsSizeBytes = 0
	p, err := Resolve(testRegistry(), testDefaults, ctx, newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.TmpfsSizeBytes != DefaultTmpfsSize {
		t.Errorf("p.TmpfsSizeBytes = %d, want DefaultTmpfsSize (%d)", p.TmpfsSizeBytes, DefaultTmpfsSize)
	}
}

// TestPolicyWithATmpfsAndNoBoundIsRefused hand-builds a minimal but otherwise
// legal Policy — one OS-runtime bind, one target bind, one KindTmpfs mount —
// and asserts Validate refuses it when TmpfsSizeBytes is 0.
func handBuiltTmpfsPolicy(size uint64) *Policy {
	p := &Policy{
		Target: "/home/u/proj",
		Home:   "/home/u",
		Mounts: map[string]Mount{
			"/usr":         {Guest: "/usr", Host: "/usr", Kind: KindBind, Access: AccessRO},
			"/home/u/proj": {Guest: "/home/u/proj", Host: "/home/u/proj", Kind: KindBind, Access: AccessRW},
			"/tmp":         {Guest: "/tmp", Kind: KindTmpfs},
		},
		TmpfsSizeBytes: size,
	}
	p.Topology = deriveTopology(p.Net.Mode, p.Podman)
	return p
}

func TestPolicyWithATmpfsAndNoBoundIsRefused(t *testing.T) {
	p := handBuiltTmpfsPolicy(0)
	err := p.Validate(newFakeEnv())
	if err == nil {
		t.Fatal("a policy with a KindTmpfs mount and TmpfsSizeBytes == 0 was accepted; " +
			"bwrap would default the mount to half of host RAM")
	}
	for _, want := range []string{"/tmp", "Policy.TmpfsSizeBytes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}

	// POSITIVE CONTROL (a): the identical policy with the field set VALIDATES.
	// Without this, "size == 0 is refused" could mean rejectUnboundedTmpfs
	// refuses every policy carrying a tmpfs, bound or not.
	withBound := handBuiltTmpfsPolicy(DefaultTmpfsSize)
	if err := withBound.Validate(newFakeEnv()); err != nil {
		t.Errorf("control: the same policy with TmpfsSizeBytes set should validate: %v", err)
	}

	// POSITIVE CONTROL (b): a policy with NO tmpfs at all and a zero field also
	// validates — the check must not fire on a tmpfs-free selection. Without
	// this, the refusal above could be a blanket "TmpfsSizeBytes must be
	// nonzero" rule rather than one scoped to policies that actually emit a
	// KindTmpfs mount.
	noTmpfs := handBuiltTmpfsPolicy(0)
	delete(noTmpfs.Mounts, "/tmp")
	if err := noTmpfs.Validate(newFakeEnv()); err != nil {
		t.Errorf("control: a policy with no tmpfs mount and TmpfsSizeBytes == 0 should still "+
			"validate: %v", err)
	}
}

// TestOnlyResolveSetsTmpfsSizeBytes lives in tmpfssizewriter_test.go, alongside
// the module-wide AST sweep it needs.

// TestTmpfsBoundIsOrderIndependent: resolve([a,b]) and resolve([b,a]) must
// agree on TmpfsSizeBytes.
//
// This is trivially true today — TmpfsSizeBytes is a single scalar copied from
// ctx once, in Resolve's own Policy{} literal, and no profile can touch it (see
// TestProfileCannotSetATmpfsSize in internal/profile) — and that triviality IS
// the argument for keeping it a scalar rather than a per-Mount field
// (types.go's doc comment). This test exists so that if it is ever demoted to
// a per-Mount field with a MIN join — the wrong join, since min is the
// restriction operation invariant 1 forbids — the order-dependence such a join
// would introduce fails loudly here rather than shipping unnoticed.
func TestTmpfsBoundIsOrderIndependent(t *testing.T) {
	a := mustResolve(t, "@sys", "@home", "@cwd-rw", "@parent-ro")
	b := mustResolve(t, "@parent-ro", "@cwd-rw", "@home", "@sys")
	if a.TmpfsSizeBytes != b.TmpfsSizeBytes {
		t.Errorf("resolve([a,b]).TmpfsSizeBytes = %d, resolve([b,a]).TmpfsSizeBytes = %d; "+
			"the bound depends on profile order", a.TmpfsSizeBytes, b.TmpfsSizeBytes)
	}
}

// TestFormatBytes guards the string that reaches --dry-run and `snug config`:
// a change here is a change to what a human reads as the sandbox's own
// disclosure of its writable surface's bound.
func TestFormatBytes(t *testing.T) {
	cases := []struct {
		n    uint64
		want string
	}{
		{1 << 30, "1 GiB"},
		{512 << 20, "512 MiB"},
		{6 << 30, "6 GiB"},
		{1, "1 bytes"},
		{0, "0 bytes"},
	}
	for _, tc := range cases {
		if got := FormatBytes(tc.n); got != tc.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
