package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestEngineKeyIgnoresTheProfileSelection is issue #276's part 1, asserted
// directly against engineKey rather than through New (TestStoreKeyIdentifiesTheSandbox
// asserts the same fact end to end, through real directories, and predates this
// test — this one isolates the pure function so the property does not need a
// filesystem to check).
//
// engineKey used to also hash the sorted profile set, so two runs of the same
// project with different selections landed in two different stores for no
// reason a user could see. Since #276 the profile selection is not part of the
// preimage at all.
//
// POSITIVE CONTROL: two DIFFERENT targets must still get two different keys —
// without it, "two selections on one target agree" would pass equally on an
// engineKey that returns a constant.
func TestEngineKeyIgnoresTheProfileSelection(t *testing.T) {
	a := engineKey(&policy.Policy{Target: "/proj/one", Profiles: []policy.ProfileName{"@sys"}})
	b := engineKey(&policy.Policy{Target: "/proj/one",
		Profiles: []policy.ProfileName{"@podman-socket", "@sys", "@net"}})
	if a != b {
		t.Errorf("engineKey changed with the profile selection alone: %q (@sys) vs %q "+
			"(@podman-socket,@sys,@net), same target /proj/one", a, b)
	}

	c := engineKey(&policy.Policy{Target: "/proj/two", Profiles: []policy.ProfileName{"@sys"}})
	if a == c {
		t.Fatalf("control failed: /proj/one and /proj/two produced the same key (%q) — the "+
			"assertion above would pass on an engineKey that ignores EVERYTHING, not just "+
			"the profile set", a)
	}
}

// TestEngineKeyUsesTheCanonicalTarget is a REGRESSION PIN, not a bug fix, and
// its own doc comment says so because a test that claims to close a hole it
// never found is worse than no test (CLAUDE.md).
//
// Issue #276's body described a defect — "engineKey hashes pol.Target, which
// is filepath.Abs(target) only" — that the issue's own follow-up comment
// falsified before any code changed: policy.Resolve already runs
// env.EvalSymlinks on the target (internal/policy/resolve.go) before storing
// it in pol.Target, and both engine call sites (internal/cli/container.go)
// pass pol.Target, never ctx.Target. So a symlinked target and its realpath
// already produced the identical key on `main`, before this PR. This test
// exists so a FUTURE change that routes a raw ctx.Target, a bare
// filepath.Abs, or a hand-rolled realpath into engineKey instead of
// pol.Target is caught, rather than assumed impossible because the doc
// comment says so.
func TestEngineKeyUsesTheCanonicalTarget(t *testing.T) {
	home := t.TempDir()
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link-to-real")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	// Validate refuses a selection with no OS runtime and no reachable target
	// ("the selected profiles grant nothing"), so a minimal registry needs
	// both — the fact under test is canonicalisation, not what a real
	// profile set grants.
	reg := map[policy.ProfileName]*policy.Profile{
		"sys": {Name: "sys", RO: []string{"/usr"}},
		"rw":  {Name: "rw", RW: []string{"{target}"}},
	}
	sel := []policy.ProfileName{"sys", "rw"}

	env := policy.OSEnviron{}
	polReal, err := policy.Resolve(reg, sel, policy.Context{Target: real, Home: home}, env)
	if err != nil {
		t.Fatalf("resolving the real target: %v", err)
	}
	polLink, err := policy.Resolve(reg, sel, policy.Context{Target: link, Home: home}, env)
	if err != nil {
		t.Fatalf("resolving the symlinked target: %v", err)
	}

	// CONTROL: policy.Resolve itself must already have canonicalised both to
	// the identical string — this is the fact issue #276's follow-up comment
	// measured, restated here so a regression in Resolve's own canonicalisation
	// fails THIS test rather than silently making the assertion below vacuous.
	if polReal.Target != polLink.Target {
		t.Fatalf("control failed: policy.Resolve did not canonicalise the symlinked target — "+
			"got %q for the real directory and %q for the symlink", polReal.Target, polLink.Target)
	}

	if engineKey(polReal) != engineKey(polLink) {
		t.Errorf("engineKey(%q) != engineKey(%q) even though policy.Resolve already canonicalised "+
			"both to the identical target string", polReal.Target, polLink.Target)
	}
}

// recursiveEntries lists every path under root except root itself, mirroring
// `find root -mindepth 1` (VERIFY.md's own by-hand check for this).
func recursiveEntries(t *testing.T, root string) []string {
	t.Helper()
	var got []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root {
			got = append(got, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return got
}

// TestPlannedPathsCreatesNothing promotes VERIFY.md's by-hand check
// ("A dry run still creates none of them") into `make gate`. PlannedPaths is
// what --dry-run calls (internal/cli/container.go), and its own doc comment's
// whole contract is that it is string arithmetic over the environment — no
// filesystem access at all. A regression here would make --dry-run, the one
// place CLAUDE.md says a human decides whether to trust snug at all, silently
// start creating the store or the runroot it only claims to describe.
func TestPlannedPathsCreatesNothing(t *testing.T) {
	dataHome := t.TempDir()
	tmp := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("TMPDIR", tmp)

	pol := testPol([]policy.ProfileName{"@podman-socket"}, "/proj")
	paths, err := PlannedPaths(pol)
	if err != nil {
		t.Fatal(err)
	}

	// CONTROL: PlannedPaths actually predicted something under both scratch
	// roots — otherwise "nothing was created" would be true of a function
	// that predicts nothing at all.
	if !strings.HasPrefix(paths.Store, dataHome) {
		t.Fatalf("control failed: predicted store %q is not under the scratch XDG_DATA_HOME %q",
			paths.Store, dataHome)
	}
	if !strings.HasPrefix(paths.Runroot, tmp) {
		t.Fatalf("control failed: predicted runroot %q is not under the scratch TMPDIR %q",
			paths.Runroot, tmp)
	}

	for _, root := range []string{dataHome, tmp} {
		if got := recursiveEntries(t, root); len(got) != 0 {
			t.Errorf("PlannedPaths left %d entr(y/ies) under %s: %v — a dry run must create "+
				"nothing (issue #21, VERIFY.md's own check)", len(got), root, got)
		}
	}
}
