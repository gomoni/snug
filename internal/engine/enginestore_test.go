package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestEngineStoreRefusesASymlinkedComponent is issue #328's regression: a
// same-uid attacker who can write into a shared, world-writable directory
// (the default XDG_DATA_HOME parent is 0755, and /tmp is 1777) can plant a
// SYMLINK at the exact name snug is about to claim, before snug gets there.
// Measured on `main` before this fix: os.MkdirAll on such a name returns
// <nil>, leaves the planted name a symlink, and creates content INSIDE the
// attacker's own directory — read/write disclosure at minimum, and a
// hooks.prestart TOCTOU write at worst (issue #276's part 3 commit message).
//
// THE LOAD-BEARING DETAIL IS WHICH COMPONENT IS CHECKED. Both walks
// (verifyEngineStore under dataHome, verifyEngineRunroot under os.TempDir())
// must refuse a symlink at their own FIRST snug-owned component —
// "snug" under dataHome, and "snug-engines-<uid>-<key>" under TMPDIR — not
// merely at some directory further down the chain. A walk that only started
// protecting one level lower (at "engines", or at "rr") would leave the top
// name wide open while every directory beneath it looked hardened, which is
// exactly the shape issue #328 named: "rooting the check one level lower
// would leave the top name wide open".
//
// Each case pre-plants the symlink at the TOP component only, so the
// mutation this test exists to catch — rooting the walk one level lower — is
// the one that makes it pass on a broken implementation. A test that only
// planted the trap deeper in the chain would not tell the two apart.
func TestEngineStoreRefusesASymlinkedComponent(t *testing.T) {
	t.Run("store: snug under XDG_DATA_HOME", func(t *testing.T) {
		dataHome := t.TempDir()
		tmp := t.TempDir()
		t.Setenv("XDG_DATA_HOME", dataHome)
		t.Setenv("TMPDIR", tmp)

		attacker := filepath.Join(dataHome, "attacker-owned")
		if err := os.Mkdir(attacker, 0o700); err != nil {
			t.Fatal(err)
		}
		// RELATIVE target: os.Root already refuses an absolute in-root
		// symlink on its own, so an absolute trap would test os.Root rather
		// than snug's own Lstat guard (see rundir_test.go's identical note).
		if err := os.Symlink("attacker-owned", filepath.Join(dataHome, "snug")); err != nil {
			t.Fatal(err)
		}

		pol := testPol([]policy.ProfileName{"@podman-socket"}, "/proj/symlinked-store")
		if _, err := New(pol); err == nil {
			t.Fatal("New accepted a pre-planted symlink at dataHome/snug, the store's top " +
				"snug-owned component")
		}
		if got := recursiveEntries(t, attacker); len(got) != 0 {
			t.Errorf("content was created INSIDE the attacker's directory through the symlink: %v", got)
		}
	})

	t.Run("runroot: snug-engines-<uid>-<key> under TMPDIR", func(t *testing.T) {
		dataHome := t.TempDir()
		tmp := t.TempDir()
		t.Setenv("XDG_DATA_HOME", dataHome)
		t.Setenv("TMPDIR", tmp)

		pol := testPol([]policy.ProfileName{"@podman-socket"}, "/proj/symlinked-runroot")
		key := engineKey(pol)

		attacker := filepath.Join(tmp, "attacker-owned")
		if err := os.Mkdir(attacker, 0o700); err != nil {
			t.Fatal(err)
		}
		topName := fmt.Sprintf("snug-engines-%d-%s", os.Getuid(), key)
		if err := os.Symlink("attacker-owned", filepath.Join(tmp, topName)); err != nil {
			t.Fatal(err)
		}

		if _, err := New(pol); err == nil {
			t.Fatal("New accepted a pre-planted symlink at the runroot's top component " +
				"(issue #328)")
		}
		if _, err := os.Stat(filepath.Join(attacker, "rr", "tmp")); err == nil {
			t.Fatal("rr/tmp was created INSIDE the attacker's directory through the symlink " +
				"(issue #328's exact reproduction)")
		}
	})
}

// TestEngineReusesAWarmStore is TestEngineStoreRefusesASymlinkedComponent's
// POSITIVE CONTROL, named in issue #276's own specification: a fix that made
// the store/runroot walk refuse a pre-planted symlink could just as easily
// have refused REUSE outright (SecureSubdir instead of MustCreateSubdir), and
// that would break the exact warm start the target-only key exists to
// produce (issue #276 part 1's whole point). So this asserts the other
// direction directly: two `New` calls against the SAME target, with nothing
// planted, must agree on the store and the runroot — not merely both
// succeed.
func TestEngineReusesAWarmStore(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	pol := testPol([]policy.ProfileName{"@podman-socket"}, "/proj/warm")
	first, err := New(pol)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	second, err := New(pol)
	if err != nil {
		t.Fatalf("second run on the identical target was refused, not reused: %v", err)
	}

	if first.Store() != second.Store() {
		t.Errorf("two runs of the same target got different stores: %q vs %q — reuse is broken",
			first.Store(), second.Store())
	}
	if first.Runroot() != second.Runroot() {
		t.Errorf("two runs of the same target got different runroots: %q vs %q — podman's "+
			"libpod database (already inside the shared store) would refuse the second run",
			first.Runroot(), second.Runroot())
	}

	// Both directories must actually still exist and still be usable — reuse
	// is a claim about the SECOND call succeeding against them, not merely
	// about the two calls returning equal strings.
	for _, d := range []string{first.Store(), second.Runroot()} {
		fi, statErr := os.Stat(d)
		if statErr != nil {
			t.Fatalf("%s: %v", d, statErr)
		}
		if !fi.IsDir() {
			t.Fatalf("%s is not a directory", d)
		}
	}
}

// TestEngineRunrootRefusesAWorldReadableDir stands in for the cross-uid case
// this test suite cannot stage (issue #276's follow-up comment: "every
// cross-uid conclusion is REASONED, not measured — the round could not stage
// a second uid on this box"). VerifyOwnedAndPrivate's mode check is the half
// that would refuse a directory a DIFFERENT uid on this host created and
// chmod'd loosely — same uid here, wrong mode, is the closest this suite gets
// without a second account.
//
// 0755 refused, 0700 accepted: the second half is the positive control,
// because a check that refuses every mode would pass the first half for the
// wrong reason.
func TestEngineRunrootRefusesAWorldReadableDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	key := strings.Repeat("a", 16)
	top := filepath.Join(tmp, fmt.Sprintf("snug-engines-%d-%s", os.Getuid(), key))

	if err := os.Mkdir(top, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyEngineRunroot(key); err == nil {
		t.Fatal("verifyEngineRunroot accepted a world-readable (0755) top directory")
	} else if !strings.Contains(err.Error(), "0755") {
		t.Errorf("the refusal does not name the offending mode, so a reader cannot tell what "+
			"to fix: %v", err)
	}

	if err := os.Remove(top); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(top, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyEngineRunroot(key); err != nil {
		t.Fatalf("control: verifyEngineRunroot refused a properly-permissioned (0700) "+
			"directory, so the refusal above proves nothing about the MODE specifically: %v", err)
	}
}

// TestEngineCreatedPathsMatchPlannedPaths extends issue #252's
// predicted-vs-created equality check (New's own comment: "the created paths
// must be the predicted ones") to Store and Runroot, which issue #276's part
// 3 gave a second way to diverge from planPaths' string arithmetic: the vdir
// walk's own path construction. Before this the check only covered
// sockDir/confDir; a divergence in the store or the runroot would have made
// --dry-run describe a store the run does not use, with nothing here to
// catch it.
func TestEngineCreatedPathsMatchPlannedPaths(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	pol := testPol([]policy.ProfileName{"@podman-socket"}, "/proj/planned-vs-created")
	planned, err := PlannedPaths(pol)
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(pol)
	if err != nil {
		t.Fatal(err)
	}

	if e.Store() != planned.Store {
		t.Errorf("New created store %q but PlannedPaths (what --dry-run shows) predicted %q",
			e.Store(), planned.Store)
	}
	if e.Runroot() != planned.Runroot {
		t.Errorf("New created runroot %q but PlannedPaths (what --dry-run shows) predicted %q",
			e.Runroot(), planned.Runroot)
	}
}
