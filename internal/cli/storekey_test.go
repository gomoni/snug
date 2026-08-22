package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
)

// TestStoreKeyAndTargetLockAgreeOnOneCanonicalTarget is issue #276's
// anti-drift assertion, and it is the ONE place that can make it: the engine
// store's key (internal/engine's engineKey, reached here only through the
// exported PlannedPaths) and the per-target lock's key (targetKeyPrefix,
// package-private to internal/cli) are two independent hashes of what is
// supposed to be the identical canonical target string. Nothing in either
// package checks that they agree; this test is that check.
//
// Both hash pol.Target — already the EvalSymlinks form policy.Resolve
// produces (internal/policy/resolve.go) — so this constructs the *policy.Policy
// by hand with Target set directly, the same way internal/engine's own
// testPol fixture does, rather than resolving a full profile set: the fact
// under test is about the TWO KEYS agreeing on one string, not about profile
// resolution.
//
// POSITIVE CONTROL: a sibling REAL directory (not a symlink of the same one)
// must produce a DIFFERENT key in both places — without it, "the symlink and
// its realpath agree" would pass equally on a pair of functions that always
// return the same constant.
func TestStoreKeyAndTargetLockAgreeOnOneCanonicalTarget(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link-to-real")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(root, "sibling")
	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatal(err)
	}

	// pol.Target IS the canonical (EvalSymlinks'd) string by the time either
	// key sees it — this is what makes "canon" below the shared input both
	// engineKey and targetKeyPrefix must agree is one target.
	canon := func(t *testing.T, p string) string {
		t.Helper()
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			t.Fatal(err)
		}
		return real
	}

	realCanon := canon(t, real)
	linkCanon := canon(t, link)
	siblingCanon := canon(t, sibling)

	if realCanon != linkCanon {
		t.Fatalf("control failed: filepath.EvalSymlinks did not canonicalise the symlink to the "+
			"same string as its realpath: %q vs %q", realCanon, linkCanon)
	}
	if realCanon == siblingCanon {
		t.Fatalf("control failed: a distinct sibling directory canonicalised to the same string "+
			"as %q", realCanon)
	}

	storeFor := func(t *testing.T, target string) string {
		t.Helper()
		paths, err := engine.PlannedPaths(&policy.Policy{Target: target})
		if err != nil {
			t.Fatal(err)
		}
		return paths.Store
	}

	storeReal := storeFor(t, realCanon)
	storeLink := storeFor(t, linkCanon)
	storeSibling := storeFor(t, siblingCanon)

	lockReal := targetKeyPrefix(realCanon)
	lockLink := targetKeyPrefix(linkCanon)
	lockSibling := targetKeyPrefix(siblingCanon)

	if storeReal != storeLink {
		t.Errorf("the engine store key disagrees about the SAME canonical target: %q (real) vs "+
			"%q (symlink, canonicalised identically)", storeReal, storeLink)
	}
	if lockReal != lockLink {
		t.Errorf("the target lock key disagrees about the SAME canonical target: %q (real) vs "+
			"%q (symlink, canonicalised identically)", lockReal, lockLink)
	}

	// The soundness rule from engineKey's own doc comment (paths.go), checked
	// directly: S(a) = S(b) must imply L(a) = L(b). Today S = L exactly, so
	// this also holds in the strict sense, but the implication is the
	// property that matters if a future change ever makes S coarser than L.
	if storeReal == storeLink && lockReal != lockLink {
		t.Fatalf("the store's partition is COARSER than the lock's: two targets share a store " +
			"key but not a lock key — a second run could reach a store a live sandbox still owns")
	}

	if storeReal == storeSibling {
		t.Errorf("two DIFFERENT targets (%q and %q) share an engine store key", real, sibling)
	}
	if lockReal == lockSibling {
		t.Errorf("two DIFFERENT targets (%q and %q) share a target-lock key", real, sibling)
	}
}
