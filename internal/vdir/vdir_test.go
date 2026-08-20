package vdir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These are the checks every caller inherits, tested where they live — one
// implementation, one suite. Before #233 they were tested only through
// internal/cli's runtime directory, so the two other copies of them (the
// engine's, prepareHostTmpDir's) had no coverage at all, which is how they
// came to be missing one guard each.

func mustRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

// TestSecureSubdirRefusesAnInRootSymlink is the case os.Root does NOT cover,
// and the reason this package has an Lstat at all.
//
// os.Root's documented contract is that its methods FOLLOW symlinks as long as
// the target stays inside the root. So an ABSOLUTE symlink is refused by
// os.Root itself and tests nothing of ours — measured: with this refusal
// deleted, an absolute-symlink test still passed. A RELATIVE, in-root symlink
// is the one os.Root will happily follow, and at a name snug creates for
// itself that is one degree more permissive than any caller wants.
func TestSecureSubdirRefusesAnInRootSymlink(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "elsewhere"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(base, "mine")); err != nil {
		t.Fatal(err)
	}

	_, _, err := SecureSubdir(mustRoot(t, base), base, "mine")
	if err == nil {
		t.Fatal("SecureSubdir followed a relative in-root symlink instead of refusing it")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	// CONTROL: the same name, no symlink, must succeed.
	if err := os.Remove(filepath.Join(base, "mine")); err != nil {
		t.Fatal(err)
	}
	child, created, err := SecureSubdir(mustRoot(t, base), base, "mine")
	if err != nil {
		t.Fatalf("control: SecureSubdir refused a clean name: %v", err)
	}
	child.Close()
	if !created {
		t.Error("control: created flag is false for a directory that did not exist")
	}
}

func TestSecureSubdirRefusesAWrongMode(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "loose"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, err := SecureSubdir(mustRoot(t, base), base, "loose")
	if err == nil {
		t.Fatal("SecureSubdir accepted a group/other-readable directory")
	}
	if !strings.Contains(err.Error(), "mode") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
	// Refused, never repaired (invariant 5): a chmod here would hide whatever
	// the wrong mode already exposed.
	fi, statErr := os.Stat(filepath.Join(base, "loose"))
	if statErr != nil {
		t.Fatal(statErr)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("the directory's mode was CHANGED to %#o; snug refuses, it does not repair",
			fi.Mode().Perm())
	}
}

// TestSecureSubdirReportsReuse is the flag two callers read in opposite
// directions: internal/cli's runtime directory reuses the shared "snug"
// directory between runs by design, while the engine's run directory must
// never find one (MustCreateSubdir).
func TestSecureSubdirReportsReuse(t *testing.T) {
	base := t.TempDir()

	child, created, err := SecureSubdir(mustRoot(t, base), base, "d")
	if err != nil {
		t.Fatal(err)
	}
	child.Close()
	if !created {
		t.Fatal("first call did not report creating the directory")
	}

	child, created, err = SecureSubdir(mustRoot(t, base), base, "d")
	if err != nil {
		t.Fatalf("second call refused a directory it created itself: %v", err)
	}
	child.Close()
	if created {
		t.Error("second call reported creating a directory that already existed")
	}
}

func TestMustCreateSubdirRefusesReuse(t *testing.T) {
	base := t.TempDir()

	child, err := MustCreateSubdir(mustRoot(t, base), base, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	child.Close()

	if _, err := MustCreateSubdir(mustRoot(t, base), base, "run-1"); err == nil {
		t.Fatal("MustCreateSubdir reused an existing directory; the name is unique per run, " +
			"so an entry already at it is a leftover or something planted first")
	}
}

// TestOpenExistingSubdirCreatesNothing is the property `snug attach`'s
// discovery depends on: looking for a run must never bring a directory into
// existence.
func TestOpenExistingSubdirCreatesNothing(t *testing.T) {
	base := t.TempDir()

	if _, err := OpenExistingSubdir(mustRoot(t, base), base, "absent"); err == nil {
		t.Fatal("OpenExistingSubdir succeeded on a directory that does not exist")
	}
	if _, err := os.Lstat(filepath.Join(base, "absent")); !os.IsNotExist(err) {
		t.Errorf("OpenExistingSubdir created %s just by looking for it (err=%v)",
			filepath.Join(base, "absent"), err)
	}
}
