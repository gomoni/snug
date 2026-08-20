package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRunDirsRemoveGoesThroughTheDescriptorNotThePath is the test that can
// tell the two implementations apart. `os.RemoveAll(d.path)` and
// `parent.RemoveAll(d.name)` are indistinguishable on an undisturbed
// filesystem — both leave the directory gone — so an assertion that only
// checks "it is gone afterwards" proves nothing about which one is running.
//
// Renaming the PARENT after the handles were opened separates them. A
// descriptor names an inode, so removal through it still finds this run's
// directory; a path string names a route that no longer exists, and
// os.RemoveAll treats a missing path as SUCCESS — so the path version would
// report a clean teardown having removed nothing, leaving this run's engine
// socket and generated config on disk.
func TestRunDirsRemoveGoesThroughTheDescriptorNotThePath(t *testing.T) {
	base := t.TempDir()
	dirs, err := openRunDirs(base, "snug-test-rundir")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := dirs.sub("sock"); err != nil {
		t.Fatal(err)
	}

	moved := filepath.Join(filepath.Dir(base), filepath.Base(base)+"-moved")
	if err := os.Rename(base, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(moved) })

	if err := dirs.remove(); err != nil {
		t.Fatalf("remove after the parent was renamed: %v — removal is re-walking the path "+
			"instead of using the descriptor the checks left open", err)
	}
	if _, err := os.Stat(filepath.Join(moved, "snug-test-rundir")); !os.IsNotExist(err) {
		t.Errorf("the run directory survived remove at its new location (err=%v); a path-based "+
			"removal would report success having removed nothing", err)
	}
}

// TestRunDirsRefusesAPreplantedSymlink asserts the OUTCOME for this caller —
// a planted symlink does not become this run's directory, and nothing is
// created through it — and says plainly which rule delivers that, because two
// do and only one of them is the symlink guard.
//
// Measured by deleting vdir's Lstat refusal: this test still passed. The
// refusal that fires first here is MustCreateSubdir's no-reuse rule — an entry
// already at a pid-carrying name is refused whatever it is. The symlink guard
// is the one that matters where reuse is legitimate, and it is discriminated
// there instead: internal/vdir's own TestSecureSubdirRefusesAnInRootSymlink
// and internal/cli's TestHostTmpDirRefusesAPreplantedSymlink both fail when it
// is removed. Belt and braces is worth having; claiming a test proves the
// brace when the belt is holding is not.
func TestRunDirsRefusesAPreplantedSymlink(t *testing.T) {
	base := t.TempDir()
	trap := filepath.Join(base, "attacker-owned")
	if err := os.Mkdir(trap, 0o700); err != nil {
		t.Fatal(err)
	}
	// RELATIVE: os.Root refuses an absolute symlink target on its own (it
	// leaves the root), so an absolute trap tests os.Root rather than snug's
	// guard. A relative, in-root symlink is exactly what os.Root's contract
	// says it will FOLLOW, and vdir's Lstat refusal is what stops it.
	if err := os.Symlink(filepath.Base(trap), filepath.Join(base, "snug-test-rundir")); err != nil {
		t.Fatal(err)
	}

	if _, err := openRunDirs(base, "snug-test-rundir"); err == nil {
		t.Fatal("openRunDirs followed a pre-planted symlink instead of refusing it")
	}
	if _, err := os.Stat(filepath.Join(trap, "sock")); err == nil {
		t.Fatal("a run directory was created INSIDE the attacker's directory through the symlink")
	}

	// CONTROL: the same base, without the trap, must succeed — otherwise this
	// passes on an openRunDirs that refuses everything.
	if err := os.Remove(filepath.Join(base, "snug-test-rundir")); err != nil {
		t.Fatal(err)
	}
	dirs, err := openRunDirs(base, "snug-test-rundir")
	if err != nil {
		t.Fatalf("control: openRunDirs failed once the symlink was gone: %v", err)
	}
	dirs.close()
}

// TestRunDirsRefusesAWronglyPermissionedDirectory: mode is checked on the
// opened handle, not on the name, and a wrong mode is refused rather than
// chmod'd back (invariant 5 — repairing it quietly hides whatever the wrong
// mode already broke). A hostile umask can weaken the mode Mkdir asked for,
// which is why this is checked even for a directory just created.
func TestRunDirsRefusesAWronglyPermissionedDirectory(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "snug-test-rundir"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := openRunDirs(base, "snug-test-rundir")
	if err == nil {
		t.Fatal("openRunDirs accepted a group/other-readable directory")
	}
	// It must be refused for EXISTING first — the reuse rule fires before the
	// mode check — and either refusal is correct here; what must not happen is
	// silent acceptance.
	t.Logf("refused with: %v", err)
}
