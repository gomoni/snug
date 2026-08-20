package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// The shared /tmp directory had NO test of its guards before issue #233, which
// is the reason its spelling of them was the weakest of the three: it checked a
// path rather than a descriptor, and nothing would have noticed if a guard were
// dropped entirely. These are the checks the directory has always claimed.
//
// $TMPDIR is what hostTmpDirPath builds on (os.TempDir reads it), so each test
// gets its own base and none of them touches the developer's real /tmp.

func TestHostTmpDirRefusesAPreplantedSymlink(t *testing.T) {
	base := t.TempDir()
	t.Setenv("TMPDIR", base)

	const target = "/proj"
	path := hostTmpDirPath(target)
	trap := filepath.Join(base, "attacker-owned")
	if err := os.Mkdir(trap, 0o700); err != nil {
		t.Fatal(err)
	}
	// RELATIVE, and that is the whole point of the case: os.Root refuses to
	// follow a symlink whose target is ABSOLUTE (it leaves the root), so an
	// absolute trap is blocked by os.Root itself and proves nothing about
	// snug's own guard. A relative, in-root symlink is what os.Root's
	// documented contract FOLLOWS, and vdir's Lstat refusal is the only thing
	// standing in front of it. Measured: with that refusal deleted, an
	// absolute-symlink version of this test still passed.
	if err := os.Symlink(filepath.Base(trap), path); err != nil {
		t.Fatal(err)
	}

	if _, err := prepareHostTmpDir(target); err == nil {
		t.Fatal("prepareHostTmpDir followed a pre-planted symlink instead of refusing it — " +
			"this directory becomes the sandbox's /tmp, so following one hands the payload's " +
			"writes to whoever planted it")
	}

	// CONTROL: the same base without the trap must succeed, or the refusal
	// above proves nothing about the symlink specifically.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	got, err := prepareHostTmpDir(target)
	if err != nil {
		t.Fatalf("control: prepareHostTmpDir failed once the symlink was gone: %v", err)
	}
	if got != path {
		t.Errorf("prepareHostTmpDir = %q, want %q", got, path)
	}
}

func TestHostTmpDirRefusesADirectoryOthersCanReach(t *testing.T) {
	base := t.TempDir()
	t.Setenv("TMPDIR", base)

	const target = "/proj"
	path := hostTmpDirPath(target)
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareHostTmpDir(target); err == nil {
		t.Fatal("prepareHostTmpDir accepted a group/other-readable directory as the sandbox's " +
			"/tmp; refuse rather than repair — a chmod here would hide whatever the wrong " +
			"mode already exposed")
	}

	// CONTROL: 0700 at the same path is accepted, so the refusal is about the
	// mode and not about the directory existing.
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareHostTmpDir(target); err != nil {
		t.Fatalf("control: prepareHostTmpDir refused a 0700 directory it should accept: %v", err)
	}
}

// TestHostTmpDirIsReusedAcrossRuns pins the property that makes this directory
// different from the engine's run directory, and the reason it calls
// SecureSubdir rather than MustCreateSubdir: the name is derived from the
// target, so a project gets the SAME directory next run and a build cache
// stays warm. A conversion that made reuse a refusal would have passed every
// guard test above and broken the feature.
func TestHostTmpDirIsReusedAcrossRuns(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	const target = "/proj"
	first, err := prepareHostTmpDir(target)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(first, "cache-marker")
	if err := os.WriteFile(marker, []byte("warm"), 0o600); err != nil {
		t.Fatal(err)
	}

	second, err := prepareHostTmpDir(target)
	if err != nil {
		t.Fatalf("a second run was refused its own directory: %v", err)
	}
	if second != first {
		t.Errorf("two runs on one target got different directories: %s then %s", first, second)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the second run did not find the first run's contents (%v); the shared /tmp "+
			"exists to keep a build cache warm", err)
	}

	// And two DIFFERENT targets never share one.
	other, err := prepareHostTmpDir("/other")
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Errorf("two different targets got the same directory %s", other)
	}
}
