package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/policy"
)

// plantRunDir creates one directory under dir with the given name, and a lock
// file inside it when withLock. It returns the path.
//
// It writes the lock file the way lockEngineRunDir does — name and mode — but
// does NOT flock it, which is the state a SIGKILLed run leaves behind: the file
// is there and nobody holds it.
func plantRunDir(t *testing.T, dir, name string, withLock bool) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if withLock {
		f, err := os.OpenFile(filepath.Join(path, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	return path
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	return err == nil
}

// TestSweepReclaimsARunDirectoryWhoseOwnerIsGone is issue #425's first bullet:
// /tmp/snug-<uid>-<pid>/ survived any run that ended in a SIGKILL, because Stop
// is the only thing that removed it and a SIGKILLed process runs nothing on its
// way out. sweepStaleRunDirs could not see these at all — its base is one
// directory level up from where they live.
//
// The POSITIVE CONTROL is the first subtest and it is mandatory: a sweep that
// removes nothing is indistinguishable from a sweep with a broken name filter,
// which is the failure this project has measured before (an `awk '$0=="--tmpfs"'`
// that matched nothing over fixtures putting flag and operand on one line, read
// as the property holding).
func TestSweepReclaimsARunDirectoryWhoseOwnerIsGone(t *testing.T) {
	uid := os.Getuid()

	t.Run("positive control: an unlocked lock file is a dead owner", func(t *testing.T) {
		tmp := t.TempDir()
		t.Setenv("TMPDIR", tmp)
		stale := plantRunDir(t, tmp, fmt.Sprintf("snug-%d-999999", uid), true)

		sweepStaleEngineRunDirs()

		if exists(t, stale) {
			t.Fatalf("the sweep left %s, whose lock nobody holds — a run that died by SIGKILL "+
				"leaves exactly this, and it is the whole case Stop cannot cover", stale)
		}
	})

	t.Run("a HELD lock is a live run and is left alone", func(t *testing.T) {
		tmp := t.TempDir()
		t.Setenv("TMPDIR", tmp)
		live := plantRunDir(t, tmp, fmt.Sprintf("snug-%d-999998", uid), true)
		lock, err := os.OpenFile(filepath.Join(live, "lock"), os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatal(err)
		}

		sweepStaleEngineRunDirs()

		if !exists(t, live) {
			t.Fatalf("the sweep removed %s while its lock was HELD — that is a live sibling's "+
				"run directory, and removing it takes its engine socket and generated config "+
				"with it", live)
		}
	})

	t.Run("no lock file is left alone: nobody has claimed it yet", func(t *testing.T) {
		tmp := t.TempDir()
		t.Setenv("TMPDIR", tmp)
		unclaimed := plantRunDir(t, tmp, fmt.Sprintf("snug-%d-999997", uid), false)

		sweepStaleEngineRunDirs()

		if !exists(t, unclaimed) {
			t.Fatalf("the sweep removed %s, which has no lock file. lockEngineRunDir writes the "+
				"lock FIRST, so a directory without one is a run mid-creation, and removing it "+
				"destroys a live run's directory a few microseconds before it is used", unclaimed)
		}
	})
}

// TestSweepClaimsOnlyThePerRunNameShape pins the prefix against the two OTHER
// snug-owned name shapes that share os.TempDir(). Both are reclaimed by
// something else, so a looser prefix here would have this sweep deleting
// another mechanism's state — and in the runroot's case, a store keyed by
// sha256(target) that is shared across runs in time.
func TestSweepClaimsOnlyThePerRunNameShape(t *testing.T) {
	uid := os.Getuid()
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	// The per-uid RUNTIME directory, which is what internal/cli's runtimeBase
	// falls back to when $XDG_RUNTIME_DIR is unset. sweepStaleRunDirs owns it
	// and sweeps one level further down; the run dirs inside it carry locks, so
	// without the trailing dash this sweep would remove the whole thing.
	runtimeDir := plantRunDir(t, tmp, fmt.Sprintf("snug-%d", uid), true)

	// The per-TARGET runroot (paths.go). Not per-run state: keyed by
	// sha256(target), shared across runs in time, reclaimed by `snug engine gc`.
	runroot := plantRunDir(t, tmp, fmt.Sprintf("snug-engines-%d-sha256_deadbeef", uid), true)

	// The positive control, so a prefix that matches NOTHING cannot pass this
	// test: this one must go.
	stale := plantRunDir(t, tmp, fmt.Sprintf("snug-%d-999996", uid), true)

	sweepStaleEngineRunDirs()

	if !exists(t, runtimeDir) {
		t.Errorf("the sweep removed %s — that is internal/cli's own runtime directory, and the "+
			"trailing dash in engineRunDirPrefix is what separates them", runtimeDir)
	}
	if !exists(t, runroot) {
		t.Errorf("the sweep removed %s — that is the per-target runroot, keyed by sha256(target) "+
			"and shared across runs in time, not this run's own directory", runroot)
	}
	if exists(t, stale) {
		t.Fatalf("CONTROL FAILED: the sweep removed neither the two it must keep nor %s, which it "+
			"must remove — so this test proves nothing about the prefix", stale)
	}
}

// TestStopRemovesTheRunDirectory is the other half of #425's first bullet: the
// path snug DOES control. The sweep exists for SIGKILL; Stop is what makes the
// ordinary path leave nothing behind, and nothing asserted it.
func TestStopRemovesTheRunDirectory(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}
	runDir := e.runDir
	if !exists(t, runDir) {
		t.Fatalf("New did not create %s", runDir)
	}
	if !exists(t, filepath.Join(runDir, "lock")) {
		t.Fatalf("New created %s without a lock file — the sweep's liveness test is that file, "+
			"so a run directory without one can never be reclaimed after a SIGKILL", runDir)
	}

	e.Stop()

	if exists(t, runDir) {
		t.Fatalf("Stop left %s behind. It holds this run's engine socket and generated config, "+
			"and a directory snug could not clean up is state that survives the user "+
			"(invariant 4)", runDir)
	}
}
