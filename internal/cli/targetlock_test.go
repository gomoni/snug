package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// liveOnTarget is what every test below asserts through, because it is the
// only question the target lock is asked in production: sweepOneOrphan and
// `snug engine gc` both want "is any run live on this directory", and both get
// it by asking for LOCK_EX and reading EWOULDBLOCK as yes.
//
// It resolves the target itself, so a test may pass a symlink and get the same
// answer lockTarget would give — that identity is the whole subject of one of
// the tests below.
func liveOnTarget(t *testing.T, target string) bool {
	t.Helper()
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatalf("resolving %s: %v", target, err)
	}
	base, snugName, err := targetLockBase()
	if err != nil {
		t.Fatal(err)
	}
	snugPath := filepath.Join(base, snugName)
	if err := os.MkdirAll(snugPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(snugPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	held, err := targetLockIsHeld(root, snugPath, real)
	if err != nil {
		t.Fatalf("probing the target lock for %s: %v", real, err)
	}
	return held
}

// TestTargetLockAdmitsASecondRunOnTheSameDirectory is the rule: a second
// sandbox on one target is a supported shape, so the run lock is SHARED and
// two runs coexist.
//
// The CONTROL is the half that makes this a test rather than an assertion that
// nothing is locked at all: while both runs hold the lock, the exclusive probe
// every reader uses must still say a run is live, and once both release it must
// say the target is idle. A lock nobody ever takes would pass the first
// assertion and fail these two.
func TestTargetLockAdmitsASecondRunOnTheSameDirectory(t *testing.T) {
	useTargetLockBase(t)
	dir := t.TempDir()

	if liveOnTarget(t, dir) {
		t.Fatal("precondition: a target nothing has run on read as live")
	}

	unlock1, err := lockTarget(dir)
	if err != nil {
		t.Fatalf("first lockTarget failed: %v", err)
	}
	if unlock1 == nil {
		t.Fatal("first lockTarget returned a nil unlock — the lock is not held")
	}

	// A second acquisition in this same process, from a second open file
	// description. Under the exclusive lock this used to be refused precisely
	// BECAUSE flock is per-OFD, so this call is unchanged and only its expected
	// outcome flipped.
	unlock2, err := lockTarget(dir)
	if err != nil {
		t.Fatalf("a second run on the same directory was refused: %v\nTwo sandboxes on one "+
			"target is the supported shape; the run lock is shared for exactly this.", err)
	}

	if !liveOnTarget(t, dir) {
		t.Fatal("two runs held the target lock and the liveness probe said the target was idle. " +
			"That answer is what licenses the orphan sweep to SIGKILL a run's init.")
	}

	unlock1()
	if !liveOnTarget(t, dir) {
		t.Fatal("one run still held the target lock and the liveness probe said idle")
	}
	unlock2()
	if liveOnTarget(t, dir) {
		t.Fatal("every holder released and the target still read as live — the probe is stuck " +
			"saying yes, so the assertions above prove nothing")
	}
}

// TestTargetLockIsPerTargetNotGlobal proves the lock is keyed on the target,
// not a process- or host-wide mutex: a run on one directory must not make a
// DIFFERENT directory read as live.
func TestTargetLockIsPerTargetNotGlobal(t *testing.T) {
	useTargetLockBase(t)
	a := t.TempDir()
	b := t.TempDir()

	unlockA, err := lockTarget(a)
	if err != nil {
		t.Fatalf("lockTarget(a) failed: %v", err)
	}
	defer unlockA()

	if !liveOnTarget(t, a) {
		t.Fatal("the locked target did not read as live")
	}
	if liveOnTarget(t, b) {
		t.Fatal("an unrelated directory read as live while another target was locked — the " +
			"lock is not per-target")
	}
}

// TestTargetLockTreatsASymlinkAsTheSameTarget is the realpath identity: a run
// locked through a symlink and a reader asking about the real path must land on
// one inode, or the sweep looks at a lock no run holds and kills a live init.
//
// CONTROL: an unrelated directory still reads as idle, so the positive is the
// shared realpath and not "everything reads as live".
func TestTargetLockTreatsASymlinkAsTheSameTarget(t *testing.T) {
	useTargetLockBase(t)
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	unlock, err := lockTarget(link)
	if err != nil {
		t.Fatalf("lockTarget through a symlink failed: %v", err)
	}
	defer unlock()

	if !liveOnTarget(t, real) {
		t.Fatal("a run locked through a symlink was invisible to a reader asking about the real " +
			"path — the two resolved different lock inodes")
	}

	other := t.TempDir()
	if liveOnTarget(t, other) {
		t.Fatal("control: an unrelated directory read as live")
	}
}

// TestTargetLockNonexistentTargetIsNotLocked: a target that cannot be
// canonicalised (it does not exist yet) is not locked — lockTarget returns a
// no-op unlock and no error, leaving policy.Resolve to report the missing
// directory.
func TestTargetLockNonexistentTargetIsNotLocked(t *testing.T) {
	useTargetLockBase(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	unlock, err := lockTarget(missing)
	if err != nil {
		t.Fatalf("lockTarget on a missing target returned an error: %v", err)
	}
	if unlock == nil {
		t.Fatal("lockTarget returned a nil unlock for a missing target")
	}
	unlock() // must be a safe no-op
}

// TestTargetIsIdleAfterHolderKilled is the stale-holder case: a SIGKILLed run
// releases its flock (the kernel does it), so the target stops reading as live
// and the orphan sweep may clean up after it. Without this the sweep would be
// wedged out of every directory a killed run ever touched, which is the
// accumulation invariant 4 exists against.
//
// CONTROL: while the holder is ALIVE the target reads as live — so the idle
// answer after the kill is genuinely the release and not "always idle". The
// holder is a subprocess that inherits the locked descriptor and is killed by
// its exact pid only, never by name.
func TestTargetIsIdleAfterHolderKilled(t *testing.T) {
	snugDir := useTargetLockBase(t)
	dir := t.TempDir()

	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Seed the exact lock file lockTarget will compute, hold its flock SHARED
	// — the mode a run uses — and hand the descriptor to a sleeping child.
	// Closing our own copy leaves the child as the sole holder.
	if err := os.MkdirAll(snugDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(snugDir, targetLockName(real))
	held, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(held.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatalf("seeding the held lock: %v", err)
	}

	cmd := exec.Command("sleep", "30")
	cmd.ExtraFiles = []*os.File{held}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the holder process: %v", err)
	}
	held.Close() // the child's inherited copy now keeps the flock

	killed := false
	killAndWait := func() {
		if killed {
			return
		}
		killed = true
		// cmd.Process.Kill on a child this test has not yet Wait()ed: it stays
		// a zombie holding its number until reaped, so the signal cannot land
		// on a stranger.
		cmd.Process.Kill()
		cmd.Wait()
	}
	t.Cleanup(killAndWait)

	if !liveOnTarget(t, dir) {
		t.Fatal("a live shared holder did not read as live")
	}

	killAndWait()
	if liveOnTarget(t, dir) {
		t.Fatal("a target whose only holder was killed still read as live — the sweep is wedged " +
			"out of this directory forever")
	}
}

// asTargetBusy wraps errors.As to keep an assertion terse. targetBusyError is
// no longer produced for a run — it is `snug engine gc`'s liveness sentinel
// from openAndHoldTargetLock's exclusive arm.
func asTargetBusy(err error, target **targetBusyError) bool {
	return errors.As(err, target)
}

// useTargetLockBase points targetLockBase's canonical per-uid runtime directory
// at a fresh scratch directory for the duration of a test, so the lock is taken
// there rather than in the host's real /run/user/<uid>. It returns the snug-
// owned subdirectory path (base/snug), where a test that seeds a held lock by
// hand must place it. The override is env-INDEPENDENT on purpose: it is the
// same directory no matter what $XDG_RUNTIME_DIR or $TMPDIR say, which is the
// property issue #122 is about.
func useTargetLockBase(t *testing.T) (snugDir string) {
	t.Helper()
	base := t.TempDir()
	prev := canonicalRuntimeDir
	canonicalRuntimeDir = func(int) string { return base }
	t.Cleanup(func() { canonicalRuntimeDir = prev })
	return filepath.Join(base, "snug")
}

// TestTargetLockDirectoryIsIndependentOfXDGRuntimeDir is issue #122: the
// per-target lock's directory must be resolved from the uid, not from
// $XDG_RUNTIME_DIR/$TMPDIR, so a run in an interactive shell (variable set) and
// a reader under cron/systemd/ssh (variable unset, or a different $TMPDIR) land
// on the SAME lock inode.
//
// On the pre-fix code the target lock lived under runtimeBase(), which reads
// $XDG_RUNTIME_DIR then $TMPDIR: the two resolved different inodes. Under the
// exclusive lock that was a fail-OPEN of the one-sandbox-per-target rule. Under
// the shared lock the consequence is sharper, not gone: the reader is the
// orphan sweep, and a live run it cannot see is a live run whose init it
// SIGKILLs.
//
// CONTROL: the same reader, under the same environment, must say a DIFFERENT
// target is idle — otherwise "live" is what this probe says about everything.
func TestTargetLockDirectoryIsIndependentOfXDGRuntimeDir(t *testing.T) {
	dir := t.TempDir()
	idle := t.TempDir()

	assertVisibleAcrossEnv := func(t *testing.T, runEnv, readerEnv func(*testing.T)) {
		t.Helper()
		useTargetLockBase(t)

		runEnv(t)
		unlock, err := lockTarget(dir)
		if err != nil {
			t.Fatalf("lockTarget failed: %v", err)
		}
		defer unlock()

		readerEnv(t)
		if !liveOnTarget(t, dir) {
			t.Fatal("a run locked under one environment was invisible to a reader under " +
				"another — the target lock split across two inodes (issue #122)")
		}
		if liveOnTarget(t, idle) {
			t.Fatal("control: a target with no run read as live, so the assertion above is " +
				"not discriminating")
		}
	}

	t.Run("XDG set for the run, unset for the reader", func(t *testing.T) {
		assertVisibleAcrossEnv(t,
			func(t *testing.T) { t.Setenv("XDG_RUNTIME_DIR", t.TempDir()) },
			func(t *testing.T) { os.Unsetenv("XDG_RUNTIME_DIR") },
		)
	})

	t.Run("XDG unset for both, differing TMPDIR", func(t *testing.T) {
		assertVisibleAcrossEnv(t,
			func(t *testing.T) {
				os.Unsetenv("XDG_RUNTIME_DIR")
				t.Setenv("TMPDIR", t.TempDir())
			},
			func(t *testing.T) {
				os.Unsetenv("XDG_RUNTIME_DIR")
				t.Setenv("TMPDIR", t.TempDir())
			},
		)
	})
}
