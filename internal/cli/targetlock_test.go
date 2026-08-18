package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestTargetLockRefusesASecondRunOnTheSameDirectory is issue #119's core: one
// live run holds the per-target lock, a second run on the SAME directory is
// refused with a message that names `snug attach`, and once the first releases
// the lock a third run may take it.
//
// CONTROL: the first lock must actually be held — that is the only reason the
// second is refused — and the third acquisition after release proves the
// refusal was the lock, not some unrelated breakage.
func TestTargetLockRefusesASecondRunOnTheSameDirectory(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	dir := t.TempDir()

	unlock1, err := lockTarget(dir)
	if err != nil {
		t.Fatalf("first lockTarget failed: %v", err)
	}
	if unlock1 == nil {
		t.Fatal("first lockTarget returned a nil unlock — the lock is not held")
	}

	// A second acquisition in this same process contends with the first: flock
	// locks are per open file description, so a second open+flock of the same
	// file blocks even from the same pid.
	_, err = lockTarget(dir)
	var busy *targetBusyError
	if err == nil {
		t.Fatal("second lockTarget on the same directory was NOT refused")
	}
	if !asTargetBusy(err, &busy) {
		t.Fatalf("second lockTarget failed for the wrong reason: %v", err)
	}
	msg := busy.message(dir)
	if !strings.Contains(msg, "snug attach") {
		t.Errorf("refusal does not name `snug attach`: %q", msg)
	}
	if busy.holder != os.Getpid() {
		t.Errorf("refusal named holder pid %d, want this process %d", busy.holder, os.Getpid())
	}

	// Release, then a third acquisition must succeed: proves the refusal above
	// was really the held lock.
	unlock1()
	unlock3, err := lockTarget(dir)
	if err != nil {
		t.Fatalf("third lockTarget after release failed: %v", err)
	}
	unlock3()
}

// TestTargetLockIsPerTargetNotGlobal proves the lock is keyed on the target,
// not a process- or host-wide mutex: two DIFFERENT directories both acquire at
// the same time.
func TestTargetLockIsPerTargetNotGlobal(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	a := t.TempDir()
	b := t.TempDir()

	unlockA, err := lockTarget(a)
	if err != nil {
		t.Fatalf("lockTarget(a) failed: %v", err)
	}
	defer unlockA()

	unlockB, err := lockTarget(b)
	if err != nil {
		t.Fatalf("lockTarget(b) failed while a different directory was locked — the lock is not per-target: %v", err)
	}
	defer unlockB()
}

// TestTargetLockTreatsASymlinkAsTheSameTarget is the realpath identity: a
// symlink to a locked directory is refused as the same target.
//
// CONTROL: an unrelated directory still acquires, so the refusal is the shared
// realpath and not "everything is refused".
func TestTargetLockTreatsASymlinkAsTheSameTarget(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	unlock, err := lockTarget(real)
	if err != nil {
		t.Fatalf("lockTarget(real) failed: %v", err)
	}
	defer unlock()

	_, err = lockTarget(link)
	var busy *targetBusyError
	if err == nil || !asTargetBusy(err, &busy) {
		t.Fatalf("a symlink to the locked target was not refused as the same target: %v", err)
	}

	// CONTROL: an unrelated directory still acquires.
	other := t.TempDir()
	unlockOther, err := lockTarget(other)
	if err != nil {
		t.Fatalf("control: an unrelated directory was refused: %v", err)
	}
	unlockOther()
}

// TestTargetLockNonexistentTargetIsNotLocked: a target that cannot be
// canonicalised (it does not exist yet) is not locked — lockTarget returns a
// no-op unlock and no error, leaving policy.Resolve to report the missing
// directory.
func TestTargetLockNonexistentTargetIsNotLocked(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
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

// TestTargetLockReclaimsAfterHolderKilled is the stale-holder case #119 must
// handle without wedging a directory: a SIGKILLed run releases its flock (the
// kernel does it), so the next run reclaims the lock.
//
// CONTROL: while the holder is ALIVE, lockTarget is refused — so the reclaim
// after the kill is genuinely a reclaim and not "always succeed". The holder
// is a subprocess that inherits the locked descriptor and is killed by its
// exact pid only, never by name.
func TestTargetLockReclaimsAfterHolderKilled(t *testing.T) {
	runtimeBaseDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeBaseDir)
	dir := t.TempDir()

	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Seed the exact lock file lockTarget will compute, hold its flock, and
	// hand the descriptor to a sleeping child. Closing our own copy leaves the
	// child as the sole holder.
	snugDir := filepath.Join(runtimeBaseDir, "snug")
	if err := os.MkdirAll(snugDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(snugDir, targetLockName(real))
	held, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(held.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
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
		cmd.Process.Kill()
		cmd.Wait()
	}
	t.Cleanup(killAndWait)

	// CONTROL: the holder is alive, so lockTarget must be refused.
	_, err = lockTarget(dir)
	var busy *targetBusyError
	if err == nil || !asTargetBusy(err, &busy) {
		t.Fatalf("lockTarget was not refused while a live holder existed: %v", err)
	}

	// Kill the holder; its flock is released by the kernel. The next run must
	// reclaim the lock rather than being wedged.
	killAndWait()
	unlock, err := lockTarget(dir)
	if err != nil {
		t.Fatalf("lockTarget did not reclaim a lock whose holder was killed — the directory is wedged: %v", err)
	}
	unlock()
}

// asTargetBusy wraps errors.As to keep the assertions above terse.
func asTargetBusy(err error, target **targetBusyError) bool {
	return errors.As(err, target)
}
