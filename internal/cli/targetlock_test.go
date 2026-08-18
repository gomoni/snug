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
	useTargetLockBase(t)
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
	useTargetLockBase(t)
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
	useTargetLockBase(t)
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

// TestTargetLockReclaimsAfterHolderKilled is the stale-holder case #119 must
// handle without wedging a directory: a SIGKILLed run releases its flock (the
// kernel does it), so the next run reclaims the lock.
//
// CONTROL: while the holder is ALIVE, lockTarget is refused — so the reclaim
// after the kill is genuinely a reclaim and not "always succeed". The holder
// is a subprocess that inherits the locked descriptor and is killed by its
// exact pid only, never by name.
func TestTargetLockReclaimsAfterHolderKilled(t *testing.T) {
	snugDir := useTargetLockBase(t)
	dir := t.TempDir()

	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Seed the exact lock file lockTarget will compute, hold its flock, and
	// hand the descriptor to a sleeping child. Closing our own copy leaves the
	// child as the sole holder.
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
// $XDG_RUNTIME_DIR/$TMPDIR, so a holder in an interactive shell (variable set)
// and a contender under cron/systemd/ssh (variable unset, or a different
// $TMPDIR) land on the SAME lock inode and the contender is refused.
//
// On the pre-fix code the target lock lived under runtimeBase(), which reads
// $XDG_RUNTIME_DIR then $TMPDIR: the holder and the contender resolved two
// different inodes, both flocks succeeded, and two sandboxes ran on one target.
//
// CONTROL: a same-env second run is ALREADY refused (see
// TestTargetLockRefusesASecondRunOnTheSameDirectory), so a bare "refused" does
// not distinguish "refused because #122 is fixed" from "refused anyway". This
// test forces the two runs to see DIFFERENT env and asserts the refusal
// survives that difference — which only the uid-derived base can deliver.
func TestTargetLockDirectoryIsIndependentOfXDGRuntimeDir(t *testing.T) {
	dir := t.TempDir()

	// Two env shapes that pre-fix resolved to different lock inodes:
	//   holder    — $XDG_RUNTIME_DIR set (interactive shell)
	//   contender — $XDG_RUNTIME_DIR unset, $TMPDIR pointed elsewhere (cron/ssh)
	// The uid-derived base ignores both, so both must resolve the same inode.
	assertRefusedAcrossEnv := func(t *testing.T, holderEnv, contenderEnv func(*testing.T)) {
		t.Helper()
		useTargetLockBase(t)

		holderEnv(t)
		unlock, err := lockTarget(dir)
		if err != nil {
			t.Fatalf("holder lockTarget failed: %v", err)
		}
		defer unlock()

		contenderEnv(t)
		_, err = lockTarget(dir)
		var busy *targetBusyError
		if err == nil {
			t.Fatal("contender acquired a SECOND lock on the same target under different " +
				"env — the target lock split across two inodes (issue #122 fail-OPEN)")
		}
		if !asTargetBusy(err, &busy) {
			t.Fatalf("contender was refused for the wrong reason: %v", err)
		}
	}

	t.Run("XDG set for holder, unset for contender", func(t *testing.T) {
		assertRefusedAcrossEnv(t,
			func(t *testing.T) { t.Setenv("XDG_RUNTIME_DIR", t.TempDir()) },
			func(t *testing.T) { os.Unsetenv("XDG_RUNTIME_DIR") },
		)
	})

	t.Run("XDG unset for both, differing TMPDIR", func(t *testing.T) {
		assertRefusedAcrossEnv(t,
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
