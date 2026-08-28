package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// The per-target lock file and the leftover of an interrupted state write
// were created by every run and removed by nobody: 738 lock files and one
// `target-<hash>.json.tmp-<pid>` were measured in one development box's
// $XDG_RUNTIME_DIR/snug against 2 live records. Invariant 4 says a run leaves
// nothing behind, and these tests assert BOTH halves of that — what the sweep
// removes and what it must never touch — because a sweep that removed every
// lock file would pass any test that only counted survivors.

func TestSweepRemovesATargetLockNobodyHolds(t *testing.T) {
	dir, root := stateDirForTest(t)
	target := "/tmp/a-target-whose-run-is-over"
	name := targetLockName(target)
	if err := os.WriteFile(filepath.Join(dir, name), []byte("4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sweepOrphanedSandboxesIn(root, dir)

	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Errorf("the unheld target lock %s survived the sweep (err=%v); nothing else ever "+
			"removed one, which is how one box reached 738", name, err)
	}
}

// THE CONTROL. A live run holds this lock for its whole life, and its removal
// while it is held would let a second run on the same target create a fresh
// inode and acquire it — issues #119 and #122, arrived at from inside the
// cleanup path.
func TestSweepKeepsATargetLockALiveRunHolds(t *testing.T) {
	dir, root := stateDirForTest(t)
	target := "/tmp/a-target-with-a-live-run"
	holdTargetLock(t, dir, target)

	sweepOrphanedSandboxesIn(root, dir)

	if _, err := os.Stat(filepath.Join(dir, targetLockName(target))); err != nil {
		t.Errorf("the sweep removed a target lock that was HELD: %v", err)
	}
}

func TestSweepRemovesTheLeftoverOfAnInterruptedStateWrite(t *testing.T) {
	dir, root := stateDirForTest(t)
	target := "/tmp/a-target-whose-write-was-killed"
	// writeTargetFile removes only the temp name carrying its OWN pid, so a
	// write a SIGKILL interrupted leaves a name no later run can match.
	leftover := targetStateName(target) + ".tmp-999999"
	starting := initStateName(target) + ".tmp-999998"
	for _, n := range []string{targetLockName(target), leftover, starting} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	sweepOrphanedSandboxesIn(root, dir)

	for _, n := range []string{leftover, starting} {
		if _, err := os.Stat(filepath.Join(dir, n)); !os.IsNotExist(err) {
			t.Errorf("the interrupted write's leftover %s survived the sweep (err=%v)", n, err)
		}
	}
}

// The leftover goes only through a HELD lock, because the only thing that
// writes one is a process holding it: a live run mid-write must not have its
// temporary file removed underneath it.
func TestSweepKeepsAnInterruptedWriteWhoseTargetLockIsHeld(t *testing.T) {
	dir, root := stateDirForTest(t)
	target := "/tmp/a-target-mid-write"
	holdTargetLock(t, dir, target)
	leftover := targetStateName(target) + ".tmp-999999"
	if err := os.WriteFile(filepath.Join(dir, leftover), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sweepOrphanedSandboxesIn(root, dir)

	if _, err := os.Stat(filepath.Join(dir, leftover)); err != nil {
		t.Errorf("the sweep removed a temporary file while its target lock was HELD: %v", err)
	}
}

// The kernel fact the whole retry rests on, pinned rather than assumed: flock
// on a descriptor whose name has been unlinked succeeds EXACTLY as it does on
// a live one, so the lock alone cannot tell a fresh acquisition from a
// serialisation on an inode nothing points at. Nlink is what separates them.
func TestAnFlockSucceedsOnASweptLockFileAndNlinkSaysSo(t *testing.T) {
	dir, root := stateDirForTest(t)
	target := "/tmp/a-target-swept-mid-acquire"
	name := targetLockName(target)

	// The contender, mid-acquire: it has the file open and has not locked it.
	contender, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer contender.Close()

	// A concurrently starting snug's sweep gets the lock first and unlinks.
	sweepOneStaleLock(root, dir, name, nil)
	if _, serr := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(serr) {
		t.Fatalf("the fixture did not sweep the lock file: %v", serr)
	}

	if ferr := unix.Flock(int(contender.Fd()), unix.LOCK_EX|unix.LOCK_NB); ferr != nil {
		t.Fatalf("flock on the swept descriptor failed (%v); the retry in "+
			"openAndHoldTargetLock exists because it SUCCEEDS here", ferr)
	}
	linked, lerr := stillLinked(contender)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if linked {
		t.Error("stillLinked reported a swept lock file as linked; that is the only signal " +
			"openAndHoldTargetLock and targetLockIsHeld have that a sweep got there first")
	}
}

// End to end: one-sandbox-per-target survives its lock file being swept —
// the sweep does not take a HELD lock's file, and the name is lockable again
// afterwards with the busy refusal intact.
//
// What this case does NOT pin is the retry inside openAndHoldTargetLock: the
// interleaving that needs it (open, then a sweep, then the flock) happens
// between two statements of that function and there is no seam to drive it
// from a test. Its kernel premise is pinned by the case above instead —
// flock succeeds on the swept descriptor, and Nlink is the only thing that
// says so.
func TestOneRunPerTargetSurvivesTheLockFileBeingSwept(t *testing.T) {
	dir, root := stateDirForTest(t)
	target := "/tmp/a-target-locked-across-a-sweep"
	name := targetLockName(target)

	first, err := openAndHoldTargetLock(root, dir, name, target)
	if err != nil {
		t.Fatal(err)
	}
	sweepOrphanedSandboxesIn(root, dir) // must not touch a held lock
	if _, serr := os.Stat(filepath.Join(dir, name)); serr != nil {
		t.Fatalf("the sweep removed the held lock: %v", serr)
	}
	first.Close() // the run ends

	sweepOrphanedSandboxesIn(root, dir)

	second, err := openAndHoldTargetLock(root, dir, name, target)
	if err != nil {
		t.Fatalf("a target whose lock file was swept could not be locked again: %v", err)
	}
	defer second.Close()

	third, err := openAndHoldTargetLock(root, dir, name, target)
	if err == nil {
		third.Close()
		t.Fatal("two processes acquired the same target's lock after a sweep — the " +
			"one-sandbox-per-target guarantee (#119, #122) produced from inside the cleanup path")
	}
	var busy *targetBusyError
	if !errors.As(err, &busy) {
		t.Errorf("the second acquisition failed with %v, not the busy refusal that names `snug attach`", err)
	}
}
