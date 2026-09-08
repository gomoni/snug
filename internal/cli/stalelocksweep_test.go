package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	leftover := targetStateName(target, os.Getpid()) + ".tmp-999999"
	starting := initStateName(target, os.Getpid()) + ".tmp-999998"
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
	leftover := targetStateName(target, os.Getpid()) + ".tmp-999999"
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

// End to end: liveness survives the lock file being swept — the sweep does not
// take a HELD lock's file, the name is lockable again afterwards, and the
// EXCLUSIVE arm `snug engine gc` reclaims through still refuses while a run
// holds the target shared.
//
// The last assertion is the one that would rot silently. Runs no longer exclude
// each other, so "a second acquisition is refused" is only true of the
// exclusive arm, and if that arm ever became shared too the reclaim would
// proceed under a live engine with nothing failing.
//
// What this case does NOT pin is the retry inside openAndHoldTargetLock: the
// interleaving that needs it (open, then a sweep, then the flock) happens
// between two statements of that function and there is no seam to drive it
// from a test. Its kernel premise is pinned by the case above instead —
// flock succeeds on the swept descriptor, and Nlink is the only thing that
// says so.
func TestLivenessSurvivesTheLockFileBeingSwept(t *testing.T) {
	dir, root := stateDirForTest(t)
	target := "/tmp/a-target-locked-across-a-sweep"
	name := targetLockName(target)

	first, err := openAndHoldTargetLock(root, dir, name, target, unix.LOCK_SH)
	if err != nil {
		t.Fatal(err)
	}
	sweepOrphanedSandboxesIn(root, dir) // must not touch a held lock
	if _, serr := os.Stat(filepath.Join(dir, name)); serr != nil {
		t.Fatalf("the sweep removed the held lock: %v", serr)
	}

	// A second RUN on the same target, while the first still holds it.
	alongside, err := openAndHoldTargetLock(root, dir, name, target, unix.LOCK_SH)
	if err != nil {
		t.Fatalf("a second run could not take the target lock beside the first: %v", err)
	}

	// `snug engine gc`'s arm, against those two live runs.
	reclaim, err := openAndHoldTargetLock(root, dir, name, target, unix.LOCK_EX)
	if err == nil {
		reclaim.Close()
		t.Fatal("the exclusive arm acquired a target two runs were holding — `snug engine gc` " +
			"would reclaim a store under a live engine")
	}
	var busy *targetBusyError
	if !errors.As(err, &busy) {
		t.Errorf("the exclusive acquisition failed with %v, not the liveness sentinel", err)
	}

	alongside.Close()
	first.Close() // both runs end

	sweepOrphanedSandboxesIn(root, dir)

	second, err := openAndHoldTargetLock(root, dir, name, target, unix.LOCK_SH)
	if err != nil {
		t.Fatalf("a target whose lock file was swept could not be locked again: %v", err)
	}
	second.Close()
}

// F6's case, from a redteam round: the whole `.tmp-` cleanup used to hang off
// a `.lock` the same pass deletes, so a leftover whose lock file was already
// swept survived every later sweep. Nothing can be writing one — producing a
// `.tmp-` requires holding a lock file that does not exist — so it is
// collectable on its own.
func TestSweepRemovesAnInterruptedWriteWithNoLockFileBesideIt(t *testing.T) {
	dir, root := stateDirForTest(t)
	target := "/tmp/a-target-whose-lock-was-already-swept"
	leftover := targetStateName(target, os.Getpid()) + ".tmp-999999"
	if err := os.WriteFile(filepath.Join(dir, leftover), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sweepOrphanedSandboxesIn(root, dir)

	if _, err := os.Stat(filepath.Join(dir, leftover)); !os.IsNotExist(err) {
		t.Errorf("an interrupted write with no lock file beside it survived the sweep (err=%v); "+
			"it was unreachable because the cleanup hung off a lock the same pass deletes", err)
	}
}

// An flock says nothing about the NAME: it is held on the open file
// description, and the directory entry that produced it can be renamed over
// while the lock is held. A redteam round turned that into an unlink of a LIVE
// run's lock — hardlink the file, let the sweep lock it, swap the name, and
// `Nlink > 0` still reads 1. st_dev/st_ino is what separates the two.
func TestTheSweepWillNotUnlinkANameItDidNotLock(t *testing.T) {
	dir, root := stateDirForTest(t)
	name := targetLockName("/tmp/a-target-whose-name-gets-swapped")
	if err := os.WriteFile(filepath.Join(dir, name), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	locked, err := root.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Close()

	// CONTROL first: unswapped, the name is the file, and a sweep may unlink.
	if !nameStillNames(root, name, locked) {
		t.Fatal("control failed: an untouched name did not resolve to the file opened from it")
	}

	// The swap. The hardlink is what keeps the locked inode's Nlink above
	// zero once the name stops pointing at it, so stillLinked cannot see this.
	if err := os.Link(filepath.Join(dir, name), filepath.Join(dir, "pin")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "impostor")
	if err := os.WriteFile(other, []byte("2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}

	if linked, lerr := stillLinked(locked); lerr != nil || !linked {
		t.Fatalf("the premise of this test is that Nlink cannot see the swap: linked=%v err=%v", linked, lerr)
	}
	if nameStillNames(root, name, locked) {
		t.Error("the sweep would have unlinked a name it never locked — a live run's lock file, " +
			"if that is what now carries the name")
	}
}

// The lock file's CONTENT is nothing, and this pins that it stays nothing.
//
// It used to carry the holder's decimal pid, for a refusal message that named
// who was in the way. The pid was written once and never cleared, so a lock
// file left by a run that had since exited still carried it, and a redteam
// round printed `held by: snug (pid 999999)` for a corpse. There is no refusal
// left to name anybody — a target may have several holders and none of them
// excludes a run — so the write is gone, and an empty file is what makes the
// corpse unreachable rather than a liveness check on the number.
func TestTheTargetLockFileCarriesNoPID(t *testing.T) {
	useTargetLockBase(t)
	target := t.TempDir()
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}

	unlock, err := lockTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	base, snugName, err := targetLockBase()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, snugName, targetLockName(real))
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the lock file a live run holds is not readable: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("the target lock file carries %q. Its content is read by nothing and identifies "+
			"one holder of several; the flock is the whole signal.", body)
	}
}

// sweepOneStaleLock takes LOCK_EX on every unheld lock file it finds, so a
// concurrently starting snug's sweep blocks an acquiring run for the length of
// an fstat and an unlink. A redteam round measured one spurious refusal in 3413
// acquisitions across 401 lock files. The retry waits that window out.
//
// The margin is 6x: the holder below releases after 1 ms and the retry budget
// is three sleeps of targetLockRetryDelay.
func TestABriefHolderIsWaitedOutRatherThanRefused(t *testing.T) {
	snugDir := useTargetLockBase(t)
	if err := os.MkdirAll(snugDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(snugDir, targetLockName(real))
	held, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if ferr := unix.Flock(int(held.Fd()), unix.LOCK_EX|unix.LOCK_NB); ferr != nil {
		t.Fatal(ferr)
	}
	go func() {
		time.Sleep(time.Millisecond)
		_ = unix.Flock(int(held.Fd()), unix.LOCK_UN)
		held.Close()
	}()

	unlock, lerr := lockTarget(target)
	if lerr != nil {
		t.Fatalf("a lock held for 1 ms was refused as a live run: %v", lerr)
	}
	unlock()
}
