package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The permanent regression tests for issue #489: a same-uid `rm` — or `mv` —
// of a live run's per-target lock file made the next run's sweep SIGKILL that
// run's sandbox init.
//
// Every case here satisfies all four of the sweep's original conditions on
// purpose. The lock is genuinely not held (there is no lock file at all,
// which is what the `rm` leaves behind), the record's name genuinely hashes
// its target, and the pid, start time and six namespace inodes genuinely name
// the victim. Under the code this file was written against, that is a kill.
// What must stop it is the one signal an unlink cannot detach: the owning
// snug's own process.

func TestSweepDoesNotKillALiveRunWhoseLockFileWasRemoved(t *testing.T) {
	dir, root := stateDirForTest(t)

	// The victim: a record whose owner is a REAL running process, and no lock
	// file beside it — exactly the state one `rm target-<hash>.lock` leaves.
	victim := liveProcess(t)
	owner := liveProcess(t)
	target := "/tmp/unlinked-lock-target"
	st := stateFor(target, victim)
	st.Owner = liveOwner(owner)
	writeState(t, dir, target, st)

	// THE CONTROL, in the same directory and the same sweep call: an ordinary
	// orphan whose owner is gone. Without it, "the victim survived" is
	// equally explained by a sweep that has stopped killing anything at all.
	control := liveProcess(t)
	controlTarget := "/tmp/unlinked-lock-control"
	writeStateFor(t, dir, controlTarget, control)

	sweepOrphanedSandboxesIn(root, dir)

	if !waitDead(control.pid, 5*time.Second) {
		t.Fatalf("control: the sweep did not kill pid %d, an ordinary orphan whose owner is "+
			"gone — a sweep that never ran would pass the assertion below too", control.pid)
	}
	settle()
	if !processAlive(victim.pid) {
		t.Errorf("the sweep killed pid %d although the snug that owns its run (pid %d) is "+
			"still running: issue #489, where one `rm` of the lock file detaches the flock "+
			"from the NAME and targetLockIsHeld then answers \"not held\" about a live run",
			victim.pid, owner.pid)
	}
	if _, err := os.Stat(filepath.Join(dir, targetStateName(target))); err != nil {
		t.Errorf("the sweep removed a live run's state file (err=%v): `snug attach` reads that "+
			"file, so removing it makes a running sandbox unreachable", err)
	}
}

// The `mv` half, which targetstate.go measured and which leaves no trail at
// all: the kernel appends " (deleted)" to /proc/<pid>/fd/N on an unlink and
// appends nothing on a rename. The sweep sees a lock file under a name whose
// hash matches nothing, and the record's own name reads as unlocked.
func TestSweepDoesNotKillALiveRunWhoseLockFileWasRenamed(t *testing.T) {
	dir, root := stateDirForTest(t)

	victim := liveProcess(t)
	owner := liveProcess(t)
	target := "/tmp/renamed-lock-target"
	st := stateFor(target, victim)
	st.Owner = liveOwner(owner)
	writeState(t, dir, target, st)

	holdTargetLock(t, dir, target)
	if err := os.Rename(filepath.Join(dir, targetLockName(target)),
		filepath.Join(dir, "decoy.lock")); err != nil {
		t.Fatal(err)
	}

	sweepOrphanedSandboxesIn(root, dir)

	settle()
	if !processAlive(victim.pid) {
		t.Errorf("the sweep killed pid %d after its lock file was RENAMED out from under it, "+
			"while the snug owning the run (pid %d) is still running (issue #489)",
			victim.pid, owner.pid)
	}
}

// Fail closed on a record that names no owner at all — one written by a snug
// older than the field, or one edited to remove it. The alternative is a fix
// defeated by deleting two lines of JSON.
func TestSweepDoesNotKillAnInitWhoseRecordNamesNoOwner(t *testing.T) {
	dir, root := stateDirForTest(t)

	victim := liveProcess(t)
	target := "/tmp/ownerless-target"
	st := stateFor(target, victim)
	st.Owner = stateOwner{}
	writeState(t, dir, target, st)

	control := liveProcess(t)
	controlTarget := "/tmp/ownerless-control"
	writeStateFor(t, dir, controlTarget, control)

	sweepOrphanedSandboxesIn(root, dir)

	if !waitDead(control.pid, 5*time.Second) {
		t.Fatalf("control: the sweep did not kill pid %d, an ordinary orphan in the same "+
			"directory", control.pid)
	}
	settle()
	if !processAlive(victim.pid) {
		t.Errorf("the sweep killed pid %d on a record carrying no owner: an owner it cannot "+
			"confirm must read as alive, or stripping the field restores issue #489", victim.pid)
	}
	if _, err := os.Stat(filepath.Join(dir, targetStateName(target))); err != nil {
		t.Errorf("the record was removed (err=%v): nothing else on the host names that init, "+
			"and deleting the record is issue #236's accumulation from inside the cleanup path", err)
	}
}

// The ".starting" record reaches the same killOrphanInit through a different
// reader, so the gate has to be in the record it builds too.
func TestStartingSweepDoesNotKillALiveRunWhoseLockFileWasRemoved(t *testing.T) {
	dir, root := stateDirForTest(t)

	victim := liveProcess(t)
	owner := liveProcess(t)
	target := "/tmp/starting-unlinked-target"
	writeInitStateAt(t, dir, target, initState{
		Schema:        initStateSchema,
		Target:        target,
		InitPID:       victim.pid,
		InitStarttime: victim.starttime,
		Namespaces:    victim.namespaces,
		Owner:         liveOwner(owner),
	})

	sweepOrphanedSandboxesIn(root, dir)

	settle()
	if !processAlive(victim.pid) {
		t.Errorf("the sweep killed pid %d named by a \".starting\" record whose owning snug "+
			"(pid %d) is still running (issue #489)", victim.pid, owner.pid)
	}
}

func TestOwnerProvablyGoneVerdicts(t *testing.T) {
	self, err := currentOwner()
	if err != nil {
		t.Fatal(err)
	}
	if ownerProvablyGone(self) {
		t.Errorf("ownerProvablyGone said this very process is gone: %+v", self)
	}
	recycled := self
	recycled.Starttime++
	if !ownerProvablyGone(recycled) {
		t.Errorf("a pid whose recorded start time does not match the process holding the "+
			"number now is a RECYCLED number, so the owner it named is gone: %+v", recycled)
	}
	if ownerProvablyGone(stateOwner{}) {
		t.Error("an empty owner record cannot be confirmed either way, so it must read as " +
			"alive — the kill fails closed")
	}
	if ownerProvablyGone(stateOwner{PID: 1, Starttime: 1}) {
		t.Error("pid 1 is never a snug that owned a run; it must not license a kill")
	}
	stopped := spawnAndReap(t)
	if !ownerProvablyGone(stopped) {
		t.Errorf("a process that has exited and been reaped must read as gone: %+v", stopped)
	}
}

// spawnAndReap is a run owner that really did exit: started, its identity read
// while it was still there, then killed and WAITED FOR, so no zombie survives
// to answer for it. The reap matters — the kernel releases an flock at exit
// and not at reap, so ownerProvablyGone treats a zombie as gone too, and a
// fixture that left one behind would not be testing this arm.
func spawnAndReap(t *testing.T) stateOwner {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	start, err := procStartTime(pid)
	if err != nil {
		t.Fatal(err)
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	return stateOwner{PID: pid, Starttime: start}
}

// writeInitStateAt puts a ".starting" record on disk the way a run that never
// reached state.json leaves one, at the name initStateName derives.
func writeInitStateAt(t *testing.T, dir, target string, st initState) {
	t.Helper()
	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, initStateName(target)), append(blob, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
