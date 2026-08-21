package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The sweep kills a process. That is the whole reason these tests exist in
// this shape: every case below spawns a REAL process, and each asserts both
// halves — what must die and what must not — because a sweep that killed
// nothing would pass any test that only checked for survivors, and one that
// killed everything would pass any test that only checked for corpses.
//
// The four conditions are tested one at a time, each with the OTHER three
// satisfied, so a passing case cannot be passing for a neighbour's reason.
func TestSweepKillsAnOrphanedInitWhoseRunIsGone(t *testing.T) {
	dir, root := stateDirForTest(t)
	victim := liveProcess(t)
	writeStateFor(t, dir, "/tmp/orphaned-target", victim)

	sweepOrphanedSandboxesIn(root, dir)

	if !waitDead(victim.pid, 5*time.Second) {
		t.Errorf("the sweep left pid %d alive: its target lock was not held, so its run is "+
			"gone and it is exactly what issue #236 accumulates", victim.pid)
	}
	if _, err := os.Stat(filepath.Join(dir, targetStateName("/tmp/orphaned-target"))); !os.IsNotExist(err) {
		t.Errorf("the stale state file survived the sweep (err=%v). Nothing else removes it: a "+
			"state file is published per run and was removed by nobody, which is how one "+
			"development box reached 1099 of them", err)
	}
}

// THE CONTROL THAT MATTERS. A live run holds its per-target lock for its whole
// life, and the sweep must never touch it. Without this case the test above is
// satisfied by a sweep that kills every init it can find, which is the version
// of this feature that must never ship.
func TestSweepLeavesALiveRunAlone(t *testing.T) {
	dir, root := stateDirForTest(t)
	victim := liveProcess(t)
	target := "/tmp/live-target"
	writeStateFor(t, dir, target, victim)
	holdTargetLock(t, dir, target)

	sweepOrphanedSandboxesIn(root, dir)

	settle()
	if !processAlive(victim.pid) {
		t.Fatalf("the sweep killed pid %d while its target lock was HELD — that is a live "+
			"sandbox, and the lock is the same fact `snug <dir>`'s refusal and `snug attach`'s "+
			"liveness check read", victim.pid)
	}
	if _, err := os.Stat(filepath.Join(dir, targetStateName(target))); err != nil {
		t.Errorf("the sweep removed a LIVE run's state file (err=%v) — `snug attach` reads that "+
			"file, so removing it makes a running sandbox unreachable", err)
	}
}

// The pid-reuse guard, which is why the record carries a start time at all.
// A recycled pid belongs to some unrelated process — quite possibly the
// user's own shell — and the sweep must leave it alone while still removing
// the state file, whose run is dead either way.
func TestSweepDoesNotKillARecycledPid(t *testing.T) {
	dir, root := stateDirForTest(t)
	victim := liveProcess(t)
	target := "/tmp/recycled-target"
	st := stateFor(target, victim)
	st.Sandbox.InitStarttime = victim.starttime + 1 // as if the pid had been reused
	writeState(t, dir, target, st)

	sweepOrphanedSandboxesIn(root, dir)

	settle()
	if !processAlive(victim.pid) {
		t.Errorf("the sweep killed pid %d although the recorded start time did not match — "+
			"that record describes a process that has already exited, and this pid is "+
			"somebody else's", victim.pid)
	}
	if _, err := os.Stat(filepath.Join(dir, targetStateName(target))); !os.IsNotExist(err) {
		t.Errorf("the state file survived (err=%v): its run is gone regardless of what "+
			"happened to the pid, so the file is stale and must still be removed", err)
	}
}

// The name is the index. A state file whose name is not sha256(its own target)
// was not written by snug's own writer, and the sweep must not act on the pid
// it names — otherwise dropping one file into a directory this user owns is a
// way to make the next `snug` run kill an arbitrary process of theirs.
func TestSweepIgnoresAStateFileWhoseNameDoesNotMatchItsTarget(t *testing.T) {
	dir, root := stateDirForTest(t)
	victim := liveProcess(t)
	st := stateFor("/tmp/some-target", victim)

	// Written under a DIFFERENT target's name, which is what a hand-placed
	// file looks like.
	name := targetStateName("/tmp/a-completely-different-target")
	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(blob, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	sweepOrphanedSandboxesIn(root, dir)

	settle()
	if !processAlive(victim.pid) {
		t.Errorf("the sweep killed pid %d named by a state file whose name is not the hash of "+
			"the target it carries — the derived name is the only thing that ties a record to "+
			"a run", victim.pid)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Errorf("the sweep removed a file it had decided not to act on (err=%v)", err)
	}
}

// A file this snug cannot parse may have been written by a NEWER one whose run
// is live; removing it would break that run's `snug attach`, and killing on a
// half-decoded record is worse still.
func TestSweepIgnoresAStateFileItCannotParse(t *testing.T) {
	dir, root := stateDirForTest(t)
	name := targetStateName("/tmp/unparseable-target")
	if err := os.WriteFile(filepath.Join(dir, name), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	sweepOrphanedSandboxesIn(root, dir)

	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Errorf("the sweep removed a state file it could not parse (err=%v)", err)
	}
}

// ── fixtures ──────────────────────────────────────────────────────────────

// waitDead polls for the corpse. unix.Kill returns as soon as the signal is
// queued, not once the target has died, so an immediate assertion would be a
// race the test could lose on a loaded machine.
func waitDead(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return !processAlive(pid)
}

// settle is waitDead's opposite number: the pause a survival assertion needs
// so that "still alive" means the sweep chose not to kill it, rather than that
// this goroutine simply got there first.
func settle() { time.Sleep(200 * time.Millisecond) }

type testVictim struct {
	pid       int
	starttime uint64
}

// liveProcess starts a real process the sweep can be pointed at, and reads
// its start time the same way the sweep does. `sleep 60` rather than a Go
// goroutine because the thing under test is a pid: it has to be visible in
// /proc and killable from outside this process.
func liveProcess(t *testing.T) testVictim {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	start, err := procStartTime(pid)
	if err != nil {
		t.Fatalf("reading the fixture process's start time: %v", err)
	}
	return testVictim{pid: pid, starttime: start}
}

// processAlive answers the question the assertions ask, and it deliberately
// does not use os.FindProcess + Signal(0): a killed child stays a ZOMBIE
// until something reaps it, and a zombie answers Signal(0) exactly as a live
// process does. The state character in /proc/<pid>/stat is what tells them
// apart, which is the whole difference between "the sweep killed it" and "the
// sweep did nothing".
func processAlive(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// The comm field is parenthesised and may itself contain spaces, so the
	// fields after it are found from the LAST ')' — the same reasoning
	// procStartTime uses on the same file.
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return false
	}
	fields := strings.Fields(s[i+2:])
	if len(fields) == 0 {
		return false
	}
	return fields[0] != "Z" && fields[0] != "X"
}

// stateDirForTest is a state directory of this test's own, opened as an
// *os.Root the way the real one is. Never the real $XDG_RUNTIME_DIR/snug:
// these tests kill processes named by the files in it.
func stateDirForTest(t *testing.T) (string, *os.Root) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return dir, root
}

func stateFor(target string, v testVictim) runState {
	return runState{
		Schema: runStateSchema,
		Target: target,
		Sandbox: runStateSandbox{
			InitPID:       v.pid,
			InitStarttime: v.starttime,
			Namespaces:    map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6},
		},
	}
}

func writeStateFor(t *testing.T, dir, target string, v testVictim) {
	t.Helper()
	writeState(t, dir, target, stateFor(target, v))
}

func writeState(t *testing.T, dir, target string, st runState) {
	t.Helper()
	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, targetStateName(target)), append(blob, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// holdTargetLock takes the per-target flock and keeps it for the test, which
// is what a live run does for its whole life.
func holdTargetLock(t *testing.T, dir, target string) {
	t.Helper()
	path := filepath.Join(dir, targetLockName(target))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("the fixture could not take the target lock it is meant to hold: %v", err)
	}
	// A flock is held by the OPEN FILE DESCRIPTION, not by the process, so
	// keeping this descriptor open for the test is what keeps the lock held
	// — including against the sweep's own probe, which runs in this same
	// process and would succeed if flocks were process-scoped.
	t.Cleanup(func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	})
}
