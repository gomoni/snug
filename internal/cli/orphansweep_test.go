package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

	if got := killOrphanInit(st, "test"); got != orphanGone {
		t.Errorf("killOrphanInit returned %v for a starttime mismatch, want orphanGone: the "+
			"pid was recycled, so the record is spent and safe to remove", got)
	}

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

// The namespace guard (#285), and it is why the record carries six inodes at
// all. The starttime guard proves only that the pid was not RECYCLED — not that
// it is a sandbox init. A state file whose init_pid/init_starttime name any
// live same-uid process (a forged one, or a hostile one in a future where the
// uid-private state dir is exposed) must NOT be honoured when that process does
// not live in the namespaces the file recorded, or the sweep is an
// arbitrary-pid kill primitive.
//
// Two victims differing ONLY in whether their recorded namespaces match their
// real ones, so the survival of the foreign one is attributable to the
// namespace mismatch and nothing else — without the `own` control this would
// pass on a sweep that had simply stopped killing anything.
func TestSweepDoesNotKillAPidInForeignNamespaces(t *testing.T) {
	dir, root := stateDirForTest(t)

	// FOREIGN: correct pid, correct starttime, correct file name — but the
	// recorded namespace inodes are not this process's. A real sleep runs in the
	// host namespaces; these small fabricated inodes cannot match them.
	foreign := liveProcess(t)
	const foreignTarget = "/tmp/foreign-ns-target"
	fSt := stateFor(foreignTarget, foreign)
	fSt.Sandbox.Namespaces = map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6}
	writeState(t, dir, foreignTarget, fSt)

	// OWN (the control): identical in every other respect, recorded with its
	// real namespaces, so the sweep SHOULD kill it. If this one survives too,
	// the sweep is inert and the foreign assertion proves nothing.
	own := liveProcess(t)
	const ownTarget = "/tmp/own-ns-target"
	writeStateFor(t, dir, ownTarget, own)

	sweepOrphanedSandboxesIn(root, dir)

	if !waitDead(own.pid, 5*time.Second) {
		t.Fatalf("control: the sweep did not kill pid %d whose recorded namespaces MATCH its "+
			"real ones — the sweep is not killing anything, so the foreign-namespace assertion "+
			"below would prove nothing", own.pid)
	}
	settle()
	if !processAlive(foreign.pid) {
		t.Errorf("the sweep killed pid %d although its recorded namespace inodes do not match "+
			"the ones it actually runs in — the starttime matched, but that only rules out pid "+
			"reuse; a state file naming an unrelated live process must not turn the sweep into "+
			"an arbitrary-pid kill (#285)", foreign.pid)
	}
	// The stale file is removed either way: its run is gone, and the sweep's file
	// removal is unconditional. Not killing the pid does not mean keeping the file.
	if _, err := os.Stat(filepath.Join(dir, targetStateName(foreignTarget))); !os.IsNotExist(err) {
		t.Errorf("the foreign-namespace state file survived the sweep (err=%v); the pid must be "+
			"spared but the stale file must still be removed", err)
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

// TestSweepFindsARunStateRecordNamedByThePreIssue349Prefix is F2, the
// red-team round's finding on this diff: a run-state record a PRE-#349
// binary wrote is named "target-<bare-64-hex>.json", not the current
// "target-sha256_<64hex>.json" — before the fix, sweepOneOrphan's own name
// check (targetStateName(st.Target) != name) rejected every one of those on
// sight, so an orphan init a pre-upgrade binary left behind became invisible
// to the sweep forever, regardless of how long its lock had been released.
func TestSweepFindsARunStateRecordNamedByThePreIssue349Prefix(t *testing.T) {
	dir, root := stateDirForTest(t)
	victim := liveProcess(t)
	const target = "/tmp/legacy-prefix-target"
	name := legacyTargetKeyPrefix(target) + ".json"
	if name == targetStateName(target) {
		t.Fatalf("control failed: the legacy name and the current name are identical (%q) — "+
			"this fixture proves nothing about legacy tolerance", name)
	}
	writeStateAtName(t, dir, name, stateFor(target, victim))

	sweepOrphanedSandboxesIn(root, dir)

	if !waitDead(victim.pid, 5*time.Second) {
		t.Errorf("the sweep left pid %d alive: its run-state record used the PRE-#349 name "+
			"%q, which targetStateNameMatches must still recognise as %s's own record",
			victim.pid, name, target)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Errorf("the legacy-named record survived the sweep (err=%v)", err)
	}
}

// TestSweepIgnoresALegacyNamedRecordWhoseNameDoesNotMatchItsTarget is the
// "name is the index" check's OTHER half, re-asserted for the legacy
// generation specifically: accepting a SECOND name shape must not have
// widened the check into "any name ending .json", only into "either
// generation of THIS target's own derived name". A record shaped like a
// legacy name but naming a DIFFERENT target than the one it actually carries
// is exactly what a hand-placed file pointing the sweep at an arbitrary pid
// would look like.
func TestSweepIgnoresALegacyNamedRecordWhoseNameDoesNotMatchItsTarget(t *testing.T) {
	dir, root := stateDirForTest(t)
	victim := liveProcess(t)
	st := stateFor("/tmp/legacy-mismatch-real-target", victim)

	// Legacy-shaped, but for a DIFFERENT target than the one st carries.
	name := legacyTargetKeyPrefix("/tmp/legacy-mismatch-a-different-target") + ".json"
	writeStateAtName(t, dir, name, st)

	sweepOrphanedSandboxesIn(root, dir)

	settle()
	if !processAlive(victim.pid) {
		t.Errorf("the sweep killed pid %d named by a legacy-shaped record whose name is not "+
			"the legacy hash of the target it carries — accepting a second name generation "+
			"must not mean accepting any name", victim.pid)
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

// killOrphanInit's verdicts one at a time, called directly rather than
// through the sweep: orphanGone is the caller's licence to delete the
// record, and each case below is a different reason the init the record
// names cannot be alive.
func TestKillOrphanInitVerdicts(t *testing.T) {
	t.Run("pid<=1 is never a host init", func(t *testing.T) {
		st := runState{Sandbox: runStateSandbox{InitPID: 1}}
		if got := killOrphanInit(st, "test"); got != orphanGone {
			t.Errorf("killOrphanInit(pid=1) = %v, want orphanGone", got)
		}
	})

	t.Run("a reaped pid", func(t *testing.T) {
		cmd := exec.Command("/bin/true")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pid := cmd.Process.Pid
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		} // reaped: the number no longer names any task, so pidfd_open(2) is ESRCH.
		st := runState{Sandbox: runStateSandbox{InitPID: pid, InitStarttime: 1}}
		if got := killOrphanInit(st, "test"); got != orphanGone {
			t.Errorf("killOrphanInit(reaped pid %d) = %v, want orphanGone", pid, got)
		}
	})

	t.Run("namespace mismatch on an otherwise-matching pid", func(t *testing.T) {
		victim := liveProcess(t)
		st := stateFor("/tmp/table-ns-mismatch-target", victim)
		st.Sandbox.Namespaces = map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6}
		if got := killOrphanInit(st, "test"); got != orphanGone {
			t.Errorf("killOrphanInit(namespace mismatch) = %v, want orphanGone", got)
		}
		if !processAlive(victim.pid) {
			t.Errorf("pid %d was killed despite a namespace mismatch", victim.pid)
		}
	})
}

// THE LOAD-BEARING CASE. killOrphanInit returns orphanUnresolved whenever a
// /proc read fails for a reason other than "no such process" — the pid may
// still be alive, and deleting the record then would make every later sweep
// blind to it (issue #236's own accumulation, reintroduced by the cleanup
// path). This proves the record SURVIVES that case, using a real seam rather
// than a fabricated error: a live process this test does not own answers
// pidfd_open(2) and its starttime, but its /proc/<pid>/ns/* are EACCES.
//
// This needs a real other-uid process. Root's own PID 1 or a container
// entrypoint qualifies on most hosts; skip if none is found rather than
// fabricate the permission boundary.
func TestSweepKeepsARecordWhenNamespacesCannotBeRead(t *testing.T) {
	pid, start := findUnreadableNamespacePid(t)

	dir, root := stateDirForTest(t)
	target := "/tmp/unresolved-target"
	st := runState{
		Schema: runStateSchema,
		Target: target,
		Sandbox: runStateSandbox{
			InitPID:       pid,
			InitStarttime: start,
			// Presence, not value, is what decodeRunState checks; the real
			// comparison in killOrphanInit is never reached because the ns
			// read itself fails first.
			Namespaces: map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6},
		},
	}
	writeState(t, dir, target, st)

	// THE CONTROL: a second, ordinary orphan in the SAME directory and SAME
	// sweep call, which the sweep must still kill and remove. Without this,
	// "the record survived" is equally explained by a sweep that never ran.
	control := liveProcess(t)
	controlTarget := "/tmp/unresolved-control-target"
	writeStateFor(t, dir, controlTarget, control)

	sweepOrphanedSandboxesIn(root, dir)

	if !waitDead(control.pid, 5*time.Second) {
		t.Fatalf("control: the sweep did not kill pid %d, an ordinary orphan in the same "+
			"directory — without this, a sweep that never ran would pass this test too", control.pid)
	}
	if _, err := os.Stat(filepath.Join(dir, targetStateName(controlTarget))); !os.IsNotExist(err) {
		t.Fatalf("control: the ordinary orphan's record survived the sweep (err=%v)", err)
	}

	// The load-bearing assertion: an EACCES on the namespace read is
	// orphanUnresolved, not orphanGone, so sweepOneOrphan must not reach its
	// removal. No signal was ever sent either — killOrphanInit returns before
	// PidfdSendSignal on every path that yields orphanUnresolved.
	if _, err := os.Stat(filepath.Join(dir, targetStateName(target))); err != nil {
		t.Errorf("the record for an unresolvable namespace read was removed (err=%v): the pid "+
			"may still be alive and nothing else on the host names it, so this is issue #236's "+
			"accumulation happening again from inside the cleanup path", err)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
		t.Errorf("pid %d is gone at the end of the test (err=%v): it was not this test's to "+
			"kill, so its disappearance is unrelated to the sweep, but it means the assertion "+
			"above was not actually exercising the EACCES path", pid, err)
	}
}

// findUnreadableNamespacePid scans for a live, non-reaped pid this test does
// not own, whose /proc/<pid>/ns/* this uid cannot open. It returns the pid
// and its starttime (read while unprivileged /proc access still works) so the
// caller can build a state file whose starttime check passes and whose
// namespace check fails with EACCES rather than ENOENT.
func findUnreadableNamespacePid(t *testing.T) (int, uint64) {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Skip("cannot read /proc")
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}
		fi, err := os.Lstat(filepath.Join("/proc", e.Name()))
		if err != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) == os.Getuid() {
			continue // owned by us: /proc/<pid>/ns/* would be readable, defeating the seam
		}
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			continue // gone, or some other reason this candidate cannot pin
		}
		unix.Close(fd)
		start, err := procStartTime(pid)
		if err != nil {
			continue
		}
		if f, err := os.Open(filepath.Join("/proc", e.Name(), "ns", "mnt")); err == nil {
			f.Close()
			continue // readable after all (e.g. same-uid despite the Stat_t check racing)
		} else if !os.IsPermission(err) {
			continue // gone (ENOENT) rather than denied: not the seam this test needs
		}
		return pid, start
	}
	t.Skip("no other-uid process with an unreadable /proc/<pid>/ns found; skipping the " +
		"orphanUnresolved seam test")
	return 0, 0
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
	pid        int
	starttime  uint64
	namespaces map[string]uint64
}

// liveProcess starts a real process the sweep can be pointed at, and reads
// both halves of the identity the sweep checks the same way the sweep does:
// its start time and its six namespace inodes. `sleep 60` rather than a Go
// goroutine because the thing under test is a pid: it has to be visible in
// /proc and killable from outside this process.
//
// The namespace inodes are the process's REAL ones (host namespaces — this is
// an ordinary child, not a sandbox init), which is exactly what a state file a
// genuine run wrote would carry, so a fixture using them exercises the #285
// cross-check positively. A fixture that wants the MISMATCH case overrides
// them (see TestSweepDoesNotKillAPidInForeignNamespaces).
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
	ns, err := procNamespaceInodes(pid)
	if err != nil {
		t.Fatalf("reading the fixture process's namespace inodes: %v", err)
	}
	return testVictim{pid: pid, starttime: start, namespaces: ns}
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
			// The victim's REAL namespace inodes: a state file a genuine run
			// wrote carries the init's own, and killOrphanInit now cross-checks
			// them (#285). A fixture testing the MISMATCH overrides this map.
			Namespaces: v.namespaces,
		},
	}
}

func writeStateFor(t *testing.T, dir, target string, v testVictim) {
	t.Helper()
	writeState(t, dir, target, stateFor(target, v))
}

func writeState(t *testing.T, dir, target string, st runState) {
	t.Helper()
	writeStateAtName(t, dir, targetStateName(target), st)
}

// writeStateAtName is writeState with the filename chosen by the caller
// rather than derived from st.Target — what a legacy-named or hand-placed
// record on disk looks like, where the name and the content's own claimed
// target need not agree.
func writeStateAtName(t *testing.T, dir, name string, st runState) {
	t.Helper()
	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(blob, '\n'), 0o600); err != nil {
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
