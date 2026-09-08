//go:build integration

package integration

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

// TestTheSweepReapsADeadPeersInitWhileALivePeerHoldsTheTargetLock is the
// regression test for the sweep deferring behind a SHARED target lock.
//
// Two runs are live on one directory. The lock a run takes is shared, so it
// stays held until the LAST of them exits — and a sweep that returned as soon
// as it read "held" acted on NOTHING belonging to that target: neither the
// record of the run that was SIGKILLed, nor the sandbox init that run left
// behind. For as long as the surviving peer lived, that init kept its
// namespaces and its write access to the target, which is invariant 4 failing
// on an ordinary sequence with no attacker in it. Each record is judged on its
// own owner now (internal/cli/stateowner.go), so a live peer defers nothing.
//
// WHAT IS REAL HERE AND WHAT IS A STAND-IN, because one half cannot be forced.
//
//   - The live peer is a real `snug` run, with its own real record and init.
//     It is the negative half, and without it this test would pass on a sweep
//     that killed everything on a busy target.
//   - The dead peer's RECORD is a real run's, SIGKILLed after it published.
//     Deterministic: a SIGKILLed snug leaves its record whatever its init did.
//   - The orphaned INIT is a STAND-IN, and this is the honest limit of the
//     test. The window in which a SIGKILLed run leaves its init running is a
//     timing one (issue #13), and it did not open once while this test was
//     written: killing the snug at the instant its record appears — the moment
//     TestTheNextRunSweepsAnOrphanedSandboxInit's own comment records as
//     hitting the window 5 times out of 5 — produced no orphan in 5 attempts
//     through that test, 5 through an earlier draft of this one, or 3 by hand
//     polling every 2 ms for whichever record landed first (state.json each
//     time; the ".starting" record was never on disk when looked for). So this
//     test PLANTS a record naming a process that really does hold its own
//     six namespaces and whose owning process really has exited and been
//     reaped, and asserts the sweep kills it. The sweep cannot tell that
//     process from a bwrap init — the identity it checks is the pid, the start
//     time and those six inodes — so what this does not cover is the window's
//     ARRIVAL, not the sweep's judgement of what it leaves.
func TestTheSweepReapsADeadPeersInitWhileALivePeerHoldsTheTargetLock(t *testing.T) {
	budget(t, 180*time.Second)
	requireSandbox(t)

	proj, _ := target(t)

	// THE LIVE PEER. It holds the target lock, shared, for the whole test —
	// the state that used to make the sweep skip everything on this target.
	ready := filepath.Join(proj, "PEER-READY")
	peer := startBackgroundSnug(t, baseEnv(), proj,
		"touch "+shQuote(ready)+"; while true; do sleep 1; done")
	if err := waitForFile(ready, 60*time.Second); err != nil {
		t.Fatalf("the live peer never signalled readiness (%v):\n%s", err, peer.output())
	}
	peerRecord := targetStateRecordPath(t, proj, peer.cmd.Process.Pid)
	if err := waitForFile(peerRecord, 60*time.Second); err != nil {
		t.Fatalf("the live peer published no record at %s (%v) — the name carries the OWNING "+
			"snug's pid, so a run whose main process is not the one started here would need "+
			"this test rewritten:\n%s", peerRecord, err, peer.output())
	}
	peerInit := initPIDFrom(t, peerRecord)
	if peerInit == 0 {
		t.Fatalf("the live peer's record %s names no init pid", peerRecord)
	}

	// THE DEAD PEER'S RECORD: a second real run on the same target, SIGKILLed
	// once it has published.
	killedInit, killedRecord := killOnePeerRun(t, proj)

	// THE ORPHANED INIT, planted — see this test's doc comment for why it is
	// not produced by the window it stands for.
	orphan := plantOrphanRecord(t, proj)

	t.Logf("live peer: snug %d init %d; killed run: %s (init %d, still alive: %v); "+
		"planted orphan: pid %d record %s", peer.cmd.Process.Pid, peerInit,
		filepath.Base(killedRecord), killedInit, killedInit != 0,
		orphan.pid, filepath.Base(orphan.record))

	// THE SWEEP, from an ordinary snug on an unrelated target, while the peer
	// above is live and still holding this target's lock.
	other, _ := target(t)
	if out, code := cli(t, baseEnv(), other, "--", "/bin/true"); code != 0 {
		t.Fatalf("the sweeping run itself failed (exit %d):\n%s", code, out)
	}

	if !waitGone(orphan.pid, 10*time.Second) {
		t.Errorf("pid %d is still alive: it holds its own six namespaces, its record names it, "+
			"and the snug that owned that run is gone — a sweep that waits for the target to "+
			"fall quiet leaves exactly this running for the whole life of the peer beside it "+
			"(invariant 4)", orphan.pid)
	}
	if _, err := os.Stat(orphan.record); !os.IsNotExist(err) {
		t.Errorf("the planted orphan's record survived the sweep (err=%v): %s\nIf the sweep "+
			"could not PARSE it, the record shape written here has drifted from internal/cli's "+
			"— this package derives it rather than importing it", err, orphan.record)
	}
	if _, err := os.Stat(killedRecord); !os.IsNotExist(err) {
		t.Errorf("the record of a SIGKILLed run survived the sweep (err=%v): %s\nA peer is live "+
			"on this target and holds the lock SHARED, which is exactly the state in which "+
			"these accumulated", err, killedRecord)
	}
	if killedInit != 0 && !waitGone(killedInit, 10*time.Second) {
		t.Errorf("pid %d is still alive: the window DID open on this host this time, so the "+
			"init of the SIGKILLed run is a real orphan and the sweep must have killed it",
			killedInit)
	}

	// THE NEGATIVE HALF.
	time.Sleep(1 * time.Second) // a kill would have landed well inside this
	if !processAlive(peerInit) {
		t.Fatalf("the sweep killed pid %d, the init of a run whose snug (pid %d) is still "+
			"running:\n%s", peerInit, peer.cmd.Process.Pid, peer.output())
	}
	if _, err := os.Stat(peerRecord); err != nil {
		t.Errorf("the sweep removed the LIVE peer's record %s (err=%v) — it is the only thing "+
			"naming that run's init, so removing it blinds every later sweep to it",
			peerRecord, err)
	}
}

// killOnePeerRun starts a second run on proj, waits for the record it
// publishes, and SIGKILLs the snug that owns it. It returns the init pid if
// that init outlived its snug — 0 if it did not, which is what
// PR_SET_PDEATHSIG produces and what this host produced every time — and the
// path of the record left behind either way.
//
// The record is addressed by the killed snug's OWN pid rather than found by
// glob: a peer run is live on this target throughout, so the target has
// several records and only the pid separates them.
func killOnePeerRun(t *testing.T, proj string) (orphanInit int, record string) {
	t.Helper()
	bg := startBackgroundSnug(t, baseEnv(), proj, "sleep 300")
	record = targetStateRecordPath(t, proj, bg.cmd.Process.Pid)
	if err := waitForFile(record, 30*time.Second); err != nil {
		t.Fatalf("the run to be killed published no record at %s (%v):\n%s",
			record, err, bg.output())
	}
	pid := initPIDFrom(t, record)
	if pid == 0 {
		t.Fatalf("record %s names no init pid", record)
	}
	bg.killAndWait() // SIGKILL, and WAITED FOR: no zombie answers for the owner

	// Long enough for the sandbox to die WITH its snug, which is what a kill
	// outside the window produces.
	time.Sleep(1 * time.Second)
	if !processAlive(pid) {
		return 0, record
	}
	return pid, record
}

type plantedOrphan struct {
	pid    int
	record string
}

// plantOrphanRecord puts on disk what a run SIGKILLed inside bwrap's startup
// window leaves behind: a live process holding its own mount, pid, net, ipc,
// uts and cgroup namespaces, and a run-state record naming it whose OWNING
// snug process has exited and been reaped.
//
// Every field the sweep judges is real. The pid and start time are the
// process's own; the six inodes are read from its own /proc/<pid>/ns/*; the
// owner is a process this test started, whose start time it read while it was
// there, and which it then killed and WAITED FOR — ownerProvablyGone reads
// /proc, so a zombie left unreaped would still answer for it.
//
// The JSON shape is derived here rather than imported: this package drives the
// built binary and links none of snug's own packages. A drift between the two
// does not silently pass — the sweep refuses a record it cannot decode, so the
// record survives and the caller's assertion says which failure that is.
func plantOrphanRecord(t *testing.T, proj string) plantedOrphan {
	t.Helper()

	// The stand-in init. CLONE_NEWUSER is what lets an unprivileged process
	// take the other five, and it is also what makes this a fair fixture: an
	// ordinary host child shares the sweeping snug's own namespaces, so a
	// record naming one would pass the six-inode check for the wrong reason.
	victim := exec.Command("/bin/sleep", "300")
	victim.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID |
			unix.CLONE_NEWNET | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	if err := victim.Start(); err != nil {
		t.Fatalf("starting the stand-in orphan in its own six namespaces: %v (this host runs "+
			"sandboxes, so unprivileged user namespaces are available)", err)
	}
	pid := victim.Process.Pid
	t.Cleanup(func() {
		// This test's own child, not yet Wait()ed: it holds its pid number as
		// a zombie until reaped, so the number cannot have been handed to a
		// stranger. Already dead if the sweep did its job.
		_ = victim.Process.Kill()
		_, _ = victim.Process.Wait()
	})

	start, err := procStarttime(pid)
	if err != nil {
		t.Fatalf("reading the stand-in orphan's start time: %v", err)
	}
	ns := map[string]uint64{}
	for _, kind := range []string{"mnt", "pid", "net", "ipc", "uts", "cgroup"} {
		fi, serr := os.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, kind))
		if serr != nil {
			t.Fatalf("reading the stand-in orphan's %q namespace: %v", kind, serr)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("stat of /proc/%d/ns/%s carries no Stat_t", pid, kind)
		}
		ns[kind] = st.Ino
	}

	ownerPID, ownerStart := spawnAndReapOwner(t)

	real, err := filepath.EvalSymlinks(proj)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.MarshalIndent(map[string]any{
		"schema": 1,
		"target": real,
		"sandbox": map[string]any{
			"init_pid":       pid,
			"init_starttime": start,
			"namespaces":     ns,
		},
		"owner": map[string]any{"pid": ownerPID, "starttime": ownerStart},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	record := targetStateRecordPath(t, proj, ownerPID)
	if err := os.WriteFile(record, append(blob, '\n'), 0o600); err != nil {
		t.Fatalf("planting %s: %v", record, err)
	}
	t.Cleanup(func() { _ = os.Remove(record) })
	return plantedOrphan{pid: pid, record: record}
}

// spawnAndReapOwner is a run owner that really did exit: started, its identity
// read while it was still there, then killed and waited for.
func spawnAndReapOwner(t *testing.T) (pid int, starttime uint64) {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid = cmd.Process.Pid
	start, err := procStarttime(pid)
	if err != nil {
		t.Fatal(err)
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	return pid, start
}

// procStarttime is /proc/<pid>/stat field 22, read the way snug reads it: from
// the LAST ')', because the comm field is parenthesised and may itself contain
// spaces.
func procStarttime(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return 0, fmt.Errorf("/proc/%d/stat has no comm field", pid)
	}
	fields := strings.Fields(s[i+2:])
	const starttimeIndex = 22 - 3
	if len(fields) <= starttimeIndex {
		return 0, fmt.Errorf("/proc/%d/stat has %d fields after comm, want more than %d",
			pid, len(fields), starttimeIndex)
	}
	return strconv.ParseUint(fields[starttimeIndex], 10, 64)
}

// targetStateRecordPath is targetStateGlob resolved to one owner: the record
// snug publishes for target on behalf of the snug process ownerPID. Derived
// the same way and for the same reason — this package drives the built binary
// and links none of snug's own packages.
func targetStateRecordPath(t *testing.T, target string, ownerPID int) string {
	t.Helper()
	glob := targetStateGlob(t, target)
	path := strings.Replace(glob, ".*.json", "."+strconv.Itoa(ownerPID)+".json", 1)
	if path == glob {
		t.Fatalf("targetStateGlob no longer ends in the owning pid (%s), so this cannot name "+
			"one run's record among a target's several", glob)
	}
	return path
}
