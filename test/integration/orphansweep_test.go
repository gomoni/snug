//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTheNextRunSweepsAnOrphanedSandboxInit is issue #236's deferred fix, end
// to end on the real binary: a `snug` killed with SIGKILL inside bwrap's
// startup window leaves the sandbox's own init running — reparented, holding
// four namespace objects, and on the wider end of that window still running
// the payload — and the NEXT `snug` run must kill it.
//
// THE ORPHAN IS A LOTTERY AGAIN, and the Skip below is the ordinary outcome.
// When this was written the run's state file landed at ~165 ms and the orphan
// window ran from ~150 ms to ~350 ms, so killing the moment the state file
// appeared hit it 5 times out of 5. That no longer reproduces: 5 attempts
// through this helper, 5 through sweeppeer_test.go's own loop, and 3 by-hand
// kills polling every 2 ms for whichever record landed first all produced a
// sandbox that died WITH its snug. The retry loop stays, and it SKIPS rather
// than passing when no orphan can be produced: "the sweep removed nothing"
// must never be reported as success. What the sweep does to an orphan once
// there is one is asserted deterministically by
// TestTheSweepReapsADeadPeersInitWhileALivePeerHoldsTheTargetLock, which
// plants the record rather than waiting for this window.
//
// The state file is also the only place the init's pid is written down, which
// is the same fact the sweep depends on.
func TestTheNextRunSweepsAnOrphanedSandboxInit(t *testing.T) {
	budget(t, 120*time.Second)
	requireSandbox(t)

	var orphanPID int
	var statePath, proj string
	for attempt := 1; attempt <= 5 && orphanPID == 0; attempt++ {
		orphanPID, statePath, proj = makeOrphanedInit(t)
	}
	if orphanPID == 0 {
		t.Skip("could not reproduce issue #236's orphan window on this host after 5 attempts " +
			"(the sandbox died with its snug every time, which is the GOOD outcome) — nothing " +
			"for the sweep to remove, so this test would prove nothing either way")
	}
	t.Logf("control: orphaned sandbox init pid %d is alive with its snug gone (target %s)",
		orphanPID, proj)

	// The sweep runs on any ordinary run, on ANY target: the orphan's own
	// directory is not special, and this second run must not be on it (a run
	// on the same target would be refused while... in fact it would not, the
	// lock is released — but using a different target proves the sweep is a
	// housekeeping pass rather than something the same-target path does).
	other, _ := target(t)
	if out, code := cli(t, baseEnv(), other, "--", "/bin/true"); code != 0 {
		t.Fatalf("the sweeping run itself failed (exit %d):\n%s", code, out)
	}

	if !waitGone(orphanPID, 10*time.Second) {
		t.Errorf("pid %d is still alive after another snug run: the orphaned init of a dead "+
			"run must not survive it (issue #236, invariant 4)", orphanPID)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Errorf("the dead run's state file %s survived the sweep (err=%v)", statePath, err)
	}
}

// A live run must come through the sweep untouched. Without this the test
// above is satisfied by a snug that kills every sandbox init it can find on
// the machine, which would make the feature far worse than the bug.
func TestTheSweepDoesNotTouchALiveSandbox(t *testing.T) {
	budget(t, 90*time.Second)
	requireSandbox(t)

	proj, _ := target(t)
	ready := filepath.Join(proj, "READY")
	bg := startBackgroundSnug(t, baseEnv(), proj,
		"touch "+shQuote(ready)+"; while true; do sleep 1; done")
	if err := waitForFile(ready, 60*time.Second); err != nil {
		t.Fatalf("the live sandbox never signalled readiness (%v):\n%s", err, bg.output())
	}
	statePath := targetStatePath(t, proj)
	livePID := initPIDFrom(t, statePath)
	if livePID == 0 {
		t.Fatalf("the live run published no init pid in %s", statePath)
	}

	other, _ := target(t)
	if out, code := cli(t, baseEnv(), other, "--", "/bin/true"); code != 0 {
		t.Fatalf("the sweeping run itself failed (exit %d):\n%s", code, out)
	}

	// A kill would have landed well inside this second.
	time.Sleep(1 * time.Second)
	if !processAlive(livePID) {
		t.Fatalf("another snug run killed the init (pid %d) of a LIVE sandbox — the snug that "+
			"owns that run is still running, which is what the sweep reads per record:\n%s",
			livePID, bg.output())
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Errorf("another snug run removed a LIVE run's state file %s (err=%v) — it is the only "+
			"thing naming that run's init, so removing it blinds every later sweep to it",
			statePath, err)
	}
}

// makeOrphanedInit starts a run, waits for its state file (which is when the
// init pid becomes knowable AND when the orphan window is open), SIGKILLs the
// snug process, and reports the init if it survived. A zero pid means this
// attempt produced no orphan.
func makeOrphanedInit(t *testing.T) (pid int, statePath, proj string) {
	t.Helper()
	proj, _ = target(t)
	for _, old := range targetStateRecords(t, proj) {
		_ = os.Remove(old)
	}

	bg := startBackgroundSnug(t, baseEnv(), proj, "sleep 300")
	deadline := time.Now().Add(30 * time.Second)
	for {
		if statePath = targetStatePath(t, proj); statePath != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the run never published a state file matching %s:\n%s",
				targetStateGlob(t, proj), bg.output())
		}
		time.Sleep(25 * time.Millisecond)
	}
	pid = initPIDFrom(t, statePath)
	if pid == 0 {
		t.Fatalf("state file %s names no init pid", statePath)
	}
	bg.killAndWait() // SIGKILL, the case with no handler and no cleanup

	// Give the sandbox a moment to die WITH its snug, which is what a kill
	// outside the window produces.
	time.Sleep(1 * time.Second)
	if !processAlive(pid) {
		return 0, statePath, proj
	}
	return pid, statePath, proj
}

// targetStateGlob derives the same name snug does: "sha256_" followed by the
// sha256 of the target's realpath (issue #349 — the name carries its
// algorithm), then the OWNING SNUG PID, in the uid-derived directory (never
// $XDG_RUNTIME_DIR — issue #122). Recomputed here rather than imported because
// this package drives the built binary and links none of snug's own packages;
// if the two ever disagree, the polls above time out and say so.
//
// It is a glob because several runs can be live on one target and the pid is
// what separates their records.
func targetStateGlob(t *testing.T, target string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(real))
	name := "target-sha256_" + hex.EncodeToString(sum[:]) + ".*.json"

	base := fmt.Sprintf("/run/user/%d/snug", os.Getuid())
	if fi, err := os.Stat(base); err != nil || !fi.IsDir() {
		base = fmt.Sprintf("/tmp/snug-%d", os.Getuid())
	}
	return filepath.Join(base, name)
}

// targetStateRecords is every state record for the target, live or stale.
func targetStateRecords(t *testing.T, target string) []string {
	t.Helper()
	m, err := filepath.Glob(targetStateGlob(t, target))
	if err != nil {
		t.Fatalf("globbing %s: %v", targetStateGlob(t, target), err)
	}
	return m
}

// targetStatePath is that glob resolved to the one record these tests start.
// "" means none yet; two is a bug in the test, not in snug, so it fails.
func targetStatePath(t *testing.T, target string) string {
	t.Helper()
	m := targetStateRecords(t, target)
	switch len(m) {
	case 0:
		return ""
	case 1:
		return m[0]
	default:
		t.Fatalf("%d state records for %s, expected one: %v", len(m), target, m)
		return ""
	}
}

func initPIDFrom(t *testing.T, statePath string) int {
	t.Helper()
	data, err := os.ReadFile(statePath)
	if err != nil {
		return 0
	}
	var st struct {
		Sandbox struct {
			InitPID int `json:"init_pid"`
		} `json:"sandbox"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("parsing %s: %v", statePath, err)
	}
	return st.Sandbox.InitPID
}

// processAlive treats a zombie as dead: the sweep's SIGKILL leaves exactly a
// zombie until the init's reparent-to-subreaper reaps it, and "still has a
// /proc entry" would report that corpse as a survivor.
func processAlive(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return false
	}
	fields := strings.Fields(s[i+2:])
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}

func waitGone(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return !processAlive(pid)
}
