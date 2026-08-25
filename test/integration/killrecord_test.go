//go:build integration

package integration

// killrecord_test.go is issue #236's end-to-end proof and its own threat-model
// boundary, on the real binary.
//
// TestTheKillRecordLandsBeforeTheEngineIsUp is the test that would have caught
// the bug this milestone fixes: a container run's engine cold start (the
// window exec.go's own comment measures at 1-2s typical, engineSocketWaitTimeout
// 30s) used to have NO host record naming the sandbox's init at all, so a
// SIGKILL landing inside it left an orphan no sweep could find.
//
// TestTheStateDirectoryIsUnreachableFromInsideTheSandbox is the red team's own
// finding: the sweep's same-uid, arbitrary-process-naming surface
// (orphansweep.go's own doc comment: "a hostile process inside the sandbox can
// use this to ___") is out of scope only because the directory the records
// live in is never bound into any sandbox. That claim was asserted nowhere
// before this file.
import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startingPath is attachSandbox.statePath's (attach_test.go) sibling for the
// ".starting" kill record: the identical "sha256_"+sha256(realpath) stem
// (issue #349), ".starting" instead of ".json".
func (s *attachSandbox) startingPath(t *testing.T) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(s.proj)
	if err != nil {
		t.Fatalf("resolving the target %s: %v", s.proj, err)
	}
	sum := sha256.Sum256([]byte(real))
	return filepath.Join(uidRuntimeSnugDir(t), "target-sha256_"+hex.EncodeToString(sum[:])+".starting")
}

// waitForGone polls for a path to stop existing — waitForFile's opposite
// number, needed here because the ".starting" record's removal is itself
// part of the invariant under test (never both files gone, and not forever
// both present either).
func waitForGone(path string, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s still exists after %s", path, within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTheKillRecordLandsBeforeTheEngineIsUp reproduces issue #236's own
// measurement on a real @podman-socket run: the ".starting" record must exist
// BEFORE state.json does, for the whole of the engine's cold start, and both
// must resolve to exactly state.json once the run is up.
func TestTheKillRecordLandsBeforeTheEngineIsUp(t *testing.T) {
	budget(t, 60*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	bg := startAttachSandbox(t, env, []string{"-p", "@podman-socket"}, proj, `sleep 300`)

	// bg.ready(t) is deliberately NOT called before the checks below: a
	// @podman-socket run is GATED (issue #125) — the payload, and therefore
	// payloadMarker, does not run until the engine has confirmed its socket
	// and P0 has released the parked init. By the time payloadMarker would
	// appear, the whole window this test exists to catch has already closed
	// on its own. So the record has to be caught from process start.

	startingPath := bg.startingPath(t)
	statePath := bg.statePath(t)

	// POSITIVE CONTROL: the .starting record actually appears at all.
	// Without this, "state.json was not there yet" would be equally true of
	// a run that published NEITHER record — the sandbox never having reached
	// the starting line in the first place.
	if err := waitForFile(startingPath, 15*time.Second); err != nil {
		t.Fatalf("the .starting record never appeared at %s (%v):\n%s",
			startingPath, err, bg.log())
	}

	// THE ASSERTION: at the instant the .starting record exists, state.json
	// must NOT — the engine's cold start (a real podman fork, setns, capdrop,
	// exec, and a poll for its socket) is still running behind it. A
	// regression that removed the "forked" event, or that published
	// state.json before the engine finished, would pass the control above and
	// fail here.
	if _, err := os.Stat(statePath); err == nil {
		t.Fatalf("state.json already exists at %s the instant the .starting record appeared — "+
			"this test needs the engine's cold start to still be in progress for the window it "+
			"is measuring to exist at all; the engine may have started faster than expected on "+
			"this host", statePath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat %s: %v", statePath, err)
	}

	// The run finishes coming up: the payload is released, state.json lands,
	// and the .starting record is removed — never forever both present.
	bg.ready(t)
	bg.waitForState(t)
	if err := waitForGone(startingPath, 15*time.Second); err != nil {
		t.Errorf("the .starting record survived after state.json was published (%v):\n%s",
			err, bg.log())
	}
}

// TestTheStateDirectoryIsUnreachableFromInsideTheSandbox is the red team's own
// finding, load-bearing for orphansweep.go's threat model: the sweep signals
// a pid by NUMBER, confirmed only by starttime and namespace inodes, never by
// asking the sandboxed process itself — which is fine ONLY because nothing
// inside a sandbox can read or write the directory the kill records and
// state.json live in. If it could, a payload could plant its own record
// naming a foreign pid, or race the removal of its own.
//
// Measured (redteam round): inside an ordinary sandbox, `ls /run/user/<uid>`
// answers "No such file or directory" and a write under it fails the same
// way. This test reproduces exactly that, with a positive control that
// distinguishes "the sandbox cannot see it" from "the path does not exist at
// all on this host".
func TestTheStateDirectoryIsUnreachableFromInsideTheSandbox(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)

	stateDir := uidRuntimeSnugDir(t) // /run/user/<uid>/snug (or its /tmp fallback)

	// POSITIVE CONTROL: run a real snug OUTSIDE any sandbox first, so at
	// least one target-* entry is guaranteed to exist in stateDir when the
	// sandboxed probe below runs. Without this, "the sandbox could not read
	// it" is equally true of a directory that is simply empty or absent.
	proj, _ := target(t)
	if out, code := cli(t, baseEnv(), proj, "--", "/bin/true"); code != 0 {
		t.Fatalf("the control run itself failed (exit %d):\n%s", code, out)
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatalf("positive control: %s could not be read from OUTSIDE the sandbox (%v) — the "+
			"negative assertion below would prove nothing about a directory this test cannot "+
			"itself observe", stateDir, err)
	}
	foundTarget := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "target-") {
			foundTarget = true
			break
		}
	}
	if !foundTarget {
		t.Fatalf("positive control: %s has no target-* entry after a real run — nothing for the "+
			"negative assertion below to have failed to see", stateDir)
	}

	// THE NEGATIVE: from INSIDE an ordinary sandbox, the directory must be
	// unreachable for both listing and writing.
	script := fmt.Sprintf(`
ls %s 2>&1; echo LS_EXIT=$?
touch %s/probe-from-inside 2>&1; echo TOUCH_EXIT=$?
`, shQuote(stateDir), shQuote(stateDir))
	r := run(t, nil, proj, script).mustRun(t)

	if !strings.Contains(r.out, "No such file or directory") {
		t.Errorf("expected \"No such file or directory\" for both the ls and the touch of %s "+
			"from inside the sandbox, got:\n%s", stateDir, r.out)
	}
	if strings.Contains(r.out, "LS_EXIT=0") {
		t.Errorf("`ls %s` succeeded from inside the sandbox:\n%s", stateDir, r.out)
	}
	if strings.Contains(r.out, "TOUCH_EXIT=0") {
		t.Errorf("`touch %s/...` succeeded from inside the sandbox — a payload could plant its "+
			"own kill record:\n%s", stateDir, r.out)
	}

	// Nothing sandboxed could have written into the real directory: confirm
	// the probe file this script tried to create is not actually there.
	if _, err := os.Stat(filepath.Join(stateDir, "probe-from-inside")); !os.IsNotExist(err) {
		t.Errorf("a file the sandboxed payload tried to create under %s exists on the host "+
			"(err=%v) — the touch above did not actually fail the way its exit code claimed",
			stateDir, err)
	}
}
