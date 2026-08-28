//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSIGKILLBeforeThePayloadStartsLeavesNoInit is the ratchet for issue
// #101's nested pid namespace on the offline arm: bwrap is now pid 1 of the
// intermediate pid namespace snug forks it into
// (internal/sandbox/exec.go's SysProcAttr), so when snug itself is SIGKILLed,
// the kernel's own zap_pid_ns_processes tears down everything inside that
// namespace the moment bwrap's PR_SET_PDEATHSIG fires — before the sandbox's
// own init has forked a payload — rather than the outcome depending on
// confirmTeardown's sweep winning a race against bwrap's OWN init arming its
// own die-with-parent late (issue #13's original defect).
//
// Measured (redteam, this session), SIGKILL of snug at a fixed 130ms offset —
// chosen because payload start latency measures ~206ms on both arms, so
// 130ms is reliably before the payload starts but after bwrap has forked —
// 800ms settle before checking:
//
//	main:   6/6 trials left a surviving init, 6/6 had the payload run its
//	        control file AFTER snug was already dead
//	branch: 0/6 here, and 0 leaks across 18 offsets from 0 to 1200ms over
//	        144+ trials in the fuller sweep this reproduces one point of
//
// BOTH HALVES ARE ASSERTED ON PURPOSE. "No surviving init" alone passes
// trivially on a trial where nothing was ever forked at all, which is
// exactly how main's own leak would misread as clean if only processes were
// counted — the control file the payload writes on its first line is what
// tells "never started" apart from "ran after its supervisor was already
// gone".
func TestSIGKILLBeforeThePayloadStartsLeavesNoInit(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	const iterations = 6
	const offset = 130 * time.Millisecond
	const settle = 800 * time.Millisecond

	var leaks int
	for i := 1; i <= iterations; i++ {
		proj, _ := target(t)
		started := filepath.Join(proj, "started")

		bg := startBackgroundSnug(t, baseEnv(), proj, "touch "+shQuote(started)+"; sleep 120")
		time.Sleep(offset)

		// POSITIVE CONTROL: something bwrap forked must already exist to be
		// killed, or the "no survivor" check below would be equally true of
		// a trial that never reached the window this test needs to measure.
		candidates := descendantsOf(bg.cmd.Process.Pid)
		if len(candidates) == 0 {
			t.Fatalf("iteration %d: snug (pid %d) had forked nothing %s after start — this "+
				"offset is not landing inside the window this test needs", i, bg.cmd.Process.Pid, offset)
		}

		bg.killAndWait() // SIGKILL: no handler runs, nothing here helps it along
		time.Sleep(settle)

		var survivors []int
		for _, pid := range candidates {
			if processAlive(pid) {
				survivors = append(survivors, pid)
			}
		}
		_, statErr := os.Stat(started)
		ranAfterDeath := statErr == nil

		if len(survivors) > 0 || ranAfterDeath {
			leaks++
			t.Logf("iteration %d: surviving pid(s) %v, payload ran after snug died: %v",
				i, survivors, ranAfterDeath)
		}
	}

	if leaks > 0 {
		t.Errorf("%d/%d trials left the sandbox alive (a surviving process, or its payload "+
			"having run) after snug was SIGKILLed %s into the run — issue #101's nested pid "+
			"namespace no longer closes issue #13's residual on the offline arm", leaks, iterations, offset)
	}
}
