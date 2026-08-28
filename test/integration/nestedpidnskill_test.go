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
// Measured (redteam, this session), SIGKILL of snug at a fixed 130ms offset,
// 800ms settle before checking: main left 6/6 trials with a surviving
// process AND 6/6 with the payload's control file written after snug died;
// branch left 0/6 of either, and 0 leaks across 18 offsets from 0 to 1200ms
// over 144+ trials in the fuller sweep this reproduces one point of.
//
// TWO INDEPENDENT ASSERTIONS, NEITHER TIED TO ONE MACHINE'S TIMING. An
// earlier version of this test treated "the control file exists" as the
// second half, which bakes in a specific host's payload-start latency: CI's
// ubuntu-latest runner starts the payload in well under 130ms, so the file
// already existed BEFORE snug was even killed, on every trial, on a branch
// that leaks nothing — a false failure with no leak behind it.
//
//  1. Zero surviving descendants of snug's own pid, always — checked
//     regardless of whether the payload ever got that far. This is the
//     strong half, and the one that fails on main.
//  2. Whether the control file's own mtime falls AFTER the moment snug was
//     confirmed reaped (killAndWait's Wait() returning), not whether the
//     file merely exists. A file written before the reap is an ordinary
//     run that finished its "touch" ahead of a slow kill — not a leak, on
//     however fast or slow a runner. A file written after is the payload
//     having run with its supervisor already dead, issue #13's own shape.
//
// The file's mere ABSENCE says nothing either way — a trial that never got
// far enough to write it proves only that nothing leaked when nothing ran,
// which is why it is a precondition for assertion 2 rather than a pass or a
// fail. On a host whose payload start latency is comfortably above this
// offset, containment succeeding at 130ms means the payload's whole
// namespace is torn down before it ever runs, so the file may never appear
// in any trial at all — that is assertion 1 doing its job, not a gap in
// assertion 2, which stays silent (never true, never false) rather than
// wrong.
func TestSIGKILLBeforeThePayloadStartsLeavesNoInit(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	const iterations = 6
	const offset = 130 * time.Millisecond
	const settle = 800 * time.Millisecond

	var survivorLeaks, mtimeLeaks, meaningful int
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

		bg.killAndWait() // SIGKILL; blocks until snug ITSELF is reaped
		reapedAt := time.Now()
		time.Sleep(settle)

		// ASSERTION 1, unconditional: nothing bwrap forked may still be
		// alive, on however fast or slow a host this trial ran.
		var survivors []int
		for _, pid := range candidates {
			if processAlive(pid) {
				survivors = append(survivors, pid)
			}
		}
		if len(survivors) > 0 {
			survivorLeaks++
			t.Logf("iteration %d: surviving pid(s) %v", i, survivors)
		}

		// ASSERTION 2, only meaningful once the payload actually wrote its
		// control file: did that write happen AFTER snug was confirmed
		// dead? Existence alone says nothing (see the doc comment above).
		info, statErr := os.Stat(started)
		if statErr != nil {
			t.Logf("iteration %d: the control file never appeared within the settle window — "+
				"this trial says nothing about assertion 2", i)
			continue
		}
		meaningful++
		if info.ModTime().After(reapedAt) {
			mtimeLeaks++
			t.Logf("iteration %d: control file written at %s, AFTER snug was reaped at %s",
				i, info.ModTime(), reapedAt)
		}
	}

	if survivorLeaks > 0 {
		t.Errorf("%d/%d trials left a process bwrap forked alive after snug was SIGKILLed %s "+
			"into the run — issue #101's nested pid namespace no longer closes issue #13's "+
			"residual on the offline arm", survivorLeaks, iterations, offset)
	}
	if mtimeLeaks > 0 {
		t.Errorf("%d/%d trials wrote their control file AFTER snug was confirmed reaped — "+
			"the payload ran with its supervisor already dead, issue #13's own shape",
			mtimeLeaks, iterations)
	}
	t.Logf("%d/%d trials were meaningful for assertion 2 (control file appeared within the "+
		"settle window); the rest proved only that nothing ran, which assertion 1 above "+
		"already covers", meaningful, iterations)
}
