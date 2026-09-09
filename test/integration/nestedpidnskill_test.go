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
// THE WINDOW this test needs to land the SIGKILL inside is bounded on one
// side by "the sandbox's own init exists" and on the other by "the payload
// has written its control file" — both host-speed dependent, so a fixed
// sleep between starting snug and killing it either lands too early on a
// slow or loaded host (nothing exists yet to leak) or too late on a fast one
// (assertion 2 below is never meaningful). Both edges are widened directly
// instead of guessed at with a constant, and the near edge only landed on
// its current predicate after two OTHER predicates were tried and measured
// wrong — recorded here because that measurement, not the winning line, is
// what stops a future edit reintroducing either mistake:
//
//   - "Any descendant of snug" stops too EARLY. snug forks an unrelated
//     `ssh -G -v … snug-probe.invalid` child of its own before it ever
//     builds a sandbox
//     (internal/cli/sshconfig.go's host ssh_config probe) — present around
//     15-20ms into every run and gone some 20ms later, never touching bwrap.
//     A 5ms /proc timeline taken this session shows the poll stopping on
//     that probe and calling killAndWait before bwrap has even started:
//     against a build with exec.go's SysProcAttr deliberately reverted, this
//     predicate measured 0/6 leaks on both assertions, in both a quiet and a
//     loaded run — the "positive control" was controlling for the wrong
//     process.
//   - "A descendant whose comm is the payload's own shell" stops too LATE.
//     The same timeline shows bwrap forking ITS OWN internal init (its
//     `--unshare-pid` child, one level below the bwrap snug directly forked)
//     around 90-110ms, and the payload only appearing around 200-225ms —
//     by which point whatever race bwrap's init loses when it loses at all
//     has already been decided. Same reverted build, same measurement
//     method: 0/6 leaks.
//   - The predicate that actually lands inside the window: TWO of bwrap's
//     own processes present as descendants — the outer one snug forked
//     directly, and the inner one bwrap forks OF ITSELF once it unshares the
//     sandbox's own pid namespace. That inner process is "bwrap's OWN init"
//     in internal/sandbox/teardown.go's header, the process whose
//     late-arming die-with-parent is issue #13's original defect, and its
//     appearance (90-131ms across these trials) lines up with the onset
//     teardown.go's own header measured independently (leaks starting
//     around a 94-102ms offset). Confirmed both directions, 3 quiet runs and
//     3 fork-storm-loaded runs each, same session: the reverted build leaks
//     6/6 on both assertions every single run, and the unmodified fix leaks
//     0/6 every single run.
//   - FAR edge: the payload sleeps briefly before its own touch (see the
//     script below), pushing the write assertion 2 depends on well past the
//     handful of milliseconds bwrap needs to fork, on any host.
//
// TWO INDEPENDENT ASSERTIONS, NEITHER TIED TO ONE MACHINE'S TIMING.
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
//     An earlier version of this test treated "the control file exists" as
//     this half, which baked in a specific host's payload-start latency:
//     CI's ubuntu-latest runner used to start the payload well under the
//     fixed offset that version killed at, so the file already existed
//     before snug was even killed, on every trial, on a branch that leaks
//     nothing — a false failure with no leak behind it. The payload's own
//     delay before its touch (the FAR edge, above) is what keeps this half
//     meaningful instead of vacuous on a fast host.
//
// The file's mere ABSENCE says nothing either way — a trial that never got
// far enough to write it proves only that nothing leaked when nothing ran,
// which is why it is a precondition for assertion 2 rather than a pass or a
// fail.
func TestSIGKILLBeforeThePayloadStartsLeavesNoInit(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	const iterations = 6
	const pollInterval = 5 * time.Millisecond
	const forkDeadline = 5 * time.Second

	// nestedBwrapCount is the near edge's predicate — see THE WINDOW above
	// for what the other two candidates got wrong and how this one was
	// measured to land inside it: two of bwrap's own processes present as
	// descendants of snug means bwrap's own internal init (its
	// `--unshare-pid` child) exists, which is the earliest point a leak of
	// issue #13's shape is structurally possible.
	const nestedBwrapCount = 2

	// settle must stay comfortably above the payload's own pre-touch delay
	// (300ms, in the script below) or a leaking trial's touch could land
	// AFTER the settle window has already closed, and assertion 2 would see
	// nothing where a real leak occurred: 800ms leaves it a ~2.7x margin.
	const settle = 800 * time.Millisecond

	var survivorLeaks, mtimeLeaks, meaningful int
	for i := 1; i <= iterations; i++ {
		proj, _ := target(t)
		started := filepath.Join(proj, "started")

		bg := startBackgroundSnug(t, baseEnv(), proj,
			"sleep 0.3; touch "+shQuote(started)+"; sleep 120")

		// NEAR EDGE and POSITIVE CONTROL for assertion 1: poll until
		// nestedBwrapCount of bwrap's own processes exist, rather than
		// sleeping a fixed offset and hoping it landed inside the window.
		// A poll that never reaches that count means the run never got far
		// enough for a leak to be possible — a real failure, not a
		// host-speed reading — and the poll's own success IS the positive
		// control: it cannot pass without first observing the exact
		// process whose survival assertion 1 below is checking for.
		deadline := time.Now().Add(forkDeadline)
		var candidates []int
		for {
			candidates = descendantsOf(bg.cmd.Process.Pid)
			bwraps := 0
			for _, pid := range candidates {
				if commOf(pid) == "bwrap" {
					bwraps++
				}
			}
			if bwraps >= nestedBwrapCount {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("iteration %d: snug (pid %d) never reached %d nested bwrap processes "+
					"within %s of start — this run never entered the window this test needs",
					i, bg.cmd.Process.Pid, nestedBwrapCount, forkDeadline)
			}
			time.Sleep(pollInterval)
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
		t.Errorf("%d/%d trials left a process bwrap forked alive after snug was SIGKILLed — "+
			"issue #101's nested pid namespace no longer closes issue #13's residual on the "+
			"offline arm", survivorLeaks, iterations)
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
