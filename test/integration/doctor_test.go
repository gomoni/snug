//go:build integration

package integration

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestDoctorRunsCleanOnAHostThatCanRunSnug is the regression for a gap CI found
// and the committed suite did not: `snug doctor` had no test at all.
//
// CI runs `./bin/snug doctor` as its own step, and its comment says why —
// "doctor is the first thing a human runs". But that made CI the ONLY thing
// exercising it, so a change to a constructor doctor calls could pass `make
// gate` and `make integration` locally and fail after the push. That is exactly
// what happened when issue #125's C2-gate made stage.Config.BwrapInfo required:
// doctor's stage probe is the one caller that starts a stage and deliberately
// never starts a sandbox, so it was the one caller nobody updated, and it went
// from a green tick to `🚫 snug cannot run on this host as configured` with
// exit 69.
//
// The probe it guards is not incidental. doctor's own comment argues that a
// probe which APPROXIMATES the code path can pass while the code path fails,
// which is why it calls the real stage.Start rather than re-typing the clone
// flags. This test is the same argument one level up: a `make gate` that never
// runs the binary can pass while the binary is broken.
//
// It asserts a clean exit rather than parsing the whole report, because the
// report legitimately differs by host — pasta may be absent, podman may be a
// shim, TIOCSTI may be enabled. What must not differ is that a host which CAN
// run snug is told so.
func TestDoctorRunsCleanOnAHostThatCanRunSnug(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)

	out, err := exec.Command(snugBin, "doctor").CombinedOutput()
	report := string(out)
	if err != nil {
		t.Fatalf("snug doctor failed on a host the rest of this suite runs on: %v\n%s", err, report)
	}

	// The stage line specifically, because it is the one this test was written
	// for and the one whose caller is unique. A clean exit alone would also pass
	// on a doctor that stopped probing the stage altogether.
	if !strings.Contains(report, "the stage starts") {
		t.Errorf("doctor's report does not mention the stage probe at all, so a clean exit "+
			"here proves nothing about it:\n%s", report)
	}
	if strings.Contains(report, "❌") {
		t.Errorf("doctor reported a hard failure on a host that can run snug:\n%s", report)
	}

	// The inherited-hardening block (issue #526), by the one phrase all three
	// of its arms share — all five set, some weak, or some absent — because
	// which arm fires depends on the host and this test runs on several.
	// Without this, doctor could stop reading those five knobs entirely and
	// every assertion above would still pass: the block is WARN-only by
	// design, so its disappearance costs no ❌ and no exit code.
	if !strings.Contains(report, "threat model inherits") {
		t.Errorf("doctor's report says nothing about the kernel knobs snug's threat model "+
			"inherits from the host (issue #526):\n%s", report)
	}
}
