//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTheNestingScriptStillReadsALiveSandbox runs scripts/pid-nesting.py
// against a real run, and it is a SMOKE test on purpose: the property it
// prints is owned by TestOfflineArmsIntermediateBwrapIsUnaddressableFromThe
// Payload, and asserting it twice would be two copies of one state, the
// second of which nobody updates. What has no other owner is whether the
// script still WORKS — VERIFY.md §21 tells a human to run it, and nothing but
// a human has ever done so.
//
// The failure this closes is drift, measured elsewhere in this repo rather
// than imagined: internal/profile/docexamples_test.go exists because README
// and VERIFY.md carried a profile that had stopped parsing, and VERIFY.md's
// §6j exited 77 before its expected-output fence was ever printed.
func TestTheNestingScriptStillReadsALiveSandbox(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3 on this host, so scripts/pid-nesting.py cannot be run: " + err.Error())
	}
	script := filepath.Join("..", "..", "scripts", "pid-nesting.py")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("scripts/pid-nesting.py is what VERIFY.md §21 tells a human to run: %v", err)
	}

	proj, _ := target(t)
	ready := filepath.Join(proj, "READY")
	bg := startBackgroundSnug(t, baseEnv(), proj,
		"touch "+shQuote(ready)+"; sleep 60")
	if err := waitForFile(ready, 15*time.Second); err != nil {
		t.Fatalf("the sandbox never started: %v\n%s", err, bg.output())
	}

	// PID_FILE out of the way of the sandbox: the handshake half is the
	// payload's business and this test is only grading the host half.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, script, "host")
	cmd.Env = append(os.Environ(), "PID_FILE="+filepath.Join(t.TempDir(), "BWRAP_PID"))
	out, err := cmd.CombinedOutput()
	got := string(out)
	if err != nil {
		t.Fatalf("scripts/pid-nesting.py host exited %v:\n%s", err, got)
	}

	// The verdict line, not the namespace ids: the ids differ every run, and
	// a test that pinned them would fail for the one reason that is never a
	// finding.
	if !strings.Contains(got, "=> nesting PRESENT") {
		t.Errorf("the script did not reach a verdict on a live offline run. Either it has "+
			"drifted from the process tree it reads, or the nesting itself is gone — the "+
			"tests named in this file's comment say which:\n%s", got)
	}
	// A verdict with no tree above it means the walk found nothing and the
	// script guessed, which reads as a pass to anyone skimming the output.
	if !strings.Contains(got, "bwrap") {
		t.Errorf("the script printed no bwrap line, so its verdict is not about a "+
			"sandbox:\n%s", got)
	}
}
