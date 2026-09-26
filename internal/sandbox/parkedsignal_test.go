package sandbox

// Issue #605, red-team F3: once every @net run was gated, a TERM/INT/HUP caught
// while the payload was PARKED was only read by guard.wait — after the release
// byte — so the payload ran 120-420ms after the user's stop. A caught signal
// must never be followed by a release.

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCaughtReportsOnlyAPendingSignal(t *testing.T) {
	g := &teardownGuard{sig: make(chan os.Signal, 1)}
	if sig, ok := g.caught(); ok {
		t.Fatalf("caught() reported %v with nothing pending", sig)
	}
	g.sig <- syscall.SIGHUP
	sig, ok := g.caught()
	if !ok || sig != syscall.SIGHUP {
		t.Fatalf("caught() = %v, %v; want SIGHUP, true", sig, ok)
	}
}

func TestAbortBeforePayloadClaimsThenKillsTheWholeTree(t *testing.T) {
	// As in production (armTeardown): the grandchild must stay a descendant
	// of this process once its parent dies, or the sweep cannot see it.
	if err := becomeSubreaper(); err != nil {
		t.Skipf("PR_SET_CHILD_SUBREAPER unavailable on this host: %v", err)
	}
	cmd, child := spawnTwoLevelTree(t, nil)
	g := &teardownGuard{sig: make(chan os.Signal, 1), opts: Options{Warn: func(string) {}}}
	claimedWhileAlive := false
	g.onSignal(func() { claimedWhileAlive = alive(cmd.Process.Pid) && alive(child) })

	code := g.abortBeforePayload(cmd.Process.Pid, syscall.SIGTERM)
	if code != 128+int(syscall.SIGTERM) {
		t.Errorf("abortBeforePayload returned %d, want %d", code, 128+int(syscall.SIGTERM))
	}
	if !claimedWhileAlive {
		t.Error("the beforeSweep claim did not run while the tree was still alive (issue #112's order)")
	}
	_, _ = cmd.Process.Wait()
	if !waitUntil(t, 2*time.Second, func() bool { return !alive(child) }) {
		t.Errorf("pid %d survived abortBeforePayload", child)
	}
}

// Structural: in runStaged, the pending-signal look comes after the last wait
// that can hold a signal and before the release byte, and the long wait
// itself is raced against the guard.
func TestNoReleaseFollowsACaughtSignal(t *testing.T) {
	src, err := os.ReadFile("exec.go")
	if err != nil {
		t.Fatal(err)
	}
	body := funcBody(string(src), "runStaged")
	if body == "" {
		t.Fatal("PRECONDITION: no func runStaged in exec.go")
	}
	write := strings.Index(body, "release.Write(")
	look := strings.LastIndex(body, "guard.caught()")
	ready := strings.Index(body, "opts.OnEngineReady()")
	race := strings.Index(body, "case sig := <-guard.sig:")
	for name, i := range map[string]int{"release.Write(": write, "guard.caught()": look,
		"opts.OnEngineReady()": ready, "case sig := <-guard.sig:": race} {
		if i < 0 {
			t.Fatalf("PRECONDITION: runStaged no longer contains %q", name)
		}
	}
	if look > write {
		t.Error("runStaged looks for a caught signal AFTER writing the release byte: a stop " +
			"during the parked window runs the payload (F3)")
	}
	if look < ready {
		t.Error("runStaged's last signal look precedes OnEngineReady, so a signal during it is " +
			"followed by the release")
	}
	if race > ready {
		t.Error("StartSandbox is not raced against the guard")
	}
}
