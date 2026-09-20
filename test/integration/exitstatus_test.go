//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestExitStatusFromInsideIsNotAByteChannel pins today's wanted behaviour:
// `snug <dir> -- sh -c 'exit 137'` returns 137. SECRETS.md §5.4 measures why
// this is worth pinning rather than assuming: "Exit status is a byte channel,
// and it is fast … a stub that did not propagate status would be useless,
// because `gh` callers branch on it. Arbitrary code in the sibling does
// `exit(secret[i])`." That paragraph is about a DIFFERENT process (a
// credential-holding sibling snug has not built), but the mechanism it
// measures is generic: any future design that runs a tool ON THE PAYLOAD'S
// BEHALF and returns THAT TOOL's exit status — a wrapper that inspects,
// retries or reports on the payload — hands the payload 256 values per
// invocation to signal out with, for the cost of one `exit N`. If that design
// is ever built, it has to change what this test asserts, deliberately.
func TestExitStatusFromInsideIsNotAByteChannel(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	// Three values, not one, and the choice of which three is the control:
	// 137 and 3 are both nonzero AND distinct from each other and from 1. A
	// design that collapsed every nonzero payload exit to a fixed status (the
	// shape a WRAPPING tool's own exit code would take, and exactly the
	// failure this test exists to catch) would make 137 and 3 read identical
	// — a single-value test cannot tell "passed through" from "collapsed to
	// something that happens to equal the one value tried". 0 checks the
	// success path is not itself reported as failure.
	for _, want := range []int{137, 3, 0} {
		r := run(t, nil, proj, fmt.Sprintf("exit %d", want)).mustRun(t)
		if r.code != want {
			t.Errorf("snug <dir> -- sh -c 'exit %d' exited %d, want %d — the payload's own "+
				"exit status did not survive unchanged", want, r.code, want)
		}
	}
}

// TestASelfSignalledPayloadExitsAt128PlusTheSignal is the other half of "exit
// status is a byte channel": TestExitStatusFromInsideIsNotAByteChannel only
// ever exercises `exit N`, an ordinary return from main. A shell that kills
// ITSELF exits through a completely different kernel path — WIFSIGNALED, not
// WIFEXITED — and 128+signal is the shell's own convention for reporting that,
// not something snug computes. This pins that snug's propagation does not
// special-case one path and miss the other.
func TestASelfSignalledPayloadExitsAt128PlusTheSignal(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	r := run(t, nil, proj, `kill -TERM $$; sleep 5; echo SHOULD-NOT-PRINT`).mustRun(t)
	if r.code != 143 {
		t.Errorf("a payload that sent itself SIGTERM exited %d, want 143 (128+SIGTERM):\n%s",
			r.code, r.out)
	}
	if strings.Contains(r.out, "SHOULD-NOT-PRINT") {
		t.Errorf("the payload kept running after signalling itself:\n%s", r.out)
	}
}

// TestGroupDeliveredSIGINTTearsDownTheWholeSandboxWithoutForwarding is what a
// terminal's own Ctrl-C actually does today, and it is NOT what the deleted
// VERIFY.md's §11-adjacent transcript claimed: that transcript's own expected
// output has the payload's `trap 'echo caught-sigint; exit 7' INT` fire and
// snug exit 7. Measured here, five for five, it does not: SIGINT to the whole
// process group also reaches snug's own top-level process directly (nothing
// in the tree calls setpgid), and internal/sandbox/teardown.go's
// teardownGuard treats every signal in that position as "an orphan is
// possible, stop trusting anything downstream" — armTeardown registers SIGINT
// among teardownSignals, and teardownGuard.wait's caught-signal branch calls
// confirmTeardown (an immediate SIGKILL of the sandbox's root child) BEFORE
// reporting 128+signal, deliberately never giving whatever is running inside
// a chance to decide for itself. That comment names why: issue #13's orphan
// window opens in exactly the gap a "forward it and wait" design would leave.
// This is the correct, safety-motivated behaviour to pin — a future change
// that made snug wait for the payload's own handler would reopen that window
// — and the VERIFY.md transcript predates it, or was never re-run after it
// landed.
//
// -p @net is deliberate, not incidental: it is the one shape that puts a
// SECOND long-lived helper (the stage, which owns the netns) between P0 and
// bwrap, so confirmTeardown's kill of the stage has to cascade through an
// extra hop to reach the payload — the shape most likely to leave a survivor
// if the teardown were not as thorough as documented.
//
// Setpgid puts snug in a NEW process group before it execs, so sending SIGINT
// to -pid reaches snug and everything it forks without ever touching this
// test binary's own group — the same isolation `timeout` (without
// --foreground) gives a shell script, done here without shelling out to it.
func TestGroupDeliveredSIGINTTearsDownTheWholeSandboxWithoutForwarding(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	script := `trap 'echo caught-sigint; exit 7' INT; sleep 30`
	argv := append([]string{"-p", "@net"}, proj, "--", "/bin/sh", "-c",
		"printf '%s\\n' "+payloadMarker+"\n"+script)
	cmd := exec.Command(snugBin, argv...)
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	log, err := os.CreateTemp(t.TempDir(), "snug-sigint-group-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	cmd.Stdout, cmd.Stderr = log, log

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := cmd.Process.Pid
	killed := false
	t.Cleanup(func() {
		if !killed {
			syscall.Kill(-pgid, syscall.SIGKILL)
			cmd.Wait()
		}
	})

	deadline := time.Now().Add(15 * time.Second)
	for {
		if strings.Contains(readAll(log.Name()), payloadMarker) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the payload never started, so this test would prove nothing:\n%s",
				readAll(log.Name()))
		}
		time.Sleep(25 * time.Millisecond)
	}

	if err := syscall.Kill(-pgid, syscall.SIGINT); err != nil {
		t.Fatalf("SIGINT to process group %d: %v", pgid, err)
	}
	_ = cmd.Wait()
	killed = true

	out := readAll(log.Name())
	if code := cmd.ProcessState.ExitCode(); code != 128+int(syscall.SIGINT) {
		t.Errorf("snug exited %d, want %d (128+SIGINT) — teardownGuard.wait is supposed to "+
			"report the conventional signal-death code after confirming the sandbox is gone:\n%s",
			code, 128+int(syscall.SIGINT), out)
	}
	if strings.Contains(out, "caught-sigint") {
		t.Errorf("the payload's own INT trap ran to completion despite the group signal also "+
			"reaching snug directly — confirmTeardown is supposed to win that race and SIGKILL "+
			"the sandbox before anything downstream gets to decide for itself:\n%s", out)
	}

	// POSITIVE CONTROL, in a plain (non-@net) sandbox with no group signal
	// involved at all: the SAME trap syntax runs to completion and snug
	// propagates its exit code unchanged when the payload signals ITSELF.
	// Without this, "the trap never fired" above would be equally true of a
	// trap that cannot ever fire inside this sandbox for an unrelated reason,
	// which would make the negative above vacuous.
	r2 := run(t, nil, proj, `trap 'echo caught-sigint; exit 7' INT; kill -INT $$`).mustRun(t)
	if !strings.Contains(r2.out, "caught-sigint") {
		t.Fatalf("CONTROL: a payload that trapped and then signalled ITSELF never ran its own "+
			"trap — the mechanism does not work in this sandbox at all, so the negative result "+
			"above proves nothing:\n%s", r2.out)
	}
	if r2.code != 7 {
		t.Errorf("CONTROL: snug exited %d, want 7 (the trap's own exit code) for a "+
			"self-signalled INT with no group delivery involved:\n%s", r2.code, r2.out)
	}
}
