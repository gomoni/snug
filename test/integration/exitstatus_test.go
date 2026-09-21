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

// TestAGroupDeliveredSIGINTLetsThePayloadAnswerItFirst is what a terminal's own
// Ctrl-C does: the payload's `trap 'echo caught-sigint; exit 7' INT` fires and
// snug exits 7.
//
// THIS TEST ASSERTED THE OPPOSITE FOR A MILESTONE, and the wrong version is
// left described here because how it got that way is the useful part. It read
// "TearsDownTheWholeSandboxWithoutForwarding", required the trap NOT to fire
// and the exit to be 130, and justified that with: "issue #13's orphan window
// opens in exactly the gap a 'forward it and wait' design would leave. This is
// the correct, safety-motivated behaviour to pin."
//
// MEASURED FALSE. #13's window is a STARTUP window — teardown.go's own table
// has 0 leaks at 86-94ms and 8/8 at 110-160ms against a ~206ms payload start
// latency — and once a payload exists the cascade is armed without snug: a
// SIGKILL of snug at steady state leaves the payload dead 0/4 on BOTH
// topologies, heartbeat frozen at 0.4s and at 1.4s after snug's death. A wait
// that opens only once an init is named touches none of it.
//
// And the expectation it contradicted was the ORIGINAL one. The stage commit's
// own by-hand transcript expected exactly `caught-sigint` and exit 7; issue
// #105's guard flipped that four days later as a SIDE EFFECT, and the
// executable-checklist pass then turned the stale transcript into this test
// with #13 as its reason. Nobody ever decided the behaviour this pinned.
//
// WHY THE PAYLOAD IN PARTICULAR MATTERS HERE: it blocks in `sleep 30`, and a
// POSIX shell defers a trap until its foreground child returns. So this is the
// shape that works only when the relay signals the sandbox's process GROUP —
// what a terminal does — rather than the payload alone. A relay aimed at the
// payload alone leaves this trap unfired and the budget fully spent (measured,
// 1.018s), which is how the red team found it.
//
// "Nothing survives" is NOT asserted here on purpose: orphan_test.go owns it
// across every signal and offset, and a second copy is the copy nobody updates.
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
func TestAGroupDeliveredSIGINTLetsThePayloadAnswerItFirst(t *testing.T) {
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
	if !strings.Contains(out, "caught-sigint") {
		t.Errorf("the payload's own INT trap never ran. This payload blocks in `sleep 30`, and "+
			"a POSIX shell defers a trap until its foreground child returns — so this is the "+
			"shape that only works when the relay signals the sandbox's process GROUP rather "+
			"than the payload alone (issue #595, relayToPayload):\n%s", out)
	}
	if code := cmd.ProcessState.ExitCode(); code != 7 {
		t.Errorf("snug exited %d, want 7 — the payload handled the signal and chose its own "+
			"code, and teardownGuard.grace reports that rather than 128+signal:\n%s", code, out)
	}

	// POSITIVE CONTROL, in a plain (non-@net) sandbox with no group signal
	// involved at all: the SAME trap syntax runs to completion and snug
	// propagates its exit code unchanged when the payload signals ITSELF.
	// Without it, the assertions above would be equally true of a trap that
	// fires for some reason unrelated to the path under test.
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
