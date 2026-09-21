//go:build integration

package integration

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This file owns issue #595: a payload's own signal handler gets a bounded
// window before snug kills the sandbox, and every way that could become a
// guarantee snug does not keep.
//
// WHY THE TESTS HERE SIGNAL SNUG DIRECTLY AND NEVER USE A TERMINAL. The two
// delivery paths are decided by internal/sandbox's terminalWillDeliver, and
// the one a Go test can create without a pty is the relay path: no stdio here
// is a terminal, so policy.NewSession() is true, bwrap gets --new-session, the
// payload is in a session of its own and snug's relay is the ONLY thing that
// can reach it. That is also the path that used to reach the payload on no
// host at all, so it is the one worth pinning hardest.
//
// The ^C path — where the terminal delivers and snug deliberately relays
// nothing, so the payload is never signalled twice — needs a real pty and is
// measured by hand; scripts/README.md is where a check like that would live if
// it ever earns a number.

// graceBudget mirrors internal/sandbox's payloadGraceBudget. It is duplicated
// rather than exported because a test that imported the constant could not
// fail when the constant changed: the numbers below are what the OPERATOR is
// promised, and they have to be written independently of what the code says.
const graceBudget = time.Second

// startGraceSandbox runs script under snug with no terminal on any descriptor,
// waits for it to report READY, and hands back the process and its log.
func startGraceSandbox(t *testing.T, proj, script string, snugArgs ...string) *backgroundSnug {
	t.Helper()
	bg := startBackgroundSnug(t, baseEnv(), proj, script, snugArgs...)
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(bg.output(), "GRACE-READY") {
		if time.Now().After(deadline) {
			t.Fatalf("the payload never printed GRACE-READY:\n%s", bg.output())
		}
		time.Sleep(25 * time.Millisecond)
	}
	// Past the startup window this grace deliberately does not open in: the
	// relay needs a named init, and sandboxInit.get is 0 until bwrap has
	// forked one. Signalling earlier would measure the startup path instead.
	time.Sleep(300 * time.Millisecond)
	return bg
}

func waitCode(t *testing.T, bg *backgroundSnug) int {
	t.Helper()
	err := bg.cmd.Wait()
	bg.killed = true
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		t.Fatalf("waiting for snug: %v\n%s", err, bg.output())
	}
	return 0
}

// TestAPayloadsOwnHandlerGetsToFinishOnACatchableSignal is issue #595's
// positive, on both topologies.
//
// The handler does REAL WORK — 300ms of it — and that is the whole point.
// Before this landed, the handler always ENTERED and never finished: measured
// 8/8 h-start and 0/8 h-done past ~1.5ms of shell work, on both arms. A test
// whose handler only wrote a flag would have passed against the broken code,
// because one builtin redirect fit inside the window that existed by accident.
// That is exactly how issue #595's own reproduction measured the wrong thing.
func TestAPayloadsOwnHandlerGetsToFinishOnACatchableSignal(t *testing.T) {
	budget(t, 90*time.Second)
	requireSandbox(t)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"offline", nil},
		{"staged-net", []string{"-p", "@net"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "staged-net" {
				requirePasta(t)
			}
			proj, _ := target(t)
			script := `trap 'sleep 0.3; echo HANDLER-FINISHED > "$SNUG_TARGET/grace.flag"; exit 7' TERM
echo GRACE-READY
i=0; while [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done`
			bg := startGraceSandbox(t, proj, script, tc.args...)

			if err := bg.cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatalf("signalling snug: %v", err)
			}
			code := waitCode(t, bg)

			flag := filepath.Join(proj, "grace.flag")
			data, err := os.ReadFile(flag)
			if err != nil {
				t.Fatalf("the payload's own SIGTERM handler did not get to finish: %s was never "+
					"written (%v). snug is killing the sandbox before the handler's 300ms of "+
					"work completes, which is issue #595 reopened:\n%s", flag, err, bg.output())
			}
			if !strings.Contains(string(data), "HANDLER-FINISHED") {
				t.Errorf("%s does not carry the handler's own marker: %q", flag, data)
			}
			// The payload chose 7 and reached its exit. Reporting 128+SIGTERM
			// over the top would be snug inventing an outcome — see grace's
			// own comment. This is also the exact expectation the stage
			// commit's by-hand transcript carried before issue #105's guard
			// changed it by accident.
			if code != 7 {
				t.Errorf("snug exited %d, want 7 — a payload that handled the signal and chose "+
					"its own exit code must have that code reported, not 128+signal:\n%s",
					code, bg.output())
			}
		})
	}
}

// TestAPayloadThatIgnoresTheSignalIsKilledWhenItsGraceExpires is the bound on
// the test above, and without it that one would be an argument for an
// unbounded wait.
//
// Three things at once, because they are one behaviour: the payload is gone,
// snug reports 128+signal exactly as it did before issue #595, and the whole
// thing costs about the budget rather than the payload's own choice of
// forever. A payload can make every signalled exit cost this second — that is
// payloadGraceBudget's abuse sentence — and what it cannot do is make it cost
// two.
func TestAPayloadThatIgnoresTheSignalIsKilledWhenItsGraceExpires(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	proj, _ := target(t)
	script := `trap '' TERM
echo GRACE-READY
i=0; while [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done`
	bg := startGraceSandbox(t, proj, script)

	start := time.Now()
	if err := bg.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signalling snug: %v", err)
	}
	code := waitCode(t, bg)
	elapsed := time.Since(start)

	if code != 128+int(syscall.SIGTERM) {
		t.Errorf("a snug whose payload IGNORED the signal exited %d, want %d (128+SIGTERM) — "+
			"the grace must not change what an unhandled signal reports:\n%s",
			code, 128+int(syscall.SIGTERM), bg.output())
	}
	if elapsed < graceBudget/2 {
		t.Errorf("snug exited %s after the signal, sooner than half the %s budget — the payload "+
			"ignoring the signal should have COST that budget, so this says the grace never "+
			"opened and this test is not measuring it", elapsed, graceBudget)
	}
	// Generous, because the sweep and process teardown follow the budget and
	// a loaded CI host is slow. The claim is "bounded by snug's number", not
	// a latency target.
	if limit := graceBudget + 8*time.Second; elapsed > limit {
		t.Errorf("snug took %s to exit after the signal, past %s — a payload that ignores the "+
			"signal must not be able to hold teardown past snug's own budget:\n%s",
			elapsed, limit, bg.output())
	}
}

// TestASecondSignalCutsThePayloadsGraceShort pins the operator's escape hatch.
// An operator pressing Ctrl-C twice is asking for the sweep, and a grace that
// could not be cut would be a payload holding the terminal hostage for its
// full budget however hard the human pressed.
//
// The handler sleeps far longer than the budget so that "it was cut" and "it
// finished" cannot be confused: if the second signal did nothing, this exits on
// the budget instead, and the assertion below is what separates the two.
//
// IT IS AN UPPER BOUND AND CANNOT STAND ALONE. Measured by neutering grace()
// to return immediately: this test still PASSES against a snug with no grace
// at all, because "exited quickly" is equally true of never having waited.
// What makes it mean something is the company it keeps —
// TestAPayloadThatIgnoresTheSignalIsKilledWhenItsGraceExpires fails against
// that same build, so the budget is known to exist when this one runs.
func TestASecondSignalCutsThePayloadsGraceShort(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	proj, _ := target(t)
	script := `trap 'sleep 30' TERM
echo GRACE-READY
i=0; while [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done`
	bg := startGraceSandbox(t, proj, script)

	start := time.Now()
	if err := bg.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signalling snug: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := bg.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("second signal: %v", err)
	}
	code := waitCode(t, bg)
	elapsed := time.Since(start)

	if code != 128+int(syscall.SIGTERM) {
		t.Errorf("a twice-signalled snug exited %d, want %d:\n%s",
			code, 128+int(syscall.SIGTERM), bg.output())
	}
	// The budget minus a margin: the second signal landed at 150ms, so a run
	// that waited out the full second did NOT honour it.
	if limit := graceBudget - 200*time.Millisecond; elapsed > limit {
		t.Errorf("snug took %s to exit after two signals, which is not measurably shorter than "+
			"the %s budget — the second signal must cut the grace immediately rather than "+
			"being queued behind it:\n%s", elapsed, graceBudget, bg.output())
	}
}

// TestTheGraceNeverOpensBeforeThereIsAPayloadToOweItTo is what keeps issue
// #595's grace clear of issue #13's window, and it is a TIMING claim rather
// than a behavioural one: a signal that arrives before bwrap has forked an
// init must cost nothing at all, because there is nothing to wait for.
//
// Without this, the natural implementation — wait a second on every catchable
// signal — would add a second of "snug is alive and has decided to die" to the
// exact startup interval #13 is about, and #595 assumed that was unavoidable.
// sandboxInit.get returning 0 is what makes it avoidable, and this is the
// assertion that the returning-0 path is still reached.
//
// Also an upper bound, and also unable to stand alone for the reason
// TestASecondSignalCutsThePayloadsGraceShort states: a build with no grace
// passes it. The positives in this file are what make it a measurement.
func TestTheGraceNeverOpensBeforeThereIsAPayloadToOweItTo(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	proj, _ := target(t)
	// Signalled at 25ms, which teardown.go's own table puts well inside the
	// window where no payload has started (0 leaks at 86-94ms, and payload
	// start latency is ~206ms).
	for i := 0; i < 3; i++ {
		bg := startBackgroundSnug(t, baseEnv(), proj, `echo GRACE-READY; sleep 30`)
		time.Sleep(25 * time.Millisecond)
		start := time.Now()
		if err := bg.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("signalling snug: %v", err)
		}
		_ = waitCode(t, bg)
		elapsed := time.Since(start)
		if elapsed > graceBudget {
			t.Errorf("trial %d: a snug signalled %s into its own startup took %s to exit, longer "+
				"than the %s payload grace — the grace opened where there is no payload to owe "+
				"it to, which widens issue #13's window by exactly that much:\n%s",
				i+1, 25*time.Millisecond, elapsed, graceBudget, bg.output())
		}
	}
}

// TestTheRelayReachesThePayloadThroughItsOwnSession is the mechanism test for
// the half that never worked at all: with --new-session emitted (which is what
// no-terminal stdio produces), the payload is in a session of its own, so a
// signal sent to snug — or even to snug's whole process group — cannot reach
// it. MEASURED before the relay existed: `kill -INT -<pgid>` on the whole
// group did not fire the payload's trap.
//
// It is separate from the first test in this file because that one would pass
// on a build where the terminal happened to deliver; this one asserts the
// group route is genuinely dead, so the only explanation left is snug's relay.
func TestTheRelayReachesThePayloadThroughItsOwnSession(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	proj, _ := target(t)
	script := `trap 'echo RELAYED > "$SNUG_TARGET/relay.flag"; exit 9' TERM
echo GRACE-READY
i=0; while [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done`
	bg := startGraceSandbox(t, proj, script)

	// PRECONDITION: the payload really is out of snug's process group, or the
	// relay is not what this test is measuring. bwrap's init calls setsid()
	// under --new-session, so its whole subtree leaves the group.
	pgid, err := syscall.Getpgid(bg.cmd.Process.Pid)
	if err != nil {
		t.Fatalf("reading snug's process group: %v", err)
	}
	var sameGroup int
	for _, pid := range descendantsOfPID(bg.cmd.Process.Pid) {
		if g, err := syscall.Getpgid(pid); err == nil && g == pgid {
			sameGroup++
		}
	}

	if err := bg.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signalling snug: %v", err)
	}
	code := waitCode(t, bg)

	flag := filepath.Join(proj, "relay.flag")
	if _, err := os.ReadFile(flag); err != nil {
		t.Fatalf("the payload's handler never ran (%v). With --new-session the terminal and the "+
			"process group cannot reach it, so snug's own relay is the only route and it did "+
			"not fire (%d of snug's descendants share its group):\n%s",
			err, sameGroup, bg.output())
	}
	if code != 9 {
		t.Errorf("snug exited %d, want the payload's own 9:\n%s", code, bg.output())
	}
}

// descendantsOfPID is this file's own tiny process walk. It exists rather than
// reusing the suite's other helpers because it needs no notion of "this run's
// token" — the question is only "what is under this pid right now".
func descendantsOfPID(root int) []int {
	ppid := map[int]int{}
	for _, pid := range allPIDs() {
		if p, ok := ppidOf(pid); ok {
			ppid[pid] = p
		}
	}
	var out []int
	for pid := range ppid {
		p, hops := pid, 0
		for hops < 32 {
			parent, ok := ppid[p]
			if !ok || parent <= 1 {
				break
			}
			if parent == root {
				out = append(out, pid)
				break
			}
			p, hops = parent, hops+1
		}
	}
	return out
}

// TestAHandlerBehindALongBlockingChildStillRuns is the red team's finding, and
// it is the test this file most needed and did not have.
//
// A POSIX shell defers a trap until its FOREGROUND CHILD returns. The first
// test in this file uses a payload whose foreground child is `sleep 0.05`, so
// the shell returns from it and reaches the trap well inside the budget — and
// it passed against a relay that signalled the payload ALONE. Put a long child
// there instead, which is the commonest real shape (`trap cleanup TERM;
// some-long-command`), and that relay never got the handler run at all:
// MEASURED at the time, the trap did not fire and the run burned the whole
// 1.018s before the sweep.
//
// So the earlier measurement was true and proved less than it looked — the
// exact error this branch accuses issue #595's own reproduction of. The relay
// now signals the sandbox's process GROUP, which is what a terminal does, and
// the child dies so the shell reaches its trap.
//
// The timing assertion is the discriminating half: "the trap eventually ran"
// would also be true of a payload the sweep killed, so this requires the
// handler to have run WELL INSIDE the budget rather than at the end of it.
func TestAHandlerBehindALongBlockingChildStillRuns(t *testing.T) {
	budget(t, 90*time.Second)
	requireSandbox(t)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"offline", nil},
		{"staged-net", []string{"-p", "@net"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "staged-net" {
				requirePasta(t)
			}
			proj, _ := target(t)
			// `sleep 300` is the point: it outlasts the budget by two orders
			// of magnitude, so the trap can only run if the CHILD was
			// signalled too.
			script := `trap 'echo TRAPPED-BEHIND-CHILD > "$SNUG_TARGET/blocked.flag"; exit 7' TERM
echo GRACE-READY
sleep 300`
			bg := startGraceSandbox(t, proj, script, tc.args...)

			start := time.Now()
			if err := bg.cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatalf("signalling snug: %v", err)
			}
			code := waitCode(t, bg)
			elapsed := time.Since(start)

			flag := filepath.Join(proj, "blocked.flag")
			if _, err := os.ReadFile(flag); err != nil {
				t.Fatalf("a payload blocked in `sleep 300` never ran its TERM handler (%v). The "+
					"relay reached the shell but not its foreground child, so the shell "+
					"deferred the trap until a child that outlasts the budget returned:\n%s",
					err, bg.output())
			}
			if code != 7 {
				t.Errorf("snug exited %d, want the payload's own 7:\n%s", code, bg.output())
			}
			if elapsed > graceBudget-200*time.Millisecond {
				t.Errorf("the handler ran, but only after %s of a %s budget — that is the sweep "+
					"winning and the flag being written on the way out, not the payload being "+
					"given its window:\n%s", elapsed, graceBudget, bg.output())
			}
		})
	}
}

// TestASignalledRunCanReportThePayloadsOwnZero pins the contract the red team
// asked be made explicit, INCLUDING the part an operator may not want.
//
// A payload that traps the signal and exits 0 makes a signalled run report 0.
// A CI harness that deadline-kills snug and gates on $? alone can therefore be
// shown success for a run it force-stopped. That is the deliberate trade — the
// payload already chooses the code on every normal exit, and reporting
// 128+signal over a handler that ran and chose would be snug inventing an
// outcome — but it is a CHANGE, so it is pinned here rather than left to be
// discovered. Its companion is the ignoring payload, which still reports
// 128+signal, and the pair is what a future change would have to break
// deliberately.
func TestASignalledRunCanReportThePayloadsOwnZero(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	proj, _ := target(t)
	script := `trap 'exit 0' TERM
echo GRACE-READY
sleep 300`
	bg := startGraceSandbox(t, proj, script)
	if err := bg.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signalling snug: %v", err)
	}
	if code := waitCode(t, bg); code != 0 {
		t.Errorf("a payload that trapped SIGTERM and exited 0 made snug exit %d, want 0. If "+
			"this is now 128+SIGTERM the contract changed and the CI-visibility trade in "+
			"grace's own comment is stale:\n%s", code, bg.output())
	}
}
