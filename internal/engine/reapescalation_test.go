package engine

import (
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// TestStopEscalatesToSIGKILLWhenTheEngineOutlivesTheCascade drives stopLocked's
// step 3 — the SIGKILL escalation — for the first time in this repository's
// history, and is issue #344's second regression test alongside
// reapmark_test.go's TestTeardownMatchesTheArgvTheEngineIsStartedWith.
//
// stopLocked's step 3 reads:
//
//	if left := waitQuiet(e.paths(), exclude, quietBudget); len(left) > 0 {
//	    signalOwned(e.paths(), exclude, syscall.SIGKILL)
//	    if left = waitQuiet(e.paths(), exclude, killBudget); len(left) > 0 {
//	        ... the "your containers did not die with it" WARNING ...
//	    }
//	}
//
// and until this branch's fix the OUTER condition could never be true: paths()
// named the HOST socket spelling, a string no process on the machine ever
// carries, so waitQuiet's very first poll always found nothing and every line
// below it — signalOwned, the second waitQuiet, the warning — was dead code on
// every run that ever executed stopLocked (see reap.go's package comment,
// issue #344, sev:medium). That is exactly the shape CLAUDE.md names "a test
// that cannot fail is worse than no test": the escalation had a permanently
// green light for existing without once running, and nothing before this test
// could have told the difference between "it works" and "it is unreachable".
//
// The fix under test is two separate things — paths() now returns the
// recorded GUEST spelling (reap.go), and Stop now runs after the stage's own
// Pdeathsig cascade rather than at payload exit (engine.go's Detach/Stop
// split) — and neither claim, on its own, proves the SIGKILL branch actually
// fires and actually kills something. This test drives it end to end with a
// real decoy process outside snug's own process tree, kept alive across
// quietBudget by construction (see marker's own doc comment: it blocks on a
// shell `read` that nothing here closes), and asserts it is dead — by
// SIGKILL, specifically — once Stop returns.
func TestStopEscalatesToSIGKILLWhenTheEngineOutlivesTheCascade(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}
	// Spec is what RECORDS the mark (issue #344): paths() is empty until this
	// has run. A fixture that skipped it would make every assertion below
	// pass on a sweep that was never armed, which is the defect this test
	// exists to rule out.
	// noSignaturePolicy is "this host configured none", NOT nil — Spec refuses
	// nil outright as a caller that skipped ProjectHostSignaturePolicy (#307).
	// It reaches the engine as a generated policy.json under its own $HOME, so
	// no value of it changes the mark paths() records, which is all this test
	// reads out of Spec.
	if _, err := e.Spec(specPolicy(t, e, "", policy.NetPolicy{}), "/usr/bin/podman",
		[]string{"PATH=/usr/bin"}, false, "", noSignaturePolicy(t)); err != nil {
		t.Fatal(err)
	}

	marks := e.paths()
	// POSITIVE CONTROL: an empty mark set makes signalOwned/waitQuiet sweep
	// for nothing at all, and every assertion below would then pass on a Stop
	// that never looked at the decoy — the exact vacuity
	// TestOwnedPIDsMatchesOnlyThisEnginesPaths' own comment names.
	if len(marks) == 0 {
		t.Fatal("e.paths() is empty; the sweep below would look for nothing, and this test " +
			"would pass whether or not Stop ever touches the decoy")
	}

	// The decoy. marker starts a real, non-forking process — /bin/sh -c
	// 'read x' <mark> — and does not return until /proc/<pid>/cmdline is
	// confirmed to contain the mark (issue #317's arg_start window). Nothing
	// in this test closes its stdin or signals it before Stop does, so it has
	// no way to exit on its own: it survives quietBudget (2s) by
	// construction, which is what forces stopLocked's first waitQuiet to
	// still find it and take the escalation branch.
	decoy := marker(t, marks[0])

	// POSITIVE CONTROLS, restated at the point that matters to THIS test
	// rather than trusted from marker's own postcondition alone: the decoy's
	// cmdline really names the mark, and the decoy is really alive,
	// immediately before the sweep runs.
	if !cmdlineNamesPath(decoy.Process.Pid, marks) {
		t.Fatalf("decoy pid %d's cmdline does not name %v right before Stop runs — the "+
			"assertions below would not be about a process the sweep can see at all",
			decoy.Process.Pid, marks)
	}
	if err := syscall.Kill(decoy.Process.Pid, 0); err != nil {
		t.Fatalf("decoy pid %d is not alive right before Stop runs: %v", decoy.Process.Pid, err)
	}

	// Stop, the real entry point — not stopLocked directly — so the once-guard
	// and the mutex around it are exercised too. e.dialled is false (this
	// fixture never calls DialLifeline); that only suppresses stopLocked's
	// separate "answered but no mark" warning, it does not gate the sweep.
	e.Stop()

	// The decoy must be dead, and specifically by SIGKILL: it has no other way
	// to die (nothing closed its stdin, nothing else in this process signalled
	// it), so its death can only be explained by signalOwned's SIGKILL having
	// actually reached it — which only happens if the first waitQuiet found it
	// still alive and took the escalation branch this test exists to reach.
	//
	// Waited on with a BOUND, deliberately, rather than a bare
	// decoy.Process.Wait(): a mutation that breaks the escalation (SIGCONT in
	// place of SIGKILL, say) leaves the decoy genuinely alive forever — it
	// blocks on `read` and nothing but a real signal ends that — so a bare
	// Wait() would not fail this test, it would HANG it, which is a worse
	// failure than a wrong answer: the run either times out with no message
	// naming the cause, or wedges CI outright. t.Cleanup's own Kill (marker's
	// doc comment) unblocks the goroutine below whichever way this goes, so
	// nothing here leaks past the test.
	waited := make(chan *syscall.WaitStatus, 1)
	go func() {
		st, err := decoy.Process.Wait()
		if err != nil {
			waited <- nil
			return
		}
		ws, _ := st.Sys().(syscall.WaitStatus)
		waited <- &ws
	}()
	select {
	case ws := <-waited:
		if ws == nil || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			t.Fatalf("the decoy (pid %d) did not die from SIGKILL (wait status %v): Stop's "+
				"escalation either did not run at all or did not reach it", decoy.Process.Pid, ws)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the decoy (pid %d) was still alive %s after Stop() returned: Stop's SIGKILL "+
			"escalation did not reach it (a signal that does not kill, or a matcher that never "+
			"finds it, both leave the decoy running forever — this is not a race, it is a "+
			"process with nothing that can make it exit on its own)",
			decoy.Process.Pid, 5*time.Second)
	}

	// This test does NOT and cannot honestly reach the final branch — the
	// "this sandbox's containers did not die with it" warning that fires when
	// something survives the SIGKILL too. A process that ignores SIGKILL
	// cannot be constructed (the kernel does not let one), and the one thing
	// that DOES survive a SIGKILL — a zombie — reads back an EMPTY cmdline,
	// which cmdlineNamesPath already and correctly answers "not ours" to, so
	// it would never reach the warning either; it would just make waitQuiet
	// report quiet. There is no honest fixture for "signalled and still
	// there, and still identifiable", so that branch is untested here.
}
