package stage

import (
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestWaitReturnsWhenTheControlChannelClosesWithoutExited pins the property
// stage.go's own "Why this read carries no timeout and no pidfd (issue #524)"
// comment now argues for instead of a timeout or a pidfd race: Wait()'s read
// is unbounded on purpose, but P1's own death is already bounded by EOF —
// Start closes P0's copy of P1's end of the socketpair right after the fork,
// and fdseal.SealFor marks every descriptor CLOEXEC before each of P1's own
// forks, so no descendant can hold a duplicate that would keep the last write
// end open.
//
// What this test pins is the HALF of that property that lives in Wait itself:
// given an EOF, Wait returns, promptly and with an attributable error. The
// other half — that a real P1's death actually produces the EOF, no descendant
// holding a duplicate — is owned by fdseal and by
// TestTheStageClosesTheSandboxsDescriptorsAtTheFork
// (test/integration/stage_test.go), and this fake harness
// forks nothing, so it cannot and does not speak to it. Both halves are needed
// for the run-time property; only this one is a unit test.
//
// A pidfd is not the instrument that would have caught the ticket's own
// reproduction either: SIGSTOPping P1 does not make a pidfd POLLIN-ready
// (measured, stage.go's Wait comment), so racing the read against one would
// have left that case exactly as unbounded as it is documented to remain —
// nothing here re-adds that race.
//
// The positive control is TestWaitReturnsTheStatusWhenExitedArrives below:
// same fake harness, same Stage, the one difference being what the fake P1
// sends before its end closes. Without that control this test would pass
// identically on a Wait() that always returns an error, never having
// exercised the branch it claims to.
func TestWaitReturnsWhenTheControlChannelClosesWithoutExited(t *testing.T) {
	p0, p1 := fakeControlPair(t)

	const fakePID = 424242 // never a real pid; only echoed back into the error message below
	st := &Stage{control: p0, pid: fakePID}

	// The fake P1 half: closes its own end without ever sending "exited",
	// standing in for every way P1 can vanish (SIGKILL, a crash, Pdeathsig
	// firing) short of the ticket's own SIGSTOP reproduction, which by design
	// produces no EOF at all and is not what this test is about.
	p1.Close()

	type result struct {
		err error
	}
	// Read with a bound, the same shape onerequest_test.go's
	// TestTheStageReadsNoRequestAfterStart uses for the real "exited" event:
	// a regression that hangs must fail THIS test rather than the package.
	done := make(chan result, 1)
	go func() {
		_, err := st.Wait()
		done <- result{err}
	}()

	select {
	case r := <-done:
		if r.err == nil {
			t.Fatal("Wait() returned no error after the control channel closed with no " +
				"\"exited\" event ever sent")
		}
		msg := r.err.Error()
		if !strings.Contains(msg, strconv.Itoa(fakePID)) {
			t.Errorf("error does not name the stage's pid %d: %v", fakePID, r.err)
		}
		if !strings.Contains(msg, "closed the control channel") {
			t.Errorf("error does not say the control channel closed without reporting the "+
				"payload's exit: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait() never returned — issue #524's own hang, reproduced: the control " +
			"channel closed with no \"exited\" event and Wait() blocked anyway")
	}
}

// TestWaitReturnsTheStatusWhenExitedArrives is the positive control for
// TestWaitReturnsWhenTheControlChannelClosesWithoutExited above: the same
// fake harness, the same Stage, but the fake P1 sends the real "exited" event
// before its end closes. Without this, the sibling test could pass on a
// Wait() that never reads a real exit at all.
func TestWaitReturnsTheStatusWhenExitedArrives(t *testing.T) {
	p0, p1 := fakeControlPair(t)
	st := &Stage{control: p0, pid: 1}

	go func() {
		// The wire encoding of a clean exit(0): syscall.WaitStatus's own
		// underlying representation, WIFEXITED with exit code 0, is the zero
		// value (proto.go's event.WaitStatus comment).
		_ = sendEvent(p1, event{Op: "exited", WaitStatus: 0})
	}()

	type result struct {
		ws  syscall.WaitStatus
		err error
	}
	done := make(chan result, 1)
	go func() {
		ws, err := st.Wait()
		done <- result{ws, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Wait() returned an error for a real \"exited\" event: %v", r.err)
		}
		if !r.ws.Exited() || r.ws.ExitStatus() != 0 {
			t.Errorf("Wait() returned wait status %v, want a clean exit(0)", r.ws)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait() never returned for a real \"exited\" event")
	}
}
