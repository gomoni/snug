package engine

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestPathsIsEmptyUntilSpecHasRun is issue #344's third regression test,
// alongside reapmark_test.go's TestTeardownMatchesTheArgvTheEngineIsStartedWith
// and reapescalation_test.go's TestStopEscalatesToSIGKILLWhenTheEngineOutlivesTheCascade.
//
// paths() answering EMPTY before Spec has run is a decision, not an oversight —
// reap.go's own doc comment on paths() says so, and the reasoning is worth
// restating here because it is the thing this test guards: the alternative,
// falling back to e.sock (the HOST socket spelling), would be indistinguishable
// from a working sweep while matching a string no command line on the machine
// carries. That is exactly the shape #344 was. So paths() is deliberately unfit
// to sweep with until Spec has recorded the GUEST spelling the engine's argv
// actually gets exec'd with.
//
// The positive control is the whole second half of this test. Without it, an
// Engine whose paths() is simply broken — returns nil unconditionally, say —
// would satisfy "empty before Spec" perfectly and this test would report a
// working decision that in fact never engages.
func TestPathsIsEmptyUntilSpecHasRun(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
	if err != nil {
		t.Fatal(err)
	}

	if got := e.paths(); len(got) != 0 {
		t.Fatalf("paths() on a fresh Engine (Spec never run) = %v, want empty — "+
			"a fallback to e.sock here is exactly the defect issue #344 was", got)
	}

	// noSignaturePolicy is "this host configured none", NOT nil — Spec refuses
	// nil outright as a caller that skipped ProjectHostSignaturePolicy (#307).
	if _, err := e.Spec(specPolicy(t, e, "", policy.NetPolicy{}), "/usr/bin/podman",
		[]string{"PATH=/usr/bin"}, false, noSignaturePolicy(t)); err != nil {
		t.Fatalf("Spec: %v", err)
	}

	// POSITIVE CONTROL. Without this, "paths() is empty before Spec" passes on
	// an Engine whose paths() is broken and returns nil always — proving
	// nothing about the before/after distinction the doc comment claims.
	if got := e.paths(); len(got) == 0 {
		t.Fatal("paths() is still empty after Spec ran and recorded the engine's socket mark — " +
			"either Spec stopped recording guestSock, or paths() stopped reading it. Either way " +
			"the before/after distinction this test exists to prove does not hold, and every " +
			"other test in this package that calls paths() after Spec is trusting a fiction")
	}
}

// captureStderr redirects os.Stderr for the duration of fn and returns
// whatever was written to it, restoring the original descriptor afterward.
//
// This package's tests do not run with t.Parallel (none of the sibling files
// use it, and stopLocked itself does real filesystem teardown that is not
// safe to interleave), so a process-global swap of os.Stderr is safe here:
// nothing else in this package's test binary is writing to it concurrently.
// If a future test in this package adds t.Parallel, this helper stops being
// safe and must not be reused blind.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("captureStderr: os.Pipe: %v", err)
	}
	os.Stderr = w

	read := make(chan string, 1)
	go func() {
		buf, _ := io.ReadAll(r)
		read <- string(buf)
	}()

	fn()

	os.Stderr = orig
	if err := w.Close(); err != nil {
		t.Fatalf("captureStderr: closing write end: %v", err)
	}
	out := <-read
	if err := r.Close(); err != nil {
		t.Fatalf("captureStderr: closing read end: %v", err)
	}
	return out
}

// reconciliationWarning is the substring engine.go's stopLocked prints when
// the lifeline was dialled but paths() has no mark to sweep with. Matched as a
// substring rather than the whole message so this test does not have to track
// unrelated wording changes to the rest of the sentence.
const reconciliationWarning = "no command-line mark to look for"

// TestStopLockedReconcilesADialledLifelineWithNoMark is issue #344's fourth
// regression test.
//
// paths() answering empty is a correct, deliberate answer right up until the
// moment something actually dialled the engine's lifeline — DialLifeline
// requires a socket that already exists, so a dialled lifeline with no
// recorded mark means Spec never ran, or ran and did not record guestSock:
// either way the sweep is about to verify nothing while looking exactly like
// it verified something. engine.go's own comment above the check calls this
// "a wiring bug, not an engine-less run", and stopLocked's step 3 prints a
// named warning rather than sweeping vacuously (see the comment directly above
// `if e.dialled && len(e.paths()) == 0` in engine.go).
//
// Both arms are asserted, because a warning that always fires is exactly as
// useless as one that never does — either failure mode is a silent downgrade
// of invariant 5 (CLAUDE.md: "no silent downgrade, ever"). e.dialled is set
// directly rather than through DialLifeline: this is an in-package test and
// DialLifeline needs a real socket accepting connections, which is exactly the
// machinery this test is not about — it is about what stopLocked does with
// the FLAG, not about how the flag gets set honestly in production.
func TestStopLockedReconcilesADialledLifelineWithNoMark(t *testing.T) {
	t.Run("fires when dialled and no mark exists", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", t.TempDir())
		e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
		if err != nil {
			t.Fatal(err)
		}

		// POSITIVE CONTROL for the fixture itself: Spec never ran, so paths()
		// really is empty here. Without this check, a fixture that
		// accidentally recorded a mark would make the assertion below
		// meaningless — the warning would then correctly NOT fire, for the
		// wrong reason (a mark existing) rather than the right one (dialled
		// being false, which it isn't here).
		if got := e.paths(); len(got) != 0 {
			t.Fatalf("fixture is broken: paths() = %v, want empty — this arm needs a "+
				"dialled-but-markless engine, and this one already has a mark", got)
		}

		e.mu.Lock()
		e.dialled = true
		e.mu.Unlock()

		out := captureStderr(t, func() {
			e.stopLocked()
		})

		if !strings.Contains(out, reconciliationWarning) {
			t.Errorf("stopLocked printed nothing about the wiring bug when dialled=true and "+
				"paths() was empty — a dialled lifeline with no mark went unreported, which is "+
				"the vacuous-sweep half of issue #344 reopened under a different name.\n"+
				"stderr was:\n%s", out)
		}
	})

	t.Run("does not fire in the ordinary case", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", t.TempDir())
		e, err := New(testPol([]policy.ProfileName{"@podman-socket"}, "/proj"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Spec(specPolicy(t, e, "", policy.NetPolicy{}), "/usr/bin/podman",
			[]string{"PATH=/usr/bin"}, false, noSignaturePolicy(t)); err != nil {
			t.Fatalf("Spec: %v", err)
		}

		// POSITIVE CONTROL for the fixture: the mark really is there before
		// stopLocked runs. Without this, a fixture whose Spec silently failed
		// to record guestSock would make "the warning did not fire" trivially
		// true for the wrong reason.
		if got := e.paths(); len(got) == 0 {
			t.Fatal("fixture is broken: paths() is empty after Spec ran — this arm needs a " +
				"real mark on record, and there isn't one")
		}

		e.mu.Lock()
		e.dialled = true
		e.mu.Unlock()

		out := captureStderr(t, func() {
			e.stopLocked()
		})

		if strings.Contains(out, reconciliationWarning) {
			t.Errorf("stopLocked printed the wiring-bug warning even though Spec recorded a "+
				"real mark — a warning that fires unconditionally is as useless as one that "+
				"never fires; it teaches a human to ignore snug's own diagnostics.\n"+
				"stderr was:\n%s", out)
		}
	})
}
