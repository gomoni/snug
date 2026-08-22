// Package guard's engine-reap-ordering sweep is issue #344's second regression:
// a fact spread across three files and three packages that no compiler, no
// vet, and no unit test inside any one of those packages can see all of at
// once.
//
// #344 was: the teardown sweep matched the HOST spelling of the engine's
// socket, a string no process on the machine ever carried, so it verified
// nothing on every run. That half is covered in `internal/engine`, by
// reapmark_test.go's TestTeardownMatchesTheArgvTheEngineIsStartedWith and
// reapescalation_test.go's
// TestStopEscalatesToSIGKILLWhenTheEngineOutlivesTheCascade — both in that
// package, neither in this one.
//
// The fix's OTHER half is not a matcher, it is an ORDERING, and it is the one
// this file guards. `Engine.Stop`'s own sweep can only ever find something to
// verify — dead or alive — once the kernel has actually acted on the engine:
// its Pdeathsig is delivered by `forget_original_parent`, which the kernel
// runs BEFORE `do_notify_parent` wakes a blocked `wait()`. So the sweep must
// run from a position AFTER something has already waited on the stage (P1),
// never before. Three edits, each in a different package, all have to agree
// on that position:
//
//  1. internal/cli/container.go must wire eng.Stop() into the CLEANUP
//     closure and eng.Detach into onPayloadExit — never the reverse. Wiring
//     eng.Stop at payload exit is exactly what shipped and is the bug: at
//     that point runStaged has not yet run its own deferred st.Close(), so
//     the engine is alive by construction and the sweep can only go quiet by
//     waiting out the engine's own idle timeout.
//  2. internal/cli/main.go must `defer ctr.cleanup()` TEXTUALLY BEFORE it
//     calls sandbox.Run — defers run in reverse order, so a defer registered
//     first fires LAST, after sandbox.Run (and everything sandbox.Run does on
//     its own way out) has already returned.
//  3. internal/sandbox/exec.go must `defer st.Close()` TEXTUALLY BEFORE the
//     opts.OnPayloadExit() call — same reasoning, one level down: st.Close()
//     is what waits for P1 and thereby crosses the point at which the
//     kernel's Pdeathsig cascade has already been delivered to the engine,
//     and OnPayloadExit (Detach) must run inside that already-collapsing
//     window, not before it opens.
//
// Any ONE of these three edits reintroduced by itself silently reopens #344:
// nothing in internal/engine's own tests would notice, because they exercise
// stopLocked directly and never touch the wiring that decides WHEN it is
// called relative to the stage's collapse. This is why the sweep lives here,
// outside every package it reads, rather than as a unit test owned by one of
// them.
//
// EVERY REGEX BELOW IS PROVED TO MATCH TODAY'S SOURCE BEFORE IT IS TRUSTED TO
// PROVE ANYTHING'S ABSENCE (CLAUDE.md's own warning: a sweep that looks like
// proof of absence but is actually a broken pattern is how a "verified by a
// fixed-string sweep" claim in that file was itself verified wrongly). Each
// anchor's own "not found" failure is worded differently from the ordering
// failure below it, so a refactor that renames a symbol fails LOUDLY here
// rather than the sweep silently finding nothing and reporting a clean pass.
package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// readRepoFile reads a file relative to the repository root (two levels up
// from test/guard) and fails with the path if it cannot, so a moved file is a
// loud test failure rather than a silent "anchor not found" that could be
// misread as a text change.
func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	full := filepath.Join("..", "..", rel)
	b, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("cannot read %s (resolved to %s): %v — this sweep cannot check an ordering "+
			"it cannot find the source for", rel, full, err)
	}
	return string(b)
}

// mustFindOne locates re in src exactly once and returns its byte offset.
// Zero matches means the anchor this test relies on no longer exists in the
// source, which must fail the test rather than let the ordering assertion
// below it pass vacuously over two indices that are both -1 (a bug already
// caught once in this repository's history — see reap.go's package comment
// on "a check that cannot fail"). More than one match means the anchor is no
// longer unique enough to pin an ordering to, which is a different failure
// and gets a different message so the two are never confused when this test
// goes red.
func mustFindOne(t *testing.T, src, rel, label string, re *regexp.Regexp) int {
	t.Helper()
	locs := re.FindAllStringIndex(src, -1)
	if len(locs) == 0 {
		t.Fatalf("%s: %s (pattern %s) was not found at all — either the wiring this test "+
			"guards was removed, or it was renamed and this sweep needs updating with it. "+
			"Either way the ordering property below cannot be checked and must not be "+
			"reported as holding.", rel, label, re.String())
	}
	if len(locs) > 1 {
		t.Fatalf("%s: %s (pattern %s) matched %d times — it is no longer unique enough to "+
			"anchor an ordering assertion to a single position in the file", rel, label,
			re.String(), len(locs))
	}
	return locs[0][0]
}

// TestContainerRunWiresStopAtCleanupNotAtPayloadExit is edit 1 of #344's fix.
//
// The PRECONDITION check runs the same two patterns against the pre-fix text
// (issue #344's own commit message and internal/engine/reap.go's package
// comment both describe it: "onPayloadExit: eng.Stop" wired at payload exit,
// the exact bug) and requires it to be caught, before the real source is
// trusted to be clean by the same sweep.
func TestContainerRunWiresStopAtCleanupNotAtPayloadExit(t *testing.T) {
	cleanupCallsStop := regexp.MustCompile(`cleanup:\s*func\(\)\s*\{\s*p\.Close\(\);\s*eng\.Stop\(\)\s*\}`)
	payloadExitIsDetach := regexp.MustCompile(`onPayloadExit:\s*eng\.Detach`)
	payloadExitCallsStop := regexp.MustCompile(`onPayloadExit:\s*eng\.Stop\b`)

	// Precondition: the sweep must be ABLE to catch the bug it is guarding
	// against, on a fixture holding the shape #344 shipped with. Without this
	// a broken pattern that matches nothing would pass on both the buggy text
	// and the fixed text alike.
	buggyFixture := `
		return containerRun{
			cleanup:       func() { p.Close() },
			spec:          &spec,
			onEngineReady: eng.DialLifeline,
			onPayloadExit: eng.Stop,
		}, nil`
	if !payloadExitCallsStop.MatchString(buggyFixture) {
		t.Fatalf("PRECONDITION: the buggy-wiring pattern did not match its own pre-#344 " +
			"fixture — this sweep cannot be trusted to catch the real regression if it " +
			"cannot catch a synthetic one")
	}

	src := readRepoFile(t, "internal/cli/container.go")

	// Both anchors must exist in the real source, each exactly once, or the
	// wiring this test guards has been renamed out from under it.
	mustFindOne(t, src, "internal/cli/container.go", "cleanup calling eng.Stop()", cleanupCallsStop)
	mustFindOne(t, src, "internal/cli/container.go", "onPayloadExit set to eng.Detach", payloadExitIsDetach)

	// The negative: onPayloadExit must never be wired to eng.Stop, in this
	// file or anywhere the struct literal could reasonably be built. This is
	// the exact bug #344 was — Stop's own sweep running while the engine is
	// alive by construction, unable to observe anything but "still running"
	// until the engine's own idle timeout expires.
	if payloadExitCallsStop.MatchString(src) {
		t.Errorf("internal/cli/container.go wires onPayloadExit to eng.Stop — this is issue " +
			"#344's own bug: Stop's sweep would run BEFORE the stage's deferred st.Close() " +
			"has collapsed the engine, so it can only ever observe \"still running\" until " +
			"the engine's idle timeout expires on its own.")
	}
}

// TestCtrCleanupIsDeferredBeforeSandboxRun is edit 2 of #344's fix.
//
// `defer` fires in LIFO order, so `defer ctr.cleanup()` registered textually
// BEFORE the call to sandbox.Run is what makes it run AFTER sandbox.Run (and
// everything sandbox.Run's own deferred cleanup does on the way out) has
// already returned. Swap the two lines and cleanup still compiles, still
// runs, and still calls eng.Stop() — nothing else in this file would notice
// that it now runs one position earlier, back inside the window issue #344's
// fix moved it out of.
func TestCtrCleanupIsDeferredBeforeSandboxRun(t *testing.T) {
	src := readRepoFile(t, "internal/cli/main.go")

	deferCleanup := regexp.MustCompile(`defer ctr\.cleanup\(\)`)
	sandboxRun := regexp.MustCompile(`sandbox\.Run\(`)

	cleanupPos := mustFindOne(t, src, "internal/cli/main.go", "defer ctr.cleanup()", deferCleanup)
	runPos := mustFindOne(t, src, "internal/cli/main.go", "the sandbox.Run( call", sandboxRun)

	if cleanupPos >= runPos {
		t.Errorf("internal/cli/main.go: `defer ctr.cleanup()` (byte offset %d) does not appear "+
			"before the sandbox.Run( call (byte offset %d). A defer registered AFTER the call "+
			"it is meant to outlive fires BEFORE that call's own effects have finished "+
			"unwinding — here, before runStaged's own deferred st.Close() has reaped the "+
			"stage — which is exactly the ordering issue #344 depends on NOT holding.",
			cleanupPos, runPos)
	}
}

// TestStClosePrecedesOnPayloadExitInRunStaged is edit 3 of #344's fix, one
// level below TestCtrCleanupIsDeferredBeforeSandboxRun, and IT IS THE WEAKEST
// OF THE THREE — say so first, because a reader who assumes it carries the
// same weight as the other two will trust it for something it does not do.
//
// The other two pin RUNTIME ordering. This one does not, and cannot:
// opts.OnPayloadExit() (Detach) is called directly and synchronously from
// inside runStaged's own guard.wait callback, so it always executes before
// runStaged returns and therefore always executes before that function's OWN
// deferred st.Close() fires — whichever line comes first textually. Reversing
// the two lines changes nothing the Go runtime does.
//
// What the textual order still pins down is which window the call is WRITTEN
// to belong to: `defer st.Close()` registered before the call, as it is
// today, keeps the call inside the comment's own "while the engine's socket
// is still reachable" position (the exec.go comment beside opts.OnPayloadExit
// says exactly this) — the collapse has been armed but not yet run. Reversing
// the two lines does not change what the Go runtime does with either one, but
// it puts a call meant to run inside the still-alive window textually AFTER
// the mechanism that ends it, which is the shape every other ordering
// argument in this file (and in internal/engine's package comment) depends on
// a reader NOT finding — a future edit that turns opts.OnPayloadExit() into
// something order-sensitive (a second sweep, say) would silently inherit
// whichever position it happens to occupy relative to the defer, with nothing
// here to say which position was intended.
func TestStClosePrecedesOnPayloadExitInRunStaged(t *testing.T) {
	src := readRepoFile(t, "internal/sandbox/exec.go")

	deferClose := regexp.MustCompile(`defer st\.Close\(\)`)
	callOnPayloadExit := regexp.MustCompile(`opts\.OnPayloadExit\(\)`)

	closePos := mustFindOne(t, src, "internal/sandbox/exec.go", "defer st.Close()", deferClose)
	callPos := mustFindOne(t, src, "internal/sandbox/exec.go", "the opts.OnPayloadExit() call",
		callOnPayloadExit)

	if closePos >= callPos {
		t.Errorf("internal/sandbox/exec.go: `defer st.Close()` (byte offset %d) does not appear "+
			"before the opts.OnPayloadExit() call (byte offset %d) any more. The comment beside "+
			"the call site states the invariant this pins down: OnPayloadExit runs 'while the "+
			"engine's socket is still reachable', i.e. textually inside the window st.Close() "+
			"has been armed to end but has not yet ended. A refactor that reverses the two "+
			"does not change Go's own defer semantics, but it moves a call written to depend "+
			"on that window to a position no longer inside it as written.",
			closePos, callPos)
	}
}
