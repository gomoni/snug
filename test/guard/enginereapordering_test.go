// Package guard's engine-reap-ordering sweep guards two DIFFERENT orderings
// now, #344's and #174's, each spread across files and packages that no
// compiler, no vet, and no unit test inside any one of those packages can
// see all of at once.
//
// #344 was: the teardown sweep matched the HOST spelling of the engine's
// socket, a string no process on the machine ever carried, so it verified
// nothing on every run. That half is covered in `internal/engine`, by
// reapmark_test.go's TestTeardownMatchesTheArgvTheEngineIsStartedWith and
// reapescalation_test.go's
// TestStopEscalatesToSIGKILLWhenTheEngineOutlivesTheCascade — both in that
// package, neither in this one.
//
// #344's OTHER half is not a matcher, it is an ORDERING, and it is the one
// TestContainerRunWiresStopAtCleanupNotAtPayloadExit below guards.
// `Engine.Stop`'s own sweep can only ever find something to verify — dead or
// alive — once the kernel has actually acted on the engine: its Pdeathsig is
// delivered by `forget_original_parent`, which the kernel runs BEFORE
// `do_notify_parent` wakes a blocked `wait()`. So the sweep must run from a
// position AFTER something has already waited on the stage (P1), never
// before. Three edits, each in a different package, all have to agree on
// that position:
//
//  1. internal/cli/container.go must wire eng.Stop() into the CLEANUP
//     closure — never into onPayloadExit. Wiring eng.Stop at payload exit is
//     exactly what #344 shipped and is the bug: at that point runStaged has
//     not yet run its own deferred st.Close(), so the engine is alive by
//     construction and the sweep can only go quiet by waiting out the
//     engine's own idle timeout.
//  2. internal/cli/main.go must `defer ctr.cleanup()` TEXTUALLY BEFORE it
//     calls sandbox.Run — defers run in reverse order, so a defer registered
//     first fires LAST, after sandbox.Run (and everything sandbox.Run does on
//     its own way out) has already returned.
//  3. internal/sandbox/exec.go must `defer st.Close()` TEXTUALLY BEFORE the
//     opts.OnPayloadExit() call — same reasoning, one level down: st.Close()
//     is what waits for P1 and thereby crosses the point at which the
//     kernel's Pdeathsig cascade has already been delivered to the engine,
//     and OnPayloadExit (now just Detach) must run inside that
//     already-collapsing window, not before it opens.
//
// Any ONE of these three edits reintroduced by itself silently reopens #344:
// nothing in internal/engine's own tests would notice, because they exercise
// stopLocked directly and never touch the wiring that decides WHEN it is
// called relative to the stage's collapse. This is why the sweep lives here,
// outside every package it reads, rather than as a unit test owned by one of
// them.
//
// #174 moved a DIFFERENT stop — the graceful one, asked over the engine's own
// socket before #344's SIGKILL sweep ever runs — out of P0 entirely, into
// P1's own runOneSandbox (internal/stage/serve.go). P0's own attempt at it
// MEASURED `connect: connection refused` 4/4 on a clean exit: P0's Stage.Wait
// returns the instant the "exited" event's bytes ARRIVE, and P1 is already
// exiting — taking the engine down by Pdeathsig — as it sends them. So #174
// has its own ordering, inside ONE function in ONE file, guarded by
// TestGracefulStopRunsAfterTheReapAndBeforeTheExitedEventLeaves below: the
// payload must be REAPED (<-waitDone) and the parked-sandbox record DROPPED
// (parked.disarm()) before the graceful stop asks the engine anything, and
// the stop itself must run before the "exited" event actually leaves
// (sendEvent) — that send is what tells P0, and through P0 the lifeline pipe,
// and through that the kernel's Pdeathsig cascade, that this process is done.
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
// Issue #174 emptied onPayloadExit down to a bare `eng.Detach` reference — no
// closure, nothing else runs there — because the graceful stop it used to
// carry moved into P1 (TestGracefulStopRunsAfterTheReapAndBeforeTheExitedEventLeaves,
// below, guards that new ordering). What #344 needs guarded is unchanged by
// that move: eng.Stop() belongs to cleanup, and onPayloadExit — whatever
// shape it takes — must never be the thing that calls it.
//
// The PRECONDITION check runs the buggy-wiring pattern against the pre-#344
// text (issue #344's own commit message and internal/engine/reap.go's
// package comment both describe it: "onPayloadExit: eng.Stop" wired at
// payload exit) and requires it to be caught, before the real source is
// trusted to be clean by the same sweep.
func TestContainerRunWiresStopAtCleanupNotAtPayloadExit(t *testing.T) {
	cleanupCallsStop := regexp.MustCompile(`cleanup:\s*func\(\)\s*\{\s*p\.Close\(\);\s*eng\.Stop\(\)\s*\}`)
	// onPayloadExit is a bare function VALUE since issue #174 — no closure,
	// because the only thing left to do there is drop the keepalive. A
	// closure here again would be the shape that let #344's bug hide the
	// first time: something else running before (or instead of) Detach, with
	// nothing but a live-engine race to notice which.
	onPayloadExitIsDetach := regexp.MustCompile(`onPayloadExit:\s*eng\.Detach\b`)
	onPayloadExitIsAClosure := regexp.MustCompile(`onPayloadExit:\s*func\(\)`)
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
	// Precondition for the closure negative too: a fixture holding #174's OWN
	// pre-move shape (onPayloadExit as a closure running the stop itself)
	// must be caught, or that pattern is equally untrustworthy.
	closureFixture := `onPayloadExit: func() { p.StopRunContainers(rep); eng.Detach() },`
	if !onPayloadExitIsAClosure.MatchString(closureFixture) {
		t.Fatalf("PRECONDITION: the closure-shape pattern did not match its own pre-#174-move " +
			"fixture — this sweep cannot be trusted to catch that shape reappearing if it " +
			"cannot catch a synthetic one")
	}

	src := readRepoFile(t, "internal/cli/container.go")

	// Both anchors must exist in the real source, each exactly once, or the
	// wiring this test guards has been renamed out from under it.
	mustFindOne(t, src, "internal/cli/container.go", "cleanup calling eng.Stop()", cleanupCallsStop)
	mustFindOne(t, src, "internal/cli/container.go", "onPayloadExit as a bare eng.Detach reference",
		onPayloadExitIsDetach)

	// The negative #344 is about: onPayloadExit must never be wired to
	// eng.Stop, in this file or anywhere the struct literal could reasonably
	// be built. This is the exact bug #344 was — Stop's own sweep running
	// while the engine is alive by construction, unable to observe anything
	// but "still running" until the engine's idle timeout expires.
	if payloadExitCallsStop.MatchString(src) {
		t.Errorf("internal/cli/container.go wires onPayloadExit to eng.Stop — this is issue " +
			"#344's own bug: Stop's sweep would run BEFORE the stage's deferred st.Close() " +
			"has collapsed the engine, so it can only ever observe \"still running\" until " +
			"the engine's idle timeout expires on its own.")
	}
	// The negative #174's move adds: onPayloadExit must never be a closure
	// again. A closure compiles and passes every test that does not exercise
	// a live engine whatever it contains, which is exactly how #344's bug
	// shipped the first time — this refuses the SHAPE, not just the one
	// symbol #344 named.
	if onPayloadExitIsAClosure.MatchString(src) {
		t.Errorf("internal/cli/container.go wires onPayloadExit to a closure again — issue #174 " +
			"emptied it to a bare eng.Detach reference on purpose, because the graceful stop it " +
			"used to carry now runs in P1 (internal/stage/serve.go) before P1 ever reports this " +
			"run's payload as exited. A closure here can silently grow back into doing work " +
			"issue #174 measured cannot reach a live engine from this position (`connect: " +
			"connection refused` 4/4 on a clean exit).")
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

// TestGracefulStopRunsAfterTheReapAndBeforeTheExitedEventLeaves is issue
// #174's own ordering, entirely inside internal/stage/serve.go's
// runOneSandbox — a single function, unlike #344's three-file spread, but
// no less invisible to a unit test: internal/runstop's own tests drive
// Stop() directly against an httptest fixture and never touch WHEN
// runOneSandbox calls it relative to the reap, the parked-record drop, or
// the "exited" event actually leaving down the control socket.
//
// This catches a careless re-ordering edit — swapping two of these four
// textual anchors, or moving the runstop.Stop( call above the reap or the
// disarm. It does NOT catch a refactor that moves the call into a helper
// function serve.go then calls at the right textual position: the anchors
// below are literal source strings in ONE file, not a call graph, so a
// helper extraction that preserves the four-anchor ORDER in this file still
// passes, and one that changes which function the call lives in without
// changing this file's own textual order is invisible to it either way.
// That is a real gap, not an oversight: closing it needs the runtime
// (behavioural) test test/integration/containergracefulstop_test.go already
// carries, not a wider regex.
func TestGracefulStopRunsAfterTheReapAndBeforeTheExitedEventLeaves(t *testing.T) {
	// The reap this run's payload — <-waitDone — and the drop of the
	// parked-sandbox record — parked.disarm() — that must precede the
	// graceful stop. Both anchors carry extra context because neither
	// "<-waitDone" nor "parked.disarm()" alone is unique in this file: each
	// appears a second time inside takeDown(), the abort path, textually
	// EARLIER in the same file, which would make an unqualified anchor
	// falsely report multiple matches (or resolve to the wrong occurrence).
	waitDoneThenComment := regexp.MustCompile(`<-waitDone\s*\n\s*//\s*bwrap has been reaped`)
	disarmThenVarWs := regexp.MustCompile(`parked\.disarm\(\)\s*\n\s*var ws syscall\.WaitStatus`)
	gracefulStopCall := regexp.MustCompile(`runstop\.Stop\(`)
	exitedEventSend := regexp.MustCompile(`return sendEvent\(control, ev\)`)

	// Precondition: each anchor must be able to catch itself reordered. A
	// synthetic fixture holding the SWAPPED shape — the graceful stop ahead
	// of the reap it depends on — proves the disarm/reap anchor is not
	// accidentally matching the swapped text too.
	swappedFixture := `
	rep := runstop.Stop(req.EngineSock, req.EngineRunLabel)
	<-waitDone
	// bwrap has been reaped, so its pid names nothing from here on. Dropped
	parked.disarm()
	var ws syscall.WaitStatus
	return sendEvent(control, ev)`
	if !gracefulStopCall.MatchString(swappedFixture) {
		t.Fatalf("PRECONDITION: the runstop.Stop( pattern did not match its own reordered " +
			"fixture — this sweep cannot be trusted to catch the real regression if it cannot " +
			"catch a synthetic one")
	}
	swappedStopPos := gracefulStopCall.FindStringIndex(swappedFixture)[0]
	swappedWaitPos := waitDoneThenComment.FindStringIndex(swappedFixture)[0]
	if swappedStopPos >= swappedWaitPos {
		t.Fatalf("PRECONDITION: the reordered fixture does not actually place runstop.Stop( " +
			"before <-waitDone — this fixture does not exercise the failure this test guards " +
			"against, so it proves nothing about whether the real source is clean")
	}

	src := readRepoFile(t, "internal/stage/serve.go")

	waitPos := mustFindOne(t, src, "internal/stage/serve.go",
		"<-waitDone followed by the \"bwrap has been reaped\" comment", waitDoneThenComment)
	disarmPos := mustFindOne(t, src, "internal/stage/serve.go",
		"parked.disarm() followed by var ws syscall.WaitStatus", disarmThenVarWs)
	stopPos := mustFindOne(t, src, "internal/stage/serve.go", "the runstop.Stop( call", gracefulStopCall)
	sendPos := mustFindOne(t, src, "internal/stage/serve.go",
		"the return sendEvent(control, ev) that actually sends \"exited\"", exitedEventSend)

	if !(waitPos < disarmPos && disarmPos < stopPos && stopPos < sendPos) {
		t.Errorf("internal/stage/serve.go's runOneSandbox does not order <-waitDone (%d) before "+
			"parked.disarm() (%d) before the runstop.Stop( call (%d) before the return "+
			"sendEvent(control, ev) that sends \"exited\" (%d). Issue #174 MEASURED why this "+
			"order matters: P0's own Stage.Wait returns the instant the \"exited\" event's "+
			"bytes ARRIVE, and P1 is already exiting — Pdeathsigging the engine — as it sends "+
			"them, so a graceful stop attempted from any later position, or from P0 itself, "+
			"reported `connect: connection refused` 4/4 on a clean exit.",
			waitPos, disarmPos, stopPos, sendPos)
	}
}
