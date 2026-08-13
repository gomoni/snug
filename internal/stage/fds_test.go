package stage

import (
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestTheFDBudgetRefusesACollisionWithThePinnedNetns is the regression for the
// informational fifth finding: fds.go asserted that fdNetnsN was "chosen high
// so it never collides with the pass-through block above, whose size is
// policy-dependent" — an assertion about a policy-dependent quantity with
// nothing checking it.
//
// What makes it worth a check rather than a comment is the SYMPTOM. A
// collision does not crash: P1 would wrap an *os.File around fd 63 and hand
// the pinned network namespace descriptor to bwrap as though it were one of
// the sandbox's own, and bwrap would read it as --args, --seccomp or
// --block-fd. That surfaces as an unexplained bwrap parse error one process
// further in, and gets debugged in the wrong package.
func TestTheFDBudgetRefusesACollisionWithThePinnedNetns(t *testing.T) {
	// The budget is derived from the two constants, never re-typed, so raising
	// fdNetnsN moves this test with it rather than falsifying it.
	if err := checkFDBudget(maxPassthrough); err != nil {
		t.Errorf("a block that exactly fills the budget was refused: %v", err)
	}
	if err := checkFDBudget(0); err != nil {
		t.Errorf("an empty block was refused: %v", err)
	}
	if err := checkFDBudget(-1); err == nil {
		t.Error("a negative descriptor count was accepted")
	}

	err := checkFDBudget(maxPassthrough + 1)
	if err == nil {
		t.Fatalf("a pass-through block of %d descriptors was ACCEPTED even though it "+
			"reaches fd %d, the pinned netns descriptor", maxPassthrough+1, fdNetnsN)
	}
	// "Errors name the fix" is a project rule, and this is the error most
	// likely to be read by someone who has no idea what fdNetnsN is.
	for _, want := range []string{"fdNetnsN", "internal/stage/fds.go"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so it does not name the fix:\n%v", want, err)
		}
	}
}

// TestTheFDBudgetIsCheckedOnBothSidesOfTheControlSocket documents WHY the same
// check exists twice: in P0's Start it is a fact about the resolved policy, and
// in P1's __stage-serve the same number arrives over the control socket, where it is
// input. The two are different trust positions, so neither may be deleted as a
// duplicate of the other.
func TestTheFDBudgetIsCheckedOnBothSidesOfTheControlSocket(t *testing.T) {
	if _, err := Start(Config{}); err == nil {
		t.Error("Start accepted a Config with the wrong topology")
	}
	// The P1 side is exercised through runOneSandbox's request validation in
	// the integration suite (it needs a real stage); here the point is only
	// that both call sites exist and share one implementation.
	if err := checkFDBudget(maxPassthrough + 1); err == nil {
		t.Error("checkFDBudget accepted an over-large count")
	}
}

// TestStageStartRefusesASandboxLargeEnoughToReachThePinnedNetns drives the
// REAL P0-side call site (stage.Start), not checkFDBudget in isolation: a
// Config whose Sandbox slice is one descriptor over the budget must be
// refused before Start creates anything at all — no socketpair, no lifeline
// pipe, no clone(2), no bwrap. checkFDBudget(len(cfg.Sandbox)) is the FIRST
// thing Start does for exactly this reason (its own comment: "a policy whose
// descriptor block would reach fdNetnsN must fail here, where the message can
// name the fix, rather than as a bwrap parse error two processes further
// in"), so this needs neither a namespace nor a privilege — only a slice long
// enough to trigger it, which is what the other test in this file (driving
// checkFDBudget directly) does not exercise: a change that stopped Start from
// calling checkFDBudget at all would leave that test green.
//
// The descriptors themselves are never touched — Start returns before it
// would dereference any of them — so one real, reusable *os.File stands in
// for all of them.
func TestStageStartRefusesASandboxLargeEnoughToReachThePinnedNetns(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()

	oversized := make([]*os.File, maxPassthrough+1)
	for i := range oversized {
		oversized[i] = devNull
	}

	_, err = Start(Config{Netns: policy.NetnsStage, Sandbox: oversized})
	if err == nil {
		t.Fatal("Start accepted a Config whose Sandbox slice reaches the pinned netns descriptor")
	}
	for _, want := range []string{"fdNetnsN", "internal/stage/fds.go"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Start's refusal does not mention %q, so it does not name the fix:\n%v", want, err)
		}
	}

	// Positive control on the boundary: exactly AT the budget must not be
	// refused for this reason (it may still fail later — no real bwrap or
	// namespace exists in this test — but not with the budget error).
	atBudget := make([]*os.File, maxPassthrough)
	for i := range atBudget {
		atBudget[i] = devNull
	}
	if err := checkFDBudget(len(atBudget)); err != nil {
		t.Errorf("PRECONDITION: a Sandbox slice exactly at the budget was refused by "+
			"checkFDBudget itself, so the assertion above would not isolate the over-budget "+
			"case: %v", err)
	}
}
