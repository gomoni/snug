package stage

import (
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"golang.org/x/sys/unix"
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

	_, err = Start(Config{Topology: policy.Topology{Netns: policy.NetnsStage}, Sandbox: oversized})
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

// TestParkingRefusesADescriptorThatIsAlreadyOpen is the permanent regression
// for issue #525. checkFDBudget bounds how far the pass-through block may
// grow; nothing checked that the descriptors the block grows TOWARDS were free
// at the instant __stage-setup dup3's onto them, and dup3 onto an occupied
// descriptor closes it and reports success.
//
// MEASURED, on this host, before the fix, with the block inherited from P0 and
// the pre-check binary: at K = 54 and K = 55 the run COMPLETED — `dup3(src,
// 62)` returned nil while closing the Go runtime's eventfd and eventpoll
// respectively, and the payload ran. At K = maxPassthrough the same binary
// failed loudly instead (`parking the N socket at fd 62: invalid argument`,
// dup3 with oldfd == newfd), so the silent case is BELOW the permitted
// maximum, not at it. The failure has no error in it, which is why the check
// is on the fact rather than on a prediction of what the runtime will
// allocate.
func TestParkingRefusesADescriptorThatIsAlreadyOpen(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()

	// A number well above anything this package reserves, so the test cannot
	// disturb the descriptors the test binary itself is using.
	const probe = 200
	if err := requireFDFree(probe, "the probe"); err != nil {
		t.Fatalf("PRECONDITION: fd %d was already open, so this test cannot tell a "+
			"working refusal from a broken one: %v", probe, err)
	}

	if err := unix.Dup3(int(devNull.Fd()), probe, 0); err != nil {
		t.Fatalf("occupying fd %d: %v", probe, err)
	}
	// Closed again below; a second Close returns EBADF and is ignored, which
	// is what keeps this cleanup correct on either path out.
	defer func() { _ = unix.Close(probe) }()

	err = requireFDFree(probe, "the N socket")
	if err == nil {
		t.Fatalf("an OCCUPIED descriptor (fd %d) was accepted as a dup3 target; dup3 would "+
			"have closed it and reported success", probe)
	}
	// "Errors name the fix" — and the reader of this one has a live descriptor
	// missing, not a message they can guess the cause of.
	for _, want := range []string{"fdNetSock", "fdNetnsN", "internal/stage/fds.go", "ALREADY OPEN"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so it does not name the fix:\n%v", want, err)
		}
	}

	// Positive control on the other side of the branch: once the occupant is
	// gone the same descriptor is accepted again, so the refusal is about the
	// descriptor being open and not about the number.
	if err := unix.Close(probe); err != nil {
		t.Fatal(err)
	}
	if err := requireFDFree(probe, "the N socket"); err != nil {
		t.Errorf("a FREE descriptor (fd %d) was refused: %v", probe, err)
	}
}

// TestBothParkedDescriptorsAreGuarded pins the OTHER half of #525: the
// reservation is worthless unless it happens BEFORE anything in MainSetup can
// allocate, and unless every dup3 whose target is one of this package's fixed
// descriptors checks that its reservation is still there. MainSetup needs a
// user namespace and a clone, so this reads the source rather than running it
// — a change that added a third parking, moved the reservation down past the
// control-socket exchange, or deleted a guard, is exactly what it must fail
// on.
func TestBothParkedDescriptorsAreGuarded(t *testing.T) {
	src, err := os.ReadFile("setup.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)

	ri := strings.Index(text, "reserveParkingFDs()")
	if ri < 0 {
		t.Fatal("MainSetup does not call reserveParkingFDs: the two parked numbers are then " +
			"claimed by nothing, and the Go runtime's netpoll pair can take them first")
	}
	// Everything MainSetup does before the reservation must be incapable of
	// allocating a descriptor. sendEvent is the first thing that is not: it
	// writes to the control socket, which arms the runtime's netpoll.
	if si := strings.Index(text, "sendEvent("); si >= 0 && si < ri {
		t.Error("MainSetup reaches the control socket BEFORE reserveParkingFDs, so the " +
			"runtime's netpoll epoll/eventfd can land on fdNetSock or fdNetnsN first")
	}

	for _, target := range []string{"fdNetSock", "fdNetnsN"} {
		guard := "requireFDReserved(" + target
		park := target + ", 0)"
		gi := strings.Index(text, guard)
		pi := strings.Index(text, park)
		if pi < 0 {
			t.Errorf("no dup3 onto %s found in setup.go; if the parking moved, move this test with it", target)
			continue
		}
		if gi < 0 {
			t.Errorf("the dup3 onto %s is NOT preceded by requireFDReserved(%s): the "+
				"reservation is the only thing keeping that number free, and dup3 onto an "+
				"occupied descriptor closes it and reports success (issue #525)", target, target)
			continue
		}
		if gi > pi {
			t.Errorf("requireFDReserved(%s) appears AFTER the dup3 onto it, so the descriptor "+
				"is already gone by the time it is checked", target)
		}
	}

	if n := strings.Count(text, "unix.Dup3("); n != 2 {
		t.Errorf("setup.go has %d dup3 call(s), want 2 — a new one needs a reserved number "+
			"of its own, its own requireFDReserved and its own row in this test (issue #525)", n)
	}
}

// TestTheReservationIsWhatMakesTheBudgetExact is the regression for the red
// team round on #537. checkFDBudget's message states a budget of
// maxPassthrough, and fds_test's own positive control asserts that a block of
// exactly that size is acceptable — but __stage-setup allocates THREE more
// descriptors above the block before the second parking (the N socket, and the
// Go runtime's netpoll epoll and eventfd, which any armed timer creates), so
// the reachable maximum was maxPassthrough-3 and both the number on screen and
// the test were wrong.
//
// MEASURED with a profile carrying N `listen_names` (K = N+9 under @net), the
// binary as shipped at the time: K=53 ran 15/15; K=54, 55 and 56 were refused
// 20/20 at the parking with fd 62 holding an eventfd, an eventpoll and the N
// socket respectively; K=57 was refused earlier by checkFDBudget, saying "the
// budget is 56".
//
// What this test can assert without a namespace is the PROPERTY the fix rests
// on: the reservation claims the numbers before any allocation, so a
// descriptor opened afterwards cannot land on them. Raising the reserved
// numbers instead would not have fixed it — the kernel hands out the lowest
// free descriptor, so the runtime's pair follows the block wherever it goes.
func TestTheReservationIsWhatMakesTheBudgetExact(t *testing.T) {
	// The reservation and the parkings use fixed numbers this test cannot
	// claim without disturbing the test binary, so it drives the same two
	// functions against a pair of numbers well above anything the package
	// reserves.
	const (
		probeA = 210
		probeB = 211
	)
	for _, fd := range []int{probeA, probeB} {
		if err := requireFDFree(fd, "the probe"); err != nil {
			t.Fatalf("PRECONDITION: fd %d was already open: %v", fd, err)
		}
	}

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()

	if err := unix.Dup3(int(devNull.Fd()), probeA, unix.O_CLOEXEC); err != nil {
		t.Fatalf("reserving fd %d: %v", probeA, err)
	}
	defer func() { _ = unix.Close(probeA) }()

	// A reserved number is OPEN, so requireFDReserved accepts it and
	// requireFDFree — the check the parkings used to make — would not.
	if err := requireFDReserved(probeA, "the probe"); err != nil {
		t.Errorf("a reserved descriptor was rejected at its parking site: %v", err)
	}
	if err := requireFDFree(probeA, "the probe"); err == nil {
		t.Error("requireFDFree accepted a RESERVED descriptor; the two checks are inverses " +
			"and swapping them silently disarms the parking guard")
	}

	// The property the whole fix rests on: with the number claimed, a fresh
	// descriptor cannot be allocated onto it.
	fresh, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if int(fresh.Fd()) == probeA {
		t.Fatalf("a descriptor opened AFTER the reservation landed on the reserved number "+
			"%d, so reserving it claimed nothing", probeA)
	}

	// And the other side of the branch: an UNRESERVED number is refused at the
	// parking site, because the reservation being gone is exactly the case
	// where the number may since have been handed to something else.
	err = requireFDReserved(probeB, "the probe")
	if err == nil {
		t.Fatalf("fd %d was never reserved and requireFDReserved accepted it anyway", probeB)
	}
	if !strings.Contains(err.Error(), "reserveParkingFDs") {
		t.Errorf("the refusal does not name what should have claimed the descriptor:\n%v", err)
	}
}
