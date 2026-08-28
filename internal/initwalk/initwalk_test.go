package initwalk

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// The walk's whole safety is the foreign-user-namespace test: a record built
// from a walked pid is a record internal/cli's killOrphanInit will later
// SIGKILL on, so both directions are asserted here. A test that only proved it
// FINDS the init would also pass on a version that returns the first child it
// sees — and on the staged arm that version would name bwrap, which shares the
// caller's user namespace (see this package's own doc comment).

func TestTheWalkFindsAChildInItsOwnUserNamespace(t *testing.T) {
	ours, err := NamespaceInode(os.Getpid(), "user")
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("/bin/sleep", "30")
	// Exactly bwrap's shape at the instant that matters: the child is inside
	// its new user namespace from its first instruction, so the walk does not
	// depend on any settle.
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}
	if err := cmd.Start(); err != nil {
		t.Skipf("this host will not create an unprivileged user namespace: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	var got int
	deadline := time.Now().Add(2 * time.Second)
	for {
		pid, found, gone := ForeignUsernsChild(os.Getpid(), ours)
		if found {
			got = pid
			break
		}
		if gone {
			t.Fatal("the walk reported this test process gone while it is running")
		}
		if time.Now().After(deadline) {
			t.Fatal("the walk never found a child in a foreign user namespace")
		}
		time.Sleep(time.Millisecond)
	}
	if got != cmd.Process.Pid {
		t.Errorf("the walk named pid %d, want %d — the only child of this process in a "+
			"user namespace that is not ours", got, cmd.Process.Pid)
	}
}

// THE CONTROL, and it is the one that matters: an ordinary child — a helper,
// a payload's sibling, anything snug starts — shares this process's user
// namespace and must never be named. Naming one would put a stranger's pid in
// the orphan-kill record.
func TestTheWalkIgnoresAChildSharingOurUserNamespace(t *testing.T) {
	ours, err := NamespaceInode(os.Getpid(), "user")
	if err != nil {
		t.Fatal(err)
	}

	// An intermediate, so the walk looks at a parent whose children this test
	// controls entirely — `go test` itself may have others.
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 & wait")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pid, found, _ := ForeignUsernsChild(cmd.Process.Pid, ours)
		if found {
			t.Fatalf("the walk named pid %d, a child in THIS process's own user namespace; "+
				"a record built from it would make the next run's sweep kill a stranger", pid)
		}
		time.Sleep(time.Millisecond)
	}
}

// A bwrap that exits without forking ends the walk rather than spinning to the
// timeout — the difference between a goroutine that lives microseconds and one
// that lives initWatchTimeout on every failed start.
func TestTheWalkStopsWhenTheProcessItWatchesIsGone(t *testing.T) {
	cmd := exec.Command("/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	ours, err := NamespaceInode(os.Getpid(), "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, found, gone := ForeignUsernsChild(cmd.Process.Pid, ours); found || !gone {
		t.Errorf("walking a reaped pid gave found=%v gone=%v, want false/true", found, gone)
	}
}

// ── NSpidChain / ChildWithReportedPID: the depth arithmetic (issue #101) ────
//
// ChildWithReportedPID's whole correctness rests on one line:
// idx := len(NSpidChain(parent)) - 1. Get that wrong and hostInitPID either
// mistranslates bwrap's --info-fd answer into an unrelated host pid (a
// record killOrphanInit later SIGKILLs) or stops translating the ordinary,
// unnested case at all. These three tests pin the arithmetic at both depths
// it has to handle: a parent sharing this process's own pid namespace
// (today's staged arm, index 0 — an identity) and a parent that is pid 1 of a
// pid namespace of its own (the offline arm's nested construction,
// exec.go's SysProcAttr, index 1).

// TestNSpidChainOfAPlainChildIsOneElement is the baseline NSpidChain has to
// give for ChildWithReportedPID's index-0 case to be correct at all: a
// process with no pid namespace of its own reports only the one pid this
// test's own namespace already knows it by.
func TestNSpidChainOfAPlainChildIsOneElement(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	chain, err := NSpidChain(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 || chain[0] != cmd.Process.Pid {
		t.Errorf("NSpidChain(%d) = %v, want the single-element chain [%d] — this process "+
			"shares this test's own pid namespace and has none of its own",
			cmd.Process.Pid, chain, cmd.Process.Pid)
	}
}

// TestChildWithReportedPIDTranslatesOneLevelOfNesting reproduces the shape
// exec.go's offline arm creates: a process (standing in for bwrap) that is
// pid 1 of a pid namespace of its own, one level below this test's. Measured
// on that arm: "child 1071736 ... NSpid: 1071736  2  1" — bwrap reported "2"
// for its own child, and NSpid[1] of that child is exactly 2. This test is
// that shape with a two-level chain instead of three, which is all the
// arithmetic needs to get right: idx = len(parentChain)-1 = 1.
func TestChildWithReportedPIDTranslatesOneLevelOfNesting(t *testing.T) {
	np := exec.Command("/bin/sh", "-c", "sleep 30 & wait")
	np.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}},
	}
	if err := np.Start(); err != nil {
		t.Skipf("this host will not create an unprivileged user+pid namespace: %v", err)
	}
	t.Cleanup(func() { _ = np.Process.Kill(); _, _ = np.Process.Wait() })

	parentChain, err := NSpidChain(np.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if len(parentChain) != 2 || parentChain[1] != 1 {
		t.Fatalf("NSpidChain(%d) = %v, want [<host pid>, 1] — np must be pid 1 of a pid "+
			"namespace of its own for this test to measure the depth ChildWithReportedPID "+
			"is for", np.Process.Pid, parentChain)
	}

	child, found := waitForAnyChild(t, np.Process.Pid)
	if !found {
		t.Fatal("np never forked the child this test needs")
	}

	childChain, err := NSpidChain(child)
	if err != nil {
		t.Fatal(err)
	}
	idx := len(parentChain) - 1
	if idx != 1 || len(childChain) <= idx {
		t.Fatalf("child %d's NSpid chain is %v, too short to read index %d", child, childChain, idx)
	}
	reported := childChain[idx]

	got, foundIt, _ := ChildWithReportedPID(np.Process.Pid, reported)
	if !foundIt || got != child {
		t.Errorf("ChildWithReportedPID(%d, %d) = (%d, %v), want (%d, true) — the depth "+
			"arithmetic must read np's OWN pid-namespace view of the child, exactly what "+
			"bwrap reports on --info-fd one level down", np.Process.Pid, reported, got, foundIt, child)
	}
}

// TestChildWithReportedPIDIsIdentityWhenParentSharesOurPidNamespace is the
// other depth ChildWithReportedPID has to get right: today's staged arm,
// where bwrap shares the caller's own pid namespace and its --info-fd answer
// is already a host pid. idx is 0 and the translation is a no-op.
func TestChildWithReportedPIDIsIdentityWhenParentSharesOurPidNamespace(t *testing.T) {
	parent := exec.Command("/bin/sh", "-c", "sleep 30 & wait")
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Process.Kill(); _, _ = parent.Process.Wait() })

	parentChain, err := NSpidChain(parent.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if len(parentChain) != 1 {
		t.Fatalf("NSpidChain(%d) = %v, want a single element — this parent was started with "+
			"no pid namespace of its own, the shape this test needs", parent.Process.Pid, parentChain)
	}

	child, found := waitForAnyChild(t, parent.Process.Pid)
	if !found {
		t.Fatal("parent never forked the child this test needs")
	}

	got, foundIt, _ := ChildWithReportedPID(parent.Process.Pid, child)
	if !foundIt || got != child {
		t.Errorf("ChildWithReportedPID(%d, %d) = (%d, %v), want (%d, true) — with parent "+
			"sharing the caller's own pid namespace this translation must be an identity",
			parent.Process.Pid, child, got, foundIt, child)
	}
}

// waitForAnyChild polls walkChildren for the first child of parent, however
// long that fork takes to land in /proc.
func waitForAnyChild(t *testing.T, parent int) (pid int, found bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		pid, found, gone := walkChildren(parent, func(int) bool { return true })
		if found {
			return pid, true
		}
		if gone || time.Now().After(deadline) {
			return 0, false
		}
		time.Sleep(time.Millisecond)
	}
}
