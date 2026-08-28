package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/initwalk"
)

// watchForInit must not call OnInit for something that is not an init, and
// must not block its caller. A bwrap with no children at all is the shape.
func TestWatchForInitNamesNothingWhenThereIsNoInit(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	named := make(chan int, 4)
	started := time.Now()
	watchForInit(cmd.Process.Pid, Options{OnInit: func(pid int) { named <- pid }}, &initReporter{})
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Errorf("watchForInit blocked its caller for %v; it must return immediately", elapsed)
	}

	select {
	case pid := <-named:
		t.Errorf("OnInit was called with pid %d for a process that forked nothing", pid)
	case <-time.After(100 * time.Millisecond):
	}
}

// The regression test for the collision the integration suite found on the
// first run after the walk landed: two namers, one process, and
// writeTargetFile's temp name is keyed by pid — so two OnInit calls raced on
// one filename and the run ended with NO record of its init at all. Exactly
// one call, whichever source gets there first.
func TestTheInitIsNamedExactlyOnceHoweverManySourcesRace(t *testing.T) {
	var named initReporter
	calls := make(chan int, 16)
	opts := Options{OnInit: func(pid int) { calls <- pid }}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()
			named.report(opts, pid)
		}(1000 + i)
	}
	wg.Wait()
	close(calls)

	n := 0
	for range calls {
		n++
	}
	if n != 1 {
		t.Errorf("OnInit was called %d times; a second concurrent call is two writers on one "+
			"temp filename and the measured outcome was a run with no init record", n)
	}
}

// TestWatchForInitNamesBwrapsChildNotOneSharingBwrapsNamespace is redteam
// finding F4: since issue #101 gave the offline arm's bwrap a user namespace
// of its own (exec.go's SysProcAttr), watchForInit's identity test has to
// compare a candidate against BWRAP's own namespace, not snug's — see
// initwalk's package comment for why the two spellings agreed before #101 and
// stop agreeing the moment bwrap does not share the caller's user namespace.
//
// This test builds exactly the shape that makes them disagree: a fake
// "bwrap" (fake) in a user namespace foreign to this test process, with TWO
// children — an ORDINARY one sharing fake's own namespace (nothing
// interesting about it, the kind of process a future bwrap change might
// start alongside its init) and one that unshares into a namespace of its
// own, standing in for the real sandbox init. Comparing against fake's own
// namespace (watchForInit's actual spelling) correctly skips the ordinary
// child and names only the second. Comparing against this test process's own
// namespace — the pre-#101 spelling — cannot tell the two apart, because both
// read as "foreign" to it; whichever one /proc lists first would be named,
// and named is what killOrphanInit later SIGKILLs.
//
// redteam measured this is not exploitable TODAY: a real bwrap-outer has
// exactly one child for the life of a run, even loaded with 60 double-forked
// orphans and 20 setsid daemons, because find_new_reaper's subreaper search
// stops at the pid-namespace boundary and reparents any orphan to the
// sandbox's own init rather than to bwrap-outer. This test guards the
// invariant against that ever stopping being true — it is not evidence of a
// hole open now.
func TestWatchForInitNamesBwrapsChildNotOneSharingBwrapsNamespace(t *testing.T) {
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare(1) is not installed")
	}

	fake := exec.Command("/bin/sh", "-c", "sleep 30 & unshare -U sleep 30 & wait")
	fake.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}},
	}
	if err := fake.Start(); err != nil {
		t.Skipf("this host will not create an unprivileged user namespace: %v", err)
	}
	t.Cleanup(func() { _ = fake.Process.Kill(); _, _ = fake.Process.Wait() })

	fakeNS, err := initwalk.NamespaceInode(fake.Process.Pid, "user")
	if err != nil {
		t.Fatal(err)
	}
	callerNS, err := initwalk.NamespaceInode(os.Getpid(), "user")
	if err != nil {
		t.Fatal(err)
	}
	// POSITIVE CONTROL: the two references this test compares against must
	// actually differ, or nothing below distinguishes anything.
	if fakeNS == callerNS {
		t.Fatal("fake's user namespace equals this test process's own — CLONE_NEWUSER did " +
			"not do what this test needs")
	}

	var ordinary, nested int
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, kid := range childrenOf(t, fake.Process.Pid) {
			ns, err := initwalk.NamespaceInode(kid, "user")
			if err != nil {
				continue
			}
			switch ns {
			case fakeNS:
				ordinary = kid
			case callerNS:
				// impossible by construction, but never call it "nested" if so
			default:
				nested = kid
			}
		}
		if ordinary != 0 && nested != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("fake never forked both children (ordinary=%d nested=%d)", ordinary, nested)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The two candidates this test built, confirmed to have the properties
	// their names claim: ordinary shares fake's OWN namespace (so the
	// correct spelling must skip it), and it is ALSO foreign to this test
	// process's namespace (so the pre-#101 spelling could name it too — the
	// whole defect).
	if ns, _ := initwalk.NamespaceInode(ordinary, "user"); ns != fakeNS {
		t.Fatalf("ordinary child %d does not share fake's namespace", ordinary)
	}
	if ns, _ := initwalk.NamespaceInode(ordinary, "user"); ns == callerNS {
		t.Fatalf("ordinary child %d shares THIS TEST's namespace — it would correctly be "+
			"skipped by either spelling, and this test would prove nothing", ordinary)
	}

	named := make(chan int, 4)
	watchForInit(fake.Process.Pid, Options{OnInit: func(pid int) { named <- pid }}, &initReporter{})
	select {
	case pid := <-named:
		if pid != nested {
			t.Errorf("watchForInit named pid %d, want %d — the child in a namespace of its "+
				"own. Naming %d (which shares bwrap's OWN namespace) is exactly what "+
				"comparing against snug's namespace instead of bwrap's produces, since both "+
				"are foreign to snug", pid, nested, ordinary)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchForInit never named anything")
	}
}

// childrenOf reads every child of every thread of parent from
// /proc/<parent>/task/*/children, the same source internal/initwalk's own
// walk uses.
func childrenOf(t *testing.T, parent int) []int {
	t.Helper()
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", parent))
	if err != nil {
		return nil
	}
	var out []int
	for _, task := range tasks {
		blob, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", parent, task.Name()))
		if err != nil {
			continue
		}
		for _, f := range strings.Fields(string(blob)) {
			if pid, err := strconv.Atoi(f); err == nil {
				out = append(out, pid)
			}
		}
	}
	return out
}
