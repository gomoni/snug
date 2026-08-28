package sandbox

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// The walk's whole safety is the foreign-user-namespace test: a record built
// from a walked pid is a record killOrphanInit will later SIGKILL on, so both
// directions are asserted here. A test that only proved it FINDS the init
// would also pass on a version that returns the first child it sees.

func TestTheWalkFindsAChildInItsOwnUserNamespace(t *testing.T) {
	ours, err := namespaceInode(os.Getpid(), "user")
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
		pid, found, gone := foreignUsernsChild(os.Getpid(), ours)
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
	ours, err := namespaceInode(os.Getpid(), "user")
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
		pid, found, _ := foreignUsernsChild(cmd.Process.Pid, ours)
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
	ours, err := namespaceInode(os.Getpid(), "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, found, gone := foreignUsernsChild(cmd.Process.Pid, ours); found || !gone {
		t.Errorf("walking a reaped pid gave found=%v gone=%v, want false/true", found, gone)
	}
}

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
	watchForInit(cmd.Process.Pid, Options{OnInit: func(pid int) { named <- pid }})
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Errorf("watchForInit blocked its caller for %v; it must return immediately", elapsed)
	}

	select {
	case pid := <-named:
		t.Errorf("OnInit was called with pid %d for a process that forked nothing", pid)
	case <-time.After(100 * time.Millisecond):
	}
}
