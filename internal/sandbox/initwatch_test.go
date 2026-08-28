package sandbox

import (
	"os/exec"
	"sync"
	"testing"
	"time"
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
