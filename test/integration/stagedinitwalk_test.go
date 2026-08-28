//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The STAGED arm's fallback for issue #236 rests on one fact about the process
// tree, and this test is that fact measured on every run rather than believed:
// the init the run-state record names is the direct child of the bwrap the
// STAGE forked, and it is the only child of that bwrap in a user namespace
// other than the stage's own.
//
// bwrap ITSELF shares the stage's user namespace — measured 2026-08-28:
//
//	pid 663014 exe     user=4026533424   <- the stage, P1
//	pid 663038 bwrap   user=4026533424   <- P1's OWN user ns
//	pid 663045 bwrap   user=4026533635   <- the recorded init
//
// which is what makes "foreign user namespace" discriminating here rather than
// lucky. If a future bwrap changes that shape, internal/stage's fallback would
// silently name the wrong process and put it in a record internal/cli's
// killOrphanInit later SIGKILLs off — so this fails loudly instead.
func TestTheStagedInitIsTheForeignUsernsChildOfItsBwrap(t *testing.T) {
	budget(t, 90*time.Second)
	requireSandbox(t)
	requireInternet(t) // @net is what selects the staged arm

	proj, _ := target(t)
	ready := filepath.Join(proj, "READY")
	bg := startBackgroundSnug(t, baseEnv(), proj,
		"touch "+shQuote(ready)+"; while true; do sleep 1; done", "-p", "@net")
	if err := waitForFile(ready, 30*time.Second); err != nil {
		t.Fatalf("the staged run never started: %v\n%s", err, bg.output())
	}

	statePath := targetStatePath(t, proj)
	if err := waitForFile(statePath, 30*time.Second); err != nil {
		t.Fatalf("no run state for the staged run: %v\n%s", err, bg.output())
	}
	init := initPIDFrom(t, statePath)
	if init <= 1 {
		t.Fatalf("the run state named init_pid %d\n%s", init, bg.output())
	}

	parent, ok := ppidOf(init)
	if !ok || parent <= 1 {
		t.Fatalf("could not read the parent of init pid %d", init)
	}
	if comm := commOf(parent); comm != "bwrap" {
		t.Errorf("the recorded init's parent (pid %d) is %q, not bwrap — the staged fallback "+
			"walks the children of the process the STAGE started and assumes that is bwrap",
			parent, comm)
	}

	initNS, parentNS := usernsOf(t, init), usernsOf(t, parent)
	if initNS == 0 || parentNS == 0 {
		t.Fatalf("could not read a user namespace: init=%d parent=%d", initNS, parentNS)
	}
	if initNS == parentNS {
		t.Fatalf("the recorded init (pid %d) shares its bwrap's user namespace (%d), so the "+
			"foreign-user-namespace test cannot tell them apart and the staged fallback would "+
			"name bwrap instead of the init", init, initNS)
	}

	// internal/stage/serve.go's own fallback passes P1's namespace
	// (os.Getpid() there), not bwrap's — the opposite of the offline arm's
	// hostInitPID/watchForInit, which issue #101 had to switch to bwrap's OWN
	// namespace once its bwrap stopped sharing snug's (redteam finding F4,
	// see internal/sandbox/initwatch_test.go). serve.go's spelling is only
	// correct because P1's namespace and bwrap's happen to be the SAME thing
	// on this arm — asserted here rather than assumed, because that equality
	// is exactly the fact that stops holding on the offline arm and is the
	// whole reason F4 exists: the moment bwrap has a namespace of its own
	// P1 does not share, "P1's own namespace" and "bwrap's own namespace"
	// name two different things and only one of them is safe to use.
	grandparent, ok := ppidOf(parent)
	if !ok || grandparent <= 1 {
		t.Fatalf("could not read the parent of bwrap pid %d", parent)
	}
	if stageNS := usernsOf(t, grandparent); stageNS != parentNS {
		t.Fatalf("the stage (pid %d) does not share its bwrap's (pid %d) user namespace "+
			"(%d vs %d) — internal/stage/serve.go's fallback passes os.Getpid()'s namespace "+
			"as bwrap's, and that stopped being true, so it needs the same fix issue #101 "+
			"gave internal/sandbox/initwatch.go", grandparent, parent, stageNS, parentNS)
	}

	// The walk itself, over exactly what internal/stage passes it: the stage's
	// own user namespace is the bwrap parent's (measured above), so this is
	// the same question P1 asks.
	found, count := foreignChildrenOf(t, parent, parentNS)
	if count != 1 || (count == 1 && found != init) {
		t.Errorf("walking the children of bwrap pid %d for a foreign user namespace found %d "+
			"candidate(s), first %d; want exactly 1 and it must be the recorded init %d",
			parent, count, found, init)
	}
}

// usernsOf stats the /proc/<pid>/ns/user link rather than reading it, which is
// what internal/initwalk does and for the same reason: the inode is the thing,
// the rendered string is a second representation of it.
func usernsOf(t *testing.T, pid int) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(fmt.Sprintf("/proc/%d/ns/user", pid), &st); err != nil {
		return 0
	}
	return st.Ino
}

func foreignChildrenOf(t *testing.T, parent int, ours uint64) (first, count int) {
	t.Helper()
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", parent))
	if err != nil {
		return 0, 0
	}
	for _, task := range tasks {
		blob, rerr := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", parent, task.Name()))
		if rerr != nil {
			continue
		}
		for _, f := range strings.Fields(string(blob)) {
			var child int
			if _, serr := fmt.Sscanf(f, "%d", &child); serr != nil || child <= 1 {
				continue
			}
			ns := usernsOf(t, child)
			if ns != 0 && ns != ours {
				if count == 0 {
					first = child
				}
				count++
			}
		}
	}
	return first, count
}
