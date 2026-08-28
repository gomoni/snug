//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestOfflineArmsIntermediateBwrapIsUnaddressableFromThePayload is issue
// #101's positive claim, measured end to end rather than believed:
// internal/sandbox/exec.go's offline arm now forks bwrap into a pid
// namespace of its own (NP) one level above the sandbox's own (Q), so a
// process left at NP's level has no entry at all in Q's procfs — not
// "permission denied", ENOENT, because procfs only exposes members of the
// namespace it is mounted for.
//
// Measured (redteam, this session): [payload] stat /proc/<bwrap-host-pid> ->
// No such file or directory; the same read from the host succeeds and names
// "bwrap". This test reproduces that shape using the sandbox's own bwrap as
// the target.
func TestOfflineArmsIntermediateBwrapIsUnaddressableFromThePayload(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)

	proj, _ := target(t)
	ready := filepath.Join(proj, "READY")
	goFile := filepath.Join(proj, "GO")
	result := filepath.Join(proj, "RESULT")

	// The payload signals readiness, then polls for the host to hand it a
	// pid to probe (bwrap's, discovered from outside once the run exists),
	// and writes its findings for the host to read back — the target
	// directory being the one place both sides can meet.
	script := fmt.Sprintf(`
touch %s
while [ ! -f %s ]; do sleep 0.02; done
BW=$(cat %s)
{
  if [ -e /proc/$BW ]; then echo EXISTS=1; else echo EXISTS=0; fi
  ls /proc/$BW/fd >/dev/null 2>&1; echo FD_EXIT=$?
  cat /proc/$BW/mem >/dev/null 2>&1; echo MEM_EXIT=$?
} > %s
sleep 60
`, shQuote(ready), shQuote(goFile), shQuote(goFile), shQuote(result))

	bg := startBackgroundSnug(t, baseEnv(), proj, script)
	if err := waitForFile(ready, 15*time.Second); err != nil {
		t.Fatalf("the sandbox never started: %v\n%s", err, bg.output())
	}

	bwrapPid, ok := findDescendant(bg.cmd.Process.Pid, isComm("bwrap"), 10*time.Second)
	if !ok {
		t.Fatalf("never found bwrap as a descendant of snug (pid %d):\n%s",
			bg.cmd.Process.Pid, bg.output())
	}

	// POSITIVE CONTROL, from the HOST: the target of this probe really
	// exists and really is bwrap, before asking the payload whether it can
	// see it. Without this, "the payload could not see it" would be equally
	// true of a pid that was never there.
	if comm := commOf(bwrapPid); comm != "bwrap" {
		t.Fatalf("host-side control: pid %d is %q, not bwrap — this test would be probing "+
			"the wrong process", bwrapPid, comm)
	}

	// THE DEPTH ITSELF: bwrap (NP's pid 1) and this test process must be in
	// different pid namespaces, or issue #101's construction did not happen.
	selfNS, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	bwrapNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", bwrapPid))
	if err != nil {
		t.Fatalf("reading bwrap's (pid %d) own pid namespace: %v", bwrapPid, err)
	}
	if bwrapNS == selfNS {
		t.Fatalf("bwrap (pid %d) shares this test's pid namespace (%s) — issue #101's "+
			"intermediate pid namespace did not get created", bwrapPid, bwrapNS)
	}

	if err := os.WriteFile(goFile, []byte(strconv.Itoa(bwrapPid)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := waitForFile(result, 15*time.Second); err != nil {
		t.Fatalf("the payload never wrote its probe result: %v\n%s", err, bg.output())
	}
	out, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)

	if !strings.Contains(got, "EXISTS=0") {
		t.Errorf("the payload reports /proc/%d as present — an intermediate-level process "+
			"(bwrap, one pid-namespace level above the sandbox's own) must be invisible from "+
			"inside it:\n%s", bwrapPid, got)
	}
	if strings.Contains(got, "FD_EXIT=0") {
		t.Errorf("the payload could list bwrap's fd directory:\n%s", got)
	}
	if strings.Contains(got, "MEM_EXIT=0") {
		t.Errorf("the payload could read bwrap's /proc/<pid>/mem:\n%s", got)
	}
}

// TestSiblingSandboxProcessesStillShareOneNamespace is the bound on the test
// above, and it must stay in the suite for as long as that one does: issue
// #101's namespace buys a place to PUT things, not isolation INSIDE the
// sandbox. Two processes bwrap starts are still co-resident in the same pid
// namespace Q, so a sibling can still open and read another sibling's
// /proc/<pid>/fd/N exactly as before — this does NOT shrink issue #47, and a
// reader who sees the test above land and assumes it does is the mistake
// this test exists to correct.
//
// Measured (redteam, this session): a sibling read bwrap-started sibling's
// fd 7 straight through /proc, identically with and without the extra pid
// namespace level (both "flat" and "nested" gave the same secret bytes back
// through the same path).
func TestSiblingSandboxProcessesStillShareOneNamespace(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)

	proj, _ := target(t)
	secretFile := filepath.Join(proj, "secret.txt")

	script := fmt.Sprintf(`
printf '%%s' SECRET-CONTENT-101 > %s
sh -c 'exec 7<%s; sleep 5' &
APID=$!
n=0
while [ ! -e /proc/$APID/fd/7 ] && [ $n -lt 100 ]; do sleep 0.02; n=$((n+1)); done
sh -c "cat /proc/$APID/fd/7 2>&1"
`, shQuote(secretFile), shQuote(secretFile))

	r := run(t, nil, proj, script).mustRun(t)

	if !strings.Contains(r.out, "SECRET-CONTENT-101") {
		t.Errorf("a sibling process could not read another sandboxed process's fd through "+
			"/proc/<pid>/fd/N — if this now refuses, issue #47's residual actually shrank on "+
			"this arm and SUPERVISOR-DESIGN.md / CLAUDE.md need updating to say so, not this "+
			"test quietly deleted:\n%s", r.out)
	}
}
