//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestAnOfflineRunSurvivesAnOuterPidNamespaceWithNoSecondPid is the
// regression test for the failure CI run 33190731691 found and this host
// could not: bwrap answers --info-fd by reading its CHILD's /proc entry, and
// the number it uses is relative to ITS OWN pid namespace while the procfs it
// reads belongs to the one above. With the sandbox's namespace nested (issue
// #101), that number is 2 — so bwrap reads the OUTER /proc/2, which is a
// stranger, or nobody.
//
// It passed everywhere the outer pid 2 happens to be immortal. On the
// development host that is kthreadd: the O_PATH open of its 0511 ns directory
// succeeds, every fstatat under it is EACCES because bwrap is in a foreign
// user namespace, and bwrap silently reports NO namespace ids at all —
// repaired downstream by fillMissingNamespaceIDs, so nothing looked wrong.
// Inside a container it is fatal: pid 2 is whatever ran last and has usually
// exited.
//
// internal/sandbox/inpidns.go is the fix — a procfs of the intermediate pid
// namespace, mounted over /proc before the exec into bwrap — and this test is
// the shape that grades it. MEASURED, same command, two binaries:
//
//	f1d7e5b   bwrap: open /proc/2/ns/ns failed: No such file or directory
//	          snug: this run will not be attachable (reading bwrap's --info-fd: EOF)
//	fixed     PAYLOAD-RAN
//
// The four /bin/true calls are load-bearing, not filler: they advance the
// namespace's pid counter past 2 and exit, so pid 2 is GONE rather than
// merely somebody else. Without them snug's own bwrap lands on outer pid 2,
// bwrap reads itself, and the bug hides again — which is exactly why this
// host never saw it.
func TestAnOfflineRunSurvivesAnOuterPidNamespaceWithNoSecondPid(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)

	unshareBin, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("no unshare(1) on this host, so the outer pid namespace this test needs " +
			"cannot be built: " + err.Error())
	}
	proj, _ := target(t)

	// One shell, because the state being tested is the pid namespace's own
	// history: the /bin/true calls, the control reads and the run all have to
	// happen in the same namespace, in that order.
	script := strings.Join([]string{
		"/bin/true; /bin/true; /bin/true; /bin/true",
		"echo OUTER-NS=$(readlink /proc/self/ns/pid)",
		"if [ -e /proc/2 ]; then echo PID2=present; else echo PID2=absent; fi",
		"exec " + shQuote(snugBin) + " " + shQuote(proj) + " -- /bin/echo PAYLOAD-RAN",
	}, "\n")

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, unshareBin,
		"-U", "-p", "-f",
		fmt.Sprintf("--map-user=%d", os.Getuid()),
		fmt.Sprintf("--map-group=%d", os.Getgid()),
		"--mount-proc",
		"--", "/bin/sh", "-c", script)
	cmd.Env = baseEnv()
	out, _ := cmd.CombinedOutput()
	got := string(out)

	// unshare(1) failing is this host declining to nest namespaces — a skip,
	// not a finding. snug never ran, so there is nothing to grade.
	if strings.Contains(got, "unshare: unshare failed") || strings.Contains(got, "unshare: cannot") {
		t.Skipf("this host would not create the nested user+pid namespace: %s", got)
	}

	// TWO CONTROLS, both about the namespace rather than about snug: without
	// either, "the payload ran" is equally true of a test that reproduced
	// nothing at all.
	ownNS, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	outer := ""
	for _, line := range strings.Split(got, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "OUTER-NS="); ok {
			outer = v
		}
	}
	if outer == "" || outer == ownNS {
		t.Fatalf("control: the run happened in pid namespace %q and this test process is in "+
			"%q — a fresh outer namespace is the whole precondition:\n%s", outer, ownNS, got)
	}
	if !strings.Contains(got, "PID2=absent") {
		t.Fatalf("control: pid 2 still exists in that namespace, so bwrap's read of the outer "+
			"/proc/2 would find SOMETHING and the failure being tested cannot occur:\n%s", got)
	}

	if !strings.Contains(got, "PAYLOAD-RAN") {
		t.Errorf("the payload never ran in a pid namespace whose pid 2 is gone. This is CI run "+
			"33190731691's failure: bwrap resolves its child's pid against the procfs it "+
			"opened, and internal/sandbox/inpidns.go must mount one for the intermediate "+
			"namespace before exec'ing it:\n%s", got)
	}
	// The pre-fix signature, named exactly, so a future failure here is read
	// as this bug rather than as some other reason the payload was silent.
	if strings.Contains(got, "ns/ns failed") {
		t.Errorf("bwrap still resolved its child against the outer procfs:\n%s", got)
	}
}
