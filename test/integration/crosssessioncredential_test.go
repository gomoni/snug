//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestOneSessionsClaudeCredentialIsNotReadableFromAnother is the NEGATIVE half
// of issue #58's projection, and it exists because the projection alone does
// not settle the question the way it first appears to.
//
// #58 drops refreshToken on the way IN, which bounds what the host hands a
// sandbox. It says nothing about a credential that comes into being INSIDE
// one: `/login` in a running session completes a fresh OAuth flow and writes a
// full credential set — refreshToken included — into ~/.claude/.credentials.json,
// which is a writable file on the ~/.claude tmpfs and is Claude Code's to
// rewrite once snug has handed off. Measured in a real run (claude 2.1.263):
// that file's mtime landed 1421s after the payload started, and both dropped
// keys were back, refreshTokenExpiresAt 29d out.
//
// So the question this test answers is not "what did snug carry" but "given a
// live credential that exists only inside session A, can session B read it".
//
// WHAT MAKES IT TRUE, so a reader can tell whether a refactor may delete this
// file. Staged content of policy.KindData never has a filesystem name at all:
// internal/sandbox.Run puts it in an anonymous memfd (memfd_create, no path)
// and passes the descriptor to bwrap, which materialises it inside the
// sandbox's own tmpfs — device 0:163 in a measured run, an anonymous
// superblock whose mountinfo root is "/", unlike every host bind, which names
// its host subtree. A second session gets a second private mount namespace, so
// there is no name in B for the tmpfs holding A's file, and B's private PID
// namespace means /proc in B does not contain A's pids to traverse through.
//
// The claim is therefore "not readable from another SANDBOXED session", and
// NOT "not readable by this user" — the positive control below asserts the
// opposite for the host on purpose, because a test that cannot tell isolation
// apart from "the canary was never written" proves nothing.
func TestOneSessionsClaudeCredentialIsNotReadableFromAnother(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	projA, _ := target(t)
	projB, _ := target(t)

	canary := fmt.Sprintf("snug-xsession-canary-%d-%d", os.Getpid(), time.Now().UnixNano())
	credPath := filepath.Join(os.Getenv("HOME"), ".claude", ".credentials.json")
	if os.Getenv("HOME") == "" {
		t.Skip("HOME is unset, so the guest credential path cannot be derived")
	}

	// Session A mints a session-only credential the way /login does — writing
	// it from INSIDE, into its own ~/.claude tmpfs — and then holds the
	// sandbox open.
	//
	// `exec` matters: the canary reaches A through argv, so without it the
	// string would sit in a /proc/<pid>/cmdline for the whole run. After the
	// exec the payload's cmdline is "/bin/sleep 60" and the only live copy of
	// the canary is the file itself, which is what B is being asked about.
	scriptA := fmt.Sprintf("printf '%%s' %s > %s; exec /bin/sleep 60", canary, credPath)
	a := exec.Command(snugBin, "-p", "@claude", projA, "--", "/bin/sh", "-c", scriptA)
	a.Env = baseEnv()
	a.WaitDelay = waitDelay
	if err := a.Start(); err != nil {
		t.Fatalf("launching session A: %v", err)
	}
	t.Cleanup(func() {
		a.Process.Kill()
		a.Wait()
	})

	payloadA, ok := findDescendant(a.Process.Pid, isComm("sleep"), 15*time.Second)
	if !ok {
		t.Fatal("PRECONDITION: session A's payload ('sleep') never appeared, so there is no " +
			"live session to hide anything from")
	}

	// POSITIVE CONTROL, and it is also the honest limit of the claim. The same
	// uid on the HOST traverses into A's mount namespace through
	// /proc/<pid>/root and reads the file. If this cannot see the canary, the
	// sweep below is vacuous — A may never have written it, or may have died.
	viaProc := filepath.Join("/proc", fmt.Sprint(payloadA), "root", credPath)
	hostView, err := os.ReadFile(viaProc)
	if err != nil {
		t.Fatalf("control: cannot read session A's credential from the host at %s (%v). "+
			"The sweep below would pass whether or not the sandbox isolates anything.",
			viaProc, err)
	}
	if !strings.Contains(string(hostView), canary) {
		t.Fatalf("control: %s does not contain the canary, so session A never minted the "+
			"credential this test is about:\n%s", viaProc, hostView)
	}

	// Session B, launched while A is still alive, sweeps everything it can
	// read. /proc/*/root is swept explicitly rather than trusted to be empty:
	// that traversal is exactly what worked from the host a moment ago, and
	// what must not work here.
	const begin, end = "---BEGIN-SWEEP---", "---END-SWEEP---"
	sweep := fmt.Sprintf(`
		echo %s
		echo "visible-pids: $(ls -d /proc/[0-9]* 2>/dev/null | wc -l)"
		echo "own-credential:"
		cat %s 2>/dev/null || echo "(absent)"
		echo
		echo "grep-hits:"
		grep -rl %s "$HOME" /tmp /dev/shm 2>/dev/null | head -20
		echo "proc-root-hits:"
		for p in /proc/[0-9]*; do
			c="$p/root%s"
			if [ -r "$c" ]; then echo "== $c"; cat "$c" 2>/dev/null; echo; fi
		done
		echo %s
	`, begin, credPath, canary, credPath, end)

	r := run(t, []string{"-p", "@claude"}, projB, sweep).mustRun(t)
	out := between(r.out, begin, end)
	if strings.TrimSpace(out) == "" {
		t.Fatalf("control: session B's sweep produced no output between the markers, so it "+
			"asserted nothing:\n%s", r.out)
	}

	if strings.Contains(out, canary) {
		t.Errorf("session B READ session A's live Claude credential. A credential minted "+
			"inside one sandbox (what /login does, refreshToken included) is reachable from "+
			"another, which makes every session of this account one hostile payload away "+
			"from a ~29-day token.\ncanary: %s\nsweep:\n%s", canary, out)
	}

	// B must not see A's processes either: /proc/<A>/root is the traversal the
	// host just used, and it needs a visible pid to start from. Asserted
	// separately so a failure says WHICH boundary gave way — a shared /proc
	// with a private mount namespace and a shared mount namespace are
	// different bugs with different fixes.
	if strings.Contains(out, fmt.Sprintf("== /proc/%d/root", payloadA)) {
		t.Errorf("session B resolved /proc/%d/root, session A's payload — B's PID namespace "+
			"is not private, and /proc/<pid>/root is a path into another sandbox's mounts:\n%s",
			payloadA, out)
	}
}
