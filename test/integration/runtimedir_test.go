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

	"golang.org/x/sys/unix"
)

// internal/cli/runtimedir_test.go proves the guard and the sweep in-process,
// against secureSubroot/lockRunDir/sweepStaleRunDirs directly. Nothing in
// this suite had run the real binary against either claim (issue #61 part
// (c), issue #85) before these two tests — grep this package for "#85" or
// "#61" before this file existed and it found nothing, which is exactly the
// gap CLAUDE.md's definition-of-done rule 2 names.
//
// Both tests need a runtimeDir() call site to actually fire, which a plain
// default sandbox never reaches: only a pinned identity (the ssh-agent
// proxy) or containers (the podman proxy) call it. ssh_mode = "agent-proxy"
// is the cheaper of the two to stand up — no engine required — so both
// tests use it, and neither needs the sandboxed payload to actually run ssh.

// waitForLockFile polls for a run directory's lock file to appear, which is
// the last thing runLock creates before returning — so its presence is what
// tells this test "that snug process has finished claiming its runtime
// directory" rather than guessing at a sleep.
func waitForLockFile(t *testing.T, runDir string) {
	t.Helper()
	waitForSocket(t, filepath.Join(runDir, "lock"))
}

// TestStaleRuntimeDirectoryIsSweptOnTheNextRun is issue #85's actual claim,
// end to end: a run's own runtime directory survives only abnormal
// termination (a clean exit already removes its own), and SIGKILL cannot be
// caught, so nothing on the way OUT can help — the sweep has to run on the
// way IN of a LATER, unrelated snug process. internal/cli/runtimedir_test.go
// proves the same claim by calling sweepStaleRunDirs directly; this is the
// version that never imports package main and drives three real snug
// processes instead.
func TestStaleRuntimeDirectoryIsSweptOnTheNextRun(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	proj, _ := target(t)
	pub, sock := sshAgentAndKey(t)

	runtimeScratch := t.TempDir()
	snugDir := filepath.Join(runtimeScratch, "snug")
	env := writeProfile(t, "[profile.pinned]\n"+
		"description = \"one throwaway key, for the integration suite\"\n"+
		"[profile.pinned.identity]\n"+
		"ssh_mode = \"agent-proxy\"\n"+
		"ssh_key = \""+pub+"\"\n",
		"SSH_AUTH_SOCK="+sock, "XDG_RUNTIME_DIR="+runtimeScratch)

	start := func() *exec.Cmd {
		t.Helper()
		cmd := exec.Command(snugBin, "-p", "pinned", proj, "--", "/bin/sleep", "30")
		cmd.Env = env
		cmd.WaitDelay = waitDelay
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd
	}

	// POSITIVE CONTROL, started first and left running for the whole test:
	// without a genuinely live run sitting in the same shared "snug"
	// directory, "the stale one is gone" below would pass just as well on a
	// sweep that removes everything it sees.
	live := start()
	liveKilled := false
	t.Cleanup(func() {
		if !liveKilled {
			live.Process.Kill()
			live.Wait()
		}
	})
	liveDir := filepath.Join(snugDir, fmt.Sprintf("run-%d", live.Process.Pid))
	waitForLockFile(t, liveDir)

	// The run that is about to be killed for real.
	dying := start()
	dyingDir := filepath.Join(snugDir, fmt.Sprintf("run-%d", dying.Process.Pid))
	waitForLockFile(t, dyingDir)

	// Only this pid, started by this test — never pkill by name; bwrap on
	// this host is Flatpak's.
	if err := dying.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	dying.Wait()

	// PRECONDITION: the directory survives its own SIGKILL — nothing on the
	// way out removed it, which is the whole reason a sweep on the way IN is
	// needed at all. Without this check, a sweep finding nothing to sweep
	// would pass the assertion below just as easily as a working one.
	if _, err := os.Stat(dyingDir); err != nil {
		t.Fatalf("precondition: the SIGKILLed run's directory did not survive its own death, "+
			"so the sweep below would prove nothing: %v", err)
	}
	// PRECONDITION: and its lock is released — SIGKILL releases an flock the
	// same as a clean exit, which is the mechanism the sweep depends on.
	lf, err := os.OpenFile(filepath.Join(dyingDir, "lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("precondition: the SIGKILLed run's lock is still held: %v", err)
	}
	unix.Flock(int(lf.Fd()), unix.LOCK_UN)
	lf.Close()

	// A fresh, THIRD snug process under the same $XDG_RUNTIME_DIR is what
	// sweeps it — "on the way in", per the claim above.
	runEnv(t, env, []string{"-p", "pinned"}, proj, "true").mustRun(t)

	if _, err := os.Stat(dyingDir); !os.IsNotExist(err) {
		t.Errorf("the stale directory left by the SIGKILLed run survived a later, unrelated run: %v", err)
	}
	if _, err := os.Stat(liveDir); err != nil {
		t.Errorf("the sweep removed a directory belonging to a run that is still alive: %v", err)
	}

	liveKilled = true
	live.Process.Kill()
	live.Wait()
}

// TestSymlinkAtTheSharedRuntimeDirectoryIsRefusedEndToEnd is issue #61 part
// (c)'s guard, run against the real binary rather than
// secureSubroot/verifyOwnedAndPrivate directly (internal/cli/runtimedir_test.go
// covers those). Something on the host got to $XDG_RUNTIME_DIR first and
// planted a symlink at the "snug" name; snug must refuse with the guard's
// own message and must never start the payload.
func TestSymlinkAtTheSharedRuntimeDirectoryIsRefusedEndToEnd(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)
	pub, sock := sshAgentAndKey(t)

	profile := "[profile.pinned]\n" +
		"description = \"one throwaway key, for the integration suite\"\n" +
		"[profile.pinned.identity]\n" +
		"ssh_mode = \"agent-proxy\"\n" +
		"ssh_key = \"" + pub + "\"\n"

	trapBase := t.TempDir()
	trapTarget := filepath.Join(trapBase, "attacker-owned")
	if err := os.MkdirAll(trapTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(trapTarget, filepath.Join(trapBase, "snug")); err != nil {
		t.Fatal(err)
	}

	trapEnv := writeProfile(t, profile, "SSH_AUTH_SOCK="+sock, "XDG_RUNTIME_DIR="+trapBase)
	r := runEnv(t, trapEnv, []string{"-p", "pinned"}, proj, "echo MARKER")
	if r.ran {
		t.Fatalf("the payload ran despite a planted symlink at the shared runtime directory's name:\n%s", r.out)
	}
	if r.code != exitPolicyCode {
		t.Errorf("want exit %d, got %d:\n%s", exitPolicyCode, r.code, r.out)
	}
	if !strings.Contains(r.out, "symlink") {
		t.Errorf("the refusal should name the guard that fired (a symlink):\n%s", r.out)
	}

	// POSITIVE CONTROL: the identical profile and command, with a clean
	// $XDG_RUNTIME_DIR, must actually run. Without this, the refusal above
	// could mean the identity/profile setup itself is broken rather than the
	// symlink guard firing.
	clean := t.TempDir()
	cleanEnv := writeProfile(t, profile, "SSH_AUTH_SOCK="+sock, "XDG_RUNTIME_DIR="+clean)
	ctrl := runEnv(t, cleanEnv, []string{"-p", "pinned"}, proj, "echo MARKER").mustRun(t)
	if !strings.Contains(ctrl.out, "MARKER") {
		t.Errorf("control: the payload should have run and printed MARKER:\n%s", ctrl.out)
	}
}
