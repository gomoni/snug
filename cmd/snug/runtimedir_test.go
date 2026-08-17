package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRuntimeDirRefusesAPreplantedSymlinkOnTheSharedDirectory is the guard
// issue #61 part (c) asked for, tried rather than merely asserted: something
// that got to $XDG_RUNTIME_DIR first plants a symlink at the "snug" name,
// pointing at a directory it controls, and runtimeDir must refuse to follow
// it rather than silently creating this run's sockets inside the attacker's
// directory.
//
// CONTROL: the same setup with no symlink planted must succeed, so a failure
// above is known to be the guard firing and not some unrelated brokenness in
// the environment this test built.
func TestRuntimeDirRefusesAPreplantedSymlinkOnTheSharedDirectory(t *testing.T) {
	base := t.TempDir()
	trap := filepath.Join(base, "attacker-owned")
	if err := os.MkdirAll(trap, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(trap, filepath.Join(base, "snug")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", base)

	if _, err := runtimeDir(); err == nil {
		t.Fatal("runtimeDir followed a pre-planted symlink instead of refusing it")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("runtimeDir refused for the wrong reason: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(trap, fmt.Sprintf("run-%d", os.Getpid()))); err == nil {
		t.Fatal("a run directory was created INSIDE the attacker's directory through the symlink")
	}

	// CONTROL: an unplanted base must succeed.
	clean := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", clean)
	dir, err := runtimeDir()
	if err != nil {
		t.Fatalf("control: runtimeDir failed on a clean base: %v", err)
	}
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("control: runtimeDir did not create a usable directory: %s (%v)", dir, err)
	}
}

// TestRuntimeDirRefusesAPreplantedSymlinkOnTheRunSubdirectory is the same
// attack one level deeper: the shared "snug" directory is legitimate, but the
// entry this specific run would use — run-<pid>-<starttime> — is itself a
// symlink, planted by anything else running as this uid before this process
// got there. runDirName/pidStartTime are used here (not a guess at the name)
// so this test plants the EXACT entry runtimeDir is about to look for.
func TestRuntimeDirRefusesAPreplantedSymlinkOnTheRunSubdirectory(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", base)

	snugDir := filepath.Join(base, "snug")
	if err := os.MkdirAll(snugDir, 0o700); err != nil {
		t.Fatal(err)
	}

	start, err := pidStartTime(os.Getpid())
	if err != nil {
		t.Fatalf("pidStartTime(self): %v", err)
	}
	runName := runDirName(os.Getpid(), start)

	trap := filepath.Join(base, "attacker-owned-run")
	if err := os.MkdirAll(trap, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(trap, filepath.Join(snugDir, runName)); err != nil {
		t.Fatal(err)
	}

	if _, err := runtimeDir(); err == nil {
		t.Fatal("runtimeDir followed a pre-planted symlink at the run-* name instead of refusing it")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("runtimeDir refused for the wrong reason: %v", err)
	}

	// CONTROL: remove the trap and the exact same base must now succeed.
	if err := os.Remove(filepath.Join(snugDir, runName)); err != nil {
		t.Fatal(err)
	}
	dir, err := runtimeDir()
	if err != nil {
		t.Fatalf("control: runtimeDir failed once the symlink was gone: %v", err)
	}
	if filepath.Base(dir) != runName {
		t.Errorf("runtimeDir returned %s, want a directory named %s", dir, runName)
	}
}

// TestRuntimeDirRefusesAWronglyPermissionedSharedDirectory: a "snug"
// directory that already exists but is not private — created, for instance,
// by a version of snug that predates this guard, or by hand — must be
// refused rather than silently trusted or silently chmod'd back to 0700.
// Invariant 5: repairing it quietly would hide exactly the kind of mistake
// this check exists to catch.
func TestRuntimeDirRefusesAWronglyPermissionedSharedDirectory(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", base)

	if err := os.MkdirAll(filepath.Join(base, "snug"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := runtimeDir()
	if err == nil {
		t.Fatal("runtimeDir accepted a group/other-readable shared directory")
	}
	if !strings.Contains(err.Error(), "mode") {
		t.Errorf("runtimeDir refused for the wrong reason: %v", err)
	}
}

// TestRuntimeDirIsIdempotentWithinARun pins the property both call sites
// depend on (identity.go's ssh-agent proxy and container.go's engine proxy
// both call runtimeDir independently): two calls from the same process must
// land on the exact same directory, not two.
func TestRuntimeDirIsIdempotentWithinARun(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	first, err := runtimeDir()
	if err != nil {
		t.Fatal(err)
	}
	second, err := runtimeDir()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("runtimeDir returned two different directories in one run: %s then %s", first, second)
	}
}

// TestSweepStaleRunDirsDistinguishesDeadFromReusedFromLive is #85's
// regression test at the unit level: a stale run-* directory must go, a
// directory naming a pid that is technically alive again — because pids get
// reused — must ALSO go if it is not the same PROCESS, and a directory
// naming a genuinely live process must survive. An mtime-based sweep cannot
// make the middle distinction; this test is what proves the implementation
// does not fall back to one.
//
// The positive control is the live case: without it, "the stale ones are
// gone" would pass just as well on a sweep that deletes everything.
func TestSweepStaleRunDirsDistinguishesDeadFromReusedFromLive(t *testing.T) {
	snugDir := t.TempDir()

	// A real, still-running process this test started itself (never killed
	// by name — this exact pid only, in t.Cleanup).
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the positive control process: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	livePid := cmd.Process.Pid
	liveStart, err := pidStartTime(livePid)
	if err != nil {
		t.Fatalf("pidStartTime(live control): %v", err)
	}

	live := runDirName(livePid, liveStart)
	reused := runDirName(livePid, liveStart+1) // same pid, wrong start time: "pid was reused" case
	dead := runDirName(1_999_999_999, 12345)   // a pid that (almost certainly) does not exist at all

	for _, name := range []string{live, reused, dead} {
		if err := os.MkdirAll(filepath.Join(snugDir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	sweepStaleRunDirs(snugDir)

	if _, err := os.Stat(filepath.Join(snugDir, live)); err != nil {
		t.Errorf("the LIVE process's directory was removed (it must survive): %v", err)
	}
	if _, err := os.Stat(filepath.Join(snugDir, reused)); !os.IsNotExist(err) {
		t.Errorf("a directory naming a REUSED pid (same pid, wrong start time) survived the sweep: %v", err)
	}
	if _, err := os.Stat(filepath.Join(snugDir, dead)); !os.IsNotExist(err) {
		t.Errorf("a directory naming a dead pid survived the sweep: %v", err)
	}
}

// TestRuntimeDirSweepsOnStartupAcrossFallbackAndXDGBases pins #85's fix at
// the level runtimeDir itself is called: a stale directory left by an
// earlier, now-dead invocation is gone after the very next call, with no
// separate janitor command to remember to run.
func TestRuntimeDirSweepsOnStartup(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", base)

	snugDir := filepath.Join(base, "snug")
	stale := runDirName(1_999_999_998, 1)
	if err := os.MkdirAll(filepath.Join(snugDir, stale), 0o700); err != nil {
		t.Fatal(err)
	}
	// A dead ssh-agent.sock in it, the shape #85 measured: an inode with no
	// listener behind it, not merely an empty directory.
	if err := os.WriteFile(filepath.Join(snugDir, stale, "ssh-agent.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := runtimeDir(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(snugDir, stale)); !os.IsNotExist(err) {
		t.Errorf("a stale run-* directory from an earlier, dead invocation survived a later runtimeDir() call: %v", err)
	}
}
