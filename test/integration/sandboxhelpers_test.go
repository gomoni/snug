//go:build integration

package integration

// sandboxhelpers_test.go holds the helpers this suite shares for launching a
// sandbox in the BACKGROUND and finding what it published: an isolated
// $XDG_RUNTIME_DIR, a killable-and-waitable child, and the per-target state
// file. Nothing here is specific to one subject — the engine, procfs, kill
// record and run-directory tests all build on it.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// suiteEnv gives one test its own isolated $XDG_RUNTIME_DIR, so a test only
// ever sees run directories and sockets THIS test started — the same
// isolation baseEnv already gives XDG_CONFIG_HOME, applied to the directory
// a run's sockets and run lock live under.
//
// Rooted at os.MkdirTemp("", …), not t.TempDir(): the container proxy's
// socket lands at "<XDG_RUNTIME_DIR>/snug/run-<pid>/podman.sock", and
// t.TempDir() names its directory after the calling test function — long
// enough, on this suite's longest test names, to push that path past
// AF_UNIX's ~108-byte sun_path. Every one of suiteEnv's callers inherits
// this, which is what makes the length a suite-wide default rather than a
// per-test opt-in: an opt-in leaves every other call site one rename away
// from a failure that only reproduces on the random suffix os.MkdirTemp
// happened to draw.
func suiteEnv(t *testing.T) (env []string, xdgRuntime string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "snug-suite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	xdgRuntime = dir
	return baseEnv("XDG_RUNTIME_DIR=" + xdgRuntime), xdgRuntime
}

// bgProc is a background process this test starts and must both be able to
// wait for AND kill+wait for in cleanup, without the "exec: Wait was already
// called" panic that a bare *exec.Cmd gives a caller who does both.
type bgProc struct {
	cmd  *exec.Cmd
	once sync.Once
	err  error
}

func startBgProc(t *testing.T, cmd *exec.Cmd) *bgProc {
	t.Helper()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &bgProc{cmd: cmd}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		p.wait()
	})
	return p
}

func (p *bgProc) wait() error {
	p.once.Do(func() { p.err = p.cmd.Wait() })
	return p.err
}

func (p *bgProc) pid() int { return p.cmd.Process.Pid }

// bgSandbox is a background `snug <dir> -- <payload>`. Unlike run()/cli(), it
// does not block: the payload is expected to outlive this test's own
// assertions.
type bgSandbox struct {
	proc    *bgProc
	logPath string
	proj    string
}

func startBgSandbox(t *testing.T, env []string, args []string, proj, payload string) *bgSandbox {
	t.Helper()
	argv := append(append([]string{}, args...), proj, "--", "/bin/bash", "-c",
		"printf '%s\\n' "+payloadMarker+"\n"+payload)
	cmd := exec.Command(snugBin, argv...)
	cmd.Env = env

	log, err := os.CreateTemp(t.TempDir(), "snug-bg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	cmd.Stdout, cmd.Stderr = log, log

	proc := startBgProc(t, cmd)
	return &bgSandbox{proc: proc, logPath: log.Name(), proj: proj}
}

func (s *bgSandbox) log() string {
	b, _ := os.ReadFile(s.logPath)
	return string(b)
}

func (s *bgSandbox) pid() int { return s.proc.pid() }

// ready is the positive control a caller needs before its own assertions: the
// payload actually STARTED, marked by payloadMarker on the run's own stdout.
// Without it every assertion downstream would be equally true of a sandbox
// that never came up.
func (s *bgSandbox) ready(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if strings.Contains(s.log(), payloadMarker) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the background sandbox's payload never started:\n%s", s.log())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// uidRuntimeSnugDir mirrors internal/cli's targetLockBase: the directory the
// per-target lock and, since issue #123, the per-target state file live in,
// resolved FROM THE UID ALONE.
//
// Recomputed here rather than imported, deliberately, and the reason is the
// bug itself: these tests launch the real binary, so a helper that read
// $XDG_RUNTIME_DIR would be making exactly the assumption #123 removed. A run
// and every later reader of its record must land on this directory whatever
// environment each was started with, and that is what these tests are
// checking.
func uidRuntimeSnugDir(t *testing.T) string {
	t.Helper()
	uid := os.Getuid()
	canonical := fmt.Sprintf("/run/user/%d", uid)
	if fi, err := os.Stat(canonical); err == nil && fi.IsDir() {
		return filepath.Join(canonical, "snug")
	}
	return filepath.Join("/tmp", fmt.Sprintf("snug-%d", uid), "snug")
}

// statePath is where THIS run's state file lives: named from "sha256_"
// followed by the sha256 of the TARGET's realpath (issue #349), beside the
// target lock of the same name (issue #123). Note what it no longer takes —
// the test's $XDG_RUNTIME_DIR — because the answer no longer depends on it.
func (s *bgSandbox) statePath(t *testing.T) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(s.proj)
	if err != nil {
		t.Fatalf("resolving the target %s: %v", s.proj, err)
	}
	sum := sha256.Sum256([]byte(real))
	return filepath.Join(uidRuntimeSnugDir(t), "target-sha256_"+hex.EncodeToString(sum[:])+".json")
}

func (s *bgSandbox) waitForState(t *testing.T) {
	t.Helper()
	p := s.statePath(t)
	deadline := time.Now().Add(15 * time.Second)
	for {
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("state.json never appeared at %s:\n%s", p, s.log())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// runDir is this run's own runtime directory: its sockets and its run lock.
// It is still $XDG_RUNTIME_DIR-derived and still per-run — only the STATE file
// moved out of it (issue #123), because only the state file has to be found by
// a second process that may not share this one's environment.
func (s *bgSandbox) runDir(xdgRuntime string) string {
	return filepath.Join(xdgRuntime, "snug", fmt.Sprintf("run-%d", s.pid()))
}

// waitForLogLine blocks until want appears in the background sandbox's own
// output and returns everything it has printed so far.
//
// It exists because a probe that needs to run INSIDE a specific live sandbox
// has to be that sandbox's own payload. A second `snug` on the same target is a
// second, independent sandbox — its own $HOME tmpfs, its own pids, and on a
// container run its own engine — so it can answer no question about the first
// one's processes or mounts.
func waitForLogLine(t *testing.T, s *bgSandbox, want string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		out := s.log()
		if strings.Contains(out, want) {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("the sandbox's payload never printed %q within %s:\n%s", want, timeout, out)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// handToPayload writes value at name inside the target directory, where a live
// payload blocked on that file appearing will read it.
//
// The rename is not tidiness: the payload polls with `[ -f name ]` and would
// otherwise read a file the host is still writing. It is the only channel there
// is for a value the payload cannot compute — a host pid, say — and it is a
// channel precisely because the target bind is writable from both sides, which
// is the same fact --dry-run's SHARED block warns about.
func handToPayload(t *testing.T, proj, name, value string) {
	t.Helper()
	tmp := filepath.Join(proj, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte(value+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(proj, name)); err != nil {
		t.Fatal(err)
	}
}
