package wrapper

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The test binary doubles as the wrapper: with this variable set, TestMain is
// DoorExec over the arguments, which is the only way to observe what an execve
// from a Go process hands the program it becomes.
const childEnv = "SNUG_WRAPPER_TEST_DOOR"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		os.Unsetenv(childEnv)
		os.Exit(DoorExec(os.Args[1:], os.Stderr))
	}
	if os.Getenv(podmanChildEnv) == "1" {
		os.Unsetenv(podmanChildEnv)
		os.Exit(Podman(os.Args[1:], os.Getenv("PATH"), os.Stderr))
	}
	os.Exit(m.Run())
}

func door(t *testing.T, launcher string, argv ...string) (string, int) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var cmd *exec.Cmd
	if launcher == "" {
		cmd = exec.Command(self, argv...)
	} else {
		cmd = exec.Command("/bin/sh", append([]string{"-c", launcher + ` && exec "$@"`, "sh", self}, argv...)...)
	}
	cmd.Env = append(os.Environ(), childEnv+"=1", "LISTEN_PID=stale")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return out.String(), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return out.String(), 0
}

// LISTEN_PID is the pid the payload runs under, not the wrapper's parent's and
// not whatever the environment carried in: sd_listen_fds ignores the
// descriptors when the two differ, so a wrong value is a door nothing accepts
// on, silently.
func TestDoorExecListenPIDIsThePayloadsOwnPid(t *testing.T) {
	out, code := door(t, "", "/bin/sh", "-c", `echo "pid=$$ listen=$LISTEN_PID"`)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	var pid, listen string
	for f := range strings.FieldsSeq(out) {
		if v, ok := strings.CutPrefix(f, "pid="); ok {
			pid = v
		}
		if v, ok := strings.CutPrefix(f, "listen="); ok {
			listen = v
		}
	}
	if pid == "" || pid != listen {
		t.Fatalf("LISTEN_PID %q is not the payload's pid %q:\n%s", listen, pid, out)
	}
}

// The Go runtime raises its own RLIMIT_NOFILE soft limit at start. The shell
// this replaced did not, so a payload must inherit the limit the wrapper was
// STARTED with, not the one the runtime raised it to.
func TestDoorExecPassesTheStartingNofileLimitOn(t *testing.T) {
	out, code := door(t, "ulimit -Sn 777", "/bin/sh", "-c", "ulimit -Sn")
	if code != 0 || strings.TrimSpace(out) != "777" {
		t.Fatalf("exit %d, soft NOFILE after the wrapper = %q, want 777", code, out)
	}
}

// A signal ignored when the wrapper starts stays ignored in the payload, as it
// did across the shell's exec: the wrapper must not be where the payload's
// signal state is decided.
func TestDoorExecKeepsInheritedIgnoredSignals(t *testing.T) {
	out, code := door(t, "trap '' HUP", "/bin/sh", "-c", "grep SigIgn /proc/self/status")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, "SigIgn:") || strings.HasSuffix(strings.TrimSpace(out), "0000000000000000") {
		t.Fatalf("SIGHUP ignored before the wrapper is not ignored after it:\n%s", out)
	}
}

func TestDoorExecLooksTheCommandUpOnPath(t *testing.T) {
	out, code := door(t, "", "sh", "-c", "echo found")
	if code != 0 || strings.TrimSpace(out) != "found" {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestDoorExecExitCodesMatchTheShell(t *testing.T) {
	if out, code := door(t, "", "snug-no-such-command"); code != exitNotFound {
		t.Errorf("missing command: exit %d, want %d:\n%s", code, exitNotFound, out)
	}
	dir := t.TempDir()
	notExec := filepath.Join(dir, "x")
	if err := os.WriteFile(notExec, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := door(t, "", notExec); code != exitCannotRun {
		t.Errorf("non-executable command: exit %d, want %d:\n%s", code, exitCannotRun, out)
	}
	if out, code := door(t, ""); code != exitUsage {
		t.Errorf("no command: exit %d, want %d:\n%s", code, exitUsage, out)
	}
}

func TestBrowserWritesExactlyOneLine(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "browser.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	go func() {
		b, _ := os.ReadFile(fifo)
		got <- string(b)
	}()
	var stderr bytes.Buffer
	if code := Browser(fifo, []string{"https://claude.ai/oauth?x=1"}, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if g := <-got; g != "https://claude.ai/oauth?x=1\n" {
		t.Fatalf("FIFO got %q", g)
	}
}

func TestBrowserRefusesAnythingButOneLine(t *testing.T) {
	// No FIFO exists: each of these must refuse before opening it, or the test
	// would report the open error instead of the usage one.
	fifo := filepath.Join(t.TempDir(), "absent")
	for _, args := range [][]string{nil, {"a", "b"}, {"a\nb"}, {"a\x00b"}, {strings.Repeat("a", 4096)}} {
		var stderr bytes.Buffer
		if code := Browser(fifo, args, &stderr); code != exitUsage {
			t.Errorf("Browser(%q) = %d, want %d: %s", args, code, exitUsage, stderr.String())
		}
	}
}
