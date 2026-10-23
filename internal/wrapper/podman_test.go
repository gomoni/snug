package wrapper

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// podmanChildEnv makes TestMain the stub over its arguments, as childEnv makes
// it the door: the stub's success is an execve, observable only from outside.
const podmanChildEnv = "SNUG_WRAPPER_TEST_PODMAN"

// fakeClients writes, into a fresh directory, a script per name that prints
// the name it was run as and its arguments, and returns the directory.
func fakeClients(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		script := "#!/bin/sh\necho \"REACHED $0 $*\"\n"
		if err := os.WriteFile(filepath.Join(dir, n), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// stub runs the test binary as the stub with path as its whole PATH. The fake
// clients run /bin/sh by absolute path, so path holds nothing but them: a real
// docker or podman-remote on this host cannot be the one chosen.
func stub(t *testing.T, path string, args ...string) (string, int) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, args...)
	cmd.Env = []string{podmanChildEnv + "=1", "PATH=" + path}
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

func TestPodmanStubForwardsAnAllowlistedSubcommandToDocker(t *testing.T) {
	dir := fakeClients(t, "docker")
	out, code := stub(t, dir, "run", "--rm", "alpine", "echo", "hi")
	if code != 0 || !strings.Contains(out, "REACHED "+filepath.Join(dir, "docker")+" run --rm alpine echo hi") {
		t.Fatalf("exit %d, want docker reached with argv intact:\n%s", code, out)
	}
}

// Every refusal on the docker path exits 125, says "snug:" and "stub", and
// never reaches docker.
func TestPodmanStubRefusalsOnTheDockerPath(t *testing.T) {
	dir := fakeClients(t, "docker")
	for _, args := range [][]string{
		{"pod", "ps"},
		{"totally-made-up-subcommand"},
		{},
		{"--log-level=debug"},
		{"--connection", "other", "ps"},
		{"ps", "--url=unix:///x"},
		{"run", "--root", "/tmp/x", "alpine"},
	} {
		out, code := stub(t, dir, args...)
		if code != exitStub || strings.Contains(out, "REACHED") ||
			!strings.Contains(out, "snug:") || !strings.Contains(out, "stub") {
			t.Errorf("podman %q: exit %d, want %d from the stub without reaching docker:\n%s",
				args, code, exitStub, out)
		}
	}
}

// podman-remote is podman's own CLI: no docker allowlist, so a podman-only
// subcommand reaches it, verbatim and under its own name.
func TestPodmanStubForwardsVerbatimToPodmanRemote(t *testing.T) {
	dir := fakeClients(t, "podman-remote")
	out, code := stub(t, dir, "pod", "ps", "--format", "{{.Name}}")
	if code != 0 || !strings.Contains(out, "REACHED "+filepath.Join(dir, "podman-remote")+" pod ps --format {{.Name}}") {
		t.Fatalf("exit %d, want podman-remote reached with argv intact:\n%s", code, out)
	}
}

func TestPodmanStubRefusesConnectionFlagsOnThePodmanRemotePath(t *testing.T) {
	dir := fakeClients(t, "podman-remote")
	for _, f := range connectionShapingFlags {
		for _, args := range [][]string{{f, "x", "ps"}, {"ps", f + "=x"}} {
			out, code := stub(t, dir, args...)
			if code != exitStub || strings.Contains(out, "REACHED") || !strings.Contains(out, "podman-remote") {
				t.Errorf("podman %q: exit %d, want %d naming podman-remote without reaching it:\n%s",
					args, code, exitStub, out)
			}
		}
	}
}

// docker wins over podman-remote even when podman-remote's directory comes
// first on PATH: the order is per client, not per directory.
func TestPodmanStubPrefersDocker(t *testing.T) {
	remote, docker := fakeClients(t, "podman-remote"), fakeClients(t, "docker")
	out, code := stub(t, remote+":"+docker, "ps")
	if code != 0 || !strings.Contains(out, "REACHED "+filepath.Join(docker, "docker")+" ps") {
		t.Fatalf("exit %d, want docker chosen:\n%s", code, out)
	}
}

func TestPodmanStubWithNoClientNamesBoth(t *testing.T) {
	out, code := stub(t, fakeClients(t), "ps")
	if code != exitStub || !strings.Contains(out, "'docker' or 'podman-remote'") {
		t.Fatalf("exit %d, want %d naming both clients:\n%s", code, exitStub, out)
	}
}

// A relative PATH entry resolves against the target directory, so a client
// there would be one the repo ships. Neither it nor a non-executable file is
// a client.
func TestPodmanClientSkipsRelativeAndNonExecutable(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("docker", []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	abs := t.TempDir()
	if err := os.WriteFile(filepath.Join(abs, "docker"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if name, bin := podmanClient(".:" + abs + ":" + policy.StagedBinDir); bin != "" {
		t.Fatalf("podmanClient found %s at %s, want none", name, bin)
	}
}

func TestIsPodmanStub(t *testing.T) {
	for _, tc := range []struct {
		argv0, exe string
		want       bool
	}{
		{"podman", policy.WrapperGuest, true},
		{policy.PodmanStubGuest, policy.WrapperGuest, true},
		// A host snug installed or copied as podman stays the CLI.
		{"podman", "/usr/local/bin/podman", false},
		{"/home/u/bin/podman", "/home/u/bin/podman", false},
		{"docker", policy.WrapperGuest, false},
		{policy.WrapperGuest, policy.WrapperGuest, false},
	} {
		if got := IsPodmanStub(tc.argv0, tc.exe); got != tc.want {
			t.Errorf("IsPodmanStub(%q, %q) = %v, want %v", tc.argv0, tc.exe, got, tc.want)
		}
	}
}
