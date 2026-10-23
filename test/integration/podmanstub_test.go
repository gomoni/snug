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

// The podman stub (issue #691) is snug's own binary under the name podman,
// staged at /snug/bin/podman when podman on the host's PATH is a host-escape
// shim and a podman profile is selected. These tests run the real stub inside
// a real sandbox: the host PATH gets a fake distrobox-host-exec shim, the
// engine comes from $SNUG_PODMAN as for every engine test, and a fake docker
// that prints a marker is granted ahead of the sandbox's own on PATH.

// podmanStubEnv returns the environment for a stub run and the selection that
// grants the fake docker.
func podmanStubEnv(t *testing.T) (env, sel []string) {
	t.Helper()
	env, _ = containerEngineEnv(t)

	shimDir := t.TempDir()
	shim := filepath.Join(shimDir, "distrobox-host-exec")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\necho SHIM-RAN\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(shim, filepath.Join(shimDir, "podman")); err != nil {
		t.Fatal(err)
	}

	clients := t.TempDir()
	if err := os.WriteFile(filepath.Join(clients, "docker"),
		[]byte("#!/bin/sh\necho REACHED-DOCKER \"$0\" \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	layer := envProfileLayer(t, "stub.toml", fmt.Sprintf(`[profile.stubclient]
description = "a fake docker ahead of the sandbox's own on PATH"
ro = ["%s:/stubclient"]

[profile.stubclient.environ.merge]
PATH = ["/stubclient"]
`, clients), shimDir+":"+os.Getenv("PATH"))
	// envProfileLayer's PATH and XDG_CONFIG_HOME, after the engine env's own,
	// so they win.
	for _, e := range layer {
		if strings.HasPrefix(e, "PATH=") || strings.HasPrefix(e, "XDG_CONFIG_HOME=") {
			env = append(env, e)
		}
	}
	return env, []string{"-p", "@podman-socket", "-p", "stubclient"}
}

// TestPodmanStubForwardsToDockerInsideTheSandbox: the payload's bare `podman`
// is snug's stub, and an allowlisted subcommand reaches docker with argv
// intact. The bare word matters: bwrap's execvp passes argv[0] = "podman", not
// the path, which is why the stub keys on the image as well as the name.
func TestPodmanStubForwardsToDockerInsideTheSandbox(t *testing.T) {
	budget(t, 90*time.Second)
	requireSandbox(t)
	env, sel := podmanStubEnv(t)
	proj, _ := target(t)

	out, code := cli(t, env, append(append([]string{}, sel...), proj, "--", "podman", "ps", "-a")...)
	// $0 is the script's path, not argv[0]: the kernel hands the interpreter
	// the path it exec'd.
	if code != 0 || !strings.Contains(out, "REACHED-DOCKER /stubclient/docker ps -a") {
		t.Fatalf("exit %d, want the fake docker reached with `ps -a`:\n%s", code, out)
	}
	if strings.Contains(out, "SHIM-RAN") {
		t.Fatalf("the host shim ran inside the sandbox:\n%s", out)
	}
	markEngineRan(t, enginePathFromEnv(env))
}

// TestPodmanStubRefusesInsideTheSandbox: a podman-only subcommand and a
// connection-shaping flag exit 125 in the stub's voice and never reach docker.
func TestPodmanStubRefusesInsideTheSandbox(t *testing.T) {
	budget(t, 90*time.Second)
	requireSandbox(t)
	env, sel := podmanStubEnv(t)
	proj, _ := target(t)

	for _, argv := range [][]string{
		{"/snug/bin/podman", "pod", "ps"},
		{"podman", "--url=tcp://127.0.0.1:1", "ps"},
	} {
		out, code := cli(t, env, append(append(append([]string{}, sel...), proj, "--"), argv...)...)
		if code != 125 || strings.Contains(out, "REACHED-DOCKER") || !strings.Contains(out, "snug: stub refuses") {
			t.Errorf("%q: exit %d, want 125 from the stub without reaching docker:\n%s", argv, code, out)
		}
	}
}

// TestHostSnugNamedPodmanIsTheCLI: snug installed or copied as `podman` on the
// host is snug's CLI, never the stub. Nothing is at /snug/lib/snug/wrapper on
// the host, so the image half of the key cannot match.
func TestHostSnugNamedPodmanIsTheCLI(t *testing.T) {
	budget(t)
	dir := t.TempDir()
	podman := filepath.Join(dir, "podman")
	data, err := os.ReadFile(snugBin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(podman, data, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, argv0 := range []string{podman, "podman"} {
		cmd := exec.Command(podman, "--help")
		cmd.Args[0] = argv0
		out, _ := cmd.CombinedOutput()
		if strings.Contains(string(out), "stub") || !strings.Contains(string(out), "snug [flags] [dir]") {
			t.Errorf("argv[0] %q: snug named podman did not print the CLI's usage:\n%s", argv0, out)
		}
	}
}
