//go:build integration

package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// baseEnvDropping is baseEnv minus the named variables, for the spellings that
// depend on a variable being UNSET (snug's runtime directory falls back to the
// temp directory only when $XDG_RUNTIME_DIR is unset).
func baseEnvDropping(drop []string, extra ...string) []string {
	var out []string
	for _, kv := range baseEnv(extra...) {
		skip := false
		for _, d := range drop {
			if strings.HasPrefix(kv, d+"=") {
				skip = true
			}
		}
		if !skip {
			out = append(out, kv)
		}
	}
	return out
}

// holdAnEndpoint starts a sandbox B whose ssh-agent proxy socket lives under
// xdg/snug, and waits until a socket exists there. It returns B's stderr/stdout
// buffer so a caller can assert nothing from another run reached it.
func holdAnEndpoint(t *testing.T, xdg string) *bytes.Buffer {
	t.Helper()
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)
	env := writeProfile(t, "[profile.pinned]\n"+
		"description = \"one throwaway key\"\n"+
		"[profile.pinned.identity.ssh]\n"+
		"agent = \"proxy\"\n"+
		"key = \""+pub+"\"\n", "SSH_AUTH_SOCK="+sock, "XDG_RUNTIME_DIR="+xdg)

	var log bytes.Buffer
	b := exec.Command(snugBin, "-p", "pinned", proj, "--", "/bin/sleep", "60")
	b.Env = env
	b.Stdout, b.Stderr = &log, &log
	b.WaitDelay = waitDelay
	if err := b.Start(); err != nil {
		t.Fatalf("launching holder B: %v", err)
	}
	t.Cleanup(func() {
		b.Process.Kill()
		b.Wait()
	})
	if _, ok := findDescendant(b.Process.Pid, isComm("sleep"), 20*time.Second); !ok {
		t.Fatalf("PRECONDITION: B's payload never started:\n%s", log.String())
	}
	socks, _ := filepath.Glob(filepath.Join(xdg, "snug", "*", "*"))
	if len(socks) == 0 {
		t.Fatalf("PRECONDITION: B holds nothing under %s/snug, so there is no endpoint to reach", xdg)
	}
	return &log
}

func TestASandboxGrantedAPeersRuntimeDirIsRefused(t *testing.T) {
	budget(t, 90*time.Second)
	requireSandbox(t)

	xdg, err := os.MkdirTemp("/tmp", "x")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(xdg) })
	log := holdAnEndpoint(t, xdg)
	before := log.String()
	runDir := filepath.Join(xdg, "snug")

	t.Run("target contains it", func(t *testing.T) {
		out, code := cli(t, baseEnv("XDG_RUNTIME_DIR="+xdg), "-p", "@target-rw", xdg, "--", "/bin/true")
		if code != 77 {
			t.Fatalf("exit %d, want 77 (policy refusal):\n%s", code, out)
		}
		if !strings.Contains(out, runDir) {
			t.Errorf("stderr does not name %s:\n%s", runDir, out)
		}
	})

	t.Run("read-only user profile grant", func(t *testing.T) {
		proj, _ := target(t)
		env := writeProfile(t, "[profile.peek]\n"+
			"description = \"reads the runtime directory\"\n"+
			"ro = [\""+xdg+"\"]\n", "XDG_RUNTIME_DIR="+xdg)
		out, code := cli(t, env, "-p", "peek", proj, "--", "/bin/true")
		if code != 77 {
			t.Fatalf("exit %d, want 77 (policy refusal):\n%s", code, out)
		}
		if !strings.Contains(out, runDir) || !strings.Contains(out, `"peek"`) {
			t.Errorf("stderr names neither %s nor the profile:\n%s", runDir, out)
		}
	})

	time.Sleep(200 * time.Millisecond)
	if after := log.String(); after != before {
		t.Errorf("B's log grew while A was refused, so something from A reached B:\n%s",
			strings.TrimPrefix(after, before))
	}
}

func TestDryRunRefusesTmpTargetWithoutXDGRuntimeDir(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)

	// The suite's empty XDG_CONFIG_HOME is under /tmp, so a /tmp target would
	// be refused as a writable grant over the profile store before the rule
	// under test is reached. The config directory goes under $HOME instead.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory to hold an empty config: %v", err)
	}
	cfg, err := os.MkdirTemp(home, ".snug-itest-")
	if err != nil {
		t.Skipf("cannot create an empty config directory under %s: %v", home, err)
	}
	t.Cleanup(func() { os.RemoveAll(cfg) })
	want := fmt.Sprintf("/tmp/snug-%d", os.Getuid())
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"XDG unset", baseEnvDropping([]string{"XDG_RUNTIME_DIR", "TMPDIR"}, "XDG_CONFIG_HOME="+cfg), want},
		{"XDG set", baseEnv("XDG_CONFIG_HOME="+cfg, "XDG_RUNTIME_DIR=/run/user/"+fmt.Sprint(os.Getuid())), want},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := cli(t, tc.env, "-p", "@net", "--dry-run", "/tmp", "--", "sh")
			if code != 77 {
				t.Fatalf("exit %d, want 77:\n%s", code, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("refusal does not name %s:\n%s", tc.want, out)
			}
		})
	}
}
