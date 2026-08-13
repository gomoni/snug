//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// Pinning an identity is about pushing as one account, and on this class of host
// it did not work at all: the sandbox maps one uid, so every root-owned file
// under the read-only /usr bind reads as 65534 inside it, and OpenSSH refuses a
// configuration file owned by neither root nor the caller. Fatally, not with a
// warning:
//
//	$ git clone git@github.com:owner/repo.git
//	Bad owner or permissions on /usr/etc/ssh/ssh_config.d/50-suse.conf
//
// Nothing in the suite noticed, because every check of the identity feature was
// a check of what snug GENERATES — the gitconfig, the ssh config, the pinned
// key — and none of them ran ssh.
//
// This test runs ssh. `ssh -G <host>` parses the whole configuration chain and
// prints the effective settings without opening a connection, so it reproduces
// the failure exactly and needs no network, no agent upstream and no account.

// hostSystemSSHConfig returns the system-wide ssh_config this host actually has,
// or "" if it has none. A host with no system config cannot exhibit the bug and
// the test skips rather than pretending to have proved something.
func hostSystemSSHConfig(t *testing.T) string {
	t.Helper()
	for _, p := range policy.SystemSSHConfigPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// sshAgentProfile writes a profile pinning a throwaway key, and starts a real
// ssh-agent for it to proxy. The agent has to exist: ssh_mode = "agent-proxy"
// refuses to start without one, and this test is about what the identity band
// produces, so short-circuiting that would test a different code path.
func sshAgentProfile(t *testing.T) (env []string, profileName string) {
	t.Helper()
	for _, bin := range []string{"ssh", "ssh-keygen", "ssh-agent"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is not installed; nothing to measure", bin)
		}
	}

	dir := t.TempDir()
	key := filepath.Join(dir, "id_ed25519")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
		"snug-integration@example.invalid", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}

	sock := filepath.Join(dir, "agent.sock")
	agent := exec.Command("ssh-agent", "-D", "-a", sock)
	if err := agent.Start(); err != nil {
		t.Fatalf("ssh-agent: %v", err)
	}
	t.Cleanup(func() {
		_ = agent.Process.Kill()
		_, _ = agent.Process.Wait()
	})
	waitForSocket(t, sock)

	add := exec.Command("ssh-add", key)
	add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add: %v\n%s", err, out)
	}

	cfg := t.TempDir()
	pd := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	// No gh_user: this is the ssh half, and a gh account would make the test
	// depend on a token on the machine running it.
	toml := "[profile.pinned]\n" +
		"description = \"one throwaway key, for the integration suite\"\n" +
		"[profile.pinned.identity]\n" +
		"ssh_mode = \"agent-proxy\"\n" +
		"ssh_key = \"" + key + ".pub\"\n" +
		"git_name = \"Snug Integration\"\n" +
		"git_email = \"snug@example.invalid\"\n"
	if err := os.WriteFile(filepath.Join(pd, "pinned.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	return baseEnv("XDG_CONFIG_HOME="+cfg, "SSH_AUTH_SOCK="+sock), "pinned"
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("ssh-agent never created %s", path)
}

func TestSSHRunsInsideTheSandboxWhenAnIdentityIsPinned(t *testing.T) {
	sysconf := hostSystemSSHConfig(t)
	if sysconf == "" {
		t.Skip("this host has no system-wide ssh_config; the failure needs one")
	}
	env, name := sshAgentProfile(t)
	proj, _ := target(t)

	// THE POSITIVE CONTROL, and it is the half that makes the assertion mean
	// something: without a pinned identity the system config is the host's,
	// root-owned, and ssh refuses. If this stops failing, the host stopped
	// exhibiting the bug and the check below stopped proving snug fixed it.
	ctl := run(t, nil, proj,
		`ssh -G github.com >/dev/null 2>&1 && echo SSH-OK || echo SSH-REFUSED
stat -c %u `+sysconf+` 2>/dev/null || echo NO-SYSCONF`).mustRun(t)
	unpinnedRefused := strings.Contains(ctl.out, "SSH-REFUSED")

	r := runEnv(t, env, []string{"-p", name}, proj,
		`ssh -G github.com >/dev/null 2>&1 && echo SSH-OK || echo SSH-REFUSED
echo "owner=$(stat -c %u `+sysconf+`)"
echo "uid=$(id -u)"
grep -ci '^[[:space:]]*include' `+sysconf+` || echo "includes=0"`).mustRun(t)

	if !strings.Contains(r.out, "SSH-OK") {
		t.Errorf("ssh refuses to run inside a sandbox with a pinned identity, so "+
			"git-over-ssh — the point of pinning one — cannot work:\n%s", r.out)
	}
	if !unpinnedRefused {
		t.Logf("NOTE: ssh also ran without a pinned identity, so this host's %s is "+
			"readable as-is and the check above proves less than it does on a host "+
			"where it is not:\n%s", sysconf, ctl.out)
	}
	uid := strconv.Itoa(os.Getuid())
	if !strings.Contains(r.out, "owner="+uid) {
		t.Errorf("the system ssh_config inside is not owned by the sandbox uid %s, "+
			"which is the condition OpenSSH refuses:\n%s", uid, r.out)
	}
	if !strings.Contains(r.out, "includes=0") && !strings.Contains(r.out, "\n0\n") {
		t.Errorf("the generated system ssh_config still has an Include directive; "+
			"every file it names is root-owned and reads as 65534 inside:\n%s", r.out)
	}
}
