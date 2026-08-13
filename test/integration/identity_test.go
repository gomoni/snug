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

// sshAgentAndKey starts a throwaway agent with one key loaded and returns the
// public key path plus SSH_AUTH_SOCK, so a test can write its own profile.
func sshAgentAndKey(t *testing.T) (pub, sock string) {
	t.Helper()
	for _, bin := range []string{"ssh", "ssh-keygen", "ssh-agent", "ssh-add"} {
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
	sock = filepath.Join(dir, "agent.sock")
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
	return key + ".pub", sock
}

func writeProfile(t *testing.T, toml string, extraEnv ...string) []string {
	t.Helper()
	cfg := t.TempDir()
	pd := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pd, "p.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	return baseEnv(append([]string{"XDG_CONFIG_HOME=" + cfg}, extraEnv...)...)
}

// The generated ~/.ssh/config carries `IdentitiesOnly yes` and an IdentityFile
// naming ~/.ssh/id_snug.pub, and resolve.go writes that config for EVERY ssh
// mode except none. So the key has to be staged for every one of them too: an
// IdentityFile pointing at a file that does not exist, under IdentitiesOnly, is
// the state SSHConfig's own doc comment says "would have broken agent auth".
//
// Written because a draft of this milestone staged the key inside `case
// SSHAgentProxy:` and silently dropped it for host-agent. Nothing failed: both
// modes still start, and the breakage only shows up when ssh declines to offer
// an identity to a real server.
func TestThePinnedPublicKeyIsStagedInEverySSHMode(t *testing.T) {
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)

	for _, tc := range []struct {
		mode  string
		flags []string
	}{
		{"agent-proxy", nil},
		// host-agent forwards the whole agent and is gated on --i-know; the
		// staged key is not what makes it safe, but the ssh config still names
		// it and ssh still has to find it.
		{"host-agent", []string{"--i-know"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			env := writeProfile(t, "[profile.pinned]\n"+
				"description = \"one throwaway key\"\n"+
				"[profile.pinned.identity]\n"+
				"ssh_mode = \""+tc.mode+"\"\n"+
				"ssh_key = \""+pub+"\"\n", "SSH_AUTH_SOCK="+sock)

			args := append(append([]string{"--dry-run", "-p", "pinned"}, tc.flags...), proj)
			out, code := cli(t, env, args...)
			if code != 0 {
				t.Fatalf("snug --dry-run exited %d:\n%s", code, out)
			}
			if !strings.Contains(out, ".ssh/id_snug.pub") {
				t.Errorf("ssh_mode = %q stages no public key, while the generated "+
					"~/.ssh/config names one under IdentitiesOnly:\n%s", tc.mode, out)
			}
			// And it must be attributed to the profile that pinned it, like the
			// three identity files staged beside it. FILESYSTEM rows only — the
			// bwrap argv block names the same file with no provenance, by design.
			found := false
			for _, line := range strings.Split(out, "\n") {
				if !strings.HasPrefix(strings.TrimSpace(line), "data ") ||
					!strings.Contains(line, "id_snug.pub") {
					continue
				}
				found = true
				if !strings.Contains(line, "identity:pinned") {
					t.Errorf("the staged key is attributed to nobody, while its three "+
						"siblings on the same screen name the profile: %q", strings.TrimSpace(line))
				}
			}
			if !found {
				t.Errorf("no FILESYSTEM row for the staged key:\n%s", out)
			}
		})
	}
}

// A dry run inspects a policy. Refusing to print one because the HOST cannot
// mint a token makes the policy unreadable on exactly the machines where
// reading it matters — a CI box, a machine with no gh, someone reviewing a
// colleague's profile. main.go makes the same call for the @tmp-shared host
// directory, in as many words.
func TestDryRunStillPrintsThePolicyWhenTheGhAccountHasNoToken(t *testing.T) {
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)
	env := writeProfile(t, "[profile.pinned]\n"+
		"description = \"an account gh is not logged in to\"\n"+
		"[profile.pinned.identity]\n"+
		"ssh_mode = \"agent-proxy\"\n"+
		"ssh_key = \""+pub+"\"\n"+
		"gh_user = \"snug-no-such-account-here\"\n", "SSH_AUTH_SOCK="+sock)

	out, code := cli(t, env, "--dry-run", "-p", "pinned", proj)
	if code != 0 {
		t.Fatalf("--dry-run refused a policy because the host has no token for the "+
			"pinned account; it must warn and print (exit %d):\n%s", code, out)
	}
	if !strings.Contains(out, "FILESYSTEM") {
		t.Errorf("--dry-run printed no policy:\n%s", out)
	}
	if !strings.Contains(out, "no gh token") {
		t.Errorf("--dry-run continued without saying the credential is missing, which is "+
			"the silent downgrade this milestone set out to close:\n%s", out)
	}
	// The real run must still refuse. Same code path, opposite verdict, and the
	// pair is the whole point.
	out2, code2 := cli(t, env, "-p", "pinned", proj, "--", "/bin/true")
	if code2 == 0 {
		t.Errorf("a real run started with no credential for the pinned account:\n%s", out2)
	}
}

// An identity that names no gh account gets NO token — not the host's active
// one. The previous version called `gh auth token` unconditionally, so a profile
// pinning only an ssh key had whatever account the human last logged into staged
// inside as `x-access-token`: a credential nobody named, from an account the
// profile does not mention.
func TestAnIdentityWithNoGhAccountStagesNoToken(t *testing.T) {
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)
	env := writeProfile(t, "[profile.pinned]\n"+
		"description = \"ssh only, no gh account named\"\n"+
		"[profile.pinned.identity]\n"+
		"ssh_mode = \"agent-proxy\"\n"+
		"ssh_key = \""+pub+"\"\n"+
		"git_email = \"snug@example.invalid\"\n", "SSH_AUTH_SOCK="+sock)

	out, code := cli(t, env, "--dry-run", "-p", "pinned", proj)
	if code != 0 {
		t.Fatalf("snug --dry-run exited %d:\n%s", code, out)
	}
	// The positive control: the identity DID take effect, so "no hosts.yml" is
	// attributable to the gh rule and not to the profile having been ignored.
	if !strings.Contains(out, "identity:pinned") {
		t.Fatalf("the identity profile contributed nothing at all:\n%s", out)
	}
	if strings.Contains(out, "hosts.yml") || strings.Contains(out, "GH_CONFIG_DIR") {
		t.Errorf("an identity naming no gh account still staged a gh credential:\n%s", out)
	}
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
