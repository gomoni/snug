//go:build integration

package integration

import (
	"fmt"
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

// requireHostSystemSSHConfig finds the ONE spelling this host's ssh actually
// reads and returns its directory (ready to be granted by a test-authored
// profile) and the full path.
//
// Skips (loudly, via skipOrFail, so it also FAILS under SNUG_REQUIRE_SANDBOX)
// only when the SOFTWARE under test is missing — no ssh binary, or no
// system-wide ssh_config at either spelling at all. That is what
// requireSandbox-style gating is legitimately for.
//
// It deliberately does NOT skip merely because @sys does not happen to cover
// this host's layout, and a code review is the reason: an earlier version of
// this guard (both under this name and under the name hostSystemSSHConfig,
// which asked existence rather than coverage) either skipped never — Debian,
// Ubuntu and Fedora all ship a system-wide ssh_config, so the test proceeded —
// or skipped via skipOrFail's Fatal-under-CI semantics the moment it was made
// coverage-aware without also fixing the root problem. Both are wrong, for
// the same reason: SNUG_REQUIRE_SANDBOX (set for `make integration` on
// ubuntu-latest, .github/workflows/ci.yml) asserts "this host can create
// namespaces, so the suite must not silently check nothing" — it does NOT
// assert "this host has openSUSE's file layout", and @sys deliberately does
// not grant /etc/ssh at all (issue #40), so gating on that layout
// makes CI fail a job for a condition that was never wrong. Downgrading to a
// plain t.Skip instead would satisfy CI and lose the coverage on every CI run
// forever — the exact trade CLAUDE.md refuses.
//
// So the fix is not a smarter skip: it is to stop depending on @sys at all and
// SUPPLY the coverage instead. Every caller of this function selects a
// test-authored profile (see the sshcover TOML built at each call site) that
// binds this returned directory read-only at the identical guest path. The
// file is root-owned on every distro that ships one, and the sandbox never
// maps the caller to root, so the ownership refusal under test reproduces
// identically whether @sys already covers the path (a legal same-underlying-
// tree re-grant — the same shape as cwd-rw layering over parent-ro) or not
// (a brand new mount @sys never had, which is Ubuntu's shape). Verified by
// hand against this tree: binding a directory at /etc/ssh, a path @sys does
// not grant on this box either, produces a FILESYSTEM row "data
// /etc/ssh/ssh_config (snug)+replaces:<the test profile>" — the identical
// shape a Debian-shaped host will produce automatically once the real /etc/ssh
// is bound.
func requireHostSystemSSHConfig(t *testing.T) (dir, sysconf string) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		skipOrFail(t, "ssh is not installed; there is no system ssh_config to protect")
	}
	for _, p := range policy.SystemSSHConfigPaths {
		if _, err := os.Stat(p); err == nil {
			return filepath.Dir(p), p
		}
	}
	skipOrFail(t, "this host has no system-wide ssh_config at either spelling snug "+
		"knows (%s); there is nothing for the replacement to protect",
		strings.Join(policy.SystemSSHConfigPaths, " or "))
	return "", ""
}

// sshCoverageProfile is the TOML for the test-authored grant
// requireHostSystemSSHConfig's doc comment describes: a plain read-only bind
// of the host's real system ssh_config directory at the identical guest path,
// so the ownership refusal reproduces regardless of what @sys does or does
// not enumerate on this host.
func sshCoverageProfile(dir string) string {
	return "[profile.sshcover]\n" +
		"description = \"binds this host's real system-wide ssh_config directory " +
		"read-only at the identical guest path, so the ownership refusal snug's " +
		"replacement fixes reproduces on this host regardless of whether @sys " +
		"already covers it\"\n" +
		"ro = [\"" + dir + "\"]\n"
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

// sshKeyComment is the comment sshAgentWithNKeys gives its i'th generated key,
// exported as a function (rather than just inlined) so the test asserting
// enumeration and the helper that generated the keys cannot drift apart.
func sshKeyComment(i int) string {
	return fmt.Sprintf("snug-integration-key-%d@example.invalid", i)
}

// sshAgentWithNKeys starts a throwaway agent — never the developer's own, and
// never touching ~/.ssh — and loads it with n keys, each generated into a
// fresh temp dir with a distinct comment (sshKeyComment). It returns the n
// public key paths in generation order plus SSH_AUTH_SOCK, so a caller can pin
// any one of them and know exactly which comment identifies it on screen.
//
// This is what makes TestSSHAgentEnumerationIsBoundToOnePinnedKeyAmongMany an
// end-to-end measurement rather than a guess about whatever agent the machine
// running the suite happens to have: N is a number this function controls.
func sshAgentWithNKeys(t *testing.T, n int) (pubs []string, sock string) {
	t.Helper()
	for _, bin := range []string{"ssh-keygen", "ssh-agent", "ssh-add"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is not installed; nothing to measure", bin)
		}
	}
	dir := t.TempDir()
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

	for i := 0; i < n; i++ {
		key := filepath.Join(dir, fmt.Sprintf("id_ed25519_%d", i))
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
			sshKeyComment(i), "-f", key).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen %d: %v\n%s", i, err, out)
		}
		add := exec.Command("ssh-add", key)
		add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
		if out, err := add.CombinedOutput(); err != nil {
			t.Fatalf("ssh-add %d: %v\n%s", i, err, out)
		}
		pubs = append(pubs, key+".pub")
	}
	return pubs, sock
}

// hostAgentKeyCount asks the real agent directly, bypassing snug and the
// sandbox entirely — the host-side measurement every host/inside comparison
// in this file needs as its other half.
func hostAgentKeyCount(t *testing.T, sock string) int {
	t.Helper()
	list := exec.Command("ssh-add", "-l")
	list.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	out, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-add -l against the throwaway agent: %v\n%s", err, out)
	}
	n := 0
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
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

// writeProfiles is writeProfile generalised to more than one profile in the
// SAME profiles.d directory — for a test that needs two grants to compose (an
// identity plus requireHostSystemSSHConfig's coverage-only profile, say)
// rather than clobber one another the way two independent XDG_CONFIG_HOME
// values would (os/exec keeps only the LAST duplicate env entry).
func writeProfiles(t *testing.T, tomls map[string]string, extraEnv ...string) []string {
	t.Helper()
	cfg := t.TempDir()
	pd := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, toml := range tomls {
		if err := os.WriteFile(filepath.Join(pd, name+".toml"), []byte(toml), 0o644); err != nil {
			t.Fatal(err)
		}
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
// SSHAgentProxy:` and silently dropped it for the mode beside it. Nothing
// failed: both modes still started, and the breakage only showed up when ssh
// declined to offer an identity to a real server.
//
// THE TABLE HAS ONE ROW NOW, and it stays a table for that reason rather than
// in spite of it: `agent-proxy` is the only mode left that stages anything
// (`host-agent` was removed — see policy.ParseSSHMode), and the bug this pins
// is a per-branch one that only reappears when a SECOND mode is added. A row
// is what the next mode is added to; an inlined single case is what it is
// added beside.
func TestThePinnedPublicKeyIsStagedInEverySSHMode(t *testing.T) {
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)

	for _, tc := range []struct {
		mode  string
		flags []string
	}{
		{"agent-proxy", nil},
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

// TestSSHRunsInsideTheSandboxWhenAnIdentityIsPinned's positive control used to
// be "the UNPINNED run refuses" — until issue #40, the system ssh_config
// replacement rode on [identity], so an unpinned sandbox got the host's
// root-owned file untouched and ssh refused it there too. That made the
// control mean something: if the pinned run alone said SSH-OK, the identity
// machinery was doing the work.
//
// Issue #40 makes the replacement fire on EVERY run, identity pinned or not
// (issue #40) — which is the fix, and is deliberate — but it also
// makes the unpinned run say SSH-OK too, so "the unpinned run refuses" is no
// longer true on ANY host and the control had silently degraded to a t.Logf
// that could never fire. Exactly CLAUDE.md's "a test that cannot fail" shape:
// a control that needs a broken configuration to exist stops working the
// moment you fix it.
//
// Rebased per issue #40 onto two things that stay true after the
// fix:
//
//   - stat -c %u on the replaced path returns the SANDBOX's uid, proving the
//     replacement actually fired (kept from the original test).
//   - ssh still REFUSES a config that Includes a DIFFERENT root-owned file the
//     sandbox does not replace. snug's replacement is scoped to exactly the
//     one top-level file (SystemSSHConfig's doc comment: "no Include line...
//     every file it would pull in is root-owned too") — it is not a general
//     bypass of OpenSSH's ownership check. /etc/passwd is granted read-only by
//     @sys on every host (base.toml's fixed /etc list) and is root-owned on
//     every Linux host, so it needs no host-specific drop-in to reproduce:
//     measured, the file named directly to -F is itself exempt from the
//     check (an explicit human choice), but anything IT Includes is still
//     checked — that is what actually fails, and it is what proves the
//     ownership refusal is still live rather than having quietly stopped
//     applying everywhere.
//
// The identity profile alone is not enough to reproduce the failure on every
// host: it grants no path under /etc, so whether the sandbox sees a root-owned
// system ssh_config at all depends entirely on whether @sys happens to cover
// this host's layout — true on openSUSE, false on Debian/Ubuntu/Fedora, which
// is a second instance of the very existence-vs-coverage confusion this test
// exists to catch. So the "pinned" profile here composes with a SECOND,
// coverage-only profile (requireHostSystemSSHConfig, sshCoverageProfile) that
// grants this host's real system ssh_config directory explicitly, and both
// are written into ONE profiles.d directory (writeProfiles) so neither
// XDG_CONFIG_HOME clobbers the other.
func TestSSHRunsInsideTheSandboxWhenAnIdentityIsPinned(t *testing.T) {
	requireSandbox(t)
	dir, sysconf := requireHostSystemSSHConfig(t)
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)

	// No gh_user: this is the ssh half, and a gh account would make the test
	// depend on a token on the machine running it.
	env := writeProfiles(t, map[string]string{
		"pinned": "[profile.pinned]\n" +
			"description = \"one throwaway key, for the integration suite\"\n" +
			"[profile.pinned.identity]\n" +
			"ssh_mode = \"agent-proxy\"\n" +
			"ssh_key = \"" + pub + "\"\n" +
			"git_name = \"Snug Integration\"\n" +
			"git_email = \"snug@example.invalid\"\n",
		"sshcover": sshCoverageProfile(dir),
	}, "SSH_AUTH_SOCK="+sock)

	probeConf := filepath.Join(proj, "probe_ssh_config")
	if err := os.WriteFile(probeConf, []byte("Include /etc/passwd\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runEnv(t, env, []string{"-p", "pinned", "-p", "sshcover"}, proj,
		`ssh -G github.com >/dev/null 2>&1 && echo SSH-OK || echo SSH-REFUSED
echo "owner=$(stat -c %u `+sysconf+`)"
echo "uid=$(id -u)"
grep -ci '^[[:space:]]*include' `+sysconf+` || echo "includes=0"
if probeout=$(ssh -F `+probeConf+` -G github.com 2>&1); then
  echo PROBE-OK
else
  echo "PROBE-REFUSED: $probeout"
fi`).mustRun(t)

	if !strings.Contains(r.out, "SSH-OK") {
		t.Errorf("ssh refuses to run inside a sandbox with a pinned identity, so "+
			"git-over-ssh — the point of pinning one — cannot work:\n%s", r.out)
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
	if !strings.Contains(r.out, "PROBE-REFUSED") {
		t.Errorf("ssh accepted a config Including /etc/passwd, a root-owned file the "+
			"sandbox does NOT replace; the ownership refusal this whole feature routes "+
			"around is no longer enforced, so SSH-OK above proves nothing:\n%s", r.out)
	}
}

// TestSSHWorksInAPlainSandboxRun is issue #40's own reproduction, inverted —
// the exact command from the issue. Before the fix, `snug <dir> -- ssh -G
// github.com` died on any host whose system-wide ssh_config lives under a
// granted tree, with NO identity involved: the replacement rode on
// [identity], so an unpinned sandbox got the host's root-owned file untouched.
// git clone over ssh, scp, and rsync -e ssh all failed the same way for every
// user who had not pinned an account.
//
// "Plain" here means no identity and no credential of any kind — it does NOT
// mean zero -p flags, and getting that wrong is exactly the bug a code review
// caught: the guard has to be COVERAGE-aware, not existence-aware, or this
// test passes VACUOUSLY on Debian/Ubuntu/Fedora, where the host genuinely has
// a system-wide ssh_config but @sys grants nothing under /etc/ssh — ssh -G
// succeeds there because nothing root-owned was ever exposed inside, not
// because the replacement fired. Rather than skip hosts shaped that way (which
// would delete this coverage from CI forever — ubuntu-latest is exactly this
// shape, per .github/workflows/ci.yml), the sshcover profile
// (requireHostSystemSSHConfig, sshCoverageProfile) grants nothing but a
// read-only bind of this host's real system ssh_config directory at the
// identical guest path, so the ownership condition under test reproduces on
// every host — see requireHostSystemSSHConfig's doc comment for the full
// reasoning and the by-hand verification.
func TestSSHWorksInAPlainSandboxRun(t *testing.T) {
	requireSandbox(t)
	dir, _ := requireHostSystemSSHConfig(t)
	proj, _ := target(t)
	env := writeProfile(t, sshCoverageProfile(dir))

	r := runEnv(t, env, []string{"-p", "sshcover"}, proj,
		`ssh -G github.com >/dev/null 2>&1 && echo SSH-OK || echo SSH-REFUSED`).mustRun(t)

	if !strings.Contains(r.out, "SSH-OK") {
		t.Errorf("ssh -G github.com failed with no identity pinned and no credential of "+
			"any kind involved — issue #40's exact reproduction:\n%s", r.out)
	}
}

// TestSSHReachParityBetweenAPlainRunAndNet mechanises a red-team negative
// (round following issue #40's fix; measured by hand against this tree):
// `ssh` reaching the real handshake is not enough on its own to show the
// system ssh_config replacement is safe — a version that carried a stray
// credential, or one that quietly widened egress for ssh specifically, would
// ALSO make the handshake succeed. Two things have to hold together:
//
//   - `snug -p @net <dir> -- ssh … git@github.com` reaches GitHub's sshd and is
//     refused for lack of a key (Permission denied (publickey)) — proving ssh
//     now works AND that it carries no credential, since no identity is
//     pinned here at all.
//   - The SAME command in a PLAIN run, no @net, fails at NAME RESOLUTION
//     instead — proving egress is still gated for ssh specifically, and the
//     ssh_config fix did not become a side channel around the empty netns.
//
// -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null are there
// because neither run has a pinned identity, so neither has a generated
// known_hosts inside; without them ssh refuses on an unknown host key before
// it ever gets to publickey auth, which would prove nothing about egress.
func TestSSHReachParityBetweenAPlainRunAndNet(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	requirePasta(t)
	requireInternet(t)
	proj, _ := target(t)

	sshCmd := `ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no ` +
		`-o UserKnownHostsFile=/dev/null git@github.com 2>&1; echo "rc=$?"`

	withNet := run(t, []string{"-p", "@net"}, proj, sshCmd).mustRun(t)
	if !strings.Contains(withNet.out, "Permission denied (publickey)") {
		t.Errorf("snug -p @net -- ssh … git@github.com did not reach the real handshake "+
			"and refuse for lack of a key; with no identity pinned, this must be the ONLY "+
			"way it can fail — anything else means either the handshake never happened "+
			"(ssh_config still broken) or a credential reached it (a leak):\n%s", withNet.out)
	}

	offline := run(t, nil, proj, sshCmd).mustRun(t)
	if strings.Contains(offline.out, "Permission denied") {
		t.Errorf("ssh reached a real handshake with NO @net selected — egress is not "+
			"gated for ssh, which the system ssh_config replacement must not have "+
			"changed:\n%s", offline.out)
	}
	// The exact wording is the resolver's, not snug's (OpenSSH's own "Could not
	// resolve hostname", or a libc getaddrinfo message), so match on the shape
	// of a resolution failure rather than one literal string.
	resolutionFailed := strings.Contains(offline.out, "Could not resolve hostname") ||
		strings.Contains(offline.out, "Name or service not known") ||
		strings.Contains(offline.out, "Temporary failure in name resolution")
	if !resolutionFailed {
		t.Errorf("ssh without @net did not fail at name resolution as expected — egress "+
			"may be reaching further than the offline netns should allow:\n%s", offline.out)
	}
}

// TestDryRunOfADefaultSelectionNamesRequiredRSASize is the red team's second
// mechanised negative. internal/cli/dryrun_test.go's
// TestDescribeSSHNamesTheReplacedPathAndItsCost already asserts describeSSH
// names RequiredRSASize, but against a SYNTHETIC profile selection built to
// avoid host dependence ([]string{"@sys", "@home", "@cwd-rw", "sshhost"}) —
// not the actual `defaults` setting a bare `snug <dir>` resolves to. That is
// not a duplicate of what is being asked here: the downgrade this feature
// accepts (issue #40) has to stay on screen for the EXACT command
// most users run, not only for a selection a test constructed to exercise the
// renderer. A regression that only broke under the real defaults — say, a
// profile ordering bug that made describeSSH see a stale mount set — would
// pass the renderer-level test and still reopen invariant 5 here.
//
// The guard is requireHostSystemSSHConfig plus the sshcover profile, not a
// hardcoded check of the /usr/etc/ssh spelling: an earlier version of this
// test did exactly that (os.Stat("/usr/etc/ssh/ssh_config")), and a later
// version made the same mistake one layer down by skipping instead of
// supplying — both are the existence-vs-coverage confusion a code review
// caught across this whole file. "Default selection" here means the
// `defaults` profiles PLUS the coverage-only grant every call site in this
// file now adds, not zero -p flags — see requireHostSystemSSHConfig's doc
// comment for why zero flags cannot be made to work on every host without
// losing this coverage from CI.
func TestDryRunOfADefaultSelectionNamesRequiredRSASize(t *testing.T) {
	dir, _ := requireHostSystemSSHConfig(t)
	proj, _ := target(t)
	env := writeProfile(t, sshCoverageProfile(dir))

	out, code := cli(t, env, "--dry-run", "-p", "sshcover", proj)
	if code != 0 {
		t.Fatalf("snug --dry-run exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "SSH") {
		t.Fatalf("no SSH block in a --dry-run on a host whose system ssh_config "+
			"is covered:\n%s", out)
	}
	if !strings.Contains(out, "RequiredRSASize") {
		t.Errorf("the SSH block does not name RequiredRSASize; the downgrade this "+
			"feature accepts must stay on screen, or invariant 5 (no silent downgrade) "+
			"is reopened for this feature:\n%s", out)
	}
}

// TestSSHAgentEnumerationIsBoundToOnePinnedKeyAmongMany is issue #86 item 2.
//
// internal/sshproxy has unit tests for the FILTER itself, and
// TestThePinnedPublicKeyIsStagedInEverySSHMode above covers staging. Neither
// measures the property the whole ssh_mode = "agent-proxy" decision rests on:
// a host agent holding many keys, and the sandbox enumerating exactly one —
// the pinned one. The filter can stay correct in unit tests while what
// actually reaches it, end to end through a real proxy and a real sandbox,
// silently changes; this is the test that would catch that.
//
// The throwaway agent is this test's own (sshAgentWithNKeys), never the
// developer's ~/.ssh or whatever SSH_AUTH_SOCK happens to be set on the
// machine running the suite — otherwise "exactly one enumerable" would be a
// property of that machine's agent on the day, not of snug.
func TestSSHAgentEnumerationIsBoundToOnePinnedKeyAmongMany(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	const n = 6
	pubs, sock := sshAgentWithNKeys(t, n)
	proj, _ := target(t)

	// CONTROL: measured from the HOST side, against the real agent, before any
	// sandbox is involved. Without this, "exactly one enumerable inside" would
	// be equally true of an agent that only ever held one key.
	if got := hostAgentKeyCount(t, sock); got != n {
		t.Fatalf("precondition: the throwaway agent holds %d keys, not %d — this test "+
			"would prove nothing", got, n)
	}

	// An arbitrary key in the middle, not the first or last generated — rules
	// out an off-by-one on either end of the identity list as a way to pass by
	// accident.
	const pinIndex = 2
	pin := pubs[pinIndex]

	// A key that was never loaded into the agent at all, staged into the
	// target (writable, visible inside) so the sandbox can try to hand it to
	// ssh-add without needing ssh-keygen to work inside the sandbox too.
	newKey := filepath.Join(proj, "newkey_probe")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
		"not-loaded@example.invalid", "-f", newKey).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}

	env := writeProfile(t, "[profile.pinned]\n"+
		"description = \"one key pinned out of many in the agent, for the enumeration bound\"\n"+
		"[profile.pinned.identity]\n"+
		"ssh_mode = \"agent-proxy\"\n"+
		"ssh_key = \""+pin+"\"\n", "SSH_AUTH_SOCK="+sock)

	// -v is required: the two refusals below are audited to snug's own stderr
	// (internal/cli/identity.go), not to the sandboxed payload's own output, and
	// without it there would be nothing here to assert against beyond the
	// enumeration count.
	r := runEnv(t, env, []string{"-p", "pinned", "-v"}, proj,
		`raw=$(ssh-add -l 2>&1)
echo "RAW: $raw"
echo "count=$(printf '%s\n' "$raw" | grep -c .)"
ssh-add newkey_probe 2>&1
ssh-add -D 2>&1`).mustRun(t)

	// Positive control: the pinned key IS enumerable, by its comment.
	if !strings.Contains(r.out, sshKeyComment(pinIndex)) {
		t.Fatalf("the pinned key's comment does not appear in ssh-add -l inside the "+
			"sandbox, so the count assertion below would prove nothing:\n%s", r.out)
	}
	if !strings.Contains(r.out, "count=1") {
		t.Errorf("the sandbox enumerated other than exactly one key out of %d in the "+
			"host agent:\n%s", n, r.out)
	}
	for i := range pubs {
		if i == pinIndex {
			continue
		}
		if strings.Contains(r.out, sshKeyComment(i)) {
			t.Errorf("key %d, which was not pinned, is enumerable inside the sandbox:\n%s", i, r.out)
		}
	}

	if !strings.Contains(r.out, "sandbox tried to add a key to the host agent") {
		t.Errorf("adding a new key inside the sandbox was not refused with the audit "+
			"message the proxy is documented to emit:\n%s", r.out)
	}
	if !strings.Contains(r.out, "sandbox tried to remove keys from the host agent") {
		t.Errorf("ssh-add -D inside the sandbox was not refused with the audit message "+
			"the proxy is documented to emit:\n%s", r.out)
	}

	// Positive control that the refusals actually refused, not merely printed a
	// message while doing the thing anyway: the real agent, checked directly
	// from the host, still holds all n keys.
	if got := hostAgentKeyCount(t, sock); got != n {
		t.Errorf("the host agent holds %d keys after the sandboxed ssh-add/-D attempts, "+
			"not the original %d — a refusal that only logs and does not refuse is not "+
			"a refusal:\n%s", got, n, r.out)
	}
}

// TestPinnedIdentityIgnoresAPayloadAuthoredXDGGitConfig is issue #86 item 3,
// and the regression test issue #84 says keeps its residual a residual: "the
// payload can plant a git command table but it cannot beat a pinned identity"
// is a sentence without this check.
//
// resolve.go sets GIT_CONFIG_GLOBAL to the generated ~/.gitconfig whenever
// git = "extract" or an [identity] block is present — REPLACING, not merging
// with, ~/.gitconfig and $XDG_CONFIG_HOME/git/config (both read by git when
// GIT_CONFIG_GLOBAL is unset). $XDG_CONFIG_HOME is `{home}/.config`, one of
// the eight writable tmpfs paths that die with the sandbox (base.toml,
// [profile.home]) — so a payload running earlier in the SAME sandbox can
// always write $XDG_CONFIG_HOME/git/config. The question this test answers is
// whether git still obeys it once an identity is pinned.
//
// Issue #84's own investigation produced a false negative twice from the same
// mistake: running the check under `env -u GIT_CONFIG_GLOBAL` first, which
// unsets the very variable the defence depends on before ever exercising it —
// proving nothing about whether snug's own GIT_CONFIG_GLOBAL wins. This test
// does not do that anywhere. Its positive control (below) is a SEPARATE
// sandbox invocation with no identity and no git profile at all — the actual
// unprotected baseline, where snug never authors GIT_CONFIG_GLOBAL in the
// first place, matching issue #84's own reproduction of the residual — rather
// than a doctored version of the protected run.
func TestPinnedIdentityIgnoresAPayloadAuthoredXDGGitConfig(t *testing.T) {
	budget(t)
	requireSandbox(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}

	payload := func(marker string) string {
		return `mkdir -p "$XDG_CONFIG_HOME/git"
cat > "$XDG_CONFIG_HOME/git/config" <<'PAYLOAD'
[user]
	name = payloadname
[alias]
	pwn = !touch ` + marker + `
PAYLOAD
echo "global=[$GIT_CONFIG_GLOBAL]"
echo "name=[$(git config --get user.name)]"
echo "email=[$(git config --get user.email)]"
git pwn 2>&1 | head -1
echo "pwned=[$(test -f ` + marker + ` && echo yes || echo no)]"
`
	}

	// ARM A — the unprotected baseline, and the positive control for the
	// mechanism under test. No identity, no git profile, nothing else on the
	// command line beyond the defaults: GIT_CONFIG_GLOBAL is never authored,
	// so plain git behaviour applies and $XDG_CONFIG_HOME/git/config is read.
	// If this arm did NOT show the payload's identity taking effect, ARM B's
	// refusal below would prove nothing — it could just as well mean git never
	// reads XDG config on this host for an unrelated reason.
	t.Run("baseline_no_identity_is_actually_exploitable", func(t *testing.T) {
		projA, _ := target(t)
		a := run(t, nil, projA, payload("PWNED_A")).mustRun(t)

		if strings.Contains(a.out, "global=[") && !strings.Contains(a.out, "global=[]") {
			t.Errorf("no identity and no git profile were selected, yet GIT_CONFIG_GLOBAL "+
				"is set — this arm is not the unprotected baseline it claims to be:\n%s", a.out)
		}
		if !strings.Contains(a.out, "name=[payloadname]") {
			t.Fatalf("the payload-authored XDG git config was not honoured with no identity "+
				"pinned; the mechanism this test relies on to make ARM B meaningful is not "+
				"present on this host:\n%s", a.out)
		}
		if !strings.Contains(a.out, "pwned=[yes]") {
			t.Fatalf("the payload's alias did not run in the unprotected baseline; ARM B's "+
				"absence of PWNED_B below would prove nothing:\n%s", a.out)
		}
	})

	// ARM B — an identity pinned (ssh_mode = "none": this is the git half, not
	// the ssh one). The SAME payload as ARM A must be ignored.
	t.Run("pinned_identity_refuses_it", func(t *testing.T) {
		projB, _ := target(t)
		env := writeProfile(t, "[profile.pinned]\n"+
			"description = \"git identity pin for the XDG_CONFIG_HOME bound (issue #86 item 3)\"\n"+
			"[profile.pinned.identity]\n"+
			"ssh_mode = \"none\"\n"+
			"git_name = \"Pinned Name\"\n"+
			"git_email = \"pinned@example.invalid\"\n")

		b := runEnv(t, env, []string{"-p", "pinned"}, projB, payload("PWNED_B")).mustRun(t)

		// Verify the defence is ACTIVE, not merely requested: GIT_CONFIG_GLOBAL
		// really is set inside this run, pointing at snug's generated file.
		if !strings.Contains(b.out, "global=[") || strings.Contains(b.out, "global=[]") {
			t.Fatalf("GIT_CONFIG_GLOBAL is not set with an identity pinned; the mechanism "+
				"this test is meant to verify never engaged:\n%s", b.out)
		}
		if !strings.Contains(b.out, ".gitconfig") {
			t.Errorf("GIT_CONFIG_GLOBAL is set but does not name the generated ~/.gitconfig:\n%s", b.out)
		}
		if !strings.Contains(b.out, "name=[Pinned Name]") {
			t.Errorf("the payload-authored XDG git config overrode the pinned identity's "+
				"name — the residual issue #84 accepted has widened into a real defeat:\n%s", b.out)
		}
		if !strings.Contains(b.out, "email=[pinned@example.invalid]") {
			t.Errorf("the pinned email did not win over the payload-authored XDG git config:\n%s", b.out)
		}
		if !strings.Contains(b.out, "pwned=[no]") {
			t.Errorf("the payload's alias, planted only through $XDG_CONFIG_HOME/git/config, "+
				"ran anyway with an identity pinned:\n%s", b.out)
		}
		if !strings.Contains(b.out, "not a git command") {
			t.Errorf("git did not report alias.pwn as unrecognised, which is the shape a "+
				"correctly-ignored XDG config takes:\n%s", b.out)
		}
	})
}

// sshGValues runs `ssh -G` for the probe host name and returns the
// whitelisted keys it prints. The PROBE host name, not github.com, and
// deliberately: a `Host github.com` block in whoever's ~/.ssh/config is
// running the suite would make the host side of the comparison below a
// property of that file rather than of snug.
func sshGValues(t *testing.T, out string) map[string]string {
	t.Helper()
	v := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		for _, w := range policy.SSHKeyWhitelist {
			if strings.EqualFold(key, w) {
				v[w] = value
			}
		}
	}
	return v
}

// TestTheSandboxSSHResolvesTheHostsAlgorithmPolicy is issue #43's end-to-end
// measurement, and it is the one that would have caught the cost issue #40
// accepted: the replacement file made ssh RUN inside the sandbox, and every
// test written for it asserted exactly that — nothing asserted what ssh then
// NEGOTIATED. On a crypto-policy host the sandbox silently dropped to
// OpenSSH's compiled-in values, RequiredRSASize 2048 -> 1024 among them, so
// the sandbox's ssh would accept a 1024-bit RSA host or user key the host's
// ssh refuses.
//
// It compares the host and the sandbox on the SAME question — `ssh -G
// snug-probe.invalid`, the probe name snug itself uses, so no Host block in
// anyone's config can make the two sides ask different things — and requires
// every whitelisted key to agree. That holds on a host with a crypto policy
// (the values were carried) and on one without (both sides reach OpenSSH's
// compiled-in defaults), so it needs no host-shaped skip.
func TestTheSandboxSSHResolvesTheHostsAlgorithmPolicy(t *testing.T) {
	requireSandbox(t)
	dir, _ := requireHostSystemSSHConfig(t)
	proj, _ := target(t)
	env := writeProfile(t, sshCoverageProfile(dir))

	hostOut, err := exec.Command("ssh", "-G", "-o", "BatchMode=yes", "snug-probe.invalid").Output()
	if err != nil {
		t.Fatalf("ssh -G on the host: %v", err)
	}
	host := sshGValues(t, string(hostOut))
	if len(host) == 0 {
		t.Fatal("ssh -G printed none of the whitelisted keys on the host; the comparison " +
			"below would then assert nothing at all")
	}

	r := runEnv(t, env, []string{"-p", "sshcover"}, proj,
		`ssh -G -o BatchMode=yes snug-probe.invalid`).mustRun(t)
	inside := sshGValues(t, r.out)
	if len(inside) == 0 {
		t.Fatalf("ssh -G printed nothing inside the sandbox:\n%s", r.out)
	}

	for _, k := range policy.SSHKeyWhitelist {
		if host[k] != inside[k] {
			t.Errorf("%s differs between the host and the sandbox:\n  host:   %s\n  inside: %s\n"+
				"snug replaces the system-wide ssh_config, so whatever it does not carry over is "+
				"silently OpenSSH's compiled-in value inside — for RequiredRSASize that is 1024 "+
				"against the host's 2048, and the sandbox then accepts an RSA key the host refuses",
				k, host[k], inside[k])
		}
	}
}
