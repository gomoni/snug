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
// not grant /etc/ssh at all (ISSUE-40-DESIGN.md §0), so gating on that layout
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

// TestSSHRunsInsideTheSandboxWhenAnIdentityIsPinned's positive control used to
// be "the UNPINNED run refuses" — until issue #40, the system ssh_config
// replacement rode on [identity], so an unpinned sandbox got the host's
// root-owned file untouched and ssh refused it there too. That made the
// control mean something: if the pinned run alone said SSH-OK, the identity
// machinery was doing the work.
//
// Issue #40 makes the replacement fire on EVERY run, identity pinned or not
// (ISSUE-40-DESIGN.md §1) — which is the fix, and is deliberate — but it also
// makes the unpinned run say SSH-OK too, so "the unpinned run refuses" is no
// longer true on ANY host and the control had silently degraded to a t.Logf
// that could never fire. Exactly CLAUDE.md's "a test that cannot fail" shape:
// a control that needs a broken configuration to exist stops working the
// moment you fix it.
//
// Rebased per ISSUE-40-DESIGN.md §8 onto two things that stay true after the
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
// mechanised negative. cmd/snug/dryrun_test.go's
// TestDescribeSSHNamesTheReplacedPathAndItsCost already asserts describeSSH
// names RequiredRSASize, but against a SYNTHETIC profile selection built to
// avoid host dependence ([]string{"@sys", "@home", "@cwd-rw", "sshhost"}) —
// not the actual `defaults` setting a bare `snug <dir>` resolves to. That is
// not a duplicate of what is being asked here: the downgrade this feature
// accepts (ISSUE-40-DESIGN.md §6) has to stay on screen for the EXACT command
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
