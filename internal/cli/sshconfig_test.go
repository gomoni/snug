package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// measuredChain is the debug output of `ssh -G -v -o BatchMode=yes <host>` on
// the development host (OpenSSH_10.3p1, openSUSE), copied verbatim rather than
// paraphrased: the parser's whole job is to survive the shape real ssh prints,
// including the duplicate pass, and a paraphrased fixture is a test of what the
// author remembered.
const measuredChain = `OpenSSH_10.3p1, OpenSSL 3.5.3 16 Sep 2025
debug1: Reading configuration data /home/u/.ssh/config
debug1: Reading configuration data /usr/etc/ssh/ssh_config
debug1: Reading configuration data /usr/etc/ssh/ssh_config.d/50-suse.conf
debug1: Reading configuration data /etc/crypto-policies/back-ends/openssh.config
debug1: Reading configuration data /home/u/.ssh/config
debug1: Reading configuration data /usr/etc/ssh/ssh_config
debug1: Reading configuration data /usr/etc/ssh/ssh_config.d/50-suse.conf
debug1: Reading configuration data /etc/crypto-policies/back-ends/openssh.config
debug1: /usr/etc/ssh/ssh_config line 21: Applying options for *
`

func TestParseSSHConfigChainKeepsOnlyTheSystemFile(t *testing.T) {
	got := parseSSHConfigChain(measuredChain, "/home/u")
	want := []string{"/usr/etc/ssh/ssh_config"}
	if !slices.Equal(got, want) {
		t.Fatalf("parseSSHConfigChain = %q, want %q — the user's own config, the Include'd\n"+
			"fragments and the second parse pass all have to go, and the top-level system\n"+
			"file has to stay", got, want)
	}
}

// TestParseSSHConfigChainFindsAnUnlistedSpelling is the positive control that
// makes the test above mean something: the fixture host's spelling is one snug
// already knows, so a parser that returned nothing at all would look correct
// against a policy layer that has the fixed list as a floor. This is the case
// the whole issue is about — a spelling that is in no list.
func TestParseSSHConfigChainFindsAnUnlistedSpelling(t *testing.T) {
	const freebsd = `debug1: Reading configuration data /home/u/.ssh/config
debug1: Reading configuration data /usr/local/etc/ssh/ssh_config
`
	got := parseSSHConfigChain(freebsd, "/home/u")
	want := []string{"/usr/local/etc/ssh/ssh_config"}
	if !slices.Equal(got, want) {
		t.Fatalf("parseSSHConfigChain = %q, want %q", got, want)
	}
}

func TestParseSSHConfigChainRefusesWhatMustNotBecomeAMount(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"the user's own config", "debug1: Reading configuration data /home/u/.ssh/config"},
		{"a home path spelled as a system one", "debug1: Reading configuration data /home/u/etc/ssh/ssh_config"},
		{"an Include target chosen by a host config line", "debug1: Reading configuration data /tmp/evil/ssh_config.conf"},
		{"a relative path", "debug1: Reading configuration data etc/ssh/ssh_config"},
		{"an unclean path", "debug1: Reading configuration data /usr/etc/../etc/ssh/ssh_config"},
		{"a line that is not a chain line", "debug1: Connecting to /usr/etc/ssh/ssh_config"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSSHConfigChain(tc.line+"\n", "/home/u"); len(got) != 0 {
				t.Fatalf("parseSSHConfigChain kept %q from %q", got, tc.line)
			}
		})
	}
}

// TestParseSSHConfigChainNeighbouringHome is the /home/us versus /home/u case
// the home filter is written as a component test for. A string prefix would
// drop the second user's system-shaped path here, and that is the direction
// that loses a working ssh rather than the one that gains a mount — but it is
// still the filter answering a question it was not asked.
func TestParseSSHConfigChainNeighbouringHome(t *testing.T) {
	const line = "debug1: Reading configuration data /home/us/etc/ssh/ssh_config\n"
	got := parseSSHConfigChain(line, "/home/u")
	if !slices.Equal(got, []string{"/home/us/etc/ssh/ssh_config"}) {
		t.Fatalf("parseSSHConfigChain = %q; /home/us is not under /home/u", got)
	}
}

// TestSSHConfigChainOnThisHost is the end-to-end half, and it is what stops the
// parser being a test of a string constant. It runs the REAL probe against the
// REAL ssh on whatever host the suite runs on, and asserts the two properties
// that hold on every host: nothing under $HOME comes back, and everything that
// does is an absolute path named ssh_config.
//
// It deliberately does NOT assert a particular path — that would pin the suite
// to openSUSE — and it skips where there is no ssh, because a host without ssh
// has nothing to discover and nothing inside the sandbox to break.
func TestSSHConfigChainOnThisHost(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("no ssh on this host; there is nothing to ask")
	}
	home := t.TempDir() // not the real home: this asserts the filter, not the host
	probe, err := probeSSHConfig(home, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range probe.chain {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("chain entry %q is not absolute", p)
		}
		if !strings.HasSuffix(p, "/ssh_config") {
			t.Errorf("chain entry %q is not a top-level system ssh_config", p)
		}
	}
}

// TestProbeSSHConfigWaitDelayBoundsAChildHoldingThePipe reproduces the shape
// from issue #612's redteam round against probeSSHConfig's own cmd.Run,
// exactly as TestWaitDelayBoundsAChildHoldingThePipe does for
// internal/getent.Run: a `Match exec` command (or any child ssh forks before
// exec'ing itself) can background a process that inherits the stdout/stderr
// pipe, and the context kill at sshProbeTimeout only reaches the direct
// child. Without WaitDelay, Run blocks until the backgrounded process exits.
func TestProbeSSHConfigWaitDelayBoundsAChildHoldingThePipe(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "ssh")
	body := "#!/bin/sh\nsleep 30 &\nexec sleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	start := time.Now()
	_, err := probeSSHConfig(t.TempDir(), nil)
	elapsed := time.Since(start)
	if want := sshProbeTimeout + 2*time.Second; elapsed > want {
		t.Fatalf("probeSSHConfig took %s to return, want at most %s: WaitDelay is not "+
			"bounding the wait for a child holding the pipe", elapsed, want)
	}
	if err == nil {
		t.Fatal("a probe that timed out returned no error; the sandbox's ssh would run on " +
			"compiled-in defaults with nothing on screen (#688 F2)")
	}
}

// TestSSHProbeFailureRefuses is #688 F2: a host ssh that exits non-zero, or
// takes longer than sshProbeTimeout (the shape of a slow `Match exec`), used to
// go to an aside printed only under -v, and the run went ahead on OpenSSH's
// compiled-in defaults.
func TestSSHProbeFailureRefuses(t *testing.T) {
	for name, body := range map[string]string{
		"exits non-zero": "#!/bin/sh\necho 'debug1: Reading configuration data /x' >&2\necho 'ssh: bad config' >&2\nexit 255\n",
		"times out":      "#!/bin/sh\nexec /bin/sleep 30\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			probe, err := probeSSHConfig(t.TempDir(), nil)
			if err == nil {
				t.Fatalf("probeSSHConfig = %+v, nil; want a refusal", probe)
			}
			if name == "times out" && !strings.Contains(err.Error(), "did not finish within") {
				t.Errorf("a timeout is not named as one: %v", err)
			}
			// ssh's own reason, not -v's debug lines before it: "Bad owner or
			// permissions on <file>" is the one a human can act on.
			if name == "exits non-zero" && (!strings.Contains(err.Error(), "ssh: bad config") ||
				strings.Contains(err.Error(), "debug1")) {
				t.Errorf("refusal does not carry ssh's own reason alone: %v", err)
			}
			if !strings.Contains(err.Error(), "ssh -G") {
				t.Errorf("refusal does not name the probe to rerun: %v", err)
			}
			if _, err := probeSSHPin(t.TempDir(), "github.com"); err == nil {
				t.Error("probeSSHPin went ahead on a probe that failed")
			}
		})
	}
}

// measuredValues is `ssh -G` output on the development host, trimmed to the
// lines that matter plus a few that must NOT be carried. Verbatim shapes, not
// paraphrases: the parser's job is to survive what ssh really prints.
const measuredValues = `user michal
hostname snug-probe.invalid
requiredrsasize 2048
ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr
macs hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com
proxycommand /usr/bin/nc %h %p
identityfile ~/.ssh/id_rsa
permitlocalcommand no
sendenv LANG
forwardx11trusted yes
rekeylimit 0 0
`

func TestParseSSHValuesKeepsOnlyTheWhitelist(t *testing.T) {
	got, err := parseSSHValues(measuredValues)
	if err != nil {
		t.Fatal(err)
	}

	if got["requiredrsasize"] != "2048" {
		t.Errorf("requiredrsasize = %q, want 2048 — it is the one entry with security "+
			"content: without it the sandbox accepts a 1024-bit RSA key the host refuses",
			got["requiredrsasize"])
	}
	// #688 F6: every whitelisted value is carried, including one equal to
	// OpenSSH's compiled-in default, so the sandbox's ssh does not have to
	// share the host's defaults.
	if got["macs"] == "" || got["rekeylimit"] != "0 0" {
		t.Errorf("macs = %q, rekeylimit = %q; both are whitelisted and must be carried in full",
			got["macs"], got["rekeylimit"])
	}
	// ssh_config is a command table. Every key here names a program or a file,
	// and read-only does not demote one into data — which is why snug generates
	// this file instead of binding the host's.
	for _, k := range []string{"proxycommand", "identityfile", "permitlocalcommand", "sendenv", "forwardx11trusted"} {
		if v, ok := got[k]; ok {
			t.Errorf("carried %s = %q; it is not in policy.SSHKeyWhitelist", k, v)
		}
	}
}

// TestSSHValueDropRefuses is #688 F3: a whitelisted value snug cannot write
// back used to be dropped with a warning, and the sandbox's ssh then used its
// compiled-in default for it (measured: requiredrsasize 1024 against the host's
// 2048).
func TestSSHValueDropRefuses(t *testing.T) {
	// ssh will not print these — it is the host's own binary and it quotes
	// nothing — but the file snug writes is parsed by ssh, and the extractor is
	// the sink where a value stops being a string and starts being a directive.
	// Assert the predicate, not the source's good manners.
	for name, line := range map[string]string{
		"the measured shape":   "requiredrsasize 2048 (x)",
		"a comment":            "requiredrsasize 2048 # rest",
		"an escape sequence":   "requiredrsasize 2048\x1b[2J",
		"a quote":              "ciphers \"aes256-ctr\"",
		"a rekeylimit unit":    "rekeylimit 1G 3600",
		"a third rekey number": "rekeylimit 1 2 3",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := parseSSHValues(line + "\n"); err == nil {
				t.Fatalf("parseSSHValues(%q) = %q, nil; want a refusal", line, got)
			}
			// POSITIVE CONTROL: the same parser, good lines, must still keep
			// them — otherwise this passes on a parser that refuses everything.
			ok, err := parseSSHValues("requiredrsasize 2048\nrekeylimit 1073741824 3600\n")
			if err != nil || ok["requiredrsasize"] != "2048" || ok["rekeylimit"] != "1073741824 3600" {
				t.Fatalf("the control lines were refused too, so this case proves nothing: %q, %v", ok, err)
			}
		})
	}
}

// A non-whitelisted key is never judged at all: ssh prints values snug would
// refuse (proxycommand's spaces) on every host.
func TestParseSSHValuesIgnoresTheShapeOfWhatItDoesNotCarry(t *testing.T) {
	if _, err := parseSSHValues("proxycommand /usr/bin/nc %h %p\nsendenv LANG LC_*\n"); err != nil {
		t.Fatal(err)
	}
}

// TestProbeSSHConfigOnThisHost is the end-to-end half of the extraction, and
// it asserts the property that holds on every host rather than this box's
// crypto policy: whatever comes back is a whitelisted key whose value snug is
// willing to write.
func TestProbeSSHConfigOnThisHost(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("no ssh on this host; there is nothing to ask")
	}
	probe, err := probeSSHConfig(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range probe.values {
		if !slices.Contains(policy.SSHKeyWhitelist, k) {
			t.Errorf("probe returned %q, which is not in the whitelist", k)
		}
		if !policy.SSHValueOK(k, v) {
			t.Errorf("probe returned %s = %q, which snug would not write", k, v)
		}
	}
}

// The global RevokedHostKeys file is read, and one that cannot be read
// refuses: the sandbox's ssh would otherwise accept a key the host's revoked.
func TestReadGlobalRevokedHostKeys(t *testing.T) {
	dir := t.TempDir()
	krl := filepath.Join(dir, "revoked")
	if err := os.WriteFile(krl, []byte("ssh-ed25519 AAAA\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := readGlobalRevokedHostKeys("revokedhostkeys " + krl + "\n"); err != nil || string(got) != "ssh-ed25519 AAAA\n" {
		t.Errorf("readGlobalRevokedHostKeys = %q, %v; want the file verbatim", got, err)
	}
	if got, err := readGlobalRevokedHostKeys("revokedhostkeys none\n"); err != nil || got != nil {
		t.Errorf("revokedhostkeys none = %q, %v; want nil, nil", got, err)
	}
	for _, out := range []string{
		"revokedhostkeys " + filepath.Join(dir, "absent") + "\n",
		"revokedhostkeys relative/revoked\n",
	} {
		if _, err := readGlobalRevokedHostKeys(out); err == nil || !strings.Contains(err.Error(), "RevokedHostKeys") {
			t.Errorf("readGlobalRevokedHostKeys(%q) = %v; want a refusal naming RevokedHostKeys", out, err)
		}
	}
}

// A PATH listing /bin before /usr/bin finds ssh through a symlink; the policy
// must be handed the real path, or the /usr bind does not cover it.
func TestResolveSSHBinaryFollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "usr", "bin", "ssh")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/bin", filepath.Join(dir, "bin")); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(real) // t.TempDir() may itself sit under a link
	if err != nil {
		t.Fatal(err)
	}
	if got := resolveSSHBinary(filepath.Join(dir, "bin", "ssh")); got != want {
		t.Errorf("resolveSSHBinary = %q, want %q", got, want)
	}
	absent := filepath.Join(dir, "nowhere", "ssh")
	if got := resolveSSHBinary(absent); got != absent {
		t.Errorf("resolveSSHBinary(%q) = %q; an unresolvable path comes back as found", absent, got)
	}
}

// TestProbeSSHConfigHandsOnTheRevokedBytesNotThePath would catch the probe
// dropping the global RevokedHostKeys on its way to the policy (the run would
// then stage nothing and the sandbox's ssh would accept a key the host's
// refuses), handing on the PATH entry rather than the resolved binary, or the
// host's KRL path reaching the generated file. The path cannot reach it
// through the policy, which is given bytes; this holds the CLI half, and
// TestUnpinnedSSHReadsTheHostsRevokedHostKeys in test/integration holds the
// file a real sandbox's ssh reads.
func TestProbeSSHConfigHandsOnTheRevokedBytesNotThePath(t *testing.T) {
	dir := t.TempDir()
	krl := filepath.Join(dir, "host-krl-path-marker")
	content := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIg==\n")
	if err := os.WriteFile(krl, content, 0o644); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\n" +
		"echo 'debug1: Reading configuration data /etc/ssh/ssh_config' >&2\n" +
		"echo 'ciphers aes256-ctr'\n" +
		"echo 'revokedhostkeys " + krl + "'\n"
	if err := os.WriteFile(filepath.Join(real, "ssh"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	onPath := filepath.Join(dir, "bin")
	if err := os.Symlink("real", onPath); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", onPath)

	probe, err := probeSSHConfig(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(probe.revoked, content) {
		t.Errorf("probe.revoked = %q, want the host file's bytes %q", probe.revoked, content)
	}
	want, err := filepath.EvalSymlinks(filepath.Join(real, "ssh"))
	if err != nil {
		t.Fatal(err)
	}
	if probe.binary != want {
		t.Errorf("probe.binary = %q, want the resolved %q", probe.binary, want)
	}
	// POSITIVE CONTROL: the fake's other answers arrived, so the probe parsed
	// this output rather than returning a zero value that would also pass the
	// path check below.
	if probe.values["ciphers"] != "aes256-ctr" || !slices.Equal(probe.chain, []string{"/etc/ssh/ssh_config"}) {
		t.Fatalf("probe = %+v: the fake ssh's output was not parsed", probe)
	}
	sys := string(policy.SystemSSHConfigFrom(probe.values, probe.revoked != nil))
	if !strings.Contains(sys, "\nRevokedHostKeys "+policy.SystemRevokedHostKeysGuest+"\n") {
		t.Errorf("the generated file does not name the staged KRL:\n%s", sys)
	}
	if strings.Contains(sys, "host-krl-path-marker") {
		t.Errorf("the generated file carries the host's KRL path:\n%s", sys)
	}
}

// The top-level system file is the first filtered entry no Include announced:
// an Include'd file named ssh_config, even one read before the system file
// (from ~/.ssh/config), is not it.
func TestParseSSHTopConfigSkipsIncludedFiles(t *testing.T) {
	const debug = "debug1: Reading configuration data /home/u/.ssh/config\n" +
		"debug3: /home/u/.ssh/config line 1: Including file /opt/inc/ssh_config depth 0\n" +
		"debug1: Reading configuration data /opt/inc/ssh_config\n" +
		"debug1: Reading configuration data /usr/etc/ssh/ssh_config\n" +
		"debug3: /usr/etc/ssh/ssh_config line 31: Including file /usr/etc/ssh/ssh_config.d/50-suse.conf depth 0\n" +
		"debug1: Reading configuration data /usr/etc/ssh/ssh_config.d/50-suse.conf\n"
	if got := parseSSHTopConfig(debug, "/home/u"); got != "/usr/etc/ssh/ssh_config" {
		t.Errorf("parseSSHTopConfig = %q, want /usr/etc/ssh/ssh_config", got)
	}
}

// sandboxSSHFixture is a selection whose PATH puts two granted directories,
// first and second, ahead of @sys's, with a fake ssh in second that logs
// each probe to count and answers `ssh -G` with one carried value. With
// plant, probing it also puts an ssh in first, so the sandbox's PATH finds a
// different ssh on the next resolution. access is "ro" or "rw" for both
// directories.
type sandboxSSHFixture struct {
	reg           map[policy.ProfileName]*policy.Profile
	sel           []policy.ProfileName
	ctx           policy.Context
	home          string
	first, second string
	count         string
}

func newSandboxSSHFixture(t *testing.T, access string, plant bool) sandboxSSHFixture {
	t.Helper()
	reg := map[policy.ProfileName]*policy.Profile(loadTestRegistry(t))
	home, target := testTree(t)
	root := t.TempDir()
	first, second := filepath.Join(root, "first"), filepath.Join(root, "second")
	for _, d := range []string{first, second} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	count := filepath.Join(root, "probes")
	body := "#!/bin/sh\necho probe >> '" + count + "'\n"
	if plant {
		body += "printf '#!/bin/sh\\n' > '" + first + "/ssh'; chmod 755 '" + first + "/ssh'\n"
	}
	body += "echo 'debug1: Reading configuration data /etc/ssh/ssh_config' >&2\n" +
		"echo 'ciphers aes256-ctr'\n"
	if err := os.WriteFile(filepath.Join(second, "ssh"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &policy.Profile{Name: "sshdirs",
		Environ: policy.EnvGrants{Merge: map[string][]string{"PATH": {first, second}}}}
	if access == "rw" {
		p.RW = []string{first, second}
	} else {
		p.RO = []string{first, second}
	}
	reg["sshdirs"] = p
	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", HostUserName: "u", HostGroupName: "u",
		Command: []string{"/bin/sh"}, HostSSHBinary: "/usr/bin/ssh"}
	return sandboxSSHFixture{reg: reg, sel: []policy.ProfileName{"@sys", "@home", "@target-rw", "sshdirs"},
		ctx: ctx, home: home, first: first, second: second, count: count}
}

func (f sandboxSSHFixture) probes(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile(f.count)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "probe\n")
}

func (f sandboxSSHFixture) resolve(t *testing.T) (*policy.Policy, error, error) {
	t.Helper()
	pol, err := policy.Resolve(f.reg, f.sel, f.ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return resolveSandboxSSH(f.reg, f.sel, f.ctx, policy.OSEnviron{}, pol, f.home, "", false, heldSSHErrs{}, nil)
}

// TestResolveSandboxSSHProbesTheSandboxsSSHOnce is the redteam's F5 at the
// step that fixes it: the host PATH's ssh (/usr/bin/ssh) is not the ssh the
// sandbox's PATH finds, so that one is probed, exactly once, and the
// selection is resolved again with its answer. It would catch the re-probe
// being skipped (the written values would be the host PATH ssh's) or
// repeated, and the second case catches a resolution whose ssh moved again
// being accepted rather than refused.
func TestResolveSandboxSSHProbesTheSandboxsSSHOnce(t *testing.T) {
	t.Run("the sandbox's ssh is probed and its values written", func(t *testing.T) {
		f := newSandboxSSHFixture(t, "ro", false)
		pol, rerr, serr := f.resolve(t)
		if rerr != nil || serr != nil {
			t.Fatalf("resolveSandboxSSH: %v, %v", rerr, serr)
		}
		if n := f.probes(t); n != 1 {
			t.Errorf("the sandbox's ssh was probed %d times, want once", n)
		}
		want, err := filepath.EvalSymlinks(filepath.Join(f.second, "ssh"))
		if err != nil {
			t.Fatal(err)
		}
		if pol.SandboxSSHHost != want || pol.HostSSHBinary != want {
			t.Errorf("SandboxSSHHost = %q, HostSSHBinary = %q; want both %q",
				pol.SandboxSSHHost, pol.HostSSHBinary, want)
		}
		m, ok := pol.Mounts["/etc/ssh/ssh_config"]
		if !ok || !strings.Contains(string(m.Content), "\nCiphers aes256-ctr\n") {
			t.Errorf("the sandbox's ssh's answer was not written at /etc/ssh/ssh_config (present %v):\n%s",
				ok, m.Content)
		}
	})
	t.Run("the sandbox's ssh moves between resolutions", func(t *testing.T) {
		f := newSandboxSSHFixture(t, "ro", true)
		_, _, serr := f.resolve(t)
		if serr == nil || !strings.Contains(serr.Error(), "changed between two resolutions") {
			t.Fatalf("serr = %v; want a refusal naming the change", serr)
		}
		// Refused rather than probed again: a loop would probe the planted
		// ssh too.
		if n := f.probes(t); n != 1 {
			t.Errorf("probed %d times, want once", n)
		}
	})
	t.Run("CONTROL: the sandbox's ssh is the host PATH's", func(t *testing.T) {
		f := newSandboxSSHFixture(t, "ro", false)
		want, err := filepath.EvalSymlinks(filepath.Join(f.second, "ssh"))
		if err != nil {
			t.Fatal(err)
		}
		f.ctx.HostSSHBinary = want
		if _, rerr, serr := f.resolve(t); rerr != nil || serr != nil {
			t.Fatalf("resolveSandboxSSH: %v, %v", rerr, serr)
		}
		if n := f.probes(t); n != 0 {
			t.Errorf("probed %d times with nothing to ask again", n)
		}
	})
}

// TestResolveSandboxSSHRefusesAnSSHTheSandboxCanWrite would catch snug
// running, ON THE HOST, an ssh this sandbox's payload can rewrite: the
// re-probe executes the sandbox's PATH ssh to read its configuration, so a
// writable one is a payload choosing what snug runs unsandboxed next time.
// The refusal must come before anything runs, and the same directories
// granted read-only must not refuse.
func TestResolveSandboxSSHRefusesAnSSHTheSandboxCanWrite(t *testing.T) {
	f := newSandboxSSHFixture(t, "rw", false)
	pol, err := policy.Resolve(f.reg, f.sel, f.ctx, policy.OSEnviron{})
	if err != nil {
		// A writable directory ahead of /usr/bin is a choice snug allows;
		// if Resolve itself starts refusing it, this test has to move.
		t.Fatalf("Resolve refused the rw selection before resolveSandboxSSH could: %v", err)
	}
	_, _, serr := resolveSandboxSSH(f.reg, f.sel, f.ctx, policy.OSEnviron{}, pol, f.home, "", false, heldSSHErrs{}, nil)
	if serr == nil || !strings.Contains(serr.Error(), "which this sandbox can write") {
		t.Fatalf("serr = %v; want a refusal saying the sandbox can write its ssh", serr)
	}
	if n := f.probes(t); n != 0 {
		t.Errorf("the writable ssh was run %d times before the refusal", n)
	}
	// CONTROL: read-only, the same directories are probed and accepted.
	ro := newSandboxSSHFixture(t, "ro", false)
	if _, rerr, serr := ro.resolve(t); rerr != nil || serr != nil {
		t.Errorf("read-only: resolveSandboxSSH = %v, %v; want no refusal", rerr, serr)
	}
}

// A pin the host PATH's ssh cannot verify does not refuse when the sandbox
// runs another ssh that can: that ssh's answer decides. Controls: the same
// refusal stands when the sandbox's ssh cannot verify the pin either, and
// when the sandbox runs the host PATH's ssh itself.
func TestHeldPinRefusalYieldsToTheSandboxsSSH(t *testing.T) {
	reg := map[policy.ProfileName]*policy.Profile(loadTestRegistry(t))
	home, target := testTree(t)
	root := t.TempDir()
	fakeSSH := func(dir, knownHosts string) string {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(dir, "ssh")
		body := "#!/bin/sh\necho 'userknownhostsfile " + knownHosts + "'\n"
		if err := os.WriteFile(bin, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		real, err := filepath.EvalSymlinks(bin)
		if err != nil {
			t.Fatal(err)
		}
		return real
	}
	empty, known := filepath.Join(root, "kh-empty"), filepath.Join(root, "kh-known")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(known, []byte("github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIg==\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hostSSH := fakeSSH(filepath.Join(root, "host"), empty)
	_, pinErr := probeSSHPinWith(hostSSH, home, "github.com")
	if pinErr == nil {
		t.Fatal("fixture: the host PATH's ssh verified the pin")
	}
	for _, tc := range []struct {
		name       string
		sandboxKH  string // "" puts no ssh of its own on the sandbox's PATH
		wantRefuse bool
	}{
		{"the sandbox's ssh knows the pin", known, false},
		{"the sandbox's ssh does not know it either", empty, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "sandbox")
			fakeSSH(dir, tc.sandboxKH)
			reg["sshdir"] = &policy.Profile{Name: "sshdir", RO: []string{dir},
				Environ: policy.EnvGrants{Merge: map[string][]string{"PATH": {dir}}}}
			ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", HostUserName: "u",
				HostGroupName: "u", Command: []string{"/bin/sh"}, HostSSHBinary: hostSSH, HostPathSSH: hostSSH}
			sel := []policy.ProfileName{"@sys", "@home", "@target-rw", "sshdir"}
			pol, err := policy.Resolve(reg, sel, ctx, policy.OSEnviron{})
			if err != nil {
				t.Fatal(err)
			}
			_, rerr, serr := resolveSandboxSSH(reg, sel, ctx, policy.OSEnviron{}, pol, home, "github.com", true,
				heldSSHErrs{pin: pinErr}, nil)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if (serr != nil) != tc.wantRefuse {
				t.Errorf("refusal = %v, want refused = %v", serr, tc.wantRefuse)
			}
		})
	}
	t.Run("the sandbox runs the host PATH's ssh", func(t *testing.T) {
		ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", HostUserName: "u",
			HostGroupName: "u", Command: []string{"/bin/sh"}}
		sel := []policy.ProfileName{"@sys", "@home", "@target-rw"}
		pol, err := policy.Resolve(reg, sel, ctx, policy.OSEnviron{})
		if err != nil {
			t.Fatal(err)
		}
		ctx.HostSSHBinary = pol.SandboxSSHHost
		if _, _, serr := resolveSandboxSSH(reg, sel, ctx, policy.OSEnviron{}, pol, home, "github.com", true,
			heldSSHErrs{pin: pinErr}, nil); serr == nil {
			t.Error("a pin refusal from the very ssh the sandbox runs was dropped")
		}
	})
}

// writableSSHRun resolves @sys/@home/@target-rw plus extra, with the host
// PATH's ssh named as /usr/bin/ssh, and hands the result to
// resolveSandboxSSH. probes is a file each fake ssh appends to when run.
func writableSSHRun(t *testing.T, extra *policy.Profile) (serr error, rerr error) {
	t.Helper()
	reg := map[policy.ProfileName]*policy.Profile(loadTestRegistry(t))
	home, target := testTree(t)
	reg[extra.Name] = extra
	sel := []policy.ProfileName{"@sys", "@home", "@target-rw", extra.Name}
	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", HostUserName: "u", HostGroupName: "u",
		Command: []string{"/bin/sh"}, HostSSHBinary: "/usr/bin/ssh"}
	pol, err := policy.Resolve(reg, sel, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve refused before resolveSandboxSSH could: %v", err)
	}
	_, rerr, serr = resolveSandboxSSH(reg, sel, ctx, policy.OSEnviron{}, pol, home, "", false, heldSSHErrs{}, nil)
	return serr, rerr
}

// fakeSSH writes an ssh at dir/ssh that logs each run to probes and prints
// stdout as its `ssh -G` answer.
func fakeSSH(t *testing.T, dir, probes, stdout string) {
	t.Helper()
	body := "#!/bin/sh\necho probe >> '" + probes + "'\n" +
		"echo 'debug1: Reading configuration data /etc/ssh/ssh_config' >&2\n" +
		"printf '%s' '" + stdout + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func probeCount(t *testing.T, probes string) int {
	t.Helper()
	b, err := os.ReadFile(probes)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "probe\n")
}

// TestResolveSandboxSSHRefusesAWritableSSHBehindAHostSymlink would catch the
// writable-ssh refusal being asked of the PATH entry rather than the file it
// lands on. The PATH directory is granted read-only, but the ssh in it is a
// HOST symlink into a directory this sandbox binds read-write, so the file
// snug would run on the host is one the payload can rewrite. The refusal must
// come before that file runs. CONTROL: the same symlink into a read-only bind
// is probed and accepted.
func TestResolveSandboxSSHRefusesAWritableSSHBehindAHostSymlink(t *testing.T) {
	for _, access := range []string{"rw", "ro"} {
		t.Run(access, func(t *testing.T) {
			root := t.TempDir()
			pathDir, store := filepath.Join(root, "pathdir"), filepath.Join(root, "store")
			for _, d := range []string{pathDir, store} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			probes := filepath.Join(root, "probes")
			fakeSSH(t, store, probes, "ciphers aes256-ctr\n")
			if err := os.Symlink(filepath.Join(store, "ssh"), filepath.Join(pathDir, "ssh")); err != nil {
				t.Fatal(err)
			}
			p := &policy.Profile{Name: "linked", RO: []string{pathDir},
				Environ: policy.EnvGrants{Merge: map[string][]string{"PATH": {pathDir}}}}
			if access == "rw" {
				p.RW = []string{store}
			} else {
				p.RO = append(p.RO, store)
			}
			serr, rerr := writableSSHRun(t, p)
			refused := serr != nil && strings.Contains(serr.Error(), "which this sandbox can write")
			if refused != (access == "rw") || rerr != nil {
				t.Fatalf("store %s: serr = %v, rerr = %v; want a refusal exactly when it is rw", access, serr, rerr)
			}
			if want := map[string]int{"rw": 0, "ro": 1}[access]; probeCount(t, probes) != want {
				t.Errorf("store %s: the ssh ran %d times, want %d", access, probeCount(t, probes), want)
			}
		})
	}
}

// TestResolveSandboxSSHRefusesAWritableSSHBehindASymlinkGrant is the same
// guarantee through snug's own `symlink` grant rather than a host link: the
// PATH entry is a guest symlink snug creates, pointing at a directory this
// sandbox binds read-write. It would catch the sandbox's ssh being resolved
// without following snug's own links, so the writable file behind one is
// probed. CONTROL: the same link to a read-only bind is probed and accepted.
func TestResolveSandboxSSHRefusesAWritableSSHBehindASymlinkGrant(t *testing.T) {
	for _, access := range []string{"rw", "ro"} {
		t.Run(access, func(t *testing.T) {
			root := t.TempDir()
			store := filepath.Join(root, "store")
			if err := os.MkdirAll(store, 0o755); err != nil {
				t.Fatal(err)
			}
			probes := filepath.Join(root, "probes")
			fakeSSH(t, store, probes, "ciphers aes256-ctr\n")
			const link = "/snug-test-sshbin" // at the root: @sys grants /opt
			p := &policy.Profile{Name: "linkgrant",
				Symlink: []policy.Symlink{{At: link, Target: store}},
				Environ: policy.EnvGrants{Merge: map[string][]string{"PATH": {link}}}}
			if access == "rw" {
				p.RW = []string{store}
			} else {
				p.RO = []string{store}
			}
			serr, rerr := writableSSHRun(t, p)
			refused := serr != nil && strings.Contains(serr.Error(), "which this sandbox can write")
			if refused != (access == "rw") || rerr != nil {
				t.Fatalf("store %s: serr = %v, rerr = %v; want a refusal exactly when it is rw", access, serr, rerr)
			}
			if want := map[string]int{"rw": 0, "ro": 1}[access]; probeCount(t, probes) != want {
				t.Errorf("store %s: the ssh ran %d times, want %d", access, probeCount(t, probes), want)
			}
		})
	}
}

// TestResolveSandboxSSHRefusesARelativeRevokedHostKeys would catch the
// re-probe of the sandbox's ssh skipping readGlobalRevokedHostKeys' checks: a
// relative RevokedHostKeys is opened against snug's working directory, which
// can be the sandboxed tree, so the payload would choose the revocation list.
// TestReadGlobalRevokedHostKeys holds the reader; this holds that the
// re-probe goes through it. CONTROL: the same ssh naming no KRL resolves.
func TestResolveSandboxSSHRefusesARelativeRevokedHostKeys(t *testing.T) {
	for _, tc := range []struct {
		name, stdout string
		refuse       bool
	}{
		{"relative", "ciphers aes256-ctr\nrevokedhostkeys relative/krl\n", true},
		{"none", "ciphers aes256-ctr\nrevokedhostkeys none\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			probes := filepath.Join(t.TempDir(), "probes")
			fakeSSH(t, dir, probes, tc.stdout)
			p := &policy.Profile{Name: "rossh", RO: []string{dir},
				Environ: policy.EnvGrants{Merge: map[string][]string{"PATH": {dir}}}}
			serr, rerr := writableSSHRun(t, p)
			refused := serr != nil && strings.Contains(serr.Error(), "not an absolute path")
			if refused != tc.refuse || rerr != nil || (!tc.refuse && serr != nil) {
				t.Fatalf("serr = %v, rerr = %v; want refused = %v", serr, rerr, tc.refuse)
			}
			if probeCount(t, probes) != 1 {
				t.Errorf("the sandbox's ssh ran %d times, want once", probeCount(t, probes))
			}
		})
	}
}
