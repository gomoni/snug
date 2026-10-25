package cli

import (
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
	chain, _, err := probeSSHConfig(home, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range chain {
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
	_, _, err := probeSSHConfig(t.TempDir(), nil)
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
			chain, values, err := probeSSHConfig(t.TempDir(), nil)
			if err == nil {
				t.Fatalf("probeSSHConfig = %q, %v, nil; want a refusal", chain, values)
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
	_, values, err := probeSSHConfig(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range values {
		if !slices.Contains(policy.SSHKeyWhitelist, k) {
			t.Errorf("probe returned %q, which is not in the whitelist", k)
		}
		if !policy.SSHValueOK(k, v) {
			t.Errorf("probe returned %s = %q, which snug would not write", k, v)
		}
	}
}
