package cli

import (
	"os/exec"
	"slices"
	"strings"
	"testing"

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
	chain, _ := probeSSHConfig(home, false)
	for _, p := range chain {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("chain entry %q is not absolute", p)
		}
		if !strings.HasSuffix(p, "/ssh_config") {
			t.Errorf("chain entry %q is not a top-level system ssh_config", p)
		}
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
`

const measuredDefaults = `user michal
hostname snug-probe.invalid
requiredrsasize 1024
ciphers chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-ctr
macs hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com
forwardx11trusted no
`

func TestParseSSHValuesKeepsOnlyTheWhitelist(t *testing.T) {
	got := parseSSHValues(measuredValues)

	if got["requiredrsasize"] != "2048" {
		t.Errorf("requiredrsasize = %q, want 2048 — it is the one entry with security "+
			"content: without it the sandbox accepts a 1024-bit RSA key the host refuses",
			got["requiredrsasize"])
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

func TestSSHValuesDeltaIsWhatTheHostAddsToTheDefaults(t *testing.T) {
	got := sshValuesDelta(parseSSHValues(measuredValues), parseSSHValues(measuredDefaults))

	if got["requiredrsasize"] != "2048" {
		t.Errorf("requiredrsasize = %q, want 2048 (the host raises it from 1024)", got["requiredrsasize"])
	}
	if _, ok := got["ciphers"]; !ok {
		t.Error("ciphers was dropped; the host's list differs from the compiled-in one")
	}
	// The half that keeps the generated file small — and the goldens quiet on a
	// host that customises nothing. macs is IDENTICAL to the default here, so
	// restating it would be snug claiming to restore something nothing lost.
	if v, ok := got["macs"]; ok {
		t.Errorf("carried macs = %q although it equals OpenSSH's compiled-in value", v)
	}
}

// TestSSHValuesDeltaWithNoDefaultsCarriesEverything pins the fail-safe
// direction of the second probe: if `ssh -G -F /dev/null` cannot be run, snug
// has no defaults to subtract and carries the host's values whole. That is
// more of the host's own policy, never less, and every value still has to pass
// the whitelist and the shape predicate.
func TestSSHValuesDeltaWithNoDefaultsCarriesEverything(t *testing.T) {
	got := sshValuesDelta(parseSSHValues(measuredValues), nil)
	for _, k := range []string{"requiredrsasize", "ciphers", "macs"} {
		if _, ok := got[k]; !ok {
			t.Errorf("%s was dropped with no defaults to compare against", k)
		}
	}
}

func TestParseSSHValuesDropsAValueItCannotWriteSafely(t *testing.T) {
	// ssh will not print these — it is the host's own binary and it quotes
	// nothing — but the file snug writes is parsed by ssh, and the extractor is
	// the sink where a value stops being a string and starts being a directive.
	// Assert the predicate, not the source's good manners.
	for name, line := range map[string]string{
		"a directive smuggled after a newline": "requiredrsasize 2048\nproxycommand touch /tmp/PWNED",
		"a comment":                            "requiredrsasize 2048 # rest",
		"an escape sequence":                   "requiredrsasize 2048\x1b[2J",
		"a quote":                              "ciphers \"aes256-ctr\"",
	} {
		t.Run(name, func(t *testing.T) {
			got := parseSSHValues(line + "\n")
			for k, v := range got {
				if strings.ContainsAny(v, " \t\"#\n\x1b") {
					t.Fatalf("carried %s = %q", k, v)
				}
			}
			// POSITIVE CONTROL: the same parser, one good line, must still keep
			// it — otherwise this passes on a parser that returns nothing.
			if ok := parseSSHValues("requiredrsasize 2048\n"); ok["requiredrsasize"] != "2048" {
				t.Fatalf("the control line was dropped too, so this case proves nothing: %q", ok)
			}
		})
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
	_, values := probeSSHConfig(t.TempDir(), false)
	for k, v := range values {
		if !slices.Contains(policy.SSHKeyWhitelist, k) {
			t.Errorf("probe returned %q, which is not in the whitelist", k)
		}
		if !sshValueShape(v) {
			t.Errorf("probe returned %s = %q, which snug would not write", k, v)
		}
	}
}
