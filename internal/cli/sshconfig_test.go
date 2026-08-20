package cli

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
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
	for _, p := range sshConfigChain(home, false) {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("chain entry %q is not absolute", p)
		}
		if !strings.HasSuffix(p, "/ssh_config") {
			t.Errorf("chain entry %q is not a top-level system ssh_config", p)
		}
	}
}
