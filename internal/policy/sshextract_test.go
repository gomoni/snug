package policy

import (
	"slices"
	"strings"
	"testing"
)

// sshValuesFixture is the delta measured on the development host (openSUSE,
// OpenSSH_10.3p1, system-wide crypto policy): what `ssh -G` resolves to minus
// what `ssh -G -F /dev/null` resolves to. RequiredRSASize is the entry with
// security content — without it the sandbox's ssh accepts a 1024-bit RSA key
// the host's ssh refuses (issue #43).
func sshValuesFixture() SSHValues {
	return SSHValues{
		"requiredrsasize": "2048",
		"ciphers":         "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr",
		"macs":            "hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com",
	}
}

func TestSystemSSHConfigCarriesTheHostsAlgorithmPolicy(t *testing.T) {
	got := string(SystemSSHConfigFrom(sshValuesFixture()))

	for _, want := range []string{
		"RequiredRSASize 2048",
		"Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr",
		"MACs hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the generated system ssh_config does not carry %q; without it the\n"+
				"sandbox falls back to OpenSSH's compiled-in values and, for RequiredRSASize,\n"+
				"accepts a 1024-bit RSA key the host's ssh refuses:\n%s", want, got)
		}
	}
	// Still no Include, and it is the same mechanism as before #43 rather than
	// tidiness: every file an Include names is root-owned too, so a replacement
	// that kept the line would reproduce the exact error it exists to fix.
	for _, line := range directiveLines(got) {
		if strings.EqualFold(strings.Fields(line)[0], "Include") {
			t.Errorf("the generated system ssh_config has an Include directive:\n%s", got)
		}
	}
}

// TestSystemSSHConfigCarriesOnlyWhitelistedKeys is the deny-by-default arm.
// The extractor already keeps the whitelist, so this asserts the RENDERER
// refuses on its own — the same belt-and-braces GitConfigFrom has, and for the
// same reason: this is the last place a host string can be stopped before it
// is a directive the sandbox's ssh obeys.
func TestSystemSSHConfigCarriesOnlyWhitelistedKeys(t *testing.T) {
	v := sshValuesFixture()
	// Every one of these names a program, a file or a socket. ssh_config is a
	// command table, and read-only does not demote one into data.
	for _, k := range []string{
		"proxycommand", "localcommand", "knownhostscommand", "permitlocalcommand",
		"pkcs11provider", "securitykeyprovider", "identityfile", "identityagent",
		"userknownhostsfile", "controlpath", "match",
	} {
		v[k] = "definitely-not-carried"
	}
	got := string(SystemSSHConfigFrom(v))
	for _, line := range directiveLines(got) {
		key := strings.ToLower(strings.Fields(line)[0])
		if !slices.Contains(SSHKeyWhitelist, key) {
			t.Errorf("the generated system ssh_config carries %q, which is not in "+
				"SSHKeyWhitelist:\n%s", line, got)
		}
	}
	if strings.Contains(got, "definitely-not-carried") {
		t.Errorf("a non-whitelisted VALUE reached the generated file:\n%s", got)
	}
}

// TestSystemSSHConfigDropsAValueItCannotWriteSafely is the value half. The
// keys are snug's own — they got there by matching the whitelist — but the
// values are a host binary's stdout, and ssh_config's grammar ends a directive
// at a newline and starts a comment at `#`. A value that could MEAN something
// to that parser is dropped, never escaped: the key then falls back to the
// sandbox ssh's compiled-in default, which is where it was before #43.
func TestSystemSSHConfigDropsAValueItCannotWriteSafely(t *testing.T) {
	cases := map[string]string{
		"a newline":       "2048\nProxyCommand touch /tmp/PWNED",
		"a comment":       "2048 # rest",
		"a space":         "aes256-ctr aes128-ctr",
		"a quote":         "\"aes256-ctr\"",
		"a control byte":  "2048\x1b[2J",
		"a shell escape":  "$(touch /tmp/PWNED)",
		"an empty string": "",
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			got := string(SystemSSHConfigFrom(SSHValues{"requiredrsasize": val}))
			for _, line := range directiveLines(got) {
				t.Fatalf("carried %q from a value with %s:\n%s", line, name, got)
			}
			// POSITIVE CONTROL: the same renderer, one good value, must still
			// write it — otherwise this test would pass on a renderer that
			// carries nothing at all.
			ok := string(SystemSSHConfigFrom(SSHValues{"requiredrsasize": val, "ciphers": "aes256-ctr"}))
			if !strings.Contains(ok, "Ciphers aes256-ctr") {
				t.Fatalf("the control value was dropped too, so this case proves nothing:\n%s", ok)
			}
		})
	}
}

// TestSystemSSHConfigWithNothingToCarryIsCommentOnly pins the shape a host
// that customises nothing gets: the file every host got before #43. Only
// values DIFFERING from OpenSSH's compiled-in defaults are carried (the
// extractor measures both), so this is the ordinary case, not the exotic one.
func TestSystemSSHConfigWithNothingToCarryIsCommentOnly(t *testing.T) {
	got := string(SystemSSHConfigFrom(nil))
	if d := directiveLines(got); len(d) != 0 {
		t.Fatalf("the generated file carries %q with nothing extracted", d)
	}
	if !strings.Contains(got, "65534") && !strings.Contains(got, "root-owned") {
		t.Errorf("the generated file does not say why it exists; a reader finding it "+
			"will assume the host's was lost:\n%s", got)
	}
}

// TestCarriedSSHKeysMatchesTheFile is what keeps --dry-run honest: the SSH
// block names the carried keys from Policy.SystemSSHCarried, and a screen that
// claims a key the file does not carry is the "small lie" that makes the whole
// artifact untrustworthy.
func TestCarriedSSHKeysMatchesTheFile(t *testing.T) {
	v := sshValuesFixture()
	v["kexalgorithms"] = "not a list" // dropped by the renderer
	got := string(SystemSSHConfigFrom(v))

	var written []string
	for _, line := range directiveLines(got) {
		written = append(written, strings.ToLower(strings.Fields(line)[0]))
	}
	slices.Sort(written)
	claimed := slices.Clone(carriedSSHKeys(v))
	slices.Sort(claimed)
	if !slices.Equal(written, claimed) {
		t.Fatalf("carriedSSHKeys says %q, the file carries %q", claimed, written)
	}
}

// directiveLines is the line-wise sibling of this package's directives helper:
// every line the sandbox's ssh will ACT on, one per element, because each
// assertion here is about a single directive's key and value.
//
// The generated file's own prose names ProxyCommand, Match exec and Include to
// explain why they are absent, so a test that grepped the bytes would fail on
// the file's documentation — the trap gitextract_test.go's helper records
// having sprung three times.
func directiveLines(file string) []string {
	var out []string
	for _, line := range strings.Split(directives(file), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
