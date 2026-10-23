package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// carriedLines is the non-comment, non-blank lines of a generated gpg.conf.
func carriedLines(b []byte) []string {
	var out []string
	for l := range strings.SplitSeq(string(b), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// TestGPGConfOptionsNeverRunOrReach: no option that names a program, sends gpg
// to the network, or only relaxes a check is on the allowlist. Adding one is
// the change this test exists to make loud.
func TestGPGConfOptionsNeverRunOrReach(t *testing.T) {
	for _, bad := range []string{
		"exec-path", "photo-viewer", "verify-options", "list-options",
		"keyserver", "keyserver-options", "auto-key-retrieve", "auto-key-locate",
		"auto-key-import", "options", "homedir", "agent-program", "dirmngr-program",
		"keyboxd-program", "trustdb-name", "keyring", "secret-keyring", "load-extension",
		"allow-weak-digest-algos", "allow-weak-key-signatures", "allow-old-cipher-algos",
		"ignore-mdc-error", "no-require-cross-certification", "no-require-backsigs",
		"override-compliance-check", "always-trust",
	} {
		if _, ok := GPGConfOptions[bad]; ok {
			t.Errorf("%s is on GPGConfOptions", bad)
		}
	}
}

// TestGPGConfFromCarriesOnlyTheAllowlist: a host file mixing crypto choices
// with every program- and network-naming option comes out holding the crypto
// choices, in the host's order, and nothing else.
func TestGPGConfFromCarriesOnlyTheAllowlist(t *testing.T) {
	host := `# a host gpg.conf
personal-digest-preferences SHA512 SHA384 SHA256
keyserver hkps://keys.openpgp.org
keyserver-options auto-key-retrieve
exec-path /tmp/evil
photo-viewer "xdg-open %i"
auto-key-retrieve
auto-key-locate local,wkd
verify-options show-photos
	digest-algo	"SHA256"
allow-weak-digest-algos
weak-digest SHA224
require-compliance
trust-model pgp
compliance de-vs
assert-pubkey-algo >=rsa3072,ed25519
trusted-key 0xD4381E1CE2880244
`
	got, err := GPGConfFrom([]byte(host), "/h/.gnupg/gpg.conf", false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"personal-digest-preferences SHA512 SHA384 SHA256",
		"digest-algo SHA256",
		"weak-digest SHA224",
		"require-compliance",
		"trust-model pgp",
		"compliance de-vs",
		"assert-pubkey-algo >=rsa3072,ed25519",
		"trusted-key 0xD4381E1CE2880244",
	}
	if lines := carriedLines(got); strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("carried:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

// TestGPGConfFromCarriesSystemMetaCommands: the system file's meta commands
// survive in place, so gpg inside applies [force] and [ignore] to the same
// options the host's does.
func TestGPGConfFromCarriesSystemMetaCommands(t *testing.T) {
	host := "[force]\ndigest-algo SHA384\nkeyserver hkps://x\n[-force]\n[ user * ]\n[ignore-all]\ncompliance gnupg\n"
	got, err := GPGConfFrom([]byte(host), "/etc/gnupg/gpg.conf", true)
	if err != nil {
		t.Fatal(err)
	}
	want := "[force]\ndigest-algo SHA384\n[-force]\n[user *]\n[ignore-all]\ncompliance gnupg"
	if lines := strings.Join(carriedLines(got), "\n"); lines != want {
		t.Errorf("carried:\n%s\nwant:\n%s", lines, want)
	}
}

// TestGPGConfFromRefusesWhatItCannotCarry: every allowlisted line snug cannot
// render faithfully refuses the run, naming the file and line, rather than
// leaving the option to gpg's compiled-in default.
func TestGPGConfFromRefusesWhatItCannotCarry(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		system    bool
		want      string
	}{
		{"missing argument", "digest-algo\n", false, "needs an argument"},
		{"flag with argument", "require-compliance yes\n", false, "takes no argument"},
		{"unterminated quote", "digest-algo \"SHA256\n", false, "not shaped like"},
		{"trailing comment", "digest-algo SHA256 # c\n", false, "not shaped like"},
		{"embedded quote", "personal-digest-preferences SHA256\"x\n", false, "not shaped like"},
		{"control character", "digest-algo SHA256\x1b[2J\n", false, "not shaped like"},
		{"meta in user file", "[force]\n", false, "only in"},
		{"unknown meta", "[bogus]\n", true, "does not know"},
		{"unclosed meta", "[force\n", true, "does not close"},
		{"user with two words", "[user a b]\n", true, "cannot carry"},
		{"user with no name", "[user]\n", true, "cannot carry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GPGConfFrom([]byte("# first\n"+tc.src), "/h/gpg.conf", tc.system)
			if err == nil {
				t.Fatalf("%q was carried", tc.src)
			}
			if !strings.Contains(err.Error(), "/h/gpg.conf:2") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name /h/gpg.conf:2 and %q", err, tc.want)
			}
		})
	}
}

// TestGPGConfFromEmptyHostFile: a host that sets nothing gets a file that says
// so and carries no option.
func TestGPGConfFromEmptyHostFile(t *testing.T) {
	got, err := GPGConfFrom(nil, "(none)", false)
	if err != nil {
		t.Fatal(err)
	}
	if lines := carriedLines(got); len(lines) != 0 {
		t.Errorf("an empty host file carried %q", lines)
	}
	if !strings.Contains(string(got), "sets none of the carried options") {
		t.Errorf("the empty file does not say why it is empty:\n%s", got)
	}
}

// TestGPGConfFromEscapesTheHostPathInTheHeader: the host path is written into
// a comment, and a newline in it must not end the comment.
func TestGPGConfFromEscapesTheHostPathInTheHeader(t *testing.T) {
	got, err := GPGConfFrom(nil, "/h/x\ndigest-algo MD5", false)
	if err != nil {
		t.Fatal(err)
	}
	if lines := carriedLines(got); len(lines) != 0 {
		t.Errorf("a newline in the host path became a directive: %q", lines)
	}
}

// TestGoldenGPGConf is the review artifact for the two generated gpg.conf
// files: what the sandbox's gpg reads, byte for byte, from one host file of
// each kind.
func TestGoldenGPGConf(t *testing.T) {
	for _, tc := range []struct {
		name, host, src string
		system          bool
	}{
		{"gpgconf-user.txt", "/home/u/.gnupg/gpg.conf",
			"personal-digest-preferences SHA512 SHA384\nkeyserver hkps://keys.openpgp.org\n" +
				"exec-path /tmp\nweak-digest SHA224\nallow-weak-digest-algos\nrequire-compliance\n", false},
		{"gpgconf-system.txt", "/etc/gnupg/gpg.conf",
			"[force]\ncompliance de-vs\nauto-key-locate wkd\n[-force]\ntrust-model pgp\n", true},
		{"gpgconf-empty.txt", "(none: no gpg.conf in the host's GNUPGHOME)", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := GPGConfFrom([]byte(tc.src), tc.host, tc.system)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", tc.name)
			if *update {
				if err := os.WriteFile(path, b, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update and read the file)", err)
			}
			if string(want) != string(b) {
				t.Errorf("%s changed; this is the gpg.conf the sandbox's gpg reads. Run with -update "+
					"and read the diff.\n%s", tc.name, b)
			}
		})
	}
}

// TestGPGConfFromCarriesWhatTheRedTeamSawDropped: each of these lines is one the
// host's gpg applies, and an earlier GPGConfFrom dropped as unknown, leaving the
// sandbox's gpg looser than the host's. Each must be carried under the
// allowlisted spelling, or refused.
func TestGPGConfFromCarriesWhatTheRedTeamSawDropped(t *testing.T) {
	for _, tc := range []struct{ src, want string }{
		{"personal-cipher-prefs AES128\n", "personal-cipher-preferences AES128"},
		{"force-ocb\n", "force-aead"},
		{"use-ocb-sym\n", "force-aead"},
		{"digest-algo\vSHA256\n", "digest-algo SHA256"},
		{"weak-digest\fSHA224\n", "weak-digest SHA224"},
		{"personal-cipher-preferences\rAES128\n", "personal-cipher-preferences AES128"},
		{"force-aead\v\n", "force-aead"},
		// The last compliance wins on the host, so it must be the last here.
		{"compliance openpgp\ngnupg\n", "compliance openpgp\ncompliance gnupg"},
	} {
		got, err := GPGConfFrom([]byte(tc.src), "/h/gpg.conf", false)
		if err != nil {
			t.Errorf("%q refused: %v", tc.src, err)
			continue
		}
		if lines := strings.Join(carriedLines(got), "\n"); lines != tc.want {
			t.Errorf("%q carried %q, want %q", tc.src, lines, tc.want)
		}
	}
}

// TestGPGConfFromRefusesAnOptionNameItCannotRead: a keyword with a byte gpg
// does not spell options with is refused, never dropped as "not allowlisted",
// since snug cannot tell which option the host's gpg makes of it.
func TestGPGConfFromRefusesAnOptionNameItCannotRead(t *testing.T) {
	for _, src := range []string{"digest-algo\x00 SHA256\n", "DIGEST-ALGO SHA256\n", "digest-algo=SHA256\n", "digest algo SHA256\n"} {
		if _, err := GPGConfFrom([]byte(src), "/h/gpg.conf", false); err == nil {
			t.Errorf("%q was not refused", src)
		}
	}
}

// TestGPGConfSummaryNamesDropsNotValues: every option left behind is named
// once, by keyword; no value (a URL, a path) reaches the summary, and the
// carried list uses the carried spelling (an alias resolved). A refused file
// summarises as nothing.
func TestGPGConfSummaryNamesDropsNotValues(t *testing.T) {
	src := []byte("keyserver hkps://keys.example\nexec-path /tmp\n" +
		"personal-cipher-prefs AES256\nkeyserver hkps://other\nopenpgp\n")
	carried, dropped := GPGConfSummary(src, false)
	if strings.Join(carried, " ") != "personal-cipher-preferences compliance" {
		t.Errorf("carried = %q", carried)
	}
	if strings.Join(dropped, " ") != "keyserver exec-path" {
		t.Errorf("dropped = %q, want each dropped keyword once", dropped)
	}
	for _, d := range append(carried, dropped...) {
		if strings.ContainsAny(d, "/: ") {
			t.Errorf("summary entry %q carries a value", d)
		}
	}
	if c, d := GPGConfSummary([]byte("digest-algo \"x\n"), false); c != nil || d != nil {
		t.Errorf("a refused file summarised as %q / %q", c, d)
	}
}
