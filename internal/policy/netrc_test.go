package policy

import (
	"strings"
	"testing"
)

const netrcHost = "gitlab.example"

func wantNetrcRefusal(t *testing.T, data string, contains ...string) {
	t.Helper()
	login, pw, err := ParseNetrcEntry([]byte(data), netrcHost)
	if err == nil {
		t.Fatalf("parsed to login %q (%d-byte password); want a refusal of:\n%s", login, len(pw), data)
	}
	for _, c := range contains {
		if !strings.Contains(err.Error(), c) {
			t.Errorf("refusal does not contain %q: %v", c, err)
		}
	}
	// Whatever else, a refusal never prints a secret-looking token.
	if strings.Contains(err.Error(), "SECRETPW") {
		t.Errorf("refusal printed a password: %v", err)
	}
}

func TestNetrcRefusesMacdef(t *testing.T) {
	wantNetrcRefusal(t, "macdef init\nmachine "+netrcHost+" login forged password FORGED\n\n"+
		"machine "+netrcHost+" login u password SECRETPW\n", "macdef")
	wantNetrcRefusal(t, "machine other.example login a password b\nmacdef x\nls\n\n"+
		"machine "+netrcHost+" login u password SECRETPW\n", "macdef")
}

func TestNetrcRefusesQuotedToken(t *testing.T) {
	wantNetrcRefusal(t, "machine "+netrcHost+" login u password \"SECRETPW x\"\n", "double quote")
	wantNetrcRefusal(t, "machine \""+netrcHost+"\" login u password SECRETPW\n", "double quote")
	wantNetrcRefusal(t, "machine other.example login \"a b\" password x\nmachine "+netrcHost+" login u password SECRETPW\n", "double quote")
}

func TestNetrcRefusesDuplicateMachine(t *testing.T) {
	wantNetrcRefusal(t, "machine "+netrcHost+" login a password SECRETPW\nmachine "+netrcHost+" login b password y\n", "two `machine "+netrcHost)
	// Even when the first is incomplete.
	wantNetrcRefusal(t, "machine "+netrcHost+"\nmachine "+netrcHost+" login b password y\n", "two `machine")
}

func TestNetrcDefaultOnlyRefuses(t *testing.T) {
	wantNetrcRefusal(t, "machine other.example login a password b\ndefault login d password SECRETPW\n",
		"only a `default` entry would match", "never stages a default")
	wantNetrcRefusal(t, "machine other.example login a password b\n", "no `machine "+netrcHost)
}

func TestNetrcDefaultAfterMachineIsIgnored(t *testing.T) {
	login, pw, err := ParseNetrcEntry([]byte("machine "+netrcHost+" login u password tok\ndefault login d password dflt\n"), netrcHost)
	if err != nil || login != "u" || string(pw) != "tok" {
		t.Fatalf("got %q, %q, %v; want u, tok, nil", login, pw, err)
	}
	// Text after `default` is not parsed at all, so what it holds cannot refuse.
	if _, _, err := ParseNetrcEntry([]byte("machine "+netrcHost+" login u password tok\ndefault\nwhatever \"x\"\n"), netrcHost); err != nil {
		t.Errorf("text after default refused: %v", err)
	}
}

func TestNetrcMissingPasswordRefuses(t *testing.T) {
	wantNetrcRefusal(t, "machine "+netrcHost+" login u\nmachine other.example login a password b\n", "no `password`")
	wantNetrcRefusal(t, "machine "+netrcHost+" password SECRETPW\n", "no `login`")
	wantNetrcRefusal(t, "machine "+netrcHost+" login u password", "needs a value")
}

func TestNetrcUnknownKeywordRefuses(t *testing.T) {
	wantNetrcRefusal(t, "machine "+netrcHost+" login u password pw extra SECRETPW\n", "not a netrc keyword")
	// A space inside a password splits it into a keyword; the refusal says so
	// without echoing the text.
	wantNetrcRefusal(t, "machine "+netrcHost+" login u password SECRETPW tail\n", "space")
	wantNetrcRefusal(t, "login u\nmachine "+netrcHost+" login u password x\n", "before any `machine`")
	wantNetrcRefusal(t, "machine "+netrcHost+" login u login v password SECRETPW\n", "repeats `login`")
}

func TestNetrcExtractsOnlyOneMachine(t *testing.T) {
	data := "# a comment, with machine " + netrcHost + " login c password c\n" +
		"machine other.example\n  login other\n  password otherpw\n  account acct\n" +
		"machine " + netrcHost + "x login near password nearpw\n" +
		"  machine " + netrcHost + "\n\tlogin u\r\n\tpassword S3cret~+/=.-_\n\n" +
		"machine third.example login t password t\n"
	login, pw, err := ParseNetrcEntry([]byte(data), netrcHost)
	if err != nil {
		t.Fatal(err)
	}
	if login != "u" || string(pw) != "S3cret~+/=.-_" {
		t.Errorf("got %q, %q", login, pw)
	}
	// Case-insensitive, as curl's lookup is: TestNetrcMatchesTheMachineCaseInsensitively.
	if login, _, err := ParseNetrcEntry([]byte(data), "GITLAB.EXAMPLE"); err != nil || login != "u" {
		t.Errorf("an upper-case pin did not find the entry: %q %v", login, err)
	}
	// One line, every keyword.
	login, pw, err = ParseNetrcEntry([]byte("machine "+netrcHost+" login u password p"), netrcHost)
	if err != nil || login != "u" || string(pw) != "p" {
		t.Errorf("no trailing newline: %q %q %v", login, pw, err)
	}
	// A non-ASCII space is not a separator for curl and is not for us either.
	login, pw, err = ParseNetrcEntry([]byte("machine "+netrcHost+" login u password a b\n"), netrcHost)
	if err != nil || string(pw) != "a b" {
		t.Errorf("U+00A0 split a password: %q %v", pw, err)
	}
}

func TestNetrcCommentWhereAValueIsExpectedRefuses(t *testing.T) {
	wantNetrcRefusal(t, "machine "+netrcHost+" login u password\n# SECRETPW\n", "comment")
}

func TestCheckForgeTokenRefusesYAMLAndWhitespace(t *testing.T) {
	for _, ok := range []string{"glpat-AbC_123.x~y+z/w=", "A"} {
		if err := CheckForgeToken(Secret(ok)); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "a\nb: c", "a\tb", "a#b", "a:b", `a"b`, "a'b", "a\\b", "a{b", "a b", "tok\x00", "a;b", "a,b", "a&b"} {
		err := CheckForgeToken(Secret(bad))
		if err == nil {
			t.Errorf("%q accepted", bad)
			continue
		}
		if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("refusal printed the token %q: %v", bad, err)
		}
	}
}

// TestNetrcRefusesFormFeedAndVerticalTab is redteam finding F1 on #709. curl
// 8.23.0 keeps \f and \v inside a token, so for this file it sends DECOYPW to
// decoy.example and nothing to the pinned host. Splitting on them here read
// DECOYPW as the pinned host's password and staged it.
func TestNetrcRefusesFormFeedAndVerticalTab(t *testing.T) {
	for _, sep := range []string{"\f", "\v"} {
		wantNetrcRefusal(t, "machine decoy.example login alice"+sep+"machine "+netrcHost+
			" password SECRETPW login alice\n", "control byte")
	}
}

// TestNetrcRefusesNUL is redteam finding F2 on #709: curl stops a line at NUL
// and snug read past it, so the two disagreed on which entry a password
// belonged to.
func TestNetrcRefusesNUL(t *testing.T) {
	wantNetrcRefusal(t, "machine decoy.example\x00 machine "+netrcHost+"\nlogin alice password SECRETPW\n", "control byte")
	wantNetrcRefusal(t, "machine decoy.example login a password SECRETPW\x00\nmachine "+netrcHost+
		" login a password REAL\n", "control byte")
}

// TestNetrcRefusesCaseVariantDuplicateMachine is redteam finding F2 on #709.
// curl matches the machine name case-insensitively and takes the first entry,
// so for this file it sends SECRETPW; an exact-bytes compare skipped the first
// entry, missed the duplicate and staged REAL.
func TestNetrcRefusesCaseVariantDuplicateMachine(t *testing.T) {
	wantNetrcRefusal(t, "machine "+strings.ToUpper(netrcHost)+" login u password SECRETPW\n"+
		"machine "+netrcHost+" login u password REAL\n", "two `machine")
}

// TestNetrcMatchesTheMachineCaseInsensitively is the positive half: a single
// entry spelled in another case is the pinned host's, as it is for curl.
func TestNetrcMatchesTheMachineCaseInsensitively(t *testing.T) {
	login, pw, err := ParseNetrcEntry([]byte("machine "+strings.ToUpper(netrcHost)+" login u password tok\n"), netrcHost)
	if err != nil || login != "u" || string(pw) != "tok" {
		t.Fatalf("got (%q, %d bytes, %v), want (\"u\", 3 bytes, nil)", login, len(pw), err)
	}
}
