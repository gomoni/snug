package profile

import (
	"strconv"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// [identity.gpg] is two leaves: a fingerprint and a scope array. The block
// passes through the same two doors as identity.ssh and identity.kubectl, and
// the two HALF shapes — a fingerprint with no scope, a scope with no
// fingerprint — are refused at PARSE time, because `snug profile show` renders a
// *policy.Profile straight from the registry and never resolves. A half block
// that parsed would sit on that screen looking complete while granting nothing,
// the same failure TestUnknownAgentModeIsRefusedAtParseTime describes for
// identity.ssh.agent.

func gpgProfile(fingerprint, scope string) []byte {
	body := "[profile.x]\n[profile.x.identity.gpg]\n"
	if fingerprint != "" {
		body += "fingerprint = " + strconv.Quote(fingerprint) + "\n"
	}
	if scope != "" {
		body += "scope = [" + scope + "]\n"
	}
	return []byte(body)
}

const gpgFingerprint = "6732361300BBFDAE7F22972CD4381E1CE2880244"

func TestIdentityGPGBlockParsesAndCanonicalises(t *testing.T) {
	cases := []struct {
		name, scope, wantScope string
	}{
		{"sign only", `"sign"`, "sign"},
		{"decrypt only", `"decrypt"`, "decrypt"},
		// The array order is not the stored order: the stored value is the
		// canonical, sorted, comma-joined set.
		{"both, sign first", `"sign", "decrypt"`, "decrypt,sign"},
		{"both, decrypt first", `"decrypt", "sign"`, "decrypt,sign"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg, err := parse(gpgProfile(gpgFingerprint, c.scope), "mine.toml", true)
			if err != nil {
				t.Fatalf("an accepted identity.gpg block was refused: %v", err)
			}
			id := reg["x"].Identity
			if id == nil {
				t.Fatal("Identity is nil for a block that set identity.gpg")
			}
			if id.GPG.Fingerprint != gpgFingerprint {
				t.Errorf("fingerprint = %q, want %q", id.GPG.Fingerprint, gpgFingerprint)
			}
			if id.GPG.Scope != c.wantScope {
				t.Errorf("scope = %q, want the canonical %q", id.GPG.Scope, c.wantScope)
			}
		})
	}
}

func TestIdentityGPGLowercaseFingerprintIsNormalised(t *testing.T) {
	reg, err := parse(gpgProfile("6732361300bbfdae7f22972cd4381e1ce2880244", `"sign"`), "mine.toml", true)
	if err != nil {
		t.Fatalf("a lowercase fingerprint was refused: %v", err)
	}
	if got := reg["x"].Identity.GPG.Fingerprint; got != gpgFingerprint {
		t.Errorf("fingerprint = %q, want it uppercased to %q", got, gpgFingerprint)
	}
}

func TestIdentityGPGHalfBlockIsRefused(t *testing.T) {
	cases := []struct {
		name, fingerprint, scope, wants string
	}{
		{"scope with no fingerprint", "", `"sign"`, "names a scope but no fingerprint"},
		{"fingerprint with no scope", gpgFingerprint, "", "names no scope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parse(gpgProfile(c.fingerprint, c.scope), "mine.toml", true)
			if err == nil {
				t.Fatalf("a half [identity.gpg] block parsed; `snug profile show` would "+
					"render it as a key %q with the other leaf unset", c.name)
			}
			for _, want := range []string{"mine.toml", `"x"`, c.wants} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not say %q: %v", want, err)
				}
			}
		})
	}
}

func TestIdentityGPGBadValuesAreRefusedAtParseTime(t *testing.T) {
	cases := []struct {
		name, fingerprint, scope, wants string
	}{
		{"fingerprint too short", "6732361300BBFDAE", `"sign"`, "has 16 characters"},
		{"fingerprint not hex", "6732361300BBFDAE7F22972CD4381E1CE2880ZZ4", `"sign"`, "not hexadecimal"},
		{"fingerprint is a path", "/home/u/.gnupg/pubkey", `"sign"`, "has 21 characters"},
		{"scope unknown", gpgFingerprint, `"encrypt"`, "unknown identity.gpg.scope"},
		{"scope auth", gpgFingerprint, `"auth"`, "unknown identity.gpg.scope"},
		{"scope empty", gpgFingerprint, "", "names no scope"},
		{"scope repeated", gpgFingerprint, `"sign", "sign"`, "names \"sign\" twice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parse(gpgProfile(c.fingerprint, c.scope), "mine.toml", true)
			if err == nil {
				t.Fatalf("identity.gpg with %s parsed", c.name)
			}
			for _, want := range []string{"mine.toml", c.wants} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not say %q: %v", want, err)
				}
			}
		})
	}
	// "encrypt" is the value a reader most expects to exist — gpg encrypts to
	// the key — so the refusal has to name the accepted set, which is the fix.
	_, err := parse(gpgProfile(gpgFingerprint, `"encrypt"`), "mine.toml", true)
	for _, want := range []string{"sign", "decrypt"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the unknown-scope refusal does not name %q: %v", want, err)
		}
	}
}

// A block that sets NEITHER leaf is not a block: an absent [identity.gpg] takes
// no part in the join, exactly like an absent [identity.ssh]. The positive
// control for the half-block refusal above.
func TestAbsentIdentityGPGBlockIsNoGrant(t *testing.T) {
	reg, err := parse([]byte("[profile.x]\n[profile.x.identity.git]\nname = \"Some One\"\n"),
		"mine.toml", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := reg["x"].Identity.GPG; got != (policy.IdentityGPG{}) {
		t.Errorf("an absent gpg block stored %+v, want the zero block", got)
	}
	// And it takes no part in the pin: Pinned("gpg") is false.
	if reg["x"].Identity.Pinned("gpg") {
		t.Error("an absent gpg block reported itself pinned")
	}
}
