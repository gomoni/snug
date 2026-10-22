package policy

import (
	"reflect"
	"strings"
	"testing"
)

// The two doors identity.gpg passes through. Both live here rather than only in
// the profile loader because an Identity built in Go reaches Resolve without
// internal/profile, and both are properties of the profile TEXT that
// `snug profile show` — which never resolves — must report.

func TestParseFingerprintAcceptsHexAndNormalisesCase(t *testing.T) {
	cases := []struct{ in, want string }{
		// The measured key, in both cases, upper and lower.
		{"6732361300BBFDAE7F22972CD4381E1CE2880244", "6732361300BBFDAE7F22972CD4381E1CE2880244"},
		{"6732361300bbfdae7f22972cd4381e1ce2880244", "6732361300BBFDAE7F22972CD4381E1CE2880244"},
		// A 64-character v5 fingerprint is accepted too.
		{"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"},
	}
	for _, c := range cases {
		got, err := ParseFingerprint(c.in)
		if err != nil {
			t.Errorf("ParseFingerprint(%q) refused: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseFingerprint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseFingerprintRefusesTheWrongShape(t *testing.T) {
	cases := []struct{ name, in, wants string }{
		{"empty", "", "is empty"},
		{"too short", "6732361300BBFDAE7F22972CD4381E1CE288024", "has 39 characters"},
		{"too long", "6732361300BBFDAE7F22972CD4381E1CE2880244FF", "has 42 characters"},
		{"40 but not hex", "6732361300BBFDAE7F22972CD4381E1CE2880ZZ4", "not hexadecimal"},
		{"64 but not hex", "6732361300BBFDAE7F22972CD4381E1CE288024400000000000000000000000Z",
			"not hexadecimal"},
		{"path, not a fingerprint", "/home/u/.gnupg/pubring.kbx", "has 26 characters"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseFingerprint(c.in)
			if err == nil {
				t.Fatalf("ParseFingerprint(%q) accepted", c.in)
			}
			if !strings.Contains(err.Error(), c.wants) {
				t.Errorf("refusal = %v, want it to mention %q", err, c.wants)
			}
		})
	}
}

func TestParseGPGRuntimeScopeUnionsAndCanonicalises(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"sign"}, "sign"},
		{[]string{"decrypt"}, "decrypt"},
		// SORTED, so the two orders of the same set are one value.
		{[]string{"sign", "decrypt"}, "decrypt,sign"},
		{[]string{"decrypt", "sign"}, "decrypt,sign"},
	}
	for _, c := range cases {
		got, err := ParseGPGRuntimeScope(c.in)
		if err != nil {
			t.Errorf("ParseGPGRuntimeScope(%v) refused: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseGPGRuntimeScope(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseGPGRuntimeScopeRefusesAnEmptySet(t *testing.T) {
	// The load-bearing refusal: a block that names a key must say what it
	// grants. An empty array is the `podman = "off"` disease — a value that is
	// accepted and grants nothing.
	for _, in := range [][]string{nil, {}} {
		_, err := ParseGPGRuntimeScope(in)
		if err == nil {
			t.Fatalf("ParseGPGRuntimeScope(%v) accepted an empty set", in)
		}
		for _, want := range []string{"sets nothing", "sign", "decrypt"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal = %v, want it to name %q", err, want)
			}
		}
	}
}

func TestParseGPGRuntimeScopeRefusesUnknownAndRepeatedValues(t *testing.T) {
	cases := []struct {
		name, in, wants string
	}{
		{"encrypt is not a value", "encrypt", "unknown identity.gpg.scope"},
		{"auth is not a value", "auth", "unknown identity.gpg.scope"},
		{"empty both", "none", "unknown identity.gpg.scope"},
		{"repeated", "sign,sign", "names \"sign\" twice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseGPGRuntimeScope(strings.Split(c.in, ","))
			if err == nil {
				t.Fatalf("ParseGPGRuntimeScope(%q) accepted", c.in)
			}
			if !strings.Contains(err.Error(), c.wants) {
				t.Errorf("refusal = %v, want it to mention %q", err, c.wants)
			}
		})
	}
	// An unknown value names the accepted set, so the message is the fix.
	_, err := ParseGPGRuntimeScope([]string{"encrypt"})
	for _, want := range []string{"sign", "decrypt"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("an unknown-value refusal does not name %q: %v", want, err)
		}
	}
}

func TestGPGScopeHas(t *testing.T) {
	cases := []struct {
		scope, cap string
		want       bool
	}{
		{"sign", "sign", true},
		{"sign", "decrypt", false},
		{"decrypt", "decrypt", true},
		{"decrypt", "sign", false},
		{"decrypt,sign", "sign", true},
		{"decrypt,sign", "decrypt", true},
		{"decrypt,sign", "encrypt", false},
		{"", "sign", false},
	}
	for _, c := range cases {
		if got := GPGScopeHas(c.scope, c.cap); got != c.want {
			t.Errorf("GPGScopeHas(%q, %q) = %v, want %v", c.scope, c.cap, got, c.want)
		}
	}
}

// TestIdentityGPGFingerprintIsNotAPathLeaf pins the shape: the fingerprint has
// no `path` role, because snug reads no key file for this block — the host
// agent holds the key. A `path` tag here would send it through Resolve's
// expand-and-symlink-check loop and produce a refusal telling a human to copy a
// PUBLIC half, which is the wrong instruction for a fingerprint.
func TestIdentityGPGFingerprintIsNotAPathLeaf(t *testing.T) {
	var fingerprint *identityField
	for i := range identityFields {
		if identityFields[i].Key == "gpg.fingerprint" {
			fingerprint = &identityFields[i]
		}
	}
	if fingerprint == nil {
		t.Fatal("identityFields has no gpg.fingerprint; the block did not derive")
	}
	if fingerprint.Path {
		t.Error("gpg.fingerprint is a path leaf; it names a key in the host agent, not a file")
	}
	if _, ok := identityPathRoles["gpg.fingerprint"]; ok {
		t.Error("identityPathRoles has an entry for gpg.fingerprint, which is not a path")
	}
}

// TestIdentityGPGIsItsOwnPinWithTwoLeaves pins the partition: the block joins
// as one pin like every other, and its two leaves are the fingerprint and the
// canonical scope.
func TestIdentityGPGIsItsOwnPinWithTwoLeaves(t *testing.T) {
	var leaves []string
	for _, f := range identityFields {
		if f.Pin == "gpg" {
			leaves = append(leaves, f.Key)
		}
	}
	want := []string{"gpg.fingerprint", "gpg.scope"}
	if !reflect.DeepEqual(leaves, want) {
		t.Errorf("gpg leaves = %v, want %v", leaves, want)
	}
	found := false
	for _, p := range identityPins {
		if p.Key == "gpg" {
			found = true
		}
	}
	if !found {
		t.Error("gpg is not an identity pin")
	}
}
