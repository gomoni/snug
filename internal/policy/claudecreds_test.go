package policy

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
)

// hostShapedCredential is the shape of a real host's
// ~/.claude/.credentials.json (claude 2.1.232), with fixture tokens. Every
// test below starts from this and mutates one thing, so a test that fails
// names the mutation rather than the fixture.
const hostShapedCredential = `{"claudeAiOauth":{` +
	`"accessToken":"sk-ant-oat-FIXTURE",` +
	`"refreshToken":"sk-ant-ort-FIXTURE",` +
	`"expiresAt":4102444800000,` +
	`"refreshTokenExpiresAt":4102444800000,` +
	`"scopes":["user:inference","user:profile"],` +
	`"subscriptionType":"max",` +
	`"rateLimitTier":"default_claude_max_5x"}}`

// TestStagedClaudeCredentialCarriesExactlyTheAllowlistedFields is issue #58's
// central assertion, and it asserts the SET rather than the absence of one
// name. Checking only that "refreshToken" is gone would pass just as well on a
// projection that carried a field upstream added tomorrow — and the whole
// argument for staging a projection rather than a copy is that snug decides
// what crosses, not the host's file.
func TestStagedClaudeCredentialCarriesExactlyTheAllowlistedFields(t *testing.T) {
	projected, _, err := ProjectClaudeCredentials([]byte(hostShapedCredential))
	if err != nil {
		t.Fatalf("a host-shaped credential did not project: %v", err)
	}

	var envelope map[string]map[string]json.RawMessage
	if err := json.Unmarshal(projected, &envelope); err != nil {
		t.Fatalf("the projected credential is not the same envelope shape: %v\n%s", err, projected)
	}
	if len(envelope) != 1 {
		t.Errorf("the projection invented or kept a top-level key: %v", keysOf(envelope))
	}
	oauth, ok := envelope["claudeAiOauth"]
	if !ok {
		t.Fatalf("the projection lost the claudeAiOauth envelope:\n%s", projected)
	}

	got := sortedNames(oauth)
	want := make([]string, 0, len(ClaudeCredentialAllowlist))
	for _, k := range ClaudeCredentialAllowlist {
		want = append(want, k.Name)
	}
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the projected field SET is %v, want exactly %v — a field appearing or "+
			"disappearing here is a change to what crosses into the sandbox", got, want)
	}
}

// TestTheProjectedCredentialCannotMintANewToken is the same property stated as
// the consequence rather than as a field list, because that is the sentence
// --dry-run and base.toml both make to a human: nothing inside the sandbox can
// renew the credential, so a stolen one dies with the access token.
//
// POSITIVE CONTROL: reconstruct the verbatim copy this replaced and assert the
// check FIRES on it. Without that, "no refreshToken in the output" would pass
// on an empty string, on a projection that dropped everything, and on a check
// that was looking at the wrong bytes.
func TestTheProjectedCredentialCannotMintANewToken(t *testing.T) {
	carriesRefresh := func(b []byte) bool {
		return strings.Contains(string(b), "refreshToken") ||
			strings.Contains(string(b), "sk-ant-ort-")
	}

	// CONTROL: today's-shaped host file, copied verbatim, must trip the check.
	if !carriesRefresh([]byte(hostShapedCredential)) {
		t.Fatal("control: the check does not fire on a VERBATIM copy of a host credential " +
			"file, so it cannot be detecting a refresh token at all")
	}

	projected, _, err := ProjectClaudeCredentials([]byte(hostShapedCredential))
	if err != nil {
		t.Fatal(err)
	}
	if carriesRefresh(projected) {
		t.Errorf("the staged credential carries a refresh token, which mints new access "+
			"tokens indefinitely and so outlives the sandbox without bound (issue #58):\n%s",
			projected)
	}
	// And it is still a usable credential, not merely a stripped one.
	if !strings.Contains(string(projected), "sk-ant-oat-FIXTURE") {
		t.Errorf("the projection dropped the ACCESS token too, so the assertion above would "+
			"pass on a file that authenticates nothing:\n%s", projected)
	}
}

// TestAnUnprojectableCredentialStagesNothing is the failure mode a self-written
// test is least likely to think of, and it is the one that would silently undo
// this change: a parse failure must NOT degrade to staging the host bytes.
//
// This asserts at the boundary the caller has to respect — every refusal comes
// back as ErrClaudeCredentialShape with NO projected bytes — because
// stageClaudeCredentials's own contract is "warn and stage nothing", and a
// non-nil projection alongside an error is what would let a caller stage a
// half-projected credential by writing the obvious code.
func TestAnUnprojectableCredentialStagesNothing(t *testing.T) {
	cases := map[string]string{
		"not JSON at all":           `sk-ant-oat-FIXTURE`,
		"JSON but not an object":    `["accessToken"]`,
		"no OAuth envelope":         `{"somethingElse":{"accessToken":"x"}}`,
		"envelope is not an object": `{"claudeAiOauth":"sk-ant-oat-FIXTURE"}`,
		"no access token":           `{"claudeAiOauth":{"refreshToken":"sk-ant-ort-FIXTURE"}}`,
		"empty access token":        `{"claudeAiOauth":{"accessToken":""}}`,
		"access token is a number":  `{"claudeAiOauth":{"accessToken":1234}}`,
		"expiresAt is a string":     `{"claudeAiOauth":{"accessToken":"x","expiresAt":"soon"}}`,
		"scopes is not an array":    `{"claudeAiOauth":{"accessToken":"x","scopes":"user:inference"}}`,
		"truncated mid-object":      `{"claudeAiOauth":{"accessToken":"sk-ant-oat-FIX`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			projected, expiresAt, err := ProjectClaudeCredentials([]byte(raw))
			if err == nil {
				t.Fatalf("this projected instead of failing:\n%s", projected)
			}
			if !errors.Is(err, ErrClaudeCredentialShape) {
				t.Errorf("the error is not ErrClaudeCredentialShape, so a caller cannot tell "+
					"'unprojectable' from any other failure: %v", err)
			}
			if projected != nil {
				t.Errorf("bytes were returned ALONGSIDE the error. A caller writing the "+
					"obvious code would stage a half-projected credential:\n%s", projected)
			}
			if expiresAt != 0 {
				t.Errorf("an expiry was returned alongside the error: %d", expiresAt)
			}
			// The error must not quote the value it refused: one of these keys
			// is an access token.
			if strings.Contains(err.Error(), "sk-ant-") {
				t.Errorf("the error message quotes credential material: %v", err)
			}
		})
	}
}

// TestTheProjectionReportsTheHostsOwnExpiry: snug carries the host's expiry
// forward untouched and reads it only to say something legible before the run.
// It computes nothing, so the value out must be the value in.
func TestTheProjectionReportsTheHostsOwnExpiry(t *testing.T) {
	_, expiresAt, err := ProjectClaudeCredentials([]byte(hostShapedCredential))
	if err != nil {
		t.Fatal(err)
	}
	if expiresAt != 4102444800000 {
		t.Errorf("expiresAt = %d, want the host's own 4102444800000 — snug must not compute "+
			"this value, only carry it", expiresAt)
	}

	// A host file with no expiry is NOT an error: measured, an absent or past
	// expiry does not stop Claude Code working, so refusing here would refuse
	// over something that works.
	_, zero, err := ProjectClaudeCredentials([]byte(`{"claudeAiOauth":{"accessToken":"x"}}`))
	if err != nil {
		t.Fatalf("a credential with no expiry was refused: %v", err)
	}
	if zero != 0 {
		t.Errorf("an absent expiry reported as %d rather than 0", zero)
	}
}

// TestTheCredentialAllowlistNamesNoRefreshingField is the mechanical guard on
// the list itself. A future edit adding "refreshToken" back — or any field
// whose name says it renews something — fails here rather than in a review
// nobody runs.
func TestTheCredentialAllowlistNamesNoRefreshingField(t *testing.T) {
	for _, k := range ClaudeCredentialAllowlist {
		if strings.Contains(strings.ToLower(k.Name), "refresh") {
			t.Errorf("ClaudeCredentialAllowlist carries %q. A refresh-shaped field is the one "+
				"thing issue #58 removes: it mints new access tokens indefinitely, so a "+
				"credential stolen from inside the sandbox outlives it without bound", k.Name)
		}
	}
	// CONTROL: the check can fire.
	if !strings.Contains(strings.ToLower("refreshTokenExpiresAt"), "refresh") {
		t.Fatal("control: the substring check cannot match a refresh-shaped name")
	}
}

func sortedNames(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keysOf(m map[string]map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
