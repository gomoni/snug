package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// loginNow is the fixed clock every renewal test reads: 2026-10-26T12:00:00Z.
var loginNow = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func fixtureLogin() ClaudeLoginResult {
	return ClaudeLoginResult{
		AccessToken:           Secret("sk-ant-oat-NEW"),
		RefreshToken:          Secret("sk-ant-ort-NEW"),
		ExpiresIn:             8 * time.Hour,
		RefreshTokenExpiresIn: 25 * 24 * time.Hour,
		Scopes:                []string{"user:inference", "user:profile"},
		OrganizationType:      "claude_max",
		RateLimitTier:         "default_claude_max_5x",
		RequestID:             "req_011CUVabcdefXYZ-_09",
	}
}

// TestRenewedCredentialsCarryExactlyClaudesFieldsInClaudesOrder pins the
// bytes: Claude Code's eight keys in its own order, epoch milliseconds,
// compact, no trailing newline, and nothing else.
func TestRenewedCredentialsCarryExactlyClaudesFieldsInClaudesOrder(t *testing.T) {
	got, err := RenewClaudeCredentials(nil, fixtureLogin(), loginNow)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"claudeAiOauth":{"accessToken":"sk-ant-oat-NEW","refreshToken":"sk-ant-ort-NEW",` +
		`"expiresAt":1793044800000,"refreshTokenExpiresAt":1795176000000,` +
		`"scopes":["user:inference","user:profile"],"subscriptionType":"max",` +
		`"subscriptionTypeSource":"sign_in","rateLimitTier":"default_claude_max_5x"}}`
	if string(got) != want {
		t.Errorf("renewed file:\n got %s\nwant %s", string(got), want)
	}
	// The milliseconds are the clock plus the lifetimes, not a re-derivation.
	if loginNow.Add(8*time.Hour).UnixMilli() != 1793044800000 ||
		loginNow.Add(25*24*time.Hour).UnixMilli() != 1795176000000 {
		t.Fatal("control: the expected epoch milliseconds are not the fixture's")
	}
}

// TestRenewalPreservesForeignTopLevelKeys: every top-level key other than
// claudeAiOauth survives byte for byte and in its place, claudeAiOauth is
// replaced wholesale (its unknown keys included), and a file that has no
// claudeAiOauth gets one appended.
func TestRenewalPreservesForeignTopLevelKeys(t *testing.T) {
	existing := `{"cloudSessionsOauth":{"a":1,"b":[true,null]},"claudeAiOauth":{"accessToken":"OLD",` +
		`"refreshToken":"OLD-R","clientId":"x","futureKey":7},"designOauth":"d<&>","primaryApiKey":"sk-x"}`
	got, err := RenewClaudeCredentials([]byte(existing), fixtureLogin(), loginNow)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if !strings.HasPrefix(s, `{"cloudSessionsOauth":{"a":1,"b":[true,null]},"claudeAiOauth":{"accessToken":"sk-ant-oat-NEW",`) ||
		!strings.HasSuffix(s, `},"designOauth":"d<&>","primaryApiKey":"sk-x"}`) {
		t.Errorf("foreign keys moved or changed:\n%s", s)
	}
	for _, gone := range []string{"OLD", "clientId", "futureKey"} {
		if strings.Contains(s, gone) {
			t.Errorf("the old claudeAiOauth's %s survived:\n%s", gone, s)
		}
	}

	appended, err := RenewClaudeCredentials([]byte(`{"primaryApiKey":"sk-x"}`), fixtureLogin(), loginNow)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(appended), `{"primaryApiKey":"sk-x","claudeAiOauth":{`) {
		t.Errorf("claudeAiOauth not appended after the existing key:\n%s", appended)
	}

	// A key twice keeps its first place and its last value, as JSON.parse does.
	dup, err := RenewClaudeCredentials([]byte(`{"a":1,"b":2,"a":3}`), fixtureLogin(), loginNow)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(dup), `{"a":3,"b":2,"claudeAiOauth":`) {
		t.Errorf("duplicate key: %s", dup)
	}

	// Not one JSON object: nothing in it to carry.
	for _, raw := range []string{"", "not json", `["a"]`, `{"a":1} trailing`, `{"a":`} {
		got, err := RenewClaudeCredentials([]byte(raw), fixtureLogin(), loginNow)
		if err != nil || !strings.HasPrefix(string(got), `{"claudeAiOauth":{"accessToken":"sk-ant-oat-NEW"`) ||
			strings.Count(string(got), `":`) != 9 {
			t.Errorf("%q: %s, %v", raw, got, err)
		}
	}
}

// TestRenewalDefaultsRefreshExpiryToThirtyDays: an answer with no
// refresh_token_expires_in gets the client's own thirty days.
func TestRenewalDefaultsRefreshExpiryToThirtyDays(t *testing.T) {
	r := fixtureLogin()
	r.RefreshTokenExpiresIn = 0
	got, err := RenewClaudeCredentials(nil, r, loginNow)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		OAuth struct {
			RefreshTokenExpiresAt int64 `json:"refreshTokenExpiresAt"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(got, &f); err != nil {
		t.Fatal(err)
	}
	if want := loginNow.UnixMilli() + 2592000000; f.OAuth.RefreshTokenExpiresAt != want {
		t.Errorf("refreshTokenExpiresAt = %d, want now + 2592000000 ms = %d", f.OAuth.RefreshTokenExpiresAt, want)
	}
}

func renewedOAuth(t *testing.T, existing string, r ClaudeLoginResult) map[string]json.RawMessage {
	t.Helper()
	got, err := RenewClaudeCredentials([]byte(existing), r, loginNow)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]map[string]json.RawMessage
	if err := json.Unmarshal(got, &f); err != nil {
		t.Fatal(err)
	}
	return f["claudeAiOauth"]
}

// TestRenewalStampsSubscriptionSourceFromTheRequestID: "sign_in" exactly when
// the profile response's request-id has the client's shape, "profile"
// otherwise, and no source at all when there is no subscription.
func TestRenewalStampsSubscriptionSourceFromTheRequestID(t *testing.T) {
	for id, want := range map[string]string{
		"req_011CUVabcdefXYZ-_09":        `"sign_in"`,
		"req_" + strings.Repeat("a", 36): `"sign_in"`,
		"req_" + strings.Repeat("a", 37): `"profile"`,
		"req_":                           `"profile"`,
		"":                               `"profile"`,
		"REQ_abc":                        `"profile"`,
		"req_abc\n":                      `"profile"`,
		"xreq_abc":                       `"profile"`,
		"req_a.b":                        `"profile"`,
	} {
		r := fixtureLogin()
		r.RequestID = id
		if got := string(renewedOAuth(t, "", r)["subscriptionTypeSource"]); got != want {
			t.Errorf("request-id %q: subscriptionTypeSource %s, want %s", id, got, want)
		}
	}
	for orgType, want := range map[string]string{
		"claude_max": `"max"`, "claude_pro": `"pro"`, "claude_enterprise": `"enterprise"`,
		"claude_team": `"team"`, "claude_free": "null", "": "null",
	} {
		r := fixtureLogin()
		r.OrganizationType = orgType
		o := renewedOAuth(t, "", r)
		if got := string(o["subscriptionType"]); got != want {
			t.Errorf("organization_type %q: subscriptionType %s, want %s", orgType, got, want)
		}
		if _, has := o["subscriptionTypeSource"]; has != (want != "null") {
			t.Errorf("organization_type %q: subscriptionTypeSource present = %v", orgType, has)
		}
	}
}

// TestRenewalNeverDowngradesSubscriptionType: a profile that names no
// subscription the client knows — an unmapped organization_type, or a profile
// request that failed — keeps the subscriptionType, subscriptionTypeSource and
// rateLimitTier the file already had, in the host's file and in the sandbox's.
func TestRenewalNeverDowngradesSubscriptionType(t *testing.T) {
	existing := `{"claudeAiOauth":{"accessToken":"OLD","refreshToken":"OLD-R","subscriptionType":"max",` +
		`"subscriptionTypeSource":"sign_in","rateLimitTier":"default_claude_max_20x"}}`
	for _, orgType := range []string{"", "claude_free", "something_new"} {
		r := fixtureLogin()
		r.OrganizationType, r.RateLimitTier, r.RequestID = orgType, "", ""
		o := renewedOAuth(t, existing, r)
		for k, want := range map[string]string{
			"subscriptionType": `"max"`, "subscriptionTypeSource": `"sign_in"`, "rateLimitTier": `"default_claude_max_20x"`,
		} {
			if got := string(o[k]); got != want {
				t.Errorf("organization_type %q: %s = %s, want the existing %s", orgType, k, got, want)
			}
		}
		projected, err := ProjectClaudeLogin([]byte(existing), r, loginNow)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(projected), `"subscriptionType": "max"`) ||
			!strings.Contains(string(projected), `"rateLimitTier": "default_claude_max_20x"`) {
			t.Errorf("organization_type %q: the sandbox's projection downgraded:\n%s", orgType, projected)
		}
	}
	// CONTROL: a mapped organization_type is the profile's answer, and wins.
	o := renewedOAuth(t, existing, fixtureLogin())
	if string(o["subscriptionType"]) != `"max"` || string(o["rateLimitTier"]) != `"default_claude_max_5x"` {
		t.Errorf("control: the profile's own answer did not replace the existing one: %s %s",
			o["subscriptionType"], o["rateLimitTier"])
	}
	// A value of a kind the client never writes there is not carried.
	r := fixtureLogin()
	r.OrganizationType = ""
	o = renewedOAuth(t, `{"claudeAiOauth":{"subscriptionType":7,"rateLimitTier":{"x":1}}}`, r)
	if string(o["subscriptionType"]) != "null" || string(o["rateLimitTier"]) != `"default_claude_max_5x"` {
		t.Errorf("non-string existing values were carried: %s %s", o["subscriptionType"], o["rateLimitTier"])
	}
}

// TestTheProjectionIsASubsetOfWhatRenewalWrites: the sandbox's file after a
// host login carries a subset of the fields the host's file gets, each with
// the same value, never the refresh token or its expiry, and is the shape
// ProjectClaudeCredentials stages at the start of a run.
func TestTheProjectionIsASubsetOfWhatRenewalWrites(t *testing.T) {
	r := fixtureLogin()
	host, err := RenewClaudeCredentials(nil, r, loginNow)
	if err != nil {
		t.Fatal(err)
	}
	sandbox, err := ProjectClaudeLogin(nil, r, loginNow)
	if err != nil {
		t.Fatal(err)
	}
	var h, s map[string]map[string]json.RawMessage
	if err := json.Unmarshal(host, &h); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(sandbox, &s); err != nil {
		t.Fatal(err)
	}
	if len(s) != 1 || s["claudeAiOauth"] == nil {
		t.Fatalf("the sandbox's file is not one claudeAiOauth envelope:\n%s", sandbox)
	}
	for k, v := range s["claudeAiOauth"] {
		hv, ok := h["claudeAiOauth"][k]
		if !ok {
			t.Errorf("the sandbox gets %s, which the host's file does not have", k)
			continue
		}
		var a, b any
		json.Unmarshal(v, &a)
		json.Unmarshal(hv, &b)
		if !jsonEqual(a, b) {
			t.Errorf("%s differs: sandbox %s, host %s", k, v, hv)
		}
	}
	for _, k := range []string{"refreshToken", "refreshTokenExpiresAt"} {
		if _, ok := s["claudeAiOauth"][k]; ok {
			t.Errorf("the sandbox's file carries %s", k)
		}
	}
	// The same bytes as the start-of-run staging of the host's own file.
	staged, _, err := ProjectClaudeCredentials(host)
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != string(sandbox) {
		t.Errorf("the renewal's projection differs from staging the renewed file:\n%s\n%s", sandbox, staged)
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// TestRenewalRefusesWhatIsNotALogin: no refresh token refuses the host's file
// (the sandbox's projection does not need one), and no access token or no
// lifetime refuses both.
func TestRenewalRefusesWhatIsNotALogin(t *testing.T) {
	r := fixtureLogin()
	r.RefreshToken = nil
	if _, err := RenewClaudeCredentials(nil, r, loginNow); !errors.Is(err, ErrClaudeCredentialShape) {
		t.Errorf("no refresh token: %v", err)
	}
	if _, err := ProjectClaudeLogin(nil, r, loginNow); err != nil {
		t.Errorf("no refresh token, sandbox: %v", err)
	}
	for name, mut := range map[string]func(*ClaudeLoginResult){
		"no access token": func(r *ClaudeLoginResult) { r.AccessToken = nil },
		"no lifetime":     func(r *ClaudeLoginResult) { r.ExpiresIn = 0 },
	} {
		r := fixtureLogin()
		mut(&r)
		if _, err := RenewClaudeCredentials(nil, r, loginNow); !errors.Is(err, ErrClaudeCredentialShape) {
			t.Errorf("%s, host: %v", name, err)
		}
		if _, err := ProjectClaudeLogin(nil, r, loginNow); !errors.Is(err, ErrClaudeCredentialShape) {
			t.Errorf("%s, sandbox: %v", name, err)
		}
	}
}
