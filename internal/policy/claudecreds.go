package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ~/.claude/.credentials.json is the one file @claude stages that is a
// CREDENTIAL rather than a configuration, and until issue #58 it was copied
// verbatim. 508 bytes on the host this was measured on, carrying an
// `accessToken` AND a `refreshToken`.
//
// The payload inside the sandbox can read it. That much is by design — Claude
// Code has to authenticate. What was not by design is the blast radius, and it
// is a difference of kind rather than degree:
//
//   - an accessToken expires in hours. Measured on this host: 5h 20m.
//   - a refreshToken mints new access tokens for as long as it lives.
//     Measured on the same host, same file: 26 days.
//
// So a credential stolen from inside a sandbox OUTLIVED the sandbox without
// any bound the sandbox could set, and — since there is no sync-back — a token
// the sandbox refreshed was lost while a token it stole was not. That is the
// `A2 = true` row in .claude/design/SECRETS.md.
//
// What makes projecting viable rather than merely desirable, MEASURED (claude
// 2.1.232, twice and independently):
// Claude Code works with `refreshToken` ABSENT. Also measured,
// and it kills a plausible worry: an already-EXPIRED placeholder served a full
// session offline, and expiry passing mid-run did nothing — so there is no
// expiresAt snug has to compute or get right. It carries the host's value
// forward untouched and only READS it, to say something legible before the run
// rather than leaving an auth error to be discovered from inside.
//
// This is CLAUDE.md's "generate, don't bind" applied to a credential file, the
// same shape already used for ~/.gitconfig, gh's hosts.yml and
// /etc/resolv.conf. The allowlist below is the whole of the decision.

// ClaudeCredentialKind is the JSON kind an allowlisted credential field must
// decode to. There is no "any" — a field whose kind cannot be named here
// cannot be carried, which is what stops the allowlist quietly growing a hole
// the way a `map[string]any` passthrough would.
type ClaudeCredentialKind uint8

const (
	ClaudeCredString ClaudeCredentialKind = iota
	ClaudeCredNumber
	ClaudeCredStringArray
)

// ClaudeCredentialKey is one row of the allowlist.
type ClaudeCredentialKey struct {
	Name string
	Kind ClaudeCredentialKind

	// Required fields make the projection fail rather than produce a
	// half-projected credential. Only accessToken is required: without it the
	// staged file authenticates nothing, and staging it anyway would be
	// staging a credential-shaped file that is not a credential.
	Required bool
}

// ClaudeCredentialAllowlist is every field snug carries from the host's
// ~/.claude/.credentials.json into the one it generates, inside the
// `claudeAiOauth` object. Five fields.
//
// What is NOT here is the point, and both omissions are deliberate:
//
//   - refreshToken — the unbounded credential this whole file exists to drop.
//   - refreshTokenExpiresAt — carrying it without the token it describes would
//     be a lie in a file snug authored, and it is the one field whose presence
//     would make a reader believe the refresh token was still there.
//
// It is an ALLOWLIST rather than a denylist for the reason invariant 2 gives:
// a field that appears upstream tomorrow is DROPPED rather than carried, and
// TestStagedClaudeCredentialCarriesExactlyTheAllowlistedFields is what turns
// that into a visible failure instead of a silent widening.
//
// The three fields beyond accessToken and its expiry are carried because they
// are what Claude Code renders about the account it is signed in to — the
// subscription and rate-limit tier it prints, and the scopes it was granted.
// None of them authenticates anything: a scope list is a description of a
// token's authority, not authority itself.
var ClaudeCredentialAllowlist = []ClaudeCredentialKey{
	{Name: "accessToken", Kind: ClaudeCredString, Required: true},
	{Name: "expiresAt", Kind: ClaudeCredNumber},
	{Name: "scopes", Kind: ClaudeCredStringArray},
	{Name: "subscriptionType", Kind: ClaudeCredString},
	{Name: "rateLimitTier", Kind: ClaudeCredString},
}

// claudeCredentialEnvelope is the shape of the host's file. The OAuth
// credential lives under one key; anything else at top level is not carried,
// for the same reason a field inside it is not.
const claudeCredentialEnvelopeKey = "claudeAiOauth"

// ErrClaudeCredentialShape is returned when the host's file cannot be
// projected — it did not parse, it carries no recognisable OAuth object, or a
// required field is missing or of the wrong kind.
//
// The caller must NOT fall back to staging the host bytes on this error. That
// fallback is the exact behaviour issue #58 removes, and it is the one failure
// mode that would silently undo this whole change: a parse that goes wrong
// would restore the verbatim copy, refreshToken included, with nothing on
// screen to say so.
var ErrClaudeCredentialShape = errors.New("unrecognised Claude credential file")

// ProjectClaudeCredentials reads the host's ~/.claude/.credentials.json bytes
// and returns the file the sandbox will actually see: the same envelope, with
// only the allowlisted fields inside it.
//
// expiresAt is the host's own value in epoch MILLISECONDS, returned so the
// caller can say something legible before the run about a token that has
// already expired. It is zero when the host's file did not carry one, which is
// not an error — the measurement says an absent or past expiry does not stop
// Claude Code working.
//
// The return type is Secret so the projected bytes cannot reach a fmt, JSON or
// text sink by accident (#51). Note that issue's own documented limit: Secret
// and []byte share an underlying type, so an assignment reaches the plaintext
// with nothing conversion-shaped in the diff.
func ProjectClaudeCredentials(raw []byte) (projected Secret, expiresAt int64, err error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, 0, fmt.Errorf("%w: it is not a JSON object: %v", ErrClaudeCredentialShape, err)
	}
	rawOAuth, ok := envelope[claudeCredentialEnvelopeKey]
	if !ok {
		return nil, 0, fmt.Errorf("%w: it carries no %q object (keys present: %s)",
			ErrClaudeCredentialShape, claudeCredentialEnvelopeKey, sortedRawKeys(envelope))
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rawOAuth, &fields); err != nil {
		return nil, 0, fmt.Errorf("%w: %q is not an object: %v",
			ErrClaudeCredentialShape, claudeCredentialEnvelopeKey, err)
	}

	kept := make(map[string]json.RawMessage, len(ClaudeCredentialAllowlist))
	for _, key := range ClaudeCredentialAllowlist {
		value, present := fields[key.Name]
		if !present {
			if key.Required {
				return nil, 0, fmt.Errorf("%w: %q carries no %q",
					ErrClaudeCredentialShape, claudeCredentialEnvelopeKey, key.Name)
			}
			continue
		}
		decoded, err := decodeClaudeCredentialValue(key, value)
		if err != nil {
			// A wrong KIND is treated exactly like a missing required field
			// rather than dropped quietly, even for an optional key: a file
			// whose fields do not have the shapes this code expects is not a
			// file this code understands, and half-understanding a credential
			// is how a half-projected one gets written.
			return nil, 0, fmt.Errorf("%w: %q has the wrong shape: %v",
				ErrClaudeCredentialShape, key.Name, err)
		}
		if key.Name == "accessToken" {
			if s, _ := decoded.(string); s == "" {
				return nil, 0, fmt.Errorf("%w: %q is empty", ErrClaudeCredentialShape, key.Name)
			}
		}
		if key.Name == "expiresAt" {
			if n, ok := decoded.(float64); ok {
				expiresAt = int64(n)
			}
		}
		kept[key.Name] = value
	}

	body, err := json.MarshalIndent(map[string]any{claudeCredentialEnvelopeKey: kept}, "", "  ")
	if err != nil {
		// Unreachable: every value in `kept` is a json.RawMessage this
		// function has already decoded successfully.
		return nil, 0, fmt.Errorf("%w: re-encoding it failed: %v", ErrClaudeCredentialShape, err)
	}
	return Secret(append(body, '\n')), expiresAt, nil
}

// decodeClaudeCredentialValue enforces the declared kind and returns the
// decoded value, which the caller uses for the two fields it must also
// inspect. Nothing here reaches a formatting sink: the error names the KEY,
// never the value, because one of these keys is an access token.
func decodeClaudeCredentialValue(key ClaudeCredentialKey, value json.RawMessage) (any, error) {
	switch key.Kind {
	case ClaudeCredString:
		var s string
		if err := json.Unmarshal(value, &s); err != nil {
			return nil, errors.New("not a string")
		}
		return s, nil
	case ClaudeCredNumber:
		var n float64
		if err := json.Unmarshal(value, &n); err != nil {
			return nil, errors.New("not a number")
		}
		return n, nil
	case ClaudeCredStringArray:
		var a []string
		if err := json.Unmarshal(value, &a); err != nil {
			return nil, errors.New("not an array of strings")
		}
		return a, nil
	}
	return nil, errors.New("unknown kind")
}

// sortedRawKeys renders a map's keys for an error message. Sorted so the
// message is the same on every run — an error a human compares between two
// runs is worth more than one they have to read twice.
func sortedRawKeys(m map[string]json.RawMessage) string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// ── a login snug completed on the host (login.claude = "host") ──────────────
//
// The bytes below are what Claude Code writes at its own sign-in, as its
// 2.1.310 bundle was read for issue #662: the claudeAiOauth object's keys in
// this order, compact, no trailing newline. snug writes the host's file the
// way the client does so a host `claude` reads it as its own; every value
// comes from the vendor's two answers and the clock, and nothing from the
// sandbox.

// ClaudeRefreshDefault is the refresh token's lifetime Claude Code assumes at
// sign-in when the token endpoint names none (the client's 2592000000 ms).
const ClaudeRefreshDefault = 30 * 24 * time.Hour

// claudeSubscriptions maps the profile endpoint's organization_type to the
// subscriptionType the client stores; any other value stores null.
var claudeSubscriptions = map[string]string{
	"claude_max":        "max",
	"claude_pro":        "pro",
	"claude_enterprise": "enterprise",
	"claude_team":       "team",
}

// claudeOriginStamp is the request-id shape for which the client stamps
// subscriptionTypeSource "sign_in" rather than "profile".
var claudeOriginStamp = regexp.MustCompile(`^req_[A-Za-z0-9_-]{1,36}$`)

// ClaudeLoginResult is what a login snug completed on the host learned from
// the vendor's token and profile endpoints, already checked by the caller. It
// names no account: whose login it is was decided before any file is written.
type ClaudeLoginResult struct {
	AccessToken Secret
	// RefreshToken is empty when the token endpoint answered without one.
	// RenewClaudeCredentials refuses that; ProjectClaudeLogin never carries
	// it.
	RefreshToken Secret
	// ExpiresIn is the access token's lifetime, expires_in.
	ExpiresIn time.Duration
	// RefreshTokenExpiresIn is refresh_token_expires_in; zero when the answer
	// had none, which means ClaudeRefreshDefault.
	RefreshTokenExpiresIn time.Duration
	// Scopes is the scope the token endpoint granted, split on spaces.
	Scopes []string
	// OrganizationType is the profile endpoint's organization_type; "" when
	// it had none or the profile request failed.
	OrganizationType string
	// RateLimitTier is the profile endpoint's rate_limit_tier; "" when absent.
	RateLimitTier string
	// RequestID is the profile response's request-id header.
	RequestID string
}

// RenewClaudeCredentials returns the host's ~/.claude/.credentials.json after
// a login snug completed: existing with its claudeAiOauth object replaced
// wholesale by one built from r and now, every other top-level key carried
// byte for byte in its place, compact, with no trailing newline.
//
// existing that is empty, or is not a JSON object, contributes no key: there
// is nothing in it a reader can parse, and it is the file this login renews.
//
// When the profile endpoint named no subscription the client knows, the
// subscriptionType, subscriptionTypeSource and rateLimitTier existing already
// holds are kept rather than replaced by null: a login whose profile request
// failed is not evidence the plan changed, and writing null would downgrade
// what the host's `claude` shows and applies.
//
// The error is ErrClaudeCredentialShape when r has no access token, no
// refresh token or no positive lifetime: such a file would not be a login.
func RenewClaudeCredentials(existing []byte, r ClaudeLoginResult, now time.Time) (Secret, error) {
	if len(r.RefreshToken) == 0 {
		return nil, fmt.Errorf("%w: the login carries no refresh token, and the host's file "+
			"needs one to stay signed in", ErrClaudeCredentialShape)
	}
	order, fields := claudeEnvelope(existing)
	oauth, err := claudeLoginObject(r, now, oauthFields(fields), true)
	if err != nil {
		return nil, err
	}
	if _, ok := fields[claudeCredentialEnvelopeKey]; !ok {
		order = append(order, claudeCredentialEnvelopeKey)
	}
	fields[claudeCredentialEnvelopeKey] = oauth
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range order {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(jsonText(k))
		b.WriteByte(':')
		if err := json.Compact(&b, fields[k]); err != nil {
			return nil, fmt.Errorf("%w: top-level key %q does not re-encode: %v", ErrClaudeCredentialShape, k, err)
		}
	}
	b.WriteByte('}')
	return Secret(b.Bytes()), nil
}

// ProjectClaudeLogin returns the sandbox's credential file after a login snug
// completed on the host: the same object RenewClaudeCredentials would write,
// through ProjectClaudeCredentials, so the sandbox gets exactly what @claude
// stages at the start of a run — the access token and its description, never
// the refresh token. existing is the sandbox's current file, read for the
// subscription fields only, exactly as RenewClaudeCredentials reads the
// host's; it may be nil.
//
// The error is ErrClaudeCredentialShape when r has no access token or no
// positive lifetime.
func ProjectClaudeLogin(existing []byte, r ClaudeLoginResult, now time.Time) (Secret, error) {
	_, fields := claudeEnvelope(existing)
	oauth, err := claudeLoginObject(r, now, oauthFields(fields), false)
	if err != nil {
		return nil, err
	}
	envelope := append(append(append([]byte(`{`), jsonText(claudeCredentialEnvelopeKey)...), ':'), oauth...)
	projected, _, err := ProjectClaudeCredentials(append(envelope, '}'))
	return projected, err
}

// claudeEnvelope reads the top-level keys of a credential file in the order
// they appear. A key that appears twice keeps its first place and its last
// value, which is what JSON.parse does with it. Anything that is not exactly
// one JSON object reads as no keys at all.
func claudeEnvelope(raw []byte) (order []string, fields map[string]json.RawMessage) {
	fields = map[string]json.RawMessage{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, map[string]json.RawMessage{}
	}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok {
			return nil, map[string]json.RawMessage{}
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, map[string]json.RawMessage{}
		}
		if _, seen := fields[key]; !seen {
			order = append(order, key)
		}
		fields[key] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, map[string]json.RawMessage{}
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, map[string]json.RawMessage{}
	}
	return order, fields
}

// oauthFields is the claudeAiOauth object of an envelope claudeEnvelope read,
// or nil when there is none or it is not an object.
func oauthFields(envelope map[string]json.RawMessage) map[string]json.RawMessage {
	var oauth map[string]json.RawMessage
	if err := json.Unmarshal(envelope[claudeCredentialEnvelopeKey], &oauth); err != nil {
		return nil
	}
	return oauth
}

// claudeLoginObject builds the claudeAiOauth object in the client's key
// order. prev is the object the file held before, read for the subscription
// fields only.
func claudeLoginObject(r ClaudeLoginResult, now time.Time, prev map[string]json.RawMessage, withRefresh bool) (json.RawMessage, error) {
	if len(r.AccessToken) == 0 {
		return nil, fmt.Errorf("%w: the login carries no access token", ErrClaudeCredentialShape)
	}
	if r.ExpiresIn <= 0 {
		return nil, fmt.Errorf("%w: the access token's lifetime is not positive", ErrClaudeCredentialShape)
	}
	refreshFor := r.RefreshTokenExpiresIn
	if refreshFor <= 0 {
		refreshFor = ClaudeRefreshDefault
	}
	scopes := r.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	subscription, source, tier := json.RawMessage("null"), json.RawMessage(nil), json.RawMessage("null")
	if s, ok := claudeSubscriptions[r.OrganizationType]; ok {
		subscription = jsonText(s)
		source = jsonText("profile")
		if claudeOriginStamp.MatchString(r.RequestID) {
			source = jsonText("sign_in")
		}
		if r.RateLimitTier != "" {
			tier = jsonText(r.RateLimitTier)
		}
	} else {
		if v, ok := prevString(prev, "subscriptionType"); ok {
			subscription = v
		}
		if v, ok := prevString(prev, "subscriptionTypeSource"); ok && string(subscription) != "null" {
			source = v
		}
		if v, ok := prevString(prev, "rateLimitTier"); ok {
			tier = v
		} else if r.RateLimitTier != "" {
			tier = jsonText(r.RateLimitTier)
		}
	}

	var b bytes.Buffer
	b.WriteString(`{"accessToken":`)
	b.Write(jsonText(string(r.AccessToken)))
	if withRefresh {
		b.WriteString(`,"refreshToken":`)
		b.Write(jsonText(string(r.RefreshToken)))
	}
	fmt.Fprintf(&b, `,"expiresAt":%d`, now.Add(r.ExpiresIn).UnixMilli())
	if withRefresh {
		fmt.Fprintf(&b, `,"refreshTokenExpiresAt":%d`, now.Add(refreshFor).UnixMilli())
	}
	b.WriteString(`,"scopes":[`)
	for i, s := range scopes {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(jsonText(s))
	}
	b.WriteString(`],"subscriptionType":`)
	b.Write(subscription)
	if source != nil {
		b.WriteString(`,"subscriptionTypeSource":`)
		b.Write(source)
	}
	b.WriteString(`,"rateLimitTier":`)
	b.Write(tier)
	b.WriteByte('}')
	return json.RawMessage(b.Bytes()), nil
}

// prevString is prev[key] when it is a JSON string or null, compacted; a value
// of any other kind is not one the client wrote there and is not carried.
func prevString(prev map[string]json.RawMessage, key string) (json.RawMessage, bool) {
	raw, ok := prev[key]
	if !ok {
		return nil, false
	}
	var s *string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, false
	}
	if s == nil {
		return json.RawMessage("null"), true
	}
	return jsonText(*s), true
}

// jsonText is s as a JSON string the way JSON.stringify spells it: no HTML
// escaping, which encoding/json's Marshal would add to every '<', '>' and '&'.
func jsonText(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	// A string always encodes; Encode cannot fail on one.
	_ = enc.Encode(s)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
