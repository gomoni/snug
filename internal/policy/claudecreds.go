package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
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
// 2.1.232, .claude/scratchpad/RESEARCH-18-BROKER.md and confirmed
// independently): Claude Code works with `refreshToken` ABSENT. Also measured,
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
