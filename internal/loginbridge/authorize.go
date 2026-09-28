package loginbridge

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// authorizePrefix is byte-exact: the scheme, host and path measured for
// Claude Code's browser-bound authorize URL on a real /login (issue #455).
// Comparing with strings.HasPrefix rather than parsing the URL means an
// uppercase host, a trailing dot, a port, userinfo, an extra path segment or
// a percent-escape hiding in the path all fail the same one comparison a
// wrong scheme would — one rule instead of a parser individually taught to
// refuse each of them.
const authorizePrefix = "https://claude.com/cai/oauth/authorize?"

// consolePrefix is Claude Code's OTHER authorize URL, used for a
// console/platform account rather than claude.ai. Its scope set has never
// been measured, so a line starting with it gets its own refusal reason
// rather than falling through to the claude.com rules by coincidence of
// having "authorize?" in common.
const consolePrefix = "https://platform.claude.com/oauth/authorize?"

// clientID is Claude Code's OAuth client id, measured in the URL its browser
// opener received on a real /login (issue #455).
const clientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

// scopeTokens is the exact seven scopes Claude Code requested, in the order
// it requested them. ParseAuthorize compares the requested set against this
// one as sets (order is not meaning) but refuses a subset or a superset: a
// narrower request would be harmless, but it is a URL nobody has measured,
// and the accepted set is only what this client has actually been seen to
// ask for.
var scopeTokens = []string{
	"org%3Acreate_api_key",
	"user%3Aprofile",
	"user%3Ainference",
	"user%3Asessions%3Aclaude_code",
	"user%3Amcp_servers",
	"user%3Afile_upload",
	"user%3Aplugins",
}

// authorizeKeys is the full accepted parameter set. A key outside it is
// refused by name rather than silently ignored, so a future Claude Code
// build that adds one fails loudly instead of the added parameter being
// dropped on rebuild without anyone noticing the URL changed shape.
var authorizeKeys = map[string]bool{
	"code": true, "client_id": true, "response_type": true,
	"redirect_uri": true, "scope": true, "code_challenge": true,
	"code_challenge_method": true, "state": true,
}

// minPort and maxPort bound the port redirect_uri may name: the ephemeral
// range of a fresh network namespace, measured on the ip_local_port_range a
// real /login's browser opener used (issue #455). Nothing pinned here proves
// the sandbox cannot listen outside it — only that a value outside it is not
// a port Claude Code's own ephemeral bind would ever produce.
const (
	minPort = 32768
	maxPort = 60999
)

// Flow is a login request ParseAuthorize has checked in full: a port, a PKCE
// code challenge and a state, each shaped exactly as Claude Code's own
// authorize URL shapes them. Nothing else about the line that produced it is
// kept — AuthorizeURL rebuilds everything else from snug's own constants.
type Flow struct {
	Port          int
	CodeChallenge string
	State         string
}

// ParseAuthorize checks line against the one authorize-URL shape snug pins
// and, if every particular matches, returns the Flow to rebuild it from.
//
// line is refused, never narrowed to the nearest accepted shape: an
// unrecognised parameter, a reordered scope set, a percent-encoding
// mismatch or a byte outside the accepted range each return their own error
// naming what was wrong, so a caller can print it and so a URL a newer or
// older Claude Code build produced fails loudly rather than being forwarded
// with the parts snug does not understand quietly dropped.
func ParseAuthorize(line string) (Flow, error) {
	if err := checkAuthorizeBytes(line); err != nil {
		return Flow{}, err
	}
	if strings.Contains(line, "#") {
		return Flow{}, fmt.Errorf("the URL contains \"#\" (a fragment); the authorize URL snug pins has none")
	}
	if strings.HasPrefix(line, consolePrefix) {
		return Flow{}, fmt.Errorf("console login (platform.claude.com) is not bridged; open the URL claude printed and paste the code")
	}
	if !strings.HasPrefix(line, authorizePrefix) {
		return Flow{}, fmt.Errorf("not the Claude login URL snug pins (scheme, host or path): %s", policy.VisibleText(line))
	}

	_, values, err := parseQueryPairs(line[len(authorizePrefix):])
	if err != nil {
		return Flow{}, err
	}
	for k := range values {
		if !authorizeKeys[k] {
			return Flow{}, fmt.Errorf("parameter %q is not one snug pins", k)
		}
	}
	for k := range authorizeKeys {
		if _, ok := values[k]; !ok {
			return Flow{}, fmt.Errorf("parameter %q is missing", k)
		}
	}

	if values["code"] != "true" {
		return Flow{}, fmt.Errorf("parameter \"code\" is %q, want \"true\"", values["code"])
	}
	if values["client_id"] != clientID {
		return Flow{}, fmt.Errorf("parameter \"client_id\" is not the one snug pins")
	}
	if values["response_type"] != "code" {
		return Flow{}, fmt.Errorf("parameter \"response_type\" is %q, want \"code\"", values["response_type"])
	}
	if values["code_challenge_method"] != "S256" {
		return Flow{}, fmt.Errorf("parameter \"code_challenge_method\" is %q, want \"S256\"", values["code_challenge_method"])
	}
	if !isPKCEValue(values["code_challenge"]) {
		return Flow{}, fmt.Errorf("parameter \"code_challenge\" is not 43 characters of [A-Za-z0-9_-]")
	}
	if !isPKCEValue(values["state"]) {
		return Flow{}, fmt.Errorf("parameter \"state\" is not 43 characters of [A-Za-z0-9_-]")
	}
	if err := checkScope(values["scope"]); err != nil {
		return Flow{}, err
	}
	port, err := checkRedirectURI(values["redirect_uri"])
	if err != nil {
		return Flow{}, err
	}

	return Flow{Port: port, CodeChallenge: values["code_challenge"], State: values["state"]}, nil
}

// AuthorizeURL rebuilds the authorize URL from snug's own constants and f's
// three checked values, in the parameter order Claude Code itself used. This
// is the only thing built from the sandbox's line that a caller may open —
// the sandbox's string itself never reaches xdg-open.
func (f Flow) AuthorizeURL() string {
	var b strings.Builder
	b.WriteString(authorizePrefix)
	b.WriteString("code=true&client_id=")
	b.WriteString(clientID)
	b.WriteString("&response_type=code&redirect_uri=")
	b.WriteString(redirectURI(f.Port))
	b.WriteString("&scope=")
	b.WriteString(strings.Join(scopeTokens, "+"))
	b.WriteString("&code_challenge=")
	b.WriteString(f.CodeChallenge)
	b.WriteString("&code_challenge_method=S256&state=")
	b.WriteString(f.State)
	return b.String()
}

// redirectURI is the percent-encoded http://localhost:<port>/callback value
// Claude Code's own builder produces, byte for byte.
func redirectURI(port int) string {
	return "http%3A%2F%2Flocalhost%3A" + strconv.Itoa(port) + "%2Fcallback"
}

// checkRedirectURI matches the whole redirect_uri value against redirectURI's
// literal shape and only then parses the digits in the middle: a value that
// differs anywhere else — a different scheme, 127.0.0.1 in place of
// localhost, an extra path segment, a double percent-encoding — is refused
// by the literal mismatch rather than accepted because the digits happened to
// parse.
func checkRedirectURI(redirectURI string) (int, error) {
	const prefix, suffix = "http%3A%2F%2Flocalhost%3A", "%2Fcallback"
	if !strings.HasPrefix(redirectURI, prefix) || !strings.HasSuffix(redirectURI, suffix) {
		return 0, fmt.Errorf("parameter \"redirect_uri\" is not http://localhost:<port>/callback, percent-encoded")
	}
	digits := redirectURI[len(prefix) : len(redirectURI)-len(suffix)]
	if len(digits) != 5 || digits[0] == '0' {
		return 0, fmt.Errorf("redirect_uri's port %q is not exactly five digits with no leading zero", digits)
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("redirect_uri's port %q is not all digits", digits)
		}
	}
	port, err := strconv.Atoi(digits)
	if err != nil {
		return 0, fmt.Errorf("redirect_uri's port %q does not parse: %w", digits, err)
	}
	if port < minPort || port > maxPort {
		return 0, fmt.Errorf("port %d is outside %d-%d", port, minPort, maxPort)
	}
	return port, nil
}

// checkScope compares the requested scopes against scopeTokens as sets:
// order is not meaning, so a client-side reordering is accepted, but a
// subset, a superset, a duplicate token or a spelling that differs by even
// one percent-escape (a raw ":" where "%3A" is measured, or "%3a" in place
// of "%3A") all refuse with the same reason, because token spelling and
// membership are the only signal that this scope set is one a real Claude
// Code build produced.
func checkScope(raw string) error {
	reason := errors.New("the scope set differs from the seven snug pins — this claude may be " +
		"newer than snug; open the URL claude printed and paste the code")
	if raw == "" {
		return reason
	}
	tokens := strings.Split(raw, "+")
	seen := map[string]bool{}
	for _, t := range tokens {
		if t == "" {
			return fmt.Errorf("parameter \"scope\" has an empty token (a doubled or trailing \"+\")")
		}
		if seen[t] {
			return fmt.Errorf("parameter \"scope\" repeats %q", t)
		}
		seen[t] = true
	}
	if len(tokens) != len(scopeTokens) {
		return reason
	}
	for _, want := range scopeTokens {
		if !seen[want] {
			return reason
		}
	}
	return nil
}

// isPKCEValue matches RFC 7636's code-verifier/challenge alphabet at the
// fixed length Claude Code uses for both its state and its code_challenge:
// unreserved base64url characters, 43 of them — the length a 256-bit value
// produces once base64url-encoded with no padding.
func isPKCEValue(s string) bool {
	if len(s) != 43 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// checkAuthorizeBytes enforces the length and byte-range rule a URL's own
// grammar (RFC 3986) never needs to break: at most 2048 bytes, and every byte
// printable ASCII other than space, since a raw space, control character or
// non-ASCII byte belonging IN a URL always has a percent-escape instead.
func checkAuthorizeBytes(line string) error {
	if line == "" {
		return fmt.Errorf("empty line")
	}
	if len(line) > 2048 {
		return fmt.Errorf("line is %d bytes, more than the 2048 an authorize URL needs", len(line))
	}
	for i := 0; i < len(line); i++ {
		if b := line[i]; b < 0x21 || b > 0x7e {
			return fmt.Errorf("byte 0x%02x at offset %d is outside the printable-ASCII range "+
				"0x21-0x7e a URL's own grammar keeps to", b, i)
		}
	}
	return nil
}
