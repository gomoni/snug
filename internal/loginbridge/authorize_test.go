package loginbridge

import (
	"strings"
	"testing"
)

// measuredURL is the URL Claude Code 2.1.283 handed to $BROWSER inside
// `snug -p @claude -p @net`, captured verbatim by a logging shim (issue #455).
// The flow it began was never completed; its code_verifier died with that
// sandbox, so the challenge and state below authorise nothing.
const measuredURL = "https://claude.com/cai/oauth/authorize?code=true&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e" +
	"&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A46423%2Fcallback" +
	"&scope=org%3Acreate_api_key+user%3Aprofile+user%3Ainference+user%3Asessions%3Aclaude_code" +
	"+user%3Amcp_servers+user%3Afile_upload+user%3Aplugins" +
	"&code_challenge=fD5xTDCwgf63U088pqhV0TFHbLf0emkJPI844Pfplvs" +
	"&code_challenge_method=S256&state=qUcPYbXlvfwBNYqnh52qhKs7Ac_7GNRvan-h3ihmgk8"

func TestTheMeasuredURLRebuildsByteForByte(t *testing.T) {
	flow, err := ParseAuthorize(measuredURL)
	if err != nil {
		t.Fatalf("ParseAuthorize(measuredURL) = _, %v, want no error", err)
	}
	if flow.Port != 46423 {
		t.Errorf("flow.Port = %d, want 46423", flow.Port)
	}
	got := flow.AuthorizeURL()
	if got != measuredURL {
		t.Errorf("AuthorizeURL() did not round-trip:\n got  %s\n want %s", got, measuredURL)
	}
}

// splitQuery divides a "prefix?a=1&b=2" URL into its query-less prefix
// (including the "?") and its query pairs.
func splitQuery(url string) (prefix string, pairs []string) {
	i := strings.IndexByte(url, '?')
	if i < 0 {
		panic("splitQuery: no \"?\" in " + url)
	}
	return url[:i+1], strings.Split(url[i+1:], "&")
}

// withParam replaces the value of an existing "key=value" pair in the
// measured URL, so every refusal case starts from a URL that is otherwise
// known-good.
func withParam(url, key, newValue string) string {
	prefix, pairs := splitQuery(url)
	for i, pair := range pairs {
		if k, _, ok := strings.Cut(pair, "="); ok && k == key {
			pairs[i] = key + "=" + newValue
			return prefix + strings.Join(pairs, "&")
		}
	}
	panic("withParam: " + key + " not found in " + url)
}

// withoutParam removes an existing "key=value" pair from the measured URL.
func withoutParam(url, key string) string {
	prefix, pairs := splitQuery(url)
	for i, pair := range pairs {
		if k, _, ok := strings.Cut(pair, "="); ok && k == key {
			pairs = append(pairs[:i], pairs[i+1:]...)
			return prefix + strings.Join(pairs, "&")
		}
	}
	panic("withoutParam: " + key + " not found in " + url)
}

func TestAuthorizeRefusals(t *testing.T) {
	challenge43 := "fD5x0123456789ABCDEFGHIJKLMNOPQRSTUVWXYplvs"
	state43 := "qUcP0123456789ABCDEFGHIJKLMNOPQRSTUVWXYmgk8"

	tests := []struct {
		name   string
		line   string
		reason string // substring the error must contain
	}{
		{"http scheme", "http" + measuredURL[5:], "not the Claude login URL"},
		{"uppercase host", strings.Replace(measuredURL, "claude.com", "Claude.com", 1), "not the Claude login URL"},
		{"trailing dot", strings.Replace(measuredURL, "claude.com/", "claude.com./", 1), "not the Claude login URL"},
		{"port in host", strings.Replace(measuredURL, "claude.com/", "claude.com:443/", 1), "not the Claude login URL"},
		{"userinfo", strings.Replace(measuredURL, "https://", "https://u@", 1), "not the Claude login URL"},
		{"extra path segment", strings.Replace(measuredURL, "/authorize?", "/authorize/?", 1), "not the Claude login URL"},
		{"fragment", measuredURL + "#frag", "fragment"},
		{"console host", "https://platform.claude.com/oauth/authorize?" + measuredURL[len(authorizePrefix):],
			"console login"},

		{"login_hint", measuredURL + "&login_hint=x", "not one snug pins"},
		{"orgUUID", measuredURL + "&orgUUID=x", "not one snug pins"},
		{"login_method", measuredURL + "&login_method=x", "not one snug pins"},
		{"unknown key x", measuredURL + "&x=1", "not one snug pins"},
		{"state twice", measuredURL + "&state=" + state43, "appears twice"},
		{"code missing", withoutParam(measuredURL, "code"), "\"code\" is missing"},
		{"client_id missing", withoutParam(measuredURL, "client_id"), "\"client_id\" is missing"},
		{"response_type missing", withoutParam(measuredURL, "response_type"), "\"response_type\" is missing"},
		{"redirect_uri missing", withoutParam(measuredURL, "redirect_uri"), "\"redirect_uri\" is missing"},
		{"scope missing", withoutParam(measuredURL, "scope"), "\"scope\" is missing"},
		{"code_challenge missing", withoutParam(measuredURL, "code_challenge"), "\"code_challenge\" is missing"},
		{"code_challenge_method missing", withoutParam(measuredURL, "code_challenge_method"), "\"code_challenge_method\" is missing"},
		{"state missing", withoutParam(measuredURL, "state"), "\"state\" is missing"},

		{"other client_id", withParam(measuredURL, "client_id", "00000000-0000-0000-0000-000000000000"),
			"client_id"},
		{"response_type token", withParam(measuredURL, "response_type", "token"), "response_type"},
		{"code_challenge_method plain", withParam(measuredURL, "code_challenge_method", "plain"),
			"code_challenge_method"},

		{"challenge 42 chars", withParam(measuredURL, "code_challenge", challenge43[:42]), "code_challenge"},
		{"challenge 44 chars", withParam(measuredURL, "code_challenge", challenge43+"x"), "code_challenge"},
		{"challenge with plus", withParam(measuredURL, "code_challenge", "+"+challenge43[1:]), "code_challenge"},
		{"challenge with equals", withParam(measuredURL, "code_challenge", "="+challenge43[1:]), "code_challenge"},
		{"state 42 chars", withParam(measuredURL, "state", state43[:42]), "\"state\""},
		{"state 44 chars", withParam(measuredURL, "state", state43+"x"), "\"state\""},
		{"state with plus", withParam(measuredURL, "state", "+"+state43[1:]), "\"state\""},
		// A raw "=" in state's value gives the segment a second "=", so the query-grammar
		// check (one "=" per pair) refuses it before state's own charset check ever runs.
		{"state with equals", withParam(measuredURL, "state", "="+state43[1:]), "more than one"},

		{"scope minus one", withParam(measuredURL, "scope", strings.Join(scopeTokens[1:], "+")),
			"scope set differs"},
		{"scope plus one", withParam(measuredURL, "scope", strings.Join(scopeTokens, "+")+"+user%3Aadmin"),
			"scope set differs"},
		{"scope duplicate", withParam(measuredURL, "scope", strings.Join(scopeTokens, "+")+"+"+scopeTokens[0]),
			"repeats"},
		{"scope raw colon", withParam(measuredURL, "scope",
			"org:create_api_key+"+strings.Join(scopeTokens[1:], "+")), "scope set differs"},
		{"scope lowercase escape", withParam(measuredURL, "scope",
			"org%3acreate_api_key+"+strings.Join(scopeTokens[1:], "+")), "scope set differs"},

		{"redirect_uri 127.0.0.1", withParam(measuredURL, "redirect_uri",
			"http%3A%2F%2F127.0.0.1%3A46423%2Fcallback"), "redirect_uri"},
		{"redirect_uri evil host", withParam(measuredURL, "redirect_uri",
			"http%3A%2F%2Flocalhost.evil.com%3A46423%2Fcallback"), "redirect_uri"},
		{"redirect_uri https", withParam(measuredURL, "redirect_uri",
			"https%3A%2F%2Flocalhost%3A46423%2Fcallback"), "redirect_uri"},
		{"redirect_uri extra path", withParam(measuredURL, "redirect_uri",
			"http%3A%2F%2Flocalhost%3A46423%2Fcallbackx"), "redirect_uri"},
		{"redirect_uri double escape", withParam(measuredURL, "redirect_uri",
			"http%253A%252F%252Flocalhost%253A46423%252Fcallback"), "redirect_uri"},
		{"port 80", withParam(measuredURL, "redirect_uri", "http%3A%2F%2Flocalhost%3A80%2Fcallback"),
			"redirect_uri"},
		{"port 32767", withParam(measuredURL, "redirect_uri", "http%3A%2F%2Flocalhost%3A32767%2Fcallback"),
			"outside"},
		{"port 61000", withParam(measuredURL, "redirect_uri", "http%3A%2F%2Flocalhost%3A61000%2Fcallback"),
			"outside"},
		{"port leading zero", withParam(measuredURL, "redirect_uri", "http%3A%2F%2Flocalhost%3A065535%2Fcallback"),
			"redirect_uri"},

		{"2049 bytes", measuredURL + strings.Repeat("x", 2049-len(measuredURL)), "2048"},
		{"NUL", measuredURL + "\x00", "0x00"},
		{"space", measuredURL + " ", "0x20"},
		{"TAB", measuredURL + "\t", "0x09"},
		{"CR", measuredURL + "\r", "0x0d"},
		{"LF", measuredURL + "\n", "0x0a"},
		{"DEL", measuredURL + "\x7f", "0x7f"},
		{"non-ASCII", measuredURL + "é", "outside the printable-ASCII"},

		{"semicolon separator", measuredURL + ";evil", "\"state\""}, // ';' is not "&"; it lands in state's own value
		{"double ampersand", measuredURL + "&&x=1", "empty parameter"},
		{"trailing ampersand", measuredURL + "&", "empty parameter"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAuthorize(tt.line)
			if err == nil {
				t.Fatalf("ParseAuthorize(%q) = nil error, want one containing %q", tt.line, tt.reason)
			}
			if !strings.Contains(err.Error(), tt.reason) {
				t.Errorf("ParseAuthorize error = %q, want it to contain %q", err.Error(), tt.reason)
			}
		})
	}
}

func TestParseAuthorizeEmptyLine(t *testing.T) {
	if _, err := ParseAuthorize(""); err == nil {
		t.Fatal("ParseAuthorize(\"\") = nil error, want one")
	}
}
