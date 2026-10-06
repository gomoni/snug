package loginbridge

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// forgingIn returns the first rune of s that could author, erase or reverse a
// line on a terminal or in a review UI. It is written out here rather than
// asked of policy.IsForgingRune, so a widening or narrowing of that predicate
// cannot quietly move the goalposts of the tests that check its callers. nlOK
// lets a multi-line stderr through its own line breaks.
func forgingIn(s string, nlOK bool) (rune, bool) {
	if !utf8.ValidString(s) {
		return utf8.RuneError, true
	}
	for _, r := range s {
		switch {
		case r == '\n' && nlOK:
		case unicode.IsControl(r), r == ' ', r == ' ',
			r >= '‪' && r <= '‮', r >= '⁦' && r <= '⁩':
			return r, true
		}
	}
	return 0, false
}

// TestAuthorizeRefusesHostileSpellings fails if any spelling of "the Claude
// login URL" that is not byte-for-byte the pinned prefix and a value set of
// the pinned shapes reaches a Flow, which is what the opener's rebuilt URL is
// built from. The hosts are the confusables an eye or a URL parser would
// accept (userinfo, backslash, IDN, punycode, a second URL in the query); the
// suffix loop appends each hostile tail to every parameter's value in turn, so
// a value check that exists for seven parameters and not the eighth fails
// here.
//
// Controls: measuredURL itself parses, and every refusal is an error whose
// text carries no raw forging rune. It does not show a real Claude Code
// never emits one of these; only that snug would not open it.
func TestAuthorizeRefusesHostileSpellings(t *testing.T) {
	if _, err := ParseAuthorize(measuredURL); err != nil {
		t.Fatalf("control: the measured URL is refused: %v", err)
	}
	rest := measuredURL[len(authorizePrefix):]

	prefixes := map[string]string{
		"userinfo claude.com@other":       "https://claude.com@evil.example/cai/oauth/authorize?",
		"backslash before at":             "https://evil.example\\@claude.com/cai/oauth/authorize?",
		"backslash after host":            "https://claude.com\\@evil.example/cai/oauth/authorize?",
		"escaped slash then userinfo":     "https://claude.com%2f@evil.example/cai/oauth/authorize?",
		"NUL escape in host":              "https://claude.com%00.evil.example/cai/oauth/authorize?",
		"NUL escape before query":         "https://claude.com/cai/oauth/authorize%00?",
		"backslash paths":                 "https://claude.com\\cai\\oauth\\authorize?",
		"one backslash in path":           "https://claude.com/cai\\oauth/authorize?",
		"percent in path":                 "https://claude.com/%63ai/oauth/authorize?",
		"dot-dot in path":                 "https://claude.com/cai/oauth/../oauth/authorize?",
		"doubled slash":                   "https://claude.com//cai/oauth/authorize?",
		"subdomain of evil":               "https://claude.com.evil.example/cai/oauth/authorize?",
		"suffix host":                     "https://evilclaude.com/cai/oauth/authorize?",
		"punycode host":                   "https://xn--claude-9ya.com/cai/oauth/authorize?",
		"punycode TLD":                    "https://claude.xn--com-9o0a/cai/oauth/authorize?",
		"cyrillic a in host":              "https://clаude.com/cai/oauth/authorize?",
		"one dot leader":                  "https://claude․com/cai/oauth/authorize?",
		"ideographic full stop":           "https://claude。com/cai/oauth/authorize?",
		"fullwidth dot":                   "https://claude．com/cai/oauth/authorize?",
		"RLO in host":                     "https://claude.com‮/cai/oauth/authorize?",
		"zero width space in host":        "https://cl​aude.com/cai/oauth/authorize?",
		"uppercase scheme":                "HTTPS://claude.com/cai/oauth/authorize?",
		"one slash":                       "https:/claude.com/cai/oauth/authorize?",
		"backslash scheme separator":      "https:\\\\claude.com/cai/oauth/authorize?",
		"leading space":                   " https://claude.com/cai/oauth/authorize?",
		"leading tab":                     "\thttps://claude.com/cai/oauth/authorize?",
		"second URL smuggled in a query":  "https://evil.example/?u=https://claude.com/cai/oauth/authorize?",
		"javascript scheme":               "javascript:alert(1)//https://claude.com/cai/oauth/authorize?",
		"file scheme":                     "file:///etc/passwd?",
		"option-looking line":             "--help?",
		"bare host":                       "claude.com/cai/oauth/authorize?",
		"authorize without query marker":  "https://claude.com/cai/oauth/authorize",
		"percent-encoded query separator": "https://claude.com/cai/oauth/authorize%3F",
	}
	for name, p := range prefixes {
		line := p + rest
		t.Run("prefix/"+name, func(t *testing.T) {
			f, err := ParseAuthorize(line)
			if err == nil {
				t.Fatalf("ParseAuthorize(%q) accepted it as %+v", line, f)
			}
			if f != (Flow{}) {
				t.Errorf("a refusal still returned a Flow: %+v", f)
			}
			if r, bad := forgingIn(err.Error(), false); bad {
				t.Errorf("the refusal carries a raw forging rune %U: %q", r, err.Error())
			}
		})
	}

	suffixes := map[string]string{
		"NUL escape":          "%00",
		"bare percent":        "%",
		"truncated escape":    "%2",
		"non-hex escape":      "%zz",
		"overlong utf-8":      "%c0%af",
		"double encoded":      "%25",
		"backslash":           "\\",
		"raw NUL":             "\x00",
		"CRLF escape":         "%0d%0a",
		"RLO":                 "‮",
		"non-ascii":           "é",
		"userinfo-looking":    "@evil.example",
		"fragment":            "#",
		"another query":       "?x=1",
		"trailing ampersand":  "&",
		"unicode escape":      "%u0041",
		"raw newline + text":  "\nhttps://evil.example/",
		"raw CRLF + text":     "\r\nGET / HTTP/1.1",
		"semicolon parameter": ";x=1",
	}
	for key := range authorizeKeys {
		_, pairs := splitQuery(measuredURL)
		var value string
		for _, p := range pairs {
			if k, v, ok := strings.Cut(p, "="); ok && k == key {
				value = v
			}
		}
		if value == "" {
			t.Fatalf("control: the measured URL has no %q value to mutate", key)
		}
		for sname, s := range suffixes {
			line := withParam(measuredURL, key, value+s)
			t.Run("value/"+key+"/"+sname, func(t *testing.T) {
				if f, err := ParseAuthorize(line); err == nil {
					t.Fatalf("ParseAuthorize(%q) accepted it as %+v", line, f)
				} else if r, bad := forgingIn(err.Error(), false); bad {
					t.Errorf("the refusal carries a raw forging rune %U: %q", r, err.Error())
				}
			})
		}
	}

	// ParseAuthorize takes ONE line: the reader splits on newlines before
	// calling it, so a joined string reaching it is itself the attack.
	for name, line := range map[string]string{
		"valid then newline then text":  measuredURL + "\nmore text",
		"valid then newline then valid": measuredURL + "\n" + measuredURL,
		"valid then CRLF":               measuredURL + "\r\n",
		"valid then NUL then text":      measuredURL + "\x00https://evil.example/",
	} {
		if _, err := ParseAuthorize(line); err == nil {
			t.Errorf("%s: ParseAuthorize accepted a line with an embedded line break or NUL", name)
		}
	}
}
