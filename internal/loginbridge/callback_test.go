package loginbridge

import (
	"strings"
	"testing"
)

const testState = "qUcP0123456789ABCDEFGHIJKLMNOPQRSTUVWXYmgk8"

func TestParseCallbackAccepts(t *testing.T) {
	cb, err := ParseCallback("GET", "/callback?code=abc.123-_~&state="+testState, testState)
	if err != nil {
		t.Fatalf("ParseCallback = _, %v, want no error", err)
	}
	if cb.Code != "abc.123-_~" {
		t.Errorf("cb.Code = %q, want %q", cb.Code, "abc.123-_~")
	}
}

func TestParseCallbackAcceptsPercentEscapedCode(t *testing.T) {
	cb, err := ParseCallback("GET", "/callback?code=a%2Fb%3D&state="+testState, testState)
	if err != nil {
		t.Fatalf("ParseCallback = _, %v, want no error", err)
	}
	if cb.Code != "a%2Fb%3D" {
		t.Errorf("cb.Code = %q, want the raw, still-encoded value", cb.Code)
	}
}

func TestCallbackRefusals(t *testing.T) {
	good := "/callback?code=abcXYZ019&state=" + testState

	tests := []struct {
		name   string
		method string
		target string
		state  string
		reason string
	}{
		{"POST", "POST", good, testState, "want GET"},
		{"HEAD", "HEAD", good, testState, "want GET"},
		{"HTTP/2 preface", "PRI", "*", testState, "want GET"},
		{"trailing slash", "GET", "/callback/?code=abcXYZ019&state=" + testState, testState, "\"/callback\""},
		{"wrong case", "GET", "/Callback?code=abcXYZ019&state=" + testState, testState, "\"/callback\""},
		{"absolute-form target", "GET", "http://localhost/callback?code=abcXYZ019&state=" + testState,
			testState, "origin-form"},
		{"extra key iss", "GET", good + "&iss=https://claude.com", testState, "not one snug relays"},
		{"every unknown key and the whole set are named", "GET", good + "&iss=x&session_state=y", testState,
			`parameter "iss", "session_state" is not one snug relays (the callback's keys: "code", "state", "iss", "session_state")`},
		{"missing code", "GET", "/callback?state=" + testState, testState, "\"code\" is missing"},
		{"missing state", "GET", "/callback?code=abcXYZ019", testState, "\"state\" is missing"},
		{"duplicate code", "GET", good + "&code=def", testState, "appears twice"},
		{"state off by one byte", "GET", good, testState[:len(testState)-1] + "Z", "does not match"},
		{"state prefix", "GET", good, testState[:len(testState)-1], "does not match"},
		{"empty code", "GET", "/callback?code=&state=" + testState, testState, "\"code\""},
		{"code with space", "GET", "/callback?code=a b&state=" + testState, testState, "\"code\""},
		{"code with CR", "GET", "/callback?code=a\rb&state=" + testState, testState, "\"code\""},
		{"code with LF", "GET", "/callback?code=a\nb&state=" + testState, testState, "\"code\""},
		{"code truncated escape", "GET", "/callback?code=a%2&state=" + testState, testState, "\"code\""},
		{"code non-hex escape", "GET", "/callback?code=a%zz&state=" + testState, testState, "\"code\""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCallback(tt.method, tt.target, tt.state)
			if err == nil {
				t.Fatalf("ParseCallback(%q, %q, _) = nil error, want one containing %q",
					tt.method, tt.target, tt.reason)
			}
			if !strings.Contains(err.Error(), tt.reason) {
				t.Errorf("ParseCallback error = %q, want it to contain %q", err.Error(), tt.reason)
			}
		})
	}
}

func TestParseCallbackCodeLengthBounds(t *testing.T) {
	t.Run("1023 chars ok", func(t *testing.T) {
		code := strings.Repeat("a", 1023)
		if _, err := ParseCallback("GET", "/callback?code="+code+"&state="+testState, testState); err != nil {
			t.Errorf("ParseCallback = _, %v, want no error at 1023 bytes", err)
		}
	})
	t.Run("1025 chars refused", func(t *testing.T) {
		code := strings.Repeat("a", 1025)
		_, err := ParseCallback("GET", "/callback?code="+code+"&state="+testState, testState)
		if err == nil || !strings.Contains(err.Error(), "\"code\"") {
			t.Errorf("ParseCallback error = %v, want a \"code\" refusal", err)
		}
	})
}
