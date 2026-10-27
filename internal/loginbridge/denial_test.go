package loginbridge

import (
	"strconv"
	"strings"
	"testing"
)

func denialReq(port int, query string) string {
	return "GET /callback?" + query + " HTTP/1.1\r\nHost: localhost:" + strconv.Itoa(port) + "\r\n\r\n"
}

// TestADeniedSignInEndsTheClientsWait fails if a callback saying the human
// declined, carrying this flow's state, is answered 404 and left to wait out
// FlowTTL — the client's own /login hanging with it. It must spend one relay
// on snug's constant access_denied callback with the client's state, answer
// the browser with snug's page, and end the flow.
func TestADeniedSignInEndsTheClientsWait(t *testing.T) {
	for _, q := range []string{
		"error=access_denied&state=" + testState,
		"error=access_denied&error_description=The+user+denied+access&state=" + testState,
		"state=" + testState + "&error_uri=https%3A%2F%2Fx&error=access_denied",
	} {
		r := newRig(t)
		f := r.openFlow(t)
		resp := browse(t, f.Port, denialReq(f.Port, q))
		if !strings.HasPrefix(resp, "HTTP/1.1 200 ") || !strings.Contains(resp, "You declined the Claude sign-in") {
			t.Fatalf("%s: browser answer:\n%s", q, resp)
		}
		got := r.sandbox.requests()
		want := string(RelayErrorRequest(f.Port, "access_denied", deniedText, testState))
		if len(got) != 1 || string(got[0]) != want {
			t.Fatalf("%s: relayed %q, want exactly %q", q, got, want)
		}
		if strings.Contains(string(got[0]), "code=") || strings.Contains(string(got[0]), "denied+access") {
			t.Errorf("%s: the relay carries the browser's bytes: %q", q, got[0])
		}
		if !refuses(f.Port) {
			t.Errorf("%s: the flow is still listening after the denial", q)
		}
		if !strings.Contains(r.stderr.String(), "the sign-in was declined in the browser") {
			t.Errorf("%s: stderr: %s", q, r.stderr.String())
		}
	}
}

// TestADenialIsCheckedLikeACallback: a denial with another state, another
// error, an extra key or a code is answered 404 and the flow survives —
// the control at the end is the real callback relaying afterwards.
func TestADenialIsCheckedLikeACallback(t *testing.T) {
	r := newRig(t)
	f := r.openFlow(t)
	for _, q := range []string{
		"error=access_denied&state=" + testState[:42] + "X",
		"error=access_denied",
		"error=server_error&state=" + testState,
		"error=Access_Denied&state=" + testState,
		"error=access_denied&state=" + testState + "&iss=https%3A%2F%2Fclaude.com",
		"error=access_denied&code=x&state=" + testState,
		"error=access_denied&error=access_denied&state=" + testState,
	} {
		if resp := browse(t, f.Port, denialReq(f.Port, q)); !strings.HasPrefix(resp, "HTTP/1.1 404 ") {
			t.Errorf("%s: want a 404, got %s", q, firstLineOf(resp))
		}
	}
	if n := len(r.sandbox.requests()); n != 0 {
		t.Fatalf("%d refused denial(s) were relayed: %q", n, r.sandbox.requests())
	}
	if resp := sendCallback(t, f); !strings.Contains(resp, "answered HTTP 200") {
		t.Fatalf("control: the flow did not survive the refused denials: %s", resp)
	}
}

// TestTheErrorRelayIsOneEncodedQueryValue pins RelayErrorRequest's escaping:
// every byte of the description outside RFC 3986's unreserved set becomes a
// %XX, so a constant with a space, an apostrophe or a semicolon stays one
// query value and the request stays four CRLFs.
func TestTheErrorRelayIsOneEncodedQueryValue(t *testing.T) {
	got := string(RelayErrorRequest(40123, "e", "a b'c;d&e=f\r\nX: y", testState))
	want := "GET /callback?error=e&error_description=a%20b%27c%3Bd%26e%3Df%0D%0AX%3A%20y&state=" + testState +
		" HTTP/1.1\r\nHost: localhost:40123\r\nConnection: close\r\n\r\n"
	if got != want {
		t.Errorf("RelayErrorRequest:\n got %q\nwant %q", got, want)
	}
}
