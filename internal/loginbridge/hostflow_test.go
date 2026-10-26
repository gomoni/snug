package loginbridge

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// fakeVendor is the token and profile endpoints, as a Doer.
type fakeVendor struct {
	mu        sync.Mutex
	tokenCode int
	tokenBody string
	tokenErr  error
	profCode  int
	profBody  string
	// block, when set, holds the token request until it is closed or the
	// request's context ends.
	block    chan struct{}
	requests []*http.Request
	bodies   [][]byte
}

func newVendor() *fakeVendor {
	return &fakeVendor{
		tokenCode: 200,
		tokenBody: `{"token_type":"Bearer","access_token":"sk-ant-oat-NEW","refresh_token":"sk-ant-ort-NEW",` +
			`"expires_in":28800,"scope":"user:inference user:profile",` +
			`"account":{"uuid":"acc-1","email_address":"a@example.com"},"organization":{"uuid":"org-1"}}`,
		profCode: 200,
		profBody: `{"account":{"uuid":"acc-1","email":"a@example.com"},"organization":{"uuid":"org-1",` +
			`"organization_type":"claude_max","rate_limit_tier":"default_claude_max_5x"}}`,
	}
}

func (v *fakeVendor) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	v.mu.Lock()
	v.requests = append(v.requests, req)
	v.bodies = append(v.bodies, body)
	block := v.block
	v.mu.Unlock()
	answer := func(code int, b string, h http.Header) (*http.Response, error) {
		if h == nil {
			h = http.Header{}
		}
		return &http.Response{StatusCode: code, Header: h, Body: io.NopCloser(strings.NewReader(b))}, nil
	}
	switch req.URL.String() {
	case tokenURL:
		if block != nil {
			select {
			case <-block:
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}
		if v.tokenErr != nil {
			return nil, v.tokenErr
		}
		return answer(v.tokenCode, v.tokenBody, nil)
	case profileURL:
		return answer(v.profCode, v.profBody, http.Header{"Request-Id": {"req_011CUVabc"}})
	}
	return nil, errors.New("fakeVendor: unexpected URL " + req.URL.String())
}

func (v *fakeVendor) calls() ([]*http.Request, [][]byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]*http.Request(nil), v.requests...), append([][]byte(nil), v.bodies...)
}

// fakeFiles is the host-file half.
type fakeFiles struct {
	mu       sync.Mutex
	snap     HostSnapshot
	writeErr error
	renewed  []policy.ClaudeLoginResult
	keepPlan []bool
	written  []policy.ClaudeLoginResult
}

func (f *fakeFiles) Snapshot() HostSnapshot { return f.snap }

func (f *fakeFiles) RenewSandbox(_ context.Context, r policy.ClaudeLoginResult, _ time.Time, keep bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renewed = append(f.renewed, r)
	f.keepPlan = append(f.keepPlan, keep)
	return nil
}

func (f *fakeFiles) WriteHost(_ context.Context, _ HostSnapshot, r policy.ClaudeLoginResult, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return f.writeErr
	}
	f.written = append(f.written, r)
	return nil
}

func (f *fakeFiles) counts() (renewed, written int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.renewed), len(f.written)
}

func hostRig(t *testing.T) (*rig, *fakeVendor, *fakeFiles) {
	t.Helper()
	r := newRig(t)
	v := newVendor()
	files := &fakeFiles{snap: HostSnapshot{
		Pin:  AccountPin{AccountUUID: "acc-1", OrganizationUUID: "org-1", Email: "a@example.com"},
		File: CredentialFile{Exists: true, AccessToken: policy.Secret("old"), RefreshToken: policy.Secret("old-r")},
	}}
	r.b.d.Host = &HostLogin{Doer: v, Files: files}
	return r, v, files
}

var urlParam = func(u, k string) string {
	m := regexp.MustCompile(`[?&]` + k + `=([^&]*)`).FindStringSubmatch(u)
	if m == nil {
		return ""
	}
	return m[1]
}

// openHostFlow opens a host-mode flow and returns it with the URL snug
// opened.
func openHostFlow(t *testing.T, r *rig) (Flow, string) {
	t.Helper()
	f := r.openFlow(t)
	waitFor(t, func() bool { return len(r.opener.opened()) == 1 })
	return f, r.opener.opened()[0]
}

func hostCallback(t *testing.T, f Flow, opened, code string) string {
	t.Helper()
	return patientBrowse(t, f.Port, "GET /callback?code="+code+"&state="+urlParam(opened, "state")+
		" HTTP/1.1\r\nHost: localhost:"+itoa(f.Port)+"\r\n\r\n")
}

// TestHostModeExchangesWithItsOwnVerifier fails if the URL snug opens in host
// mode carries the sandbox's challenge or state, or if the exchange is not
// exactly Claude Code's: a JSON body with grant_type, code, redirect_uri,
// client_id, code_verifier and state, the verifier hashing to the URL's
// challenge, the DECODED code, and the URL's own state.
func TestHostModeExchangesWithItsOwnVerifier(t *testing.T) {
	r, v, files := hostRig(t)
	f, opened := openHostFlow(t, r)
	if c := urlParam(opened, "code_challenge"); c == f.CodeChallenge || !isPKCEValue(c) {
		t.Fatalf("the opened URL's challenge %q is the sandbox's or not PKCE-shaped", c)
	}
	if s := urlParam(opened, "state"); s == f.State || !isPKCEValue(s) {
		t.Fatalf("the opened URL's state %q is the sandbox's or not PKCE-shaped", s)
	}
	if _, err := ParseAuthorize(opened); err != nil {
		t.Fatalf("snug opened a URL its own predicate refuses: %v", err)
	}
	resp := hostCallback(t, f, opened, "AbC-12.3_x~%2Fq")
	if !strings.Contains(resp, "snug completed your Claude login on the host as a@example.com") {
		t.Fatalf("browser answer:\n%s", resp)
	}
	reqs, bodies := v.calls()
	if len(reqs) != 2 || reqs[0].URL.String() != tokenURL || reqs[0].Method != "POST" ||
		reqs[0].Header.Get("Content-Type") != "application/json" || reqs[0].Header.Get("User-Agent") != "snug" {
		t.Fatalf("token request: %+v", reqs)
	}
	var keys []string
	var body map[string]string
	if err := json.Unmarshal(bodies[0], &body); err != nil {
		t.Fatalf("token body is not a JSON object of strings: %v\n%s", err, bodies[0])
	}
	for k := range body {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if want := []string{"client_id", "code", "code_verifier", "grant_type", "redirect_uri", "state"}; !slices.Equal(keys, want) {
		t.Errorf("token body keys %v, want %v", keys, want)
	}
	sum := sha256.Sum256([]byte(body["code_verifier"]))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != urlParam(opened, "code_challenge") {
		t.Error("the verifier sent does not hash to the challenge snug opened")
	}
	for k, want := range map[string]string{
		"grant_type": "authorization_code", "code": "AbC-12.3_x~/q", "client_id": clientID,
		"redirect_uri": "http://localhost:" + itoa(f.Port) + "/callback", "state": urlParam(opened, "state"),
	} {
		if body[k] != want {
			t.Errorf("token body %s = %q, want %q", k, body[k], want)
		}
	}
	if reqs[1].URL.String() != profileURL || reqs[1].Header.Get("Authorization") != "Bearer sk-ant-oat-NEW" {
		t.Errorf("profile request: %s %v", reqs[1].URL, reqs[1].Header)
	}
	renewed, written := files.counts()
	if renewed != 1 || written != 1 {
		t.Fatalf("renewed %d, written %d; want 1 and 1", renewed, written)
	}
	got := files.written[0]
	if string(got.AccessToken) != "sk-ant-oat-NEW" || string(got.RefreshToken) != "sk-ant-ort-NEW" ||
		got.ExpiresIn != 8*time.Hour || got.OrganizationType != "claude_max" || got.RequestID != "req_011CUVabc" {
		t.Errorf("result handed to the host write: %+v", got)
	}
	if !files.keepPlan[0] {
		t.Error("the same account's renewal did not keep the sandbox's plan fields")
	}
}

// TestHostModeEndsTheClientsWaitWithAnErrorCallbackCarryingNoCode: the one
// relay is snug's constant error callback with the CLIENT's state, never a
// code, and the browser page carries no token.
func TestHostModeEndsTheClientsWaitWithAnErrorCallbackCarryingNoCode(t *testing.T) {
	r, _, _ := hostRig(t)
	f, opened := openHostFlow(t, r)
	resp := hostCallback(t, f, opened, "THE-CODE")
	got := r.sandbox.requests()
	if len(got) != 1 {
		t.Fatalf("relays %q, want exactly one", got)
	}
	want := string(RelayErrorRequest(f.Port, completedError, completedText, f.State))
	if string(got[0]) != want {
		t.Errorf("relayed %q, want %q", got[0], want)
	}
	const wire = "error=snug_completed_login&error_description=snug%20completed%20this%20sign-in%20on%20the%20host" +
		"%20and%20renewed%20this%20sandbox%27s%20token%3B%20press%20Esc&state="
	if !strings.Contains(string(got[0]), wire+f.State+" ") {
		t.Errorf("the relay's query is not the designed one:\n%q", got[0])
	}
	for _, bad := range []string{"code=", "THE-CODE", urlParam(opened, "state")} {
		if strings.Contains(string(got[0]), bad) {
			t.Errorf("the relay carries %q: %q", bad, got[0])
		}
	}
	for _, bad := range []string{"sk-ant", "THE-CODE"} {
		if strings.Contains(resp, bad) || strings.Contains(r.stderr.String(), bad) {
			t.Errorf("a token or the code reached the browser or stderr (%q)", bad)
		}
	}
	if len(completedText) > 200 {
		t.Errorf("the description is %d bytes; the client keeps 200", len(completedText))
	}
}

// TestHostModeNeverRelaysACode holds every failure arm: a refused answer, an
// unreachable token endpoint, and Close in the middle of the exchange. None
// writes anything, none relays a code, and Close leaves nothing running.
func TestHostModeNeverRelaysACode(t *testing.T) {
	t.Run("a refused answer", func(t *testing.T) {
		r, v, files := hostRig(t)
		v.tokenBody = `{"access_token":"sk-ant-oat-NEW","expires_in":28800,"scope":"user:profile"}`
		f, opened := openHostFlow(t, r)
		resp := hostCallback(t, f, opened, "C")
		assertNothingWritten(t, r, files, f, resp, "no user:inference scope")
	})
	t.Run("an unreachable token endpoint", func(t *testing.T) {
		r, v, files := hostRig(t)
		v.tokenErr = errors.New("dial tcp: lookup platform.claude.com: no such host")
		f, opened := openHostFlow(t, r)
		resp := hostCallback(t, f, opened, "C")
		assertNothingWritten(t, r, files, f, resp, "could not be reached")
	})
	t.Run("Close mid-exchange", func(t *testing.T) {
		r, v, files := hostRig(t)
		v.block = make(chan struct{})
		f, opened := openHostFlow(t, r)
		done := make(chan string)
		go func() { done <- hostCallback(t, f, opened, "C") }()
		waitFor(t, func() bool { reqs, _ := v.calls(); return len(reqs) == 1 })
		closed := make(chan struct{})
		go func() { r.b.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatal("Close did not return while the exchange was in flight")
		}
		<-done
		if renewed, written := files.counts(); renewed != 0 || written != 0 {
			t.Errorf("after Close mid-exchange: renewed %d, written %d", renewed, written)
		}
		if n := len(r.sandbox.requests()); n != 0 {
			t.Errorf("Close mid-exchange relayed %d request(s): %q", n, r.sandbox.requests())
		}
	})
}

func assertNothingWritten(t *testing.T, r *rig, files *fakeFiles, f Flow, resp, why string) {
	t.Helper()
	if renewed, written := files.counts(); renewed != 0 || written != 0 {
		t.Errorf("renewed %d, written %d; want nothing", renewed, written)
	}
	got := r.sandbox.requests()
	want := string(RelayErrorRequest(f.Port, failedError, failedText, f.State))
	if len(got) != 1 || string(got[0]) != want {
		t.Errorf("relayed %q, want exactly the failure callback %q", got, want)
	}
	if !strings.HasPrefix(resp, "HTTP/1.1 502 ") || !strings.Contains(resp, why) {
		t.Errorf("browser answer does not give the reason %q:\n%s", why, resp)
	}
	if !strings.Contains(r.stderr.String(), why) || !strings.Contains(r.stderr.String(), "do NOT paste a code") {
		t.Errorf("stderr: %s", r.stderr.String())
	}
}

// TestHostModeARefusedResponseShape: each answer that is no login refuses
// the whole flow, naming why.
func TestHostModeARefusedResponseShape(t *testing.T) {
	for body, why := range map[string]string{
		`[]`:   "not a JSON object",
		`nope`: "not a JSON object",
		`{"expires_in":28800,"scope":"user:inference"}`:                                                "no access_token",
		`{"access_token":"","expires_in":28800,"scope":"user:inference"}`:                              "no access_token",
		`{"access_token":"` + strings.Repeat("a", 8193) + `","expires_in":1,"scope":"user:inference"}`: "no access_token",
		`{"access_token":"a","token_type":"mac","expires_in":28800,"scope":"user:inference"}`:          "token_type",
		`{"access_token":"a","expires_in":0,"scope":"user:inference"}`:                                 "expires_in",
		`{"access_token":"a","expires_in":31536001,"scope":"user:inference"}`:                          "expires_in",
		`{"access_token":"a","expires_in":"28800","scope":"user:inference"}`:                           "expires_in",
		`{"access_token":"a","expires_in":28800}`:                                                      "no user:inference",
		`{"access_token":"a","expires_in":28800,"scope":"user:inference user:admin"}`:                  "did not request",
	} {
		r, v, files := hostRig(t)
		v.tokenBody = body
		f, opened := openHostFlow(t, r)
		resp := hostCallback(t, f, opened, "C")
		assertNothingWritten(t, r, files, f, resp, why)
	}
	// A non-200 answer is refused naming the status and the error field.
	r, v, files := hostRig(t)
	v.tokenCode, v.tokenBody = 400, `{"error":"invalid_grant"}`
	f, opened := openHostFlow(t, r)
	assertNothingWritten(t, r, files, f, hostCallback(t, f, opened, "C"), "HTTP 400 (invalid_grant)")
}

// TestHostModeServesTheSandboxWhenTheHostIsKept: an answer with no refresh
// token, a pin mismatch, no pin, or a write the host files refuse each
// renew the sandbox and leave the host's file alone, saying why.
func TestHostModeServesTheSandboxWhenTheHostIsKept(t *testing.T) {
	for name, tc := range map[string]struct {
		mut func(*fakeVendor, *fakeFiles)
		why string
	}{
		"without a refresh token": {func(v *fakeVendor, _ *fakeFiles) {
			v.tokenBody = `{"access_token":"a","expires_in":28800,"scope":"user:inference"}`
		}, "without a refresh token"},
		"on a pin mismatch": {func(_ *fakeVendor, f *fakeFiles) {
			f.snap.Pin = AccountPin{AccountUUID: "acc-2", OrganizationUUID: "org-1", Email: "b@example.com"}
		}, "this host is signed in as b@example.com"},
		"without a pin": {func(_ *fakeVendor, f *fakeFiles) { f.snap.Pin = AccountPin{} },
			"this host has no Claude login to renew"},
		"on a half pin": {func(_ *fakeVendor, f *fakeFiles) { f.snap.Pin.OrganizationUUID = "" },
			"this host has no Claude login to renew"},
		"when the write is refused": {func(_ *fakeVendor, f *fakeFiles) {
			f.writeErr = errors.New("another program on the host wrote a newer login while this one ran; it keeps that one")
		}, "another program on the host wrote a newer login"},
		"when the profile fails and the answer names no account": {func(v *fakeVendor, _ *fakeFiles) {
			v.profCode = 500
			v.tokenBody = `{"access_token":"a","refresh_token":"r","expires_in":28800,"scope":"user:inference"}`
		}, "could not learn whose account"},
	} {
		t.Run(name, func(t *testing.T) {
			r, v, files := hostRig(t)
			tc.mut(v, files)
			f, opened := openHostFlow(t, r)
			resp := hostCallback(t, f, opened, "C")
			renewed, _ := files.counts()
			if renewed != 1 {
				t.Errorf("the sandbox was renewed %d times, want 1", renewed)
			}
			if name != "when the write is refused" {
				if _, written := files.counts(); written != 0 {
					t.Errorf("the host file was written")
				}
			}
			if !strings.Contains(resp, "did not rewrite this host&#39;s login: ") || !strings.Contains(resp, htmlEscape(tc.why)) {
				t.Errorf("browser answer:\n%s", resp)
			}
			if !strings.Contains(r.stderr.String(), "was NOT rewritten: ") || !strings.Contains(r.stderr.String(), tc.why) {
				t.Errorf("stderr: %s", r.stderr.String())
			}
			want := string(RelayErrorRequest(f.Port, completedError, completedText, f.State))
			if got := r.sandbox.requests(); len(got) != 1 || string(got[0]) != want {
				t.Errorf("relayed %q", got)
			}
		})
	}
}

// TestHostModeRefusesRedirectsAndNonPinnedHosts: send refuses any URL but
// https to the two pinned hosts before a request exists, and the real Doer
// follows no redirect.
func TestHostModeRefusesRedirectsAndNonPinnedHosts(t *testing.T) {
	v := newVendor()
	for _, u := range []string{
		"http://platform.claude.com/v1/oauth/token", "https://evil.example/v1/oauth/token",
		"https://platform.claude.com:8443/x", "https://api.anthropic.com.evil.example/",
	} {
		req, _ := http.NewRequest("GET", u, nil)
		if _, _, _, err := send(context.Background(), v, req); err == nil || !strings.Contains(err.Error(), "refusing to send") {
			t.Errorf("%s: %v", u, err)
		}
	}
	if reqs, _ := v.calls(); len(reqs) != 0 {
		t.Fatalf("a refused URL reached the Doer: %v", reqs)
	}
	c, ok := NewDoer().(*http.Client)
	if !ok || c.CheckRedirect == nil {
		t.Fatal("NewDoer has no redirect refusal")
	}
	next, _ := url.Parse("https://evil.example/")
	if err := c.CheckRedirect(&http.Request{URL: next}, []*http.Request{{}}); !errors.Is(err, errRedirect) {
		t.Errorf("CheckRedirect = %v, want errRedirect", err)
	}
	// A 3xx reaching the flow is a refused answer like any other non-200.
	r, vv, files := hostRig(t)
	vv.tokenCode, vv.tokenBody = 302, ``
	f, opened := openHostFlow(t, r)
	assertNothingWritten(t, r, files, f, hostCallback(t, f, opened, "C"), "HTTP 302")
}

// TestHostModeAnnouncesTheHostRewriteWhenTheBrowserOpens: the line printed
// as the page opens says approving rewrites the host's login, and not to
// paste a code inside.
func TestHostModeAnnouncesTheHostRewriteWhenTheBrowserOpens(t *testing.T) {
	r, _, _ := hostRig(t)
	openHostFlow(t, r)
	s := r.stderr.String()
	for _, w := range []string{"REWRITES this host's Claude login", "a@example.com", "do NOT paste a code"} {
		if !strings.Contains(s, w) {
			t.Errorf("open line lacks %q: %s", w, s)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// TestHostModeListenerKeepsTheBridgesGate re-runs the listener's gate with
// the exchange behind it: another uid is answered 403 and exchanges nothing;
// a callback carrying the SANDBOX's state — the one the line from inside
// named, not snug's — is answered 404 and the flow survives; and a second
// callback while the first is exchanging is dropped without a second
// exchange.
func TestHostModeListenerKeepsTheBridgesGate(t *testing.T) {
	r, v, files := hostRig(t)
	v.block = make(chan struct{})
	f, opened := openHostFlow(t, r)

	r.mu.Lock()
	r.peerUID = os.Getuid() + 1
	r.mu.Unlock()
	if resp := hostCallback(t, f, opened, "C"); !strings.HasPrefix(resp, "HTTP/1.1 403 ") {
		t.Fatalf("another uid: %s", firstLineOf(resp))
	}
	r.mu.Lock()
	r.peerUID = os.Getuid()
	r.mu.Unlock()

	resp := patientBrowse(t, f.Port, "GET /callback?code=C&state="+f.State+" HTTP/1.1\r\nHost: localhost:"+itoa(f.Port)+"\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 404 ") {
		t.Fatalf("the sandbox's own state was accepted in host mode: %s", firstLineOf(resp))
	}
	if reqs, _ := v.calls(); len(reqs) != 0 {
		t.Fatalf("a refused callback reached the token endpoint: %d request(s)", len(reqs))
	}

	first := make(chan string)
	go func() { first <- hostCallback(t, f, opened, "C") }()
	waitFor(t, func() bool { reqs, _ := v.calls(); return len(reqs) == 1 })
	if second := hostCallback(t, f, opened, "C"); !strings.HasPrefix(second, "HTTP/1.1 404 ") {
		t.Errorf("a second callback during the exchange: %s", firstLineOf(second))
	}
	close(v.block)
	if resp := <-first; !strings.Contains(resp, "snug completed your Claude login") {
		t.Fatalf("control: the first callback did not complete: %s", resp)
	}
	if reqs, _ := v.calls(); len(reqs) != 2 {
		t.Errorf("token and profile requests: %d, want 2 (one exchange)", len(reqs))
	}
	if renewed, written := files.counts(); renewed != 1 || written != 1 {
		t.Errorf("renewed %d, written %d", renewed, written)
	}
}
