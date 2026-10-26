package loginbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// The two endpoints host mode calls, and their bounds, each beside the name
// Claude Code 2.1.310's bundle gives it. Constants on purpose: no flag,
// variable or file re-aims them, so a test double is a Doer, not a knob in
// the binary.
const (
	tokenURL   = "https://platform.claude.com/v1/oauth/token"  // TOKEN_URL
	profileURL = "https://api.anthropic.com/api/oauth/profile" // Bb
	// maxExpiresIn is a year in seconds, the longest lifetime the client
	// itself ever asks for (Kse); a longer one is not an answer snug believes.
	maxExpiresIn = 31536000

	exchangeTimeout = 30 * time.Second
	profileTimeout  = 10 * time.Second
	maxAnswerBytes  = 1 << 20
	maxAccessToken  = 8 << 10
	// userAgent is snug's own: copying Claude Code's would be a decision,
	// not a detail.
	userAgent = "snug"
)

// pinnedHosts is every host send will speak to, over https only.
var pinnedHosts = map[string]bool{"platform.claude.com": true, "api.anthropic.com": true}

// Doer sends one HTTP request. *http.Client is one; tests inject a fake.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// errRedirect is NewDoer's answer to a redirect.
var errRedirect = errors.New("the endpoint answered with a redirect, and snug follows none")

// NewDoer returns the client a real run uses: the default transport, and no
// redirect followed — a 3xx from either endpoint is an error, never a second
// request somewhere else.
func NewDoer() Doer {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect }}
}

// send performs req through d, refusing any URL that is not https to a
// pinned host, and returns the status, headers and at most maxAnswerBytes of
// the body.
func send(ctx context.Context, d Doer, req *http.Request) (int, http.Header, []byte, error) {
	if req.URL.Scheme != "https" || !pinnedHosts[req.URL.Host] {
		return 0, nil, nil, fmt.Errorf("refusing to send to %s: snug speaks only https to %s",
			policy.VisibleText(req.URL.Redacted()), strings.Join(slices.Sorted(mapKeys(pinnedHosts)), " and "))
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := d.Do(req.WithContext(ctx))
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes+1))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("reading the answer: %v", err)
	}
	if len(body) > maxAnswerBytes {
		return 0, nil, nil, fmt.Errorf("the answer is longer than %d bytes", maxAnswerBytes)
	}
	return resp.StatusCode, resp.Header, body, nil
}

func mapKeys(m map[string]bool) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// tokenRequest is the authorization_code exchange's body, in the order and
// with the keys Claude Code sends it.
type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	CodeVerifier string `json:"code_verifier"`
	State        string `json:"state"`
}

// exchangeCode trades code for tokens at tokenURL with snug's verifier and
// state. A non-200 answer is an error naming the status and, when the body
// carries one, its error field.
func exchangeCode(ctx context.Context, d Doer, code string, port int, verifier policy.Secret, state string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()
	body, err := json.Marshal(tokenRequest{
		GrantType: "authorization_code", Code: code,
		RedirectURI: "http://localhost:" + strconv.Itoa(port) + "/callback",
		ClientID:    clientID, CodeVerifier: string(verifier), State: state,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, tokenURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	status, _, answer, err := send(ctx, d, req)
	if err != nil {
		return nil, fmt.Errorf("the token endpoint could not be reached: %v", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("the token endpoint answered HTTP %d%s", status, answerError(answer))
	}
	return answer, nil
}

// answerError renders an error answer's `error` field, when it has a short
// string one, for a message.
func answerError(body []byte) string {
	var a struct {
		Error any `json:"error"`
	}
	if json.Unmarshal(body, &a) != nil {
		return ""
	}
	if s, ok := a.Error.(string); ok && s != "" && len(s) <= 64 {
		return " (" + policy.VisibleText(s) + ")"
	}
	return ""
}

// profileAnswer is what host mode reads from the profile endpoint.
type profileAnswer struct {
	Account struct {
		UUID  string `json:"uuid"`
		Email string `json:"email"`
	} `json:"account"`
	Organization struct {
		UUID             string  `json:"uuid"`
		OrganizationType *string `json:"organization_type"`
		RateLimitTier    *string `json:"rate_limit_tier"`
	} `json:"organization"`
	requestID string
}

// fetchProfile reads the account the new access token belongs to.
func fetchProfile(ctx context.Context, d Doer, access policy.Secret) (profileAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, profileTimeout)
	defer cancel()
	req, err := http.NewRequest(http.MethodGet, profileURL, nil)
	if err != nil {
		return profileAnswer{}, err
	}
	req.Header.Set("Authorization", "Bearer "+string(access))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	status, header, body, err := send(ctx, d, req)
	if err != nil {
		return profileAnswer{}, fmt.Errorf("the profile endpoint could not be reached: %v", err)
	}
	if status != http.StatusOK {
		return profileAnswer{}, fmt.Errorf("the profile endpoint answered HTTP %d", status)
	}
	var p profileAnswer
	if err := json.Unmarshal(body, &p); err != nil {
		return profileAnswer{}, fmt.Errorf("the profile endpoint's answer is not the profile shape: %v", err)
	}
	p.requestID = header.Get("request-id")
	return p, nil
}

// tokenAnswer is the token endpoint's answer, checked.
type tokenAnswer struct {
	Access, Refresh policy.Secret
	ExpiresIn       time.Duration
	// RefreshExpiresIn is zero when the answer named none.
	RefreshExpiresIn time.Duration
	Scopes           []string
	AccountUUID      string
	AccountEmail     string
	OrganizationUUID string
	// hostProblem is why the answer serves the sandbox but not the host's
	// file; "" when it serves both.
	hostProblem string
}

// checkTokenAnswer reads the token endpoint's answer. A non-nil error means
// the answer is no login at all and nothing may be written anywhere; a
// tokenAnswer with a hostProblem serves the sandbox but not the host's file.
func checkTokenAnswer(body []byte) (tokenAnswer, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return tokenAnswer{}, errors.New("the token endpoint's answer was not a JSON object")
	}
	str := func(k string) (string, bool) {
		var s string
		if json.Unmarshal(obj[k], &s) != nil {
			return "", false
		}
		return s, true
	}
	num := func(k string) (float64, bool) {
		var n float64
		if json.Unmarshal(obj[k], &n) != nil {
			return 0, false
		}
		return n, true
	}
	var a tokenAnswer
	access, ok := str("access_token")
	if !ok || access == "" || len(access) > maxAccessToken {
		return tokenAnswer{}, fmt.Errorf("the token endpoint's answer carried no access_token of 1 to %d bytes", maxAccessToken)
	}
	a.Access = policy.Secret(access)
	if raw, present := obj["token_type"]; present {
		tt, ok := str("token_type")
		if !ok || !strings.EqualFold(tt, "bearer") {
			return tokenAnswer{}, fmt.Errorf("the token endpoint's answer has token_type %s, not bearer",
				policy.VisibleText(string(raw)))
		}
	}
	expires, ok := num("expires_in")
	if !ok || expires <= 0 || expires > maxExpiresIn {
		return tokenAnswer{}, fmt.Errorf("the token endpoint's answer has no expires_in between 1 and %d seconds", maxExpiresIn)
	}
	a.ExpiresIn = time.Duration(expires * float64(time.Second))
	if scope, _ := str("scope"); scope != "" {
		a.Scopes = strings.Split(scope, " ")
	}
	pinned := PinnedScopes()
	for _, s := range a.Scopes {
		if !slices.Contains(pinned, s) {
			return tokenAnswer{}, fmt.Errorf("the login granted scope %s, which snug did not request", policy.VisibleText(strconvQuote(s)))
		}
	}
	if !slices.Contains(a.Scopes, "user:inference") {
		return tokenAnswer{}, errors.New("the login granted no user:inference scope; Claude Code cannot use it")
	}

	if refresh, ok := str("refresh_token"); ok && refresh != "" {
		a.Refresh = policy.Secret(refresh)
	} else {
		a.hostProblem = "the token endpoint answered without a refresh token (an inference-only login); the host keeps its own"
	}
	if _, present := obj["refresh_token_expires_in"]; present {
		v, ok := num("refresh_token_expires_in")
		if !ok || v <= 0 || v > maxExpiresIn {
			if a.hostProblem == "" {
				a.hostProblem = fmt.Sprintf("the token endpoint's refresh_token_expires_in is not between 1 and %d "+
					"seconds; the host keeps its own login", maxExpiresIn)
			}
		} else {
			a.RefreshExpiresIn = time.Duration(v * float64(time.Second))
		}
	}
	var who struct {
		Account struct {
			UUID  string `json:"uuid"`
			Email string `json:"email_address"`
		} `json:"account"`
		Organization struct {
			UUID string `json:"uuid"`
		} `json:"organization"`
	}
	if json.Unmarshal(body, &who) == nil {
		a.AccountUUID, a.AccountEmail, a.OrganizationUUID = who.Account.UUID, who.Account.Email, who.Organization.UUID
	}
	return a, nil
}

func strconvQuote(s string) string { return strconv.Quote(s) }
