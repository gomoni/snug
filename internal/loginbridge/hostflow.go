package loginbridge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// HostWriteBudget is how long a HostFiles.WriteHost may wait on another
// writer before it refuses.
const HostWriteBudget = 10 * time.Second

// HostLogin is what a Bridge needs to complete each login on the host
// (login.claude = "host"): snug opens the authorize URL with its OWN PKCE
// verifier and state, so the code the browser brings back is exchangeable by
// snug alone; snug exchanges it, renews the sandbox's credential with the
// access token, rewrites the host's credential file when every host check
// passes, and ends the client's /login wait with a constant error callback.
//
// ABUSE: a hostile process inside the sandbox can use this to open Claude's
// consent page in your browser — at most MaxOpensPerRun times per run, one at
// a time, SupersedeAfter apart — and, if you approve, have snug REPLACE the
// refresh token in your host ~/.claude/.credentials.json for the account the
// host is already signed in to, never another, at most MaxRelaysPerRun times
// per run, and hand the sandbox a fresh access token that lasts hours and
// renews nothing. It cannot choose the URL, the account, see the code or the
// refresh token, reach the listener, or put a byte into the host file. If the
// human pastes a code into claude's own /login prompt inside, the sandbox
// exchanges it itself and holds a refresh token in memory: the flow above
// never hands it one, and the human can.
type HostLogin struct {
	// Doer sends the token and profile requests; nil is NewDoer().
	Doer Doer
	// Files is the host-file half, which internal/cli implements.
	Files HostFiles
	// Rand is where the verifier and state come from; nil is crypto/rand.
	Rand io.Reader
}

// HostFiles is the host-file half of a host-mode login. It lives in
// internal/cli, where host I/O lives; this package decides only what to ask
// of it.
//
// A WriteHost that waits on another writer gives up within HostWriteBudget,
// which the browser's page deadline counts on.
type HostFiles interface {
	// Snapshot reads, when a flow starts, the account the host is signed in
	// to and the host credential file's tokens, for WriteHost's
	// compare-and-swap.
	Snapshot() HostSnapshot
	// RenewSandbox replaces the sandbox's credential with r's access token.
	// keepPlan says r's account is the host's, so the sandbox's current
	// subscription fields may be carried over an answer that names none.
	RenewSandbox(ctx context.Context, r policy.ClaudeLoginResult, now time.Time, keepPlan bool) error
	// WriteHost rewrites the host's credential file from r if it still holds
	// what snap recorded. A non-nil error is the reason it did not, worded
	// to follow "was NOT rewritten: ".
	WriteHost(ctx context.Context, snap HostSnapshot, r policy.ClaudeLoginResult, now time.Time) error
}

// AccountPin is the account a host is signed in to, as ~/.claude.json's
// oauthAccount names it.
type AccountPin struct {
	AccountUUID      string
	OrganizationUUID string
	Email            string
}

// Present reports whether p names an account: both uuids, since one alone is
// not an identity the client itself would compare.
func (p AccountPin) Present() bool { return p.AccountUUID != "" && p.OrganizationUUID != "" }

// CredentialFile is the host credential file as a flow found it.
type CredentialFile struct {
	Exists       bool
	AccessToken  policy.Secret
	RefreshToken policy.Secret
}

// HostSnapshot is HostFiles.Snapshot's answer.
type HostSnapshot struct {
	Pin AccountPin
	// PinProblem is why the pin could not be read; "" when it was.
	PinProblem string
	File       CredentialFile
}

// hostFlow is one host-mode flow's own values.
type hostFlow struct {
	h        *HostLogin
	Verifier policy.Secret
	// Challenge and State are snug's, in the URL it opens; ClientState is
	// the state the client's own listener accepts, for the end-of-wait
	// callback.
	Challenge   string
	State       string
	ClientState string
	Snapshot    HostSnapshot
}

// begin draws a verifier and a state and takes the host-side snapshot.
func (h *HostLogin) begin(f Flow) (*hostFlow, error) {
	if h.Files == nil {
		return nil, errNoHostFiles
	}
	r := h.Rand
	if r == nil {
		r = rand.Reader
	}
	draw := func() (string, error) {
		var b [32]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", fmt.Errorf("could not draw a PKCE value: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b[:]), nil
	}
	verifier, err := draw()
	if err != nil {
		return nil, err
	}
	state, err := draw()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(verifier))
	return &hostFlow{
		h: h, Verifier: policy.Secret(verifier),
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]), State: state, ClientState: f.State,
		Snapshot: h.Files.Snapshot(),
	}, nil
}

// noPaste is the instruction every host-mode line ends with: the client's own
// /login printed a URL and asks for a code, and pasting one there signs the
// sandbox in by itself, refresh token included.
const noPaste = "do NOT open the URL claude printed inside and do NOT paste a code into it"

// announce is the stderr line for the moment the browser opens.
func (hf *hostFlow) announce() string {
	who := "the account this host is signed in to"
	if e := hf.Snapshot.Pin.Email; e != "" {
		who = policy.VisibleText(e)
	}
	return fmt.Sprintf("opening Claude's sign-in page in your browser. Approving it REWRITES this host's "+
		"Claude login in ~/.claude/.credentials.json (for %s) and renews the sandbox's token; %s.", who, noPaste)
}

// outcome is what completing a login on the host came to.
type outcome struct {
	// failed is why nothing was written anywhere; "" when the login served.
	failed  string
	email   string
	org     string
	sandbox error
	// hostKept is why the host's file was not rewritten; "" when it was.
	hostKept string
}

// completeOnHost is host mode's consumer: exchange, check, renew, write, then
// tell the human and end the client's wait. Nothing it relays carries a code.
func (b *Bridge) completeOnHost(fl *flow, hf *hostFlow, c net.Conn, cb Callback) {
	o := b.exchangeOnHost(fl, hf, cb)
	if b.ctx.Err() != nil {
		return
	}
	errCode, text := completedError, completedText
	if o.failed != "" {
		errCode, text = failedError, failedText
	}
	b.reportOutcome(o)
	status, rerr := b.relay(fl, RelayErrorRequest(fl.f.Port, errCode, text, hf.ClientState))
	if rerr != nil {
		fmt.Fprintf(b.d.Stderr, "snug: login bridge: could not end the sandbox's /login wait — %s; press Esc "+
			"in claude inside.\n", policy.VisibleText(rerr.Error()))
	} else {
		fmt.Fprintf(b.d.Stderr, "snug: login bridge: ended the sandbox's /login wait; it answered HTTP %d.\n", status)
	}
	switch {
	case o.failed != "":
		writePage(c, 502, "snug could not complete this Claude login: "+o.failed+
			". Nothing was written. Run /login again inside the sandbox.")
	case o.sandbox != nil:
		writePage(c, 502, "snug completed the Claude login as "+o.email+" but could not renew the sandbox's token: "+
			o.sandbox.Error()+".")
	case o.hostKept != "":
		writePage(c, 200, "snug completed your Claude login as "+o.email+" and renewed the sandbox's token, "+
			"but did not rewrite this host's login: "+o.hostKept+". You can close this tab.")
	default:
		writePage(c, 200, "snug completed your Claude login on the host as "+o.email+
			" and renewed the sandbox's token. You can close this tab.")
	}
}

// reportOutcome prints the line that tells the human what happened, before
// the client's wait is ended, so it is on screen when claude's /login gives
// up and prints its own prompt.
func (b *Bridge) reportOutcome(o outcome) {
	switch {
	case o.failed != "":
		fmt.Fprintf(b.d.Stderr, "snug: login bridge: could not complete the login on the host: %s. Nothing was "+
			"written. claude inside reports its /login as failed; run /login again there — %s.\n", o.failed, noPaste)
	case o.sandbox != nil:
		fmt.Fprintf(b.d.Stderr, "snug: login bridge: completed the login as %s (%s) but could not renew the "+
			"sandbox's token: %s. %s.\n", o.email, o.org, policy.VisibleText(o.sandbox.Error()), hostLine(o))
	default:
		fmt.Fprintf(b.d.Stderr, "snug: login bridge: completed the login as %s (%s); %s; the sandbox's token "+
			"was renewed. claude inside reports its own /login as failed because snug, not claude, exchanged "+
			"the code — %s; press Esc and retry your request.\n", o.email, o.org, hostLine(o), noPaste)
	}
}

func hostLine(o outcome) string {
	if o.hostKept != "" {
		return "the host's ~/.claude/.credentials.json was NOT rewritten: " + o.hostKept
	}
	return "the host's ~/.claude/.credentials.json was rewritten"
}

// exchangeOnHost runs the flow's network half and the checks, and asks
// HostFiles for the two writes. Every string it puts in the outcome is
// snug's, with network values made visible.
func (b *Bridge) exchangeOnHost(fl *flow, hf *hostFlow, cb Callback) outcome {
	ctx := b.ctx
	doer := hf.h.Doer
	if doer == nil {
		doer = NewDoer()
	}
	code, err := url.PathUnescape(cb.Code)
	if err != nil {
		return outcome{failed: "the callback's code does not decode"}
	}
	body, err := exchangeCode(ctx, doer, code, fl.f.Port, hf.Verifier, hf.State)
	if err != nil {
		return outcome{failed: policy.VisibleText(err.Error())}
	}
	tok, err := checkTokenAnswer(body)
	if err != nil {
		return outcome{failed: err.Error()}
	}
	prof, perr := fetchProfile(ctx, doer, tok.AccessToken)
	if ctx.Err() != nil {
		return outcome{failed: "snug is shutting down"}
	}

	r := policy.ClaudeLoginResult{
		AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken,
		ExpiresIn: tok.ExpiresIn, RefreshTokenExpiresIn: tok.RefreshExpiresIn, Scopes: tok.Scopes,
	}
	who := AccountPin{AccountUUID: tok.AccountUUID, OrganizationUUID: tok.OrganizationUUID, Email: tok.AccountEmail}
	if perr == nil {
		if prof.Organization.OrganizationType != nil {
			r.OrganizationType = *prof.Organization.OrganizationType
		}
		if prof.Organization.RateLimitTier != nil {
			r.RateLimitTier = *prof.Organization.RateLimitTier
		}
		r.RequestID = prof.requestID
		if prof.Account.UUID != "" && prof.Organization.UUID != "" {
			who = AccountPin{AccountUUID: prof.Account.UUID, OrganizationUUID: prof.Organization.UUID, Email: prof.Account.Email}
		}
	}
	o := outcome{email: "an account snug could not name", org: "organization unknown"}
	if who.Email != "" {
		o.email = policy.VisibleText(who.Email)
	}
	if who.OrganizationUUID != "" {
		o.org = "organization " + policy.VisibleText(who.OrganizationUUID)
	}

	pin := hf.Snapshot.Pin
	same := who.Present() && pin.Present() && who.AccountUUID == pin.AccountUUID &&
		who.OrganizationUUID == pin.OrganizationUUID
	now := b.d.Clock.Now()
	// A Close from here on must leave both files as they were: Close waits
	// for this goroutine, so a write that started would finish.
	if ctx.Err() != nil {
		return outcome{failed: "snug is shutting down"}
	}
	o.sandbox = hf.h.Files.RenewSandbox(ctx, r, now, same)

	switch {
	case tok.hostProblem != "":
		o.hostKept = tok.hostProblem
	case !who.Present():
		o.hostKept = "snug could not learn whose account this login is; the host keeps its login"
	case hf.Snapshot.PinProblem != "":
		o.hostKept = hf.Snapshot.PinProblem
	case !pin.Present():
		o.hostKept = "this host has no Claude login to renew; sign in once with `claude` on the host"
	case !same:
		host := "another account"
		if pin.Email != "" {
			host = policy.VisibleText(pin.Email)
		}
		o.hostKept = fmt.Sprintf("the browser signed in as %s; this host is signed in as %s; snug renews the "+
			"same account only. To switch the host, run `claude auth login` there", o.email, host)
	case !now.Add(r.ExpiresIn).After(now) || refreshEnd(r, now) <= now.Add(r.ExpiresIn).UnixMilli():
		o.hostKept = "the new login's expiry times are not in the future; the host keeps its own login"
	case ctx.Err() != nil:
		return outcome{failed: "snug is shutting down"}
	default:
		if err := hf.h.Files.WriteHost(ctx, hf.Snapshot, r, now); err != nil {
			o.hostKept = policy.VisibleText(err.Error())
		}
	}
	return o
}

// refreshEnd is the refresh token's expiry the renewal will write, in epoch
// milliseconds.
func refreshEnd(r policy.ClaudeLoginResult, now time.Time) int64 {
	d := r.RefreshTokenExpiresIn
	if d <= 0 {
		d = policy.ClaudeRefreshDefault
	}
	return now.Add(d).UnixMilli()
}

// errNoHostFiles is what a HostLogin without Files refuses with.
var errNoHostFiles = errors.New("host mode has no host-file half")
