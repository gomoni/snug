// Package kubebroker is the exec-credential broker behind identity.kube: a
// listener in snug's own process that answers the in-sandbox shim with a
// short-lived token for the one pinned ServiceAccount.
//
// THE REQUEST CARRIES NOTHING, and that is enforced here rather than by the
// shim: the broker never reads a connection. Anything inside the sandbox can
// connect to the socket, not only the shim, so a request field — a cluster, a
// namespace, a "refresh now" — would be content the payload chooses. The
// answer is a function of the profile and the clock alone: the cached token
// while it is fresh, a new mint once it is not, never a mint before.
package kubebroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// Token is one minted credential and the expiry the CLUSTER returned.
type Token struct {
	Value  policy.Secret
	Expiry time.Time
}

// Config is the broker's fixed shape. Mint is injected by internal/cli; the
// rest are bounds, and the zero value of each is replaced by its default in New.
type Config struct {
	Socket       string                               // host path; created 0600
	Mint         func(context.Context) (Token, error) // one host-side mint
	Budget       int                                  // mints per run, the first token included
	Skew         time.Duration                        // a token is stale this long before its expiry
	MintTimeout  time.Duration
	ConnDeadline time.Duration
	FailBackoff  time.Duration // a failed mint is answered from cache this long
	MaxConns     int
	Now          func() time.Time
	Audit        func(string)
}

// Broker serves Config.Socket. The zero value is not usable; use New.
type Broker struct {
	cfg    Config
	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	slots  chan struct{}
	wg     sync.WaitGroup

	mu        sync.Mutex // held across a mint: concurrent callers share it
	tok       Token
	mints     int
	failErr   error
	failUntil time.Time
}

// New listens on cfg.Socket and caches first, the token the preflight mint
// returned, which counts against the budget. It returns an error when the
// socket cannot be created or restricted to this user, or when Mint is nil.
func New(cfg Config, first Token) (*Broker, error) {
	if cfg.Mint == nil {
		return nil, errors.New("kube token broker: no mint function")
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	if cfg.Budget == 0 {
		cfg.Budget = policy.KubeMintBudget
	}
	def(&cfg.Skew, 60*time.Second)
	def(&cfg.MintTimeout, 30*time.Second)
	def(&cfg.ConnDeadline, 35*time.Second)
	def(&cfg.FailBackoff, 10*time.Second)
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 16
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Audit == nil {
		cfg.Audit = func(string) {}
	}
	ln, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		return nil, fmt.Errorf("kube token broker socket: %w", err)
	}
	// The socket lives in a private per-run directory, but anything that can
	// connect gets a cluster token.
	if err := os.Chmod(cfg.Socket, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("kube token broker: could not restrict %s to this user (%w); anything "+
			"else on this host that can connect to it could take a cluster token", cfg.Socket, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Broker{cfg: cfg, ln: ln, ctx: ctx, cancel: cancel,
		slots: make(chan struct{}, cfg.MaxConns), tok: first, mints: 1}, nil
}

// Serve accepts until Close. Past MaxConns concurrent connections a new one is
// closed unanswered: the shim reports it, and kubectl retries.
func (b *Broker) Serve() {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		select {
		case b.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			defer func() { <-b.slots }()
			defer c.Close()
			_ = c.SetDeadline(b.cfg.Now().Add(b.cfg.ConnDeadline))
			_, _ = c.Write(b.answer())
		}()
	}
}

// Close stops accepting, cancels a mint in flight and waits for every handler.
func (b *Broker) Close() {
	b.cancel()
	b.ln.Close()
	b.wg.Wait()
}

const (
	statusOK    = 0x00
	statusError = 0x01
)

func (b *Broker) answer() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.cfg.Now()
	if now.Before(b.tok.Expiry.Add(-b.cfg.Skew)) {
		return okFrame(b.tok, b.cfg.Skew)
	}
	if now.Before(b.failUntil) {
		return errFrame(b.failErr.Error())
	}
	if b.mints >= b.cfg.Budget {
		return errFrame(fmt.Sprintf("this run has minted %d tokens, its whole budget; restart snug", b.mints))
	}
	ctx, cancel := context.WithTimeout(b.ctx, b.cfg.MintTimeout)
	defer cancel()
	t, err := b.cfg.Mint(ctx)
	b.mints++
	if err != nil {
		b.failErr = errors.New("the host-side token mint failed; snug's own output on the host says why")
		b.failUntil = now.Add(b.cfg.FailBackoff)
		b.cfg.Audit(fmt.Sprintf("kube token mint failed: %v", err))
		return errFrame(b.failErr.Error())
	}
	b.tok = t
	b.cfg.Audit(fmt.Sprintf("kube token minted, valid until %s", t.Expiry.UTC().Format(time.RFC3339)))
	return okFrame(t, b.cfg.Skew)
}

// okFrame is 0x00 then the ExecCredential client-go reads. The expiry it
// states is the cluster's minus Skew, so kubectl asks again before the token
// is refused rather than after.
func okFrame(t Token, skew time.Duration) []byte {
	type status struct {
		Token               string `json:"token"`
		ExpirationTimestamp string `json:"expirationTimestamp"`
	}
	cred := struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     status `json:"status"`
	}{"client.authentication.k8s.io/v1", "ExecCredential",
		status{string(t.Value), t.Expiry.Add(-skew).UTC().Format(time.RFC3339)}}
	out, err := json.Marshal(cred)
	if err != nil {
		return errFrame("encoding the credential failed")
	}
	return append([]byte{statusOK}, out...)
}

func errFrame(msg string) []byte { return append([]byte{statusError}, msg...) }
