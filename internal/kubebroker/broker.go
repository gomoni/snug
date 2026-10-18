// Package kubebroker is the token source behind identity.kube: the one place a
// run's credential for the pinned cluster is minted and cached, in snug's own
// process. Its only caller is internal/kubeproxy, which writes the token into
// the Authorization header of a request to the pinned server; nothing in the
// sandbox ever holds it.
//
// THE CALLER CHOOSES NOTHING. Token takes no argument but a context, so no
// request from inside — a cluster, a namespace, a "refresh now", an upstream
// 401 a pod the sandbox controls can provoke at will — reaches the decision to
// mint. The answer is a function of the profile and the clock alone: the
// cached token while it is fresh, a new mint once it is not, never a mint
// before.
package kubebroker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// Token is one minted credential and the expiry its issuer returned.
type Token struct {
	Value  policy.Secret
	Expiry time.Time
}

// Config is the source's fixed shape. Mint is injected by internal/cli; the
// rest are bounds, and the zero value of each is replaced by its default in New.
type Config struct {
	Mint        func(context.Context) (Token, error) // one host-side mint
	Budget      int                                  // mints per run, the first token included
	Skew        time.Duration                        // a token is stale this long before its expiry
	MintTimeout time.Duration
	FailBackoff time.Duration // a failed mint is answered from cache this long
	Now         func() time.Time
	Audit       func(string)
}

// Source hands out the run's token. The zero value is not usable; use New.
type Source struct {
	cfg    Config
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex // held across a mint: concurrent callers share it
	tok       Token
	mints     int
	failErr   error
	failUntil time.Time
}

// New caches first, the token the preflight mint returned, which counts
// against the budget. It returns an error when Mint is nil.
func New(cfg Config, first Token) (*Source, error) {
	if cfg.Mint == nil {
		return nil, errors.New("kube token source: no mint function")
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
	def(&cfg.FailBackoff, 10*time.Second)
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Audit == nil {
		cfg.Audit = func(string) {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Source{cfg: cfg, ctx: ctx, cancel: cancel, tok: first, mints: 1}, nil
}

// Close cancels a mint in flight. A Token call after Close fails.
func (s *Source) Close() { s.cancel() }

// Token returns the cached token while now < expiry-Skew, and otherwise mints
// once for every caller waiting. A failed mint is answered from cache for
// FailBackoff; past Budget mints every call fails. ctx bounds only this
// caller's wait: a mint in flight runs on the source's own context, so one
// caller giving up does not cancel the mint every other caller shares.
func (s *Source) Token(ctx context.Context) (policy.Secret, error) {
	type result struct {
		tok policy.Secret
		err error
	}
	ch := make(chan result, 1)
	go func() {
		t, err := s.token()
		ch <- result{t, err}
	}()
	select {
	case r := <-ch:
		return r.tok, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Source) token() (policy.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return nil, errors.New("the run is ending")
	}
	now := s.cfg.Now()
	if now.Before(s.tok.Expiry.Add(-s.cfg.Skew)) {
		return s.tok.Value, nil
	}
	if now.Before(s.failUntil) {
		return nil, s.failErr
	}
	if s.mints >= s.cfg.Budget {
		return nil, fmt.Errorf("this run has minted %d tokens, its whole budget; restart snug", s.mints)
	}
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.MintTimeout)
	defer cancel()
	t, err := s.cfg.Mint(ctx)
	s.mints++
	if err != nil {
		s.failErr = errors.New("the host-side token mint failed; snug's own output on the host says why")
		s.failUntil = now.Add(s.cfg.FailBackoff)
		s.cfg.Audit(fmt.Sprintf("kube token mint failed: %v", err))
		return nil, s.failErr
	}
	s.tok = t
	s.cfg.Audit(fmt.Sprintf("kube token minted, valid until %s", t.Expiry.UTC().Format(time.RFC3339)))
	return t.Value, nil
}
