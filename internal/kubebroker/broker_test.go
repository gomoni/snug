package kubebroker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func start(t *testing.T, cfg Config, first Token) *Source {
	t.Helper()
	s, err := New(cfg, first)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func ask(t *testing.T, s *Source) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok, err := s.Token(ctx)
	return string(tok), err
}

func TestBrokerServesCachedWithinTTL(t *testing.T) {
	clk := &clock{t: t0}
	var mints atomic.Int32
	s := start(t, Config{Now: clk.now, Mint: func(context.Context) (Token, error) {
		mints.Add(1)
		return Token{Value: policy.Secret("fresh"), Expiry: clk.now().Add(time.Hour)}, nil
	}}, Token{Value: policy.Secret("first"), Expiry: t0.Add(time.Hour)})
	for range 3 {
		if got, _ := ask(t, s); got != "first" {
			t.Fatalf("token = %q, want the cached first token", got)
		}
	}
	if mints.Load() != 0 {
		t.Errorf("minted %d times within the TTL", mints.Load())
	}
	clk.set(t0.Add(time.Hour - 30*time.Second)) // inside the skew
	if got, _ := ask(t, s); got != "fresh" || mints.Load() != 1 {
		t.Errorf("past expiry-skew: token %q after %d mints, want one fresh mint", got, mints.Load())
	}
}

func TestBrokerSingleFlights(t *testing.T) {
	clk := &clock{t: t0.Add(time.Hour - 60*time.Second)} // exactly Expiry - Skew
	var mints atomic.Int32
	release := make(chan struct{})
	s := start(t, Config{Now: clk.now, Mint: func(context.Context) (Token, error) {
		mints.Add(1)
		<-release
		return Token{Value: policy.Secret("fresh"), Expiry: t0.Add(2 * time.Hour)}, nil
	}}, Token{Value: policy.Secret("first"), Expiry: t0.Add(time.Hour)})
	var wg sync.WaitGroup
	got := make([]string, 8)
	for i := range got {
		wg.Add(1)
		go func() { defer wg.Done(); tok, _ := s.Token(context.Background()); got[i] = string(tok) }()
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	if mints.Load() != 1 {
		t.Errorf("%d concurrent requests at expiry made %d mints, want 1", len(got), mints.Load())
	}
	for _, g := range got {
		if g != "fresh" {
			t.Errorf("a waiter got %q", g)
		}
	}
}

// A caller that gives up does not cancel the mint the others are waiting on.
func TestBrokerACallerGivingUpDoesNotCancelTheMint(t *testing.T) {
	clk := &clock{t: t0}
	release := make(chan struct{})
	s := start(t, Config{Now: clk.now, Mint: func(ctx context.Context) (Token, error) {
		select {
		case <-release:
			return Token{Value: policy.Secret("fresh"), Expiry: t0.Add(time.Hour)}, nil
		case <-ctx.Done():
			return Token{}, ctx.Err()
		}
	}}, Token{Expiry: t0})
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := s.Token(ctx); errc <- err }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("the cancelled caller got %v", err)
	}
	close(release)
	if got, err := ask(t, s); got != "fresh" {
		t.Errorf("after one caller gave up: %q, %v; want the mint it abandoned", got, err)
	}
}

func TestBrokerBudgetRefuses(t *testing.T) {
	clk := &clock{t: t0}
	s := start(t, Config{Now: clk.now, Budget: 3, Mint: func(context.Context) (Token, error) {
		return Token{Value: policy.Secret("x"), Expiry: clk.now()}, nil // already stale: every ask mints
	}}, Token{Value: policy.Secret("first"), Expiry: t0})
	ask(t, s)
	ask(t, s)
	if _, err := ask(t, s); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Errorf("third mint past a budget of 3 (first included): %v", err)
	}
}

func TestBrokerMintTimeoutCancels(t *testing.T) {
	s := start(t, Config{MintTimeout: 50 * time.Millisecond, Mint: func(ctx context.Context) (Token, error) {
		<-ctx.Done()
		return Token{}, ctx.Err()
	}}, Token{})
	if _, err := ask(t, s); err == nil {
		t.Error("a hung mint answered with a token")
	}
}

func TestBrokerFailureBackoff(t *testing.T) {
	clk := &clock{t: t0}
	var mints atomic.Int32
	s := start(t, Config{Now: clk.now, Mint: func(context.Context) (Token, error) {
		mints.Add(1)
		return Token{}, errors.New("boom")
	}}, Token{})
	ask(t, s)
	ask(t, s)
	if mints.Load() != 1 {
		t.Errorf("a failed mint was retried %d times inside the backoff", mints.Load())
	}
	clk.set(t0.Add(11 * time.Second))
	ask(t, s)
	if mints.Load() != 2 {
		t.Errorf("no retry after the backoff: %d mints", mints.Load())
	}
}

func TestBrokerCloseCancelsInflight(t *testing.T) {
	started := make(chan struct{})
	ended := make(chan struct{})
	s := start(t, Config{Mint: func(ctx context.Context) (Token, error) {
		close(started)
		<-ctx.Done()
		close(ended)
		return Token{}, ctx.Err()
	}}, Token{})
	go s.Token(context.Background())
	<-started
	s.Close()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel the mint in flight")
	}
	if _, err := ask(t, s); err == nil {
		t.Error("Token after Close returned a token")
	}
}
