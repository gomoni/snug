package kubebroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
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

func start(t *testing.T, cfg Config, first Token) (*Broker, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "kb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfg.Socket = filepath.Join(dir, "s")
	b, err := New(cfg, first)
	if err != nil {
		t.Fatal(err)
	}
	go b.Serve()
	t.Cleanup(b.Close)
	return b, cfg.Socket
}

// dial is ask without the testing.T, for goroutines.
func dial(sock string) []byte {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	return b
}

// ask connects, optionally writes junk, and returns the frame.
func ask(t *testing.T, sock string, junk []byte) []byte {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if junk != nil {
		go c.Write(junk)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return b
}

func tokenOf(t *testing.T, frame []byte) string {
	t.Helper()
	if len(frame) == 0 || frame[0] != statusOK {
		t.Fatalf("frame = %q, want a credential", frame)
	}
	var cred struct {
		Status struct{ Token, ExpirationTimestamp string }
	}
	if err := json.Unmarshal(frame[1:], &cred); err != nil {
		t.Fatal(err)
	}
	return cred.Status.Token
}

func TestBrokerServesCachedWithinTTL(t *testing.T) {
	clk := &clock{t: t0}
	var mints atomic.Int32
	_, sock := start(t, Config{Now: clk.now, Mint: func(context.Context) (Token, error) {
		mints.Add(1)
		return Token{Value: policy.Secret("fresh"), Expiry: clk.now().Add(time.Hour)}, nil
	}}, Token{Value: policy.Secret("first"), Expiry: t0.Add(time.Hour)})
	for range 3 {
		if got := tokenOf(t, ask(t, sock, nil)); got != "first" {
			t.Fatalf("token = %q, want the cached first token", got)
		}
	}
	if mints.Load() != 0 {
		t.Errorf("minted %d times within the TTL", mints.Load())
	}
	clk.set(t0.Add(time.Hour - 30*time.Second)) // inside the skew
	if got := tokenOf(t, ask(t, sock, nil)); got != "fresh" || mints.Load() != 1 {
		t.Errorf("past expiry-skew: token %q after %d mints, want one fresh mint", got, mints.Load())
	}
}

func TestBrokerSingleFlights(t *testing.T) {
	clk := &clock{t: t0.Add(time.Hour - 60*time.Second)} // exactly Expiry - Skew
	var mints atomic.Int32
	release := make(chan struct{})
	_, sock := start(t, Config{Now: clk.now, ConnDeadline: 5 * time.Second, Mint: func(context.Context) (Token, error) {
		mints.Add(1)
		<-release
		return Token{Value: policy.Secret("fresh"), Expiry: t0.Add(2 * time.Hour)}, nil
	}}, Token{Value: policy.Secret("first"), Expiry: t0.Add(time.Hour)})
	var wg sync.WaitGroup
	frames := make([][]byte, 8)
	for i := range frames {
		wg.Add(1)
		go func() { defer wg.Done(); frames[i] = dial(sock) }()
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	if mints.Load() != 1 {
		t.Errorf("%d concurrent requests at expiry made %d mints, want 1", len(frames), mints.Load())
	}
	for _, f := range frames {
		if g := tokenOf(t, f); g != "fresh" {
			t.Errorf("a waiter got %q", g)
		}
	}
}

// The broker never reads, so a client that writes gets no say — and on a unix
// stream socket the kernel resets a peer whose bytes were never read when the
// broker closes, so that client may get the reset instead of the frame. Only a
// writer pays for that; the shim writes nothing.
func TestBrokerIgnoresRequestBytes(t *testing.T) {
	var mints atomic.Int32
	_, sock := start(t, Config{Mint: func(context.Context) (Token, error) {
		mints.Add(1)
		return Token{}, nil
	}}, Token{Value: policy.Secret("first"), Expiry: time.Now().Add(time.Hour)})
	junk := bytes.Repeat([]byte(`{"refresh":true,"cluster":"other"}`), 1<<15)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go c.Write(junk)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	c.Close()
	if len(b) > 0 && tokenOf(t, b) != "first" {
		t.Errorf("a writing client got %q", b)
	}
	if got := tokenOf(t, ask(t, sock, nil)); got != "first" || mints.Load() != 0 {
		t.Errorf("after a MiB of request bytes: token %q, %d mints", got, mints.Load())
	}
}

func TestBrokerBudgetRefuses(t *testing.T) {
	clk := &clock{t: t0}
	_, sock := start(t, Config{Now: clk.now, Budget: 3, Mint: func(context.Context) (Token, error) {
		return Token{Value: policy.Secret("x"), Expiry: clk.now()}, nil // already stale: every ask mints
	}}, Token{Value: policy.Secret("first"), Expiry: t0})
	ask(t, sock, nil)
	ask(t, sock, nil)
	if f := ask(t, sock, nil); f[0] != statusError || !bytes.Contains(f, []byte("budget")) {
		t.Errorf("third mint past a budget of 3 (first included): %q", f)
	}
}

func TestBrokerMintTimeoutCancels(t *testing.T) {
	_, sock := start(t, Config{MintTimeout: 50 * time.Millisecond, Mint: func(ctx context.Context) (Token, error) {
		<-ctx.Done()
		return Token{}, ctx.Err()
	}}, Token{})
	if f := ask(t, sock, nil); f[0] != statusError {
		t.Errorf("a hung mint answered %q, want an error frame", f)
	}
}

func TestBrokerFailureBackoff(t *testing.T) {
	clk := &clock{t: t0}
	var mints atomic.Int32
	_, sock := start(t, Config{Now: clk.now, Mint: func(context.Context) (Token, error) {
		mints.Add(1)
		return Token{}, errors.New("boom")
	}}, Token{})
	ask(t, sock, nil)
	ask(t, sock, nil)
	if mints.Load() != 1 {
		t.Errorf("a failed mint was retried %d times inside the backoff", mints.Load())
	}
	clk.set(t0.Add(11 * time.Second))
	ask(t, sock, nil)
	if mints.Load() != 2 {
		t.Errorf("no retry after the backoff: %d mints", mints.Load())
	}
}

func TestBrokerCloseCancelsInflight(t *testing.T) {
	started := make(chan struct{})
	b, sock := start(t, Config{Mint: func(ctx context.Context) (Token, error) {
		close(started)
		<-ctx.Done()
		return Token{}, ctx.Err()
	}}, Token{})
	go dial(sock)
	<-started
	done := make(chan struct{})
	go func() { b.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return while a mint was in flight")
	}
	if _, err := net.Dial("unix", sock); err == nil {
		t.Error("the socket still accepts after Close")
	}
}

func TestBrokerSocketIsPrivate(t *testing.T) {
	_, sock := start(t, Config{Mint: func(context.Context) (Token, error) { return Token{}, nil }}, Token{})
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %v, want 0600", fi.Mode().Perm())
	}
}

func TestShimPrintsTheCredentialAndIgnoresExecInfo(t *testing.T) {
	_, sock := start(t, Config{Mint: func(context.Context) (Token, error) { return Token{}, nil }},
		Token{Value: policy.Secret("first"), Expiry: time.Now().Add(time.Hour)})
	old := shimDial
	shimDial = func() (net.Conn, error) { return net.Dial("unix", sock) }
	t.Cleanup(func() { shimDial = old })
	t.Setenv("KUBERNETES_EXEC_INFO", `{"spec":{"cluster":{"server":"https://evil.example"}}}`)
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	rc := ShimMain()
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)
	if rc != 0 || !bytes.Contains(out, []byte(`"token":"first"`)) || !bytes.Contains(out, []byte("ExecCredential")) {
		t.Errorf("rc=%d out=%s", rc, out)
	}
}
