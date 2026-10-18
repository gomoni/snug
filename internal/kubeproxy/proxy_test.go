package kubeproxy

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

const testToken = "tok-0123456789abcdef"

// upstream is a TLS httptest server standing in for the API server. It
// records what reached it. HTTP/2 is enabled, so a test passing through it
// also proves the proxy's transport stays on HTTP/1.1.
type upstream struct {
	srv   *httptest.Server
	mu    sync.Mutex
	reqs  []*http.Request
	auths []string
	hosts []string
}

func newUpstream(t *testing.T, h http.HandlerFunc) *upstream {
	t.Helper()
	u := &upstream{}
	u.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.reqs = append(u.reqs, r)
		u.auths = append(u.auths, r.Header.Get("Authorization"))
		u.hosts = append(u.hosts, r.Host)
		u.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		fmt.Fprintf(w, "path=%s", r.URL.EscapedPath())
	}))
	u.srv.EnableHTTP2 = true
	u.srv.StartTLS()
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) count() int { u.mu.Lock(); defer u.mu.Unlock(); return len(u.reqs) }

type pfix struct {
	p      *Proxy
	addr   string
	up     *upstream
	tokens atomic.Int32
	audit  []string
	amu    sync.Mutex
}

// start runs a proxy on loopback in front of up, at server path prefix pfx.
func start(t *testing.T, up *upstream, pfx string, mod func(*Config)) *pfix {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	su, _ := url.Parse(up.srv.URL + pfx)
	pool := x509.NewCertPool()
	pool.AddCert(up.srv.Certificate())
	f := &pfix{up: up, addr: ln.Addr().String()}
	cfg := Config{
		Listener: ln, Server: su, CAs: pool, TLSName: "example.com",
		Token: func(context.Context) (policy.Secret, error) {
			f.tokens.Add(1)
			return policy.Secret(testToken), nil
		},
		Audit: func(s string) { f.amu.Lock(); f.audit = append(f.audit, s); f.amu.Unlock() },
	}
	if mod != nil {
		mod(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.vet = func(a netip.Addr) string {
		if a.IsLoopback() {
			return ""
		}
		return p.refusedAddr(a)
	}
	f.p = p
	go p.Serve()
	t.Cleanup(p.Close)
	return f
}

// raw sends req verbatim and returns the status line and body.
func raw(t *testing.T, addr, req string) (string, string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("reading the answer to %q: %v", req, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.Status, string(b)
}

func TestKubeProxyInjectsTheBearerAndForwardsToThePinnedServerOnly(t *testing.T) {
	up := newUpstream(t, nil)
	f := start(t, up, "/k8s/clusters/c1", nil)
	pinned, _ := url.Parse(up.srv.URL)
	status, body := raw(t, f.addr, "GET /api/v1/namespaces HTTP/1.1\r\nHost: evil.example\r\n"+
		"X-Forwarded-Host: evil.example\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(status, "200") || body != "path=/k8s/clusters/c1/api/v1/namespaces" {
		t.Fatalf("status %q body %q", status, body)
	}
	if up.auths[0] != "Bearer "+testToken {
		t.Errorf("upstream Authorization = %q", up.auths[0])
	}
	if up.hosts[0] != pinned.Host {
		t.Errorf("upstream Host = %q, want the pinned %q", up.hosts[0], pinned.Host)
	}
	if v := up.reqs[0].Header.Get("X-Forwarded-Host"); v != "" {
		t.Errorf("X-Forwarded-Host reached the server: %q", v)
	}
	if v := up.reqs[0].Header.Get("X-Forwarded-For"); v != "" {
		t.Errorf("X-Forwarded-For was added: %q", v)
	}
}

func TestKubeProxyRefusesIdentityHeaders(t *testing.T) {
	up := newUpstream(t, nil)
	f := start(t, up, "", nil)
	for _, h := range []string{
		"Authorization: Bearer mine",
		"authorization: Basic eDp5",
		"Proxy-Authorization: Basic eDp5",
		"Impersonate-User: admin",
		"Impersonate-Group: system:masters",
		"Impersonate-Uid: 0",
		"Impersonate-Extra-Scopes: all",
		"Impersonate_User: admin",
		"IMPERSONATE-USER: admin",
		"X-Remote-User: admin",
		"X-Remote-Group: system:masters",
		"X-Remote-Extra-Foo: bar",
		"Sec-WebSocket-Protocol: v5.channel.k8s.io, base64url.bearer.authorization.k8s.io.bWluZQ",
		"Trailer: Impersonate-User",
	} {
		status, body := raw(t, f.addr, "GET /api HTTP/1.1\r\nHost: x\r\n"+h+"\r\nConnection: close\r\n\r\n")
		if !strings.HasPrefix(status, "403") && !strings.HasPrefix(status, "400") {
			t.Errorf("%q: status %q body %q, want a refusal", h, status, body)
		}
	}
	if n := up.count(); n != 0 {
		t.Errorf("%d refused requests reached the server", n)
	}
	if n := f.tokens.Load(); n != 0 {
		t.Errorf("the token was fetched %d times for refused requests", n)
	}
}

func TestKubeProxyRefusesCONNECTAndAbsoluteURI(t *testing.T) {
	up := newUpstream(t, nil)
	f := start(t, up, "", nil)
	for _, req := range []string{
		"CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n",
		"GET https://evil.example/api HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
		"GET http://evil.example/api HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
	} {
		status, _ := raw(t, f.addr, req)
		if strings.HasPrefix(status, "2") {
			t.Errorf("%q: %s", strings.SplitN(req, "\r\n", 2)[0], status)
		}
	}
	// net/http answers "OPTIONS *" itself, 200 and empty, without calling the
	// handler; what matters is that it is not forwarded.
	raw(t, f.addr, "OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if n := up.count(); n != 0 {
		t.Errorf("%d steering requests reached the server", n)
	}
}

// A gateway in front of several clusters that normalises paths would resolve
// these outside the pinned prefix, carrying the bearer (red team, measured:
// forwarded unchanged before this refusal).
func TestKubeProxyRefusesDotSegments(t *testing.T) {
	up := newUpstream(t, nil)
	f := start(t, up, "/k8s/clusters/c1", nil)
	for _, p := range []string{
		"/../c2/api", "/api/../../c2", "/%2e%2e/c2/api", "/%2E%2E/c2", "/..%2fc2/api",
		"/api/%2f/x", "/./api", "/api//v1", `/api\..\c2`, "/api/%5c",
	} {
		status, _ := raw(t, f.addr, "GET "+p+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		if !strings.HasPrefix(status, "400") {
			t.Errorf("%s: %s, want 400", p, status)
		}
	}
	if n := up.count(); n != 0 {
		t.Errorf("%d dot-segment requests reached the server", n)
	}
	if status, _ := raw(t, f.addr, "GET /api/v1/namespaces/a.b/pods/c.d HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.HasPrefix(status, "200") {
		t.Errorf("dotted object names were refused: %s", status)
	}
}

// kubectl exec, attach and port-forward are upgrades. Go's HTTP/2 transport
// refuses them, and the upstream here offers h2, so this passing is the
// proof the transport stays on HTTP/1.1.
func TestKubeProxyUpgradeRoundTrips(t *testing.T) {
	for _, proto := range []string{"SPDY/3.1", "websocket"} {
		t.Run(proto, func(t *testing.T) {
			up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Upgrade") != proto || r.Header.Get("Authorization") != "Bearer "+testToken {
					http.Error(w, "no upgrade", 400)
					return
				}
				c, brw, err := http.NewResponseController(w).Hijack()
				if err != nil {
					return
				}
				defer c.Close()
				fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", proto)
				brw.Flush()
				line, _ := brw.ReadString('\n')
				fmt.Fprintf(brw, "echo:%s", line)
				brw.Flush()
			})
			f := start(t, up, "", nil)
			c, err := net.Dial("tcp", f.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			fmt.Fprintf(c, "POST /api/v1/namespaces/d/pods/p/exec HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", proto)
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, nil)
			if err != nil || resp.StatusCode != 101 {
				t.Fatalf("upgrade: %v %v", resp, err)
			}
			io.WriteString(c, "hello\n")
			got, _ := br.ReadString('\n')
			if got != "echo:hello\n" {
				t.Errorf("through the tunnel: %q", got)
			}
		})
	}
}

func TestKubeProxyStreamsAWatch(t *testing.T) {
	next := make(chan struct{})
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		for i := range 3 {
			fmt.Fprintf(w, "{\"event\":%d}\n", i)
			w.(http.Flusher).Flush()
			if i < 2 {
				select {
				case <-next:
				case <-time.After(5 * time.Second):
					return
				}
			}
		}
	})
	f := start(t, up, "", nil)
	resp, err := http.Get("http://" + f.addr + "/api/v1/pods?watch=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	for i := range 3 {
		line, err := br.ReadString('\n')
		if err != nil || line != fmt.Sprintf("{\"event\":%d}\n", i) {
			t.Fatalf("event %d: %q %v (an event held back until the next is written never arrives)", i, line, err)
		}
		if i < 2 {
			next <- struct{}{}
		}
	}
}

func TestKubeProxyDialerRefusesLoopbackHostAndMetadata(t *testing.T) {
	up := newUpstream(t, nil)
	for _, a := range []string{
		"127.0.0.1", "127.9.9.9", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::",
		"169.254.169.254", "fe80::1", "224.0.0.1", "ff02::1",
		"fd00:ec2::254", "100.100.100.200", "168.63.129.16", "192.0.2.10",
	} {
		addr := netip.MustParseAddr(a)
		var dialled atomic.Bool
		f := start(t, up, "", func(c *Config) {
			c.Server, _ = url.Parse("https://kube.example:6443")
			c.HostAddrs = []netip.Addr{netip.MustParseAddr("192.0.2.10")}
			c.Lookup = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{addr}, nil
			}
		})
		f.p.vet = func(x netip.Addr) string {
			why := f.p.refusedAddr(x)
			if why == "" {
				dialled.Store(true)
			}
			return why
		}
		status, body := raw(t, f.addr, "GET /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		if !strings.HasPrefix(status, "502") || !strings.Contains(body, "refusing to dial") {
			t.Errorf("%s: %s %q, want a 502 naming the refusal", a, status, body)
		}
		if dialled.Load() {
			t.Errorf("%s was dialled", a)
		}
	}
	if n := up.count(); n != 0 {
		t.Errorf("%d requests reached a server", n)
	}
}

// The proxy asks the source once per request and never again because the
// cluster said 401: a pod the sandbox controls can make it say that on every
// request, and a re-mint on 401 would spend the run's mint budget for it.
func TestKubeProxyNeverMintsOn401(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
	f := start(t, up, "", nil)
	for range 5 {
		if status, _ := raw(t, f.addr, "GET /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.HasPrefix(status, "401") {
			t.Fatalf("status %s, want the server's 401 passed through", status)
		}
	}
	if n := f.tokens.Load(); n != 5 {
		t.Errorf("5 requests answered 401 asked for the token %d times, want 5", n)
	}
	if n := up.count(); n != 5 {
		t.Errorf("the server saw %d requests for 5 sent: a 401 was retried", n)
	}
}

func TestKubeProxyAnswers503WhenTheSourceFails(t *testing.T) {
	up := newUpstream(t, nil)
	f := start(t, up, "", func(c *Config) {
		c.Token = func(context.Context) (policy.Secret, error) { return nil, errors.New("mint budget spent") }
	})
	status, body := raw(t, f.addr, "GET /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(status, "503") || !strings.Contains(body, "mint budget spent") {
		t.Errorf("%s %q", status, body)
	}
	if up.count() != 0 {
		t.Error("a request with no token reached the server")
	}
}

func TestKubeProxyCloseEndsHijackedCopies(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		c, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n")
		brw.Flush()
		io.Copy(io.Discard, brw) // holds the tunnel open until the proxy closes it
	})
	f := start(t, up, "", nil)
	c, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "POST /exec HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n")
	br := bufio.NewReader(c)
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 101 {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	done := make(chan struct{})
	go func() { f.p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return with an upgraded tunnel open")
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.ReadByte(); err == nil || errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		t.Errorf("the guest's side of the tunnel is still open after Close: %v", err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func TestKubeProxyAuditNeverCarriesTheToken(t *testing.T) {
	up := newUpstream(t, nil)
	f := start(t, up, "", nil)
	raw(t, f.addr, "GET /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	raw(t, f.addr, "GET /api HTTP/1.1\r\nHost: x\r\nImpersonate-User: a\r\nConnection: close\r\n\r\n")
	f.amu.Lock()
	defer f.amu.Unlock()
	if len(f.audit) < 2 {
		t.Fatalf("audit lines: %q", f.audit)
	}
	for _, l := range f.audit {
		if strings.Contains(l, testToken) {
			t.Errorf("audit line carries the token: %q", l)
		}
	}
}

// A cloned default transport would read HTTPS_PROXY from snug's environment
// and send the bearer through whatever proxy it names.
func TestKubeProxyIgnoresProxyEnvironment(t *testing.T) {
	var hit atomic.Bool
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Store(true) }))
	defer trap.Close()
	t.Setenv("HTTPS_PROXY", trap.URL)
	t.Setenv("https_proxy", trap.URL)
	up := newUpstream(t, nil)
	f := start(t, up, "", nil)
	if status, _ := raw(t, f.addr, "GET /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.HasPrefix(status, "200") {
		t.Errorf("status %s", status)
	}
	if hit.Load() {
		t.Error("the request went through HTTPS_PROXY")
	}
}

func TestKubeProxyConnLimit(t *testing.T) {
	up := newUpstream(t, nil)
	f := start(t, up, "", func(c *Config) { c.MaxConns = 1 })
	hold, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	time.Sleep(50 * time.Millisecond)
	c, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET /api HTTP/1.1\r\nHost: x\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := bufio.NewReader(c).ReadByte(); err == nil {
		t.Error("a connection past MaxConns was answered")
	}
}
