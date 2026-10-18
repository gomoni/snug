package kubeproxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
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
	peers []string // client certificate subject per request, "" for none
}

func newUpstream(t *testing.T, h http.HandlerFunc) *upstream {
	return newUpstreamTLS(t, h, nil)
}

// newUpstreamTLS is newUpstream that requires and verifies a client
// certificate issued as clientCA, when clientCA is not nil.
func newUpstreamTLS(t *testing.T, h http.HandlerFunc, clientCA *x509.Certificate) *upstream {
	t.Helper()
	u := &upstream{}
	u.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.reqs = append(u.reqs, r)
		u.auths = append(u.auths, r.Header.Get("Authorization"))
		u.hosts = append(u.hosts, r.Host)
		peer := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peer = r.TLS.PeerCertificates[0].Subject.String()
		}
		u.peers = append(u.peers, peer)
		u.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		fmt.Fprintf(w, "path=%s", r.URL.EscapedPath())
	}))
	u.srv.EnableHTTP2 = true
	if clientCA != nil {
		pool := x509.NewCertPool()
		pool.AddCert(clientCA)
		u.srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	}
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

// clientCert is a self-signed client certificate standing in for an AKS
// local account's CN=masterclient.
func clientCert(t *testing.T) *tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7),
		Subject:   pkix.Name{CommonName: "masterclient", Organization: []string{"system:masters"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}
}

// A bearer shape SETS Authorization: the client's own is replaced, so the
// credential on the wire is the pinned one. Every other header — the
// impersonation ones included — is the cluster's to judge and is forwarded.
func TestKubeProxyBearerOverwritesTheClientsAuthorization(t *testing.T) {
	up := newUpstream(t, nil)
	f := start(t, up, "", nil)
	status, _ := raw(t, f.addr, "GET /api HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer mine\r\n"+
		"Impersonate-User: someone\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(status, "200") || up.count() != 1 {
		t.Fatalf("status %q, %d upstream requests", status, up.count())
	}
	if up.auths[0] != "Bearer "+testToken {
		t.Errorf("upstream Authorization = %q, want snug's", up.auths[0])
	}
	if v := up.reqs[0].Header.Get("Impersonate-User"); v != "someone" {
		t.Errorf("Impersonate-User upstream = %q, want it forwarded as sent", v)
	}
	if up.peers[0] != "" {
		t.Errorf("a bearer shape presented a client certificate %q", up.peers[0])
	}
}

// The certificate shape presents the client certificate in the handshake,
// adds no Authorization of snug's, and forwards the client's headers as sent.
func TestKubeProxyPresentsTheClientCertificate(t *testing.T) {
	cc := clientCert(t)
	up := newUpstreamTLS(t, nil, cc.Leaf)
	f := start(t, up, "", func(c *Config) { c.Token, c.ClientCert = nil, cc })
	status, body := raw(t, f.addr, "GET /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(status, "200") {
		t.Fatalf("status %q body %q", status, body)
	}
	if up.peers[0] != "CN=masterclient,O=system:masters" || up.auths[0] != "" {
		t.Errorf("upstream saw peer %q Authorization %q, want the certificate and no bearer", up.peers[0], up.auths[0])
	}
	raw(t, f.addr, "GET /api HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer mine\r\nImpersonate-User: someone\r\n"+
		"Connection: close\r\n\r\n")
	if up.auths[1] != "Bearer mine" || up.reqs[1].Header.Get("Impersonate-User") != "someone" {
		t.Errorf("certificate shape changed the client's headers: Authorization %q Impersonate-User %q",
			up.auths[1], up.reqs[1].Header.Get("Impersonate-User"))
	}
	f.amu.Lock()
	defer f.amu.Unlock()
	if !slices.ContainsFunc(f.audit, func(s string) bool {
		return s == "server requested a client certificate; sent CN=masterclient,O=system:masters"
	}) {
		t.Errorf("no handshake audit line: %q", f.audit)
	}
}

// Without the certificate the pinned server refuses the handshake: the
// upstream in the test above really did verify it.
func TestKubeProxyCertificateUpstreamRefusesNone(t *testing.T) {
	cc := clientCert(t)
	up := newUpstreamTLS(t, nil, cc.Leaf)
	f := start(t, up, "", nil)
	if status, _ := raw(t, f.addr, "GET /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.HasPrefix(status, "502") {
		t.Errorf("status %q without a client certificate, want 502", status)
	}
}

func TestKubeProxyNewRefusesNeitherOrBothCredentials(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	su, _ := url.Parse("https://api.example")
	tok := func(context.Context) (policy.Secret, error) { return nil, nil }
	for name, cfg := range map[string]Config{
		"neither": {Listener: ln, Server: su},
		"both":    {Listener: ln, Server: su, Token: tok, ClientCert: clientCert(t)},
	} {
		if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Errorf("%s: %v", name, err)
		}
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
// Red-team G3: TRACE and made-up methods reached the upstream carrying the
// bearer; a front-end echoing TRACE would hand it back inside.
func TestKubeProxyRefusesMethodsTheAPIDoesNotSpeak(t *testing.T) {
	up := newUpstream(t, nil)
	f := start(t, up, "", nil)
	for _, m := range []string{"TRACE", "TRACK", "FOO", "PROPFIND"} {
		if status, _ := raw(t, f.addr, m+" /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); !strings.HasPrefix(status, "405") {
			t.Errorf("%s: %s, want 405", m, status)
		}
	}
	if n := up.count(); n != 0 {
		t.Errorf("%d refused-method requests reached the server", n)
	}
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		if status, _ := raw(t, f.addr, m+" /api HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); !strings.HasPrefix(status, "200") {
			t.Errorf("%s: %s, want it forwarded", m, status)
		}
	}
}

func TestKubeProxyRefusesDotSegments(t *testing.T) {
	up := newUpstream(t, nil)
	f := start(t, up, "/k8s/clusters/c1", nil)
	for _, p := range []string{
		"/../c2/api", "/api/../../c2", "/%2e%2e/c2/api", "/%2E%2E/c2", "/..%2fc2/api",
		"/api/%2f/x", "/./api", "/api//v1", `/api\..\c2`, "/api/%5c",
		// A second decoding round, a stripped path parameter, overlong and
		// look-alike encodings (red team, measured forwarded before).
		"/%252e%252e/c2/api", "/..;/c2/api", "/api;x/v1", "/%c0%ae%c0%ae/c2", "/%e2%80%a4%e2%80%a4/c2", "/api/%00",
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
		if !strings.HasPrefix(status, "502") || strings.TrimSpace(body) != upstreamFailed {
			t.Errorf("%s: %s %q, want a 502 with the fixed body", a, status, body)
		}
		f.amu.Lock()
		audited := strings.Join(f.audit, "\n")
		f.amu.Unlock()
		if !strings.Contains(audited, "refusing to dial") {
			t.Errorf("%s: the audit does not name the refusal: %q", a, audited)
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
	if !strings.HasPrefix(status, "503") || strings.TrimSpace(body) != noToken {
		t.Errorf("%s %q, want the fixed body: the source's error carries the plugin's stderr", status, body)
	}
	if up.count() != 0 {
		t.Error("a request with no token reached the server")
	}
}

// Red-team F1: a dial or resolve error named the resolved address, the
// pinned server's name and the host's DNS resolver in the 502 body, inside an
// offline sandbox. The body is fixed; the detail is the host's audit line.
func TestKubeProxyUpstreamErrorBodyCarriesNoHostDetail(t *testing.T) {
	up := newUpstream(t, nil)
	f := start(t, up, "", func(c *Config) {
		c.Server, _ = url.Parse("https://dead.example.invalid:6443")
		c.Lookup = func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("lookup dead.example.invalid on 192.0.2.53:53: no such host")
		}
	})
	_, body := raw(t, f.addr, "GET /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	for _, bad := range []string{"dead.example", "192.0.2.53", "lookup", "6443"} {
		if strings.Contains(body, bad) {
			t.Errorf("the 502 body inside carries %q: %q", bad, body)
		}
	}
	f.amu.Lock()
	defer f.amu.Unlock()
	if !strings.Contains(strings.Join(f.audit, "\n"), "192.0.2.53") {
		t.Errorf("the detail is not on the host's audit: %q", f.audit)
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

// A server on this host is refused before the sandbox exists, and a name
// whose answer holds one local address among public ones is refused whole:
// that name points at this host.
func TestKubeProxyPreflightRefusesAServerOnThisHost(t *testing.T) {
	public := netip.MustParseAddr("203.0.113.7")
	for _, answer := range [][]string{
		{"127.0.0.1"}, {"::1"}, {"0.0.0.0"}, {"192.0.2.10"}, {"fe80::1"}, {"169.254.169.254"},
		{"203.0.113.7", "127.0.0.1"}, {"203.0.113.7", "192.0.2.10"},
	} {
		var addrs []netip.Addr
		for _, a := range answer {
			addrs = append(addrs, netip.MustParseAddr(a))
		}
		server, _ := url.Parse("https://kubernetes.docker.internal:6443")
		err := Preflight(context.Background(), Config{Server: server,
			HostAddrs: []netip.Addr{netip.MustParseAddr("192.0.2.10")},
			Lookup:    func(context.Context, string) ([]netip.Addr, error) { return addrs, nil }})
		if err == nil || !strings.Contains(err.Error(), "cluster on this host") {
			t.Errorf("%v: Preflight = %v, want the on-this-host refusal", answer, err)
		}
	}
	for _, lit := range []string{"https://127.0.0.1:6443", "https://[::1]:6443"} {
		server, _ := url.Parse(lit)
		if err := Preflight(context.Background(), Config{Server: server}); err == nil {
			t.Errorf("%s: Preflight accepted a loopback literal", lit)
		}
	}
	server, _ := url.Parse("https://aks-dev.example.azmk8s.io:443")
	if err := Preflight(context.Background(), Config{Server: server,
		Lookup: func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{public}, nil }}); err != nil {
		t.Errorf("a public server: %v", err)
	}
	if err := Preflight(context.Background(), Config{Server: server,
		Lookup: func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }}); err == nil {
		t.Error("a name that does not resolve was accepted")
	}
}

func TestKubeProxyDialerRefusesAMixedAnswer(t *testing.T) {
	up := newUpstream(t, nil)
	f := start(t, up, "", func(c *Config) {
		c.Server, _ = url.Parse("https://kube.example:6443")
		c.Lookup = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("127.0.0.1")}, nil
		}
	})
	f.p.vet = f.p.refusedAddr
	status, _ := raw(t, f.addr, "GET /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(status, "502") {
		t.Errorf("a name resolving to a public address and loopback: %s, want 502", status)
	}
	if n := up.count(); n != 0 {
		t.Errorf("%d requests reached a server", n)
	}
}
