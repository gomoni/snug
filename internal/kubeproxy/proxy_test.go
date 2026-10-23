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
	"github.com/gomoni/snug/internal/sandbox"
	"golang.org/x/sys/unix"
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

// waitAudit returns once the proxy has written at least n audit lines, or after
// 5s. A forwarded request is audited after the response is written, so a client
// that has read its answer can look before the line exists.
func (f *pfix) waitAudit(n int) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.amu.Lock()
		got := len(f.audit)
		f.amu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
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
		Audit:    func(s string) { f.amu.Lock(); f.audit = append(f.audit, s); f.amu.Unlock() },
		HostNets: noHostNets, Route: physicalRoute,
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
			c.HostNets = hostNets("192.0.2.10/32")
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
	f.waitAudit(2)
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
			HostNets: hostNets("192.0.2.10/32"), Route: physicalRoute,
			Lookup: func(context.Context, string) ([]netip.Addr, error) { return addrs, nil }})
		if err == nil || !strings.Contains(err.Error(), "cluster on this host") {
			t.Errorf("%v: Preflight = %v, want the on-this-host refusal", answer, err)
		}
	}
	for _, lit := range []string{"https://127.0.0.1:6443", "https://[::1]:6443"} {
		server, _ := url.Parse(lit)
		if err := Preflight(context.Background(), Config{Server: server, HostNets: noHostNets, Route: physicalRoute}); err == nil {
			t.Errorf("%s: Preflight accepted a loopback literal", lit)
		}
	}
	server, _ := url.Parse("https://aks-dev.example.azmk8s.io:443")
	if err := Preflight(context.Background(), Config{Server: server, HostNets: noHostNets, Route: physicalRoute,
		Lookup: func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{public}, nil }}); err != nil {
		t.Errorf("a public server: %v", err)
	}
	if err := Preflight(context.Background(), Config{Server: server, HostNets: noHostNets, Route: physicalRoute,
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

func noHostNets() ([]sandbox.HostNet, error) { return nil, nil }

// physicalRoute answers every route lookup with an allowed uplink, so a test
// about the address classes or the attached subnets is not also about routing.
func physicalRoute(netip.Addr) (sandbox.HostNet, error) {
	return sandbox.HostNet{Iface: "wlp3s0", Kind: "physical", Allowed: true, Unicast: true}, nil
}

func link(iface, kind string, allowed bool, ps ...string) func() ([]sandbox.HostNet, error) {
	return func() ([]sandbox.HostNet, error) {
		var out []sandbox.HostNet
		for _, p := range ps {
			out = append(out, sandbox.HostNet{Prefix: netip.MustParsePrefix(p), Iface: iface, Kind: kind, Allowed: allowed})
		}
		return out, nil
	}
}

// hostNets is ps on a bridge, which the dialer refuses.
func hostNets(ps ...string) func() ([]sandbox.HostNet, error) {
	return link("br-1a2b", "bridge", false, ps...)
}

func preflightAnswer(t *testing.T, nets func() ([]sandbox.HostNet, error), a string) error {
	t.Helper()
	server, _ := url.Parse("https://kube.example:6443")
	addr := netip.MustParseAddr(a)
	return Preflight(context.Background(), Config{Server: server, HostNets: nets, Route: physicalRoute,
		Lookup: func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{addr}, nil }})
}

// A subnet on a link that is not on the allow list is one hop from this host
// as a cluster's nodes; a subnet on a physical NIC or a layer-3 VPN is a
// network the host is only a neighbour on. Each refusal row has its positive
// control in the pass table.
func TestKubeProxyRefusesASubnetAttachedToThisHost(t *testing.T) {
	refused := []struct {
		name, iface, kind, prefix, addr, want string
	}{
		{"docker bridge", "br-1a2b", "bridge", "172.18.0.1/16", "172.18.0.2", "(bridge)"},
		{"libvirt bridge", "virbr0", "bridge", "192.168.39.1/24", "192.168.39.10", "(bridge)"},
		{"tap", "tap0", "tap", "192.168.50.1/24", "192.168.50.9", "(tap)"},
		{"veth", "veth1", "veth", "10.88.0.1/16", "10.88.0.4", "(veth)"},
		{"unknown kind", "foo0", "frobnicate", "10.7.0.1/24", "10.7.0.9", "a link kind snug does not treat as a remote network"},
		{"gre", "gre1", "gre", "10.8.0.1/24", "10.8.0.9", "a link kind snug does not treat as a remote network"},
		{"bridge with an enslaved NIC", "br0", "bridge", "192.168.1.120/24", "192.168.1.77", "(bridge)"},
		{"no kind, no device", "vboxnet0", "virtual", "192.168.56.1/24", "192.168.56.101", "(virtual)"},
		{"enslaved physical", "enp3s0", "enslaved physical", "192.168.1.120/24", "192.168.1.77", "(enslaved physical)"},
		{"v6 on a bridge", "br-1a2b", "bridge", "2001:db8:1::5/64", "2001:db8:1::99", "(bridge)"},
		{"v4-mapped on a bridge", "br-1a2b", "bridge", "172.18.0.1/16", "::ffff:172.18.0.2", "(bridge)"},
	}
	for _, c := range refused {
		t.Run("refuses "+c.name, func(t *testing.T) {
			err := preflightAnswer(t, link(c.iface, c.kind, false, c.prefix), c.addr)
			if err == nil || !strings.Contains(err.Error(), "a subnet on "+c.iface) || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s on %s: Preflight = %v, want the subnet refusal naming %s and %q", c.addr, c.prefix, err, c.iface, c.want)
			}
		})
	}
	passes := []struct{ name, iface, kind, prefix, addr string }{
		{"LAN on a physical NIC", "wlp3s0", "physical", "192.168.1.120/24", "192.168.1.77"},
		{"layer-3 tun", "tun0", "tun", "10.1.0.5/24", "10.1.2.3"},
		{"wireguard", "wg0", "wireguard", "10.1.0.5/16", "10.1.2.3"},
		{"v6 LAN on a physical NIC", "wlp3s0", "physical", "2001:db8:1::5/64", "2001:db8:1::99"},
	}
	for _, c := range passes {
		t.Run("passes "+c.name, func(t *testing.T) {
			if err := preflightAnswer(t, link(c.iface, c.kind, true, c.prefix), c.addr); err != nil {
				t.Errorf("%s on %s (%s): %v", c.addr, c.prefix, c.kind, err)
			}
		})
	}
	t.Run("off every refused subnet", func(t *testing.T) {
		nets := link("br-1a2b", "bridge", false, "172.18.0.1/16")
		if err := preflightAnswer(t, nets, "203.0.113.7"); err != nil {
			t.Errorf("203.0.113.7 beside a bridge: %v", err)
		}
	})
}

func routeVia(iface, kind string, allowed bool) func(netip.Addr) (sandbox.HostNet, error) {
	return func(netip.Addr) (sandbox.HostNet, error) {
		return sandbox.HostNet{Iface: iface, Kind: kind, Allowed: allowed, Unicast: true}, nil
	}
}

// routeDefaultVia is a default route (rtm_dst_len 0) out of the interface.
func routeDefaultVia(iface, kind string, allowed bool) func(netip.Addr) (sandbox.HostNet, error) {
	return func(netip.Addr) (sandbox.HostNet, error) {
		return sandbox.HostNet{Iface: iface, Kind: kind, Allowed: allowed, Default: true, Unicast: true}, nil
	}
}

// A local, broadcast or anycast entry names a configured device but the kernel
// delivers to this host: an address created by no RTM_NEWADDR is still the host.
func TestKubeProxyRefusesALocallyDeliveredRoute(t *testing.T) {
	route := func(unicast bool, typ uint8) func(netip.Addr) (sandbox.HostNet, error) {
		return func(netip.Addr) (sandbox.HostNet, error) {
			return sandbox.HostNet{Iface: "eth0", Kind: "physical", Allowed: true, Unicast: unicast, RouteBits: 16, RouteType: typ}, nil
		}
	}
	for typ, name := range map[uint8]string{unix.RTN_LOCAL: "local", unix.RTN_BROADCAST: "broadcast",
		unix.RTN_ANYCAST: "anycast", 99: "type 99"} {
		err := preflightRoute(t, route(false, typ), "10.77.1.1")
		if err == nil || !strings.Contains(err.Error(), "is a "+name+" route on eth0") {
			t.Errorf("%s route: %v, want the locally-delivered refusal", name, err)
		}
	}
	if err := preflightRoute(t, route(true, unix.RTN_UNICAST), "10.77.1.1"); err != nil {
		t.Errorf("positive control, the same entry as unicast: %v", err)
	}
	zero := func(netip.Addr) (sandbox.HostNet, error) { return sandbox.HostNet{Allowed: true, Default: true}, nil }
	if err := preflightRoute(t, zero, "10.77.1.1"); err == nil {
		t.Error("a HostNet with Unicast unset was admitted")
	}
}

func preflightRoute(t *testing.T, route func(netip.Addr) (sandbox.HostNet, error), a string) error {
	t.Helper()
	server, _ := url.Parse("https://kube.example:6443")
	addr := netip.MustParseAddr(a)
	return Preflight(context.Background(), Config{Server: server, HostNets: noHostNets, Route: route,
		Lookup: func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{addr}, nil }})
}

// 10.10.0.0/16 via a gateway on a bridge is on no attached subnet, so only the
// route lookup sees that the packet leaves through the bridge. The same
// address through a physical uplink is the positive control.
func TestKubeProxyRefusesWhenTheRouteLeavesViaAHostBridge(t *testing.T) {
	err := preflightRoute(t, routeVia("br-x", "bridge", false), "10.10.3.4")
	if err == nil || !strings.Contains(err.Error(), "leaves via br-x (bridge)") {
		t.Errorf("route via a bridge: %v, want the route refusal", err)
	}
	if err := preflightRoute(t, routeVia("wlp3s0", "physical", true), "10.10.3.4"); err != nil {
		t.Errorf("route via a physical uplink: %v", err)
	}
	// An uplink enslaved to br0 carries the default route: the internet
	// beyond it is not a cluster on this host. A specific route (the case
	// above) through the same bridge is refused.
	if err := preflightRoute(t, routeDefaultVia("br0", "bridge", false), "203.0.113.7"); err != nil {
		t.Errorf("default route via a bridge: %v, want it admitted", err)
	}
	failing := func(netip.Addr) (sandbox.HostNet, error) { return sandbox.HostNet{}, errors.New("netlink: boom") }
	if err := preflightRoute(t, failing, "10.10.3.4"); err == nil || !strings.Contains(err.Error(), "route") {
		t.Errorf("failing route lookup: %v, want a refusal", err)
	}
}

func TestKubeProxyUnknownLinkKindRefuses(t *testing.T) {
	err := preflightRoute(t, routeVia("xfrm0", "xfrm", false), "10.10.3.4")
	if err == nil || !strings.Contains(err.Error(), "a link kind snug does not treat as a remote network") {
		t.Errorf("unknown kind: %v", err)
	}
	if err := preflightRoute(t, routeVia("wg0", "wireguard", true), "10.10.3.4"); err != nil {
		t.Errorf("positive control, wireguard: %v", err)
	}
}

// A vboxnet-like link has no IFLA_INFO_KIND and no backing device; the
// classifier names it "virtual" and the dialer refuses it like any bridge.
func TestKubeProxyNoKindWithoutDeviceIsVirtual(t *testing.T) {
	err := preflightAnswer(t, link("vboxnet0", "virtual", false, "192.168.56.1/24"), "192.168.56.101")
	if err == nil || !strings.Contains(err.Error(), "vboxnet0 (virtual)") {
		t.Errorf("no-kind link without a device: %v", err)
	}
	if err := preflightAnswer(t, link("enp3s0", "physical", true, "192.168.56.1/24"), "192.168.56.101"); err != nil {
		t.Errorf("positive control, the same subnet on a physical NIC: %v", err)
	}
}

// A tap is the kernel's tun kind without IFF_POINTOPOINT: a layer-2 segment a
// VM sits on, not a VPN.
func TestKubeProxyTapIsNotAVPN(t *testing.T) {
	err := preflightAnswer(t, link("tap0", "tap", false, "10.1.0.1/24"), "10.1.0.9")
	if err == nil || !strings.Contains(err.Error(), "tap0 (tap)") {
		t.Errorf("tap: %v", err)
	}
	if err := preflightAnswer(t, link("tun0", "tun", true, "10.1.0.1/24"), "10.1.0.9"); err != nil {
		t.Errorf("positive control, tun with POINTOPOINT: %v", err)
	}
}

// Red-team round on #671: the class checks read only the address as
// written, so an IPv6 spelling that a translator or relay delivers to
// loopback or a metadata service passed, and so did 0.0.0.0/8.
func TestKubeProxyRefusesIPv6SpellingsOfLocalAddresses(t *testing.T) {
	for _, a := range []string{
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::6464:64c8", "64:ff9b:1::7f00:1",
		"2002:7f00:1::1", "2002:a9fe:a9fe::1", "::7f00:1", "::a9fe:a9fe", "::ffff:0:7f00:1",
		"64:ff9b::c000:20a", "0.1.2.3", "0.255.255.255",
	} {
		if err := preflightAnswer(t, hostNets("192.0.2.10/32"), a); err == nil {
			t.Errorf("%s: Preflight accepted it", a)
		}
	}
	// A DNS64 answer for a public cluster is how an IPv6-only network
	// reaches it, and stays usable.
	if err := preflightAnswer(t, noHostNets, "64:ff9b::cb00:7107"); err != nil {
		t.Errorf("NAT64 spelling of 203.0.113.7: %v", err)
	}
}

// Red-team round on #671: the proxy read the host's addresses once, when it
// started, so a bridge or an address the host gained during the run (kind
// create, a VPN coming up) was dialled. HostNets is read on every vet.
func TestKubeProxyRereadsHostNetsOnEveryDial(t *testing.T) {
	up := newUpstream(t, nil)
	var nets atomic.Value
	nets.Store([]sandbox.HostNet(nil))
	f := start(t, up, "", func(c *Config) {
		c.HostNets = func() ([]sandbox.HostNet, error) { return nets.Load().([]sandbox.HostNet), nil }
	})
	// The upstream is on loopback; vet it as the cluster's public address.
	stand := netip.MustParseAddr("198.51.100.5")
	f.p.vet = func(a netip.Addr) string {
		if a.IsLoopback() {
			return f.p.refusedAddr(stand)
		}
		return f.p.refusedAddr(a)
	}
	req := "GET /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
	if status, _ := raw(t, f.addr, req); !strings.HasPrefix(status, "200") {
		t.Fatalf("before the bridge: %s, want 200", status)
	}
	nets.Store([]sandbox.HostNet{{Prefix: netip.MustParsePrefix("198.51.100.1/24"), Iface: "br-new", Kind: "bridge"}})
	f.p.tr.CloseIdleConnections() // a new connection, not the pooled one
	if status, _ := raw(t, f.addr, req); !strings.HasPrefix(status, "502") {
		t.Errorf("after the host gained 198.51.100.1/24: %s, want 502", status)
	}
	if n := up.count(); n != 1 {
		t.Errorf("%d requests reached the server, want 1", n)
	}
}

// A HostNets that fails refuses the dial: an empty list would read as "this
// host owns nothing", which is the silent downgrade.
func TestKubeProxyRefusesWhenHostNetsFail(t *testing.T) {
	failing := func() ([]sandbox.HostNet, error) { return nil, errors.New("netlink: boom") }
	if err := preflightAnswer(t, failing, "203.0.113.7"); err == nil || !strings.Contains(err.Error(), "could not be listed") {
		t.Errorf("Preflight with failing HostNets: %v", err)
	}
	server, _ := url.Parse("https://kube.example:6443")
	if err := Preflight(context.Background(), Config{Server: server}); err == nil {
		t.Error("Preflight without HostNets accepted")
	}
	if err := Preflight(context.Background(), Config{Server: server, HostNets: noHostNets}); err == nil {
		t.Error("Preflight without Route accepted")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, err := New(Config{Listener: ln, Server: server, Token: func(context.Context) (policy.Secret, error) {
		return policy.Secret("x"), nil
	}}); err == nil || !strings.Contains(err.Error(), "HostNets") {
		t.Errorf("New without HostNets: %v", err)
	}
}
