// Package kubeproxy is identity.kubectl's authenticating reverse proxy: a
// server in snug's own process, on a listener whose socket lives in the
// sandbox's network namespace, that forwards what kubectl inside sends to the
// ONE pinned API server and presents the host credential on the way out.
//
// The credential never enters the sandbox. The guest's kubeconfig names
// http://127.0.0.1:6443 and carries none; this package is the only holder of
// it, and it presents it in exactly one place — the TLS client certificate or
// the Authorization header of a request to the pinned server.
//
// The proxy decides WHERE a request goes and with WHICH credential, and
// nothing else: every Kubernetes API method, and every path, query and header
// the cluster accepts, is forwarded, including the client's own Authorization
// and Impersonate-* headers. What that credential may do is the cluster's RBAC. A request that
// would change WHERE — a tunnel, an absolute target, a path that a gateway in
// front of several clusters would resolve to a different one — is refused
// with a 4xx, never quietly rewritten.
package kubeproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// Config is the proxy's fixed shape. Listener and Server are required, and
// exactly one of Token and ClientCert.
type Config struct {
	// Listener is the socket already listening inside the sandbox's netns.
	Listener net.Listener
	// Server is the pinned API server, https, as Resolve admitted it.
	Server *url.URL
	// CAs verifies the server; nil is the system pool, which is what the host
	// kubeconfig meant by carrying no certificate-authority-data.
	CAs *x509.CertPool
	// TLSName is the name the server's certificate is checked against.
	TLSName string
	// Token returns the bearer for one request, which replaces any
	// Authorization the client sent. It mints only when the cached token is
	// stale — never because the cluster answered 401, which a pod the sandbox
	// controls can make it do on every request.
	Token func(context.Context) (policy.Secret, error)
	// ClientCert is presented in the TLS handshake with the pinned server.
	// With it, the request is forwarded with its headers as sent.
	ClientCert *tls.Certificate
	// HostNets lists every prefix on every host interface, unmapped and
	// without a zone: the host's own addresses and the subnets attached to
	// them. The dialer calls it on
	// every vet, not once, because an address or a bridge added after start
	// is as much the host as one that was there before. Required; an error
	// refuses the dial.
	HostNets func() ([]netip.Prefix, error)
	// MaxConns bounds concurrent connections from inside; 0 is 64.
	MaxConns int
	// Lookup resolves the server's name; nil is net.DefaultResolver. A seam.
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// Audit receives one line per request and per refusal. It never carries
	// a header value, a body or the token.
	Audit func(string)
}

// Proxy serves Config.Listener. The zero value is not usable; use New.
type Proxy struct {
	cfg  Config
	ln   *trackingListener
	srv  *http.Server
	rp   *httputil.ReverseProxy
	tr   *http.Transport
	done chan struct{}

	// vet is refusedAddr; tests replace it to reach an httptest server on
	// loopback, which the real dialer refuses by design.
	vet func(netip.Addr) string

	mu       sync.Mutex
	upstream map[net.Conn]struct{}
	closed   bool
}

type tokenKey struct{}

// The bodies answered inside when the upstream or the token source fails.
// Fixed text: the detail is on the host's audit line (snug -v).
const (
	upstreamFailed = "snug kube proxy: the pinned API server could not be reached; snug -v on the host has the detail"
	noToken        = "snug kube proxy: no token for the pinned identity (the exec plugin failed, or its run " +
		"budget is spent); snug -v on the host has the detail"
)

// fixture is set only in a binary built with -tags snugfixture (fixture.go).
var fixture func(*Proxy)

// New builds the proxy. It does not start serving; Serve does.
func New(cfg Config) (*Proxy, error) {
	if cfg.Listener == nil || cfg.Server == nil {
		return nil, errors.New("kube proxy: Listener and Server are required")
	}
	if (cfg.Token == nil) == (cfg.ClientCert == nil) {
		return nil, errors.New("kube proxy: exactly one of Token and ClientCert is required")
	}
	if cfg.HostNets == nil {
		return nil, errors.New("kube proxy: HostNets is required")
	}
	if cfg.Server.Scheme != "https" || cfg.Server.Host == "" {
		return nil, fmt.Errorf("kube proxy: server %s is not https", policy.VisibleText(cfg.Server.String()))
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 64
	}
	if cfg.Lookup == nil {
		cfg.Lookup = defaultLookup
	}
	if cfg.Audit == nil {
		cfg.Audit = func(string) {}
	}
	if cfg.TLSName == "" {
		cfg.TLSName = cfg.Server.Hostname()
	}
	p := &Proxy{cfg: cfg, done: make(chan struct{}), upstream: map[net.Conn]struct{}{}}
	p.vet = p.refusedAddr
	if fixture != nil {
		fixture(p)
	}
	p.ln = newTrackingListener(cfg.Listener, cfg.MaxConns)
	tlsc := &tls.Config{
		RootCAs:    cfg.CAs,
		ServerName: cfg.TLSName,
		MinVersion: tls.VersionTLS12,
	}
	if c := cfg.ClientCert; c != nil {
		var once sync.Once
		tlsc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			once.Do(func() {
				subject := "?"
				if c.Leaf != nil {
					subject = c.Leaf.Subject.String()
				}
				p.cfg.Audit("server requested a client certificate; sent " + policy.VisibleText(subject))
			})
			return c, nil
		}
	}
	p.tr = &http.Transport{
		// Written out, not inherited: a transport cloned from the default
		// reads HTTPS_PROXY from snug's environment and would hand the bearer
		// to whatever proxy that names.
		Proxy:           nil,
		DialContext:     p.dial,
		TLSClientConfig: tlsc,
		// HTTP/1.1 only. Go's HTTP/2 transport refuses a request carrying
		// Upgrade, and kubectl exec, attach and port-forward are upgrades; an
		// empty, non-nil TLSNextProto is what turns h2 off.
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          8,
		ExpectContinueTimeout: time.Second,
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite:       p.rewrite,
		Transport:     p.tr,
		FlushInterval: -1, // every write, so a watch or logs -f is not held back
		// The detail goes to the host's audit only: a dial error names the
		// resolved address and the host's resolver, which an offline sandbox
		// has no other way to learn (red team, measured).
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.cfg.Audit(fmt.Sprintf("%s %s: upstream: %v", r.Method, policy.VisibleText(r.URL.Path), err))
			http.Error(w, upstreamFailed, http.StatusBadGateway)
		},
	}
	// No ReadTimeout or WriteTimeout: either one would cut a watch.
	p.srv = &http.Server{
		Handler:           http.HandlerFunc(p.serveHTTP),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          nil,
	}
	return p, nil
}

// Serve accepts until Close.
func (p *Proxy) Serve() {
	defer close(p.done)
	_ = p.srv.Serve(p.ln)
}

// Close stops accepting and ends every connection on both sides — including
// the ones an upgrade hijacked, which http.Server no longer tracks — and waits
// for Serve to return.
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closed = true
	for c := range p.upstream {
		c.Close()
	}
	p.mu.Unlock()
	p.srv.Close()
	p.ln.closeAll()
	p.tr.CloseIdleConnections()
	<-p.done
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if status, why := admit(r); status != 0 {
		p.cfg.Audit(fmt.Sprintf("refused %s %s: %s", r.Method, policy.VisibleText(r.URL.EscapedPath()), why))
		http.Error(w, "snug kube proxy: "+why, status)
		return
	}
	if p.cfg.Token != nil {
		tok, err := p.cfg.Token(r.Context())
		if err != nil {
			// The plugin's error carries its stderr, which stays on the host.
			p.cfg.Audit(fmt.Sprintf("%s %s: no token: %v", r.Method, policy.VisibleText(r.URL.Path), err))
			http.Error(w, noToken, http.StatusServiceUnavailable)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), tokenKey{}, tok))
	}
	sw := &statusWriter{ResponseWriter: w}
	start := time.Now()
	p.rp.ServeHTTP(sw, r)
	p.cfg.Audit(fmt.Sprintf("%s %s -> %d (%s)", r.Method, policy.VisibleText(r.URL.Path), sw.status(),
		time.Since(start).Round(time.Millisecond)))
}

// rewrite is the only reader of the token, and it SETS Authorization: a
// client's own is replaced, so the bearer on the wire is the pinned one. Hop-by-hop
// headers — including any the request named in Connection — are already gone
// from r.Out, so a guest cannot name Authorization there to strip it.
func (p *Proxy) rewrite(r *httputil.ProxyRequest) {
	r.SetURL(p.cfg.Server)
	r.Out.Host = p.cfg.Server.Host
	// ReverseProxy removes Forwarded and X-Forwarded-* before a Rewrite runs
	// and adds none back unless asked to (measured: deleting them here too
	// changed no test). X-Real-Ip is not on its list.
	r.Out.Header.Del("X-Real-Ip")
	r.Out.Trailer = nil
	if tok, ok := r.In.Context().Value(tokenKey{}).(policy.Secret); ok {
		r.Out.Header.Set("Authorization", "Bearer "+string(tok))
	}
}

// admit refuses a request that would change where it goes. It returns 0 when
// the request is forwarded.
func admit(r *http.Request) (int, string) {
	if r.Method == http.MethodConnect {
		return http.StatusMethodNotAllowed, "CONNECT is refused: this proxy reaches one API server"
	}
	// The methods the Kubernetes API speaks. Anything else — TRACE above
	// all, which a front-end may answer by echoing the request, Authorization
	// included — would carry the host credential for no API call (red team,
	// measured: TRACE reached the upstream with the bearer).
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions:
	default:
		return http.StatusMethodNotAllowed, fmt.Sprintf("method %s is refused: the proxy forwards the methods "+
			"the Kubernetes API speaks", policy.VisibleText(r.Method))
	}
	if r.URL.Scheme != "" || r.URL.Host != "" || !strings.HasPrefix(r.RequestURI, "/") {
		return http.StatusBadRequest, "only an origin-form request target (/path) is forwarded; the " +
			"server is pinned by identity.kubectl"
	}
	if why := badPath(r.URL.EscapedPath()); why != "" {
		return http.StatusBadRequest, why
	}
	return 0, ""
}

// badPath refuses a path a server in front of the cluster could resolve
// outside the pinned server's prefix: a dot segment, an empty segment, a
// backslash, a ';' (a path parameter some servers strip, so "..;" climbs), or
// an escape a decoding gateway could turn into one — an escaped '/', '.',
// '\' or '%' (a second decoding round), or any escaped byte outside printable
// ASCII (overlong and look-alike encodings). Kubernetes object names contain
// none of them, so kubectl never sends one.
func badPath(raw string) string {
	low := strings.ToLower(raw)
	for _, enc := range []string{"%2f", "%2e", "%5c", "%25"} {
		if strings.Contains(low, enc) {
			return fmt.Sprintf("the path holds %s; an escaped '/', '.', '\\' or '%%' is refused so that no "+
				"server in front of the cluster can resolve it outside the pinned server", enc)
		}
	}
	for i := 0; i+2 < len(raw); i++ {
		if raw[i] != '%' {
			continue
		}
		if b, err := strconv.ParseUint(raw[i+1:i+3], 16, 8); err == nil && (b < 0x20 || b > 0x7e) {
			return fmt.Sprintf("the path holds %s, an escaped byte outside printable ASCII, which is refused "+
				"so that no server in front of the cluster can decode it into a path separator", raw[i:i+3])
		}
	}
	if strings.Contains(raw, `\`) {
		return "the path holds a backslash, which is refused"
	}
	if strings.Contains(raw, ";") {
		return "the path holds ';', a path parameter some servers strip, which is refused"
	}
	segs := strings.Split(strings.TrimPrefix(raw, "/"), "/")
	for i, s := range segs {
		switch {
		case s == "." || s == "..":
			return "the path holds a dot segment, which is refused so that it cannot climb out of the " +
				"pinned server's path"
		case s == "" && i != len(segs)-1:
			return "the path holds an empty segment (//), which is refused"
		}
	}
	return ""
}

// metadataAddrs are cloud instance-metadata and platform endpoints that no
// class check catches: a credential for the HOST lives behind them, and the
// proxy dials from the host.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud metadata
	netip.MustParseAddr("168.63.129.16"),   // Azure platform (WireServer)
}

// Transition prefixes that carry an IPv4 address in their low bits: a
// translator or a tunnel relay on the path delivers to that IPv4 address, so
// it is vetted as if it had been written directly.
var (
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")   // RFC 6052
	nat64LocalUse  = netip.MustParsePrefix("64:ff9b:1::/48") // RFC 8215
	sixToFour      = netip.MustParsePrefix("2002::/16")      // RFC 3056
	// IPv4-compatible (::a.b.c.d, deprecated) and IPv4-translated
	// (::ffff:0:a.b.c.d, SIIT) name an IPv4 host and no remote cluster.
	v4Compatible = netip.MustParsePrefix("::/96")
	v4Translated = netip.MustParsePrefix("::ffff:0:0:0/96")
	// 0.0.0.0/8 is "this network" (RFC 1122): never a remote server.
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
)

// embeddedV4 returns the IPv4 address a transition prefix carries.
func embeddedV4(a netip.Addr) (netip.Addr, bool) {
	b := a.As16()
	switch {
	case nat64WellKnown.Contains(a), nat64LocalUse.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

// refusedAddr names why the dialer will not reach a, or "" when it will.
func (p *Proxy) refusedAddr(a netip.Addr) string {
	a = a.Unmap().WithZone("")
	if v4, ok := embeddedV4(a); ok {
		if why := p.refusedAddr(v4); why != "" {
			return fmt.Sprintf("%s, embedded as %s", why, v4)
		}
	}
	switch {
	case a.IsLoopback():
		return "loopback"
	case a.IsUnspecified():
		return "unspecified"
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return "link-local (169.254.169.254 is a cloud metadata service)"
	case a.IsMulticast(), a.IsInterfaceLocalMulticast():
		return "multicast"
	case thisNetwork.Contains(a):
		return "\"this network\" (0.0.0.0/8)"
	case v4Compatible.Contains(a), v4Translated.Contains(a):
		return "an IPv6 spelling of an IPv4 address"
	}
	for _, m := range metadataAddrs {
		if a == m {
			return "a cloud metadata endpoint"
		}
	}
	nets, err := p.cfg.HostNets()
	if err != nil {
		return fmt.Sprintf("this host's interfaces could not be listed to check it: %v", err)
	}
	for _, n := range nets {
		if n.Addr() == a {
			return "an address this host owns"
		}
	}
	for _, n := range nets {
		if n = n.Masked(); n.Contains(a) {
			// A bridge (kind, minikube, libvirt, podman, docker) puts a
			// cluster's nodes one hop from this host; so does the LAN.
			return fmt.Sprintf("on %s, a subnet attached to this host", n)
		}
	}
	return ""
}

// Preflight resolves cfg.Server's name on the host and refuses it when ANY
// address it names is one the dialer refuses: loopback, this host's own, one
// on a subnet attached to this host, link-local, multicast, cloud metadata,
// or an IPv6 spelling of any of them. A cluster on this host — kind, k3s,
// minikube, Docker Desktop's kubernetes.docker.internal — runs its nodes on
// this host, so the credential's reach there is the host's, not a remote
// cluster's. internal/cli runs it before the sandbox is created; the dialer
// repeats it on every connection, because a record can change after start.
func Preflight(ctx context.Context, cfg Config) error {
	if cfg.Server == nil || cfg.HostNets == nil {
		return errors.New("kube proxy: Server and HostNets are required")
	}
	p := &Proxy{cfg: cfg}
	if p.cfg.Lookup == nil {
		p.cfg.Lookup = defaultLookup
	}
	p.vet = p.refusedAddr
	if fixture != nil {
		fixture(p)
	}
	_, err := p.addrs(ctx)
	return err
}

func defaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// addrs resolves the pinned server's name and refuses the whole answer when
// any address in it is one snug does not reach on the sandbox's behalf: a
// name that resolves to a public address AND to this host is a name pointing
// at this host.
func (p *Proxy) addrs(ctx context.Context) ([]netip.Addr, error) {
	host := p.cfg.Server.Hostname()
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		var err error
		if addrs, err = p.cfg.Lookup(ctx, host); err != nil {
			return nil, fmt.Errorf("resolving %s: %w", policy.VisibleText(host), err)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolving %s: no address", policy.VisibleText(host))
	}
	var refused []string
	for _, a := range addrs {
		if why := p.vet(a); why != "" {
			refused = append(refused, fmt.Sprintf("%s (%s)", a, why))
		}
	}
	if len(refused) > 0 {
		return nil, fmt.Errorf("refusing to dial %s: it resolves to %s, which snug does not reach on the "+
			"sandbox's behalf. A cluster on this host runs its nodes on this host, so acting as you there "+
			"is acting on the host", policy.VisibleText(host), strings.Join(refused, ", "))
	}
	return addrs, nil
}

// dial resolves the pinned server's name, refuses the answer when any address
// in it is one the host must not reach on the sandbox's behalf, and dials a
// vetted IP — never the name, so a record that changes between the check and
// the connect changes nothing. TLS still verifies against Config.TLSName.
func (p *Proxy) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	port := p.cfg.Server.Port()
	if port == "" {
		port = "443"
	}
	addrs, err := p.addrs(ctx)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	var lastErr error
	for _, a := range addrs {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
		if err != nil {
			lastErr = err
			continue
		}
		return p.track(c), nil
	}
	return nil, lastErr
}

func (p *Proxy) track(c net.Conn) net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		c.Close()
		return c
	}
	p.upstream[c] = struct{}{}
	return &trackedConn{Conn: c, forget: func() {
		p.mu.Lock()
		delete(p.upstream, c)
		p.mu.Unlock()
	}}
}

type trackedConn struct {
	net.Conn
	once   sync.Once
	forget func()
}

func (c *trackedConn) Close() error {
	c.once.Do(c.forget)
	return c.Conn.Close()
}

// statusWriter records the status for the audit line. Unwrap keeps Hijack and
// Flush reachable through http.ResponseController, which ReverseProxy uses.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.code == 0 {
		s.code = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusWriter) status() int { return s.code }

// trackingListener caps concurrent connections and remembers every one it
// handed out, so Close can end the ones an upgrade hijacked. Past the cap a
// new connection is closed unanswered and kubectl retries.
type trackingListener struct {
	net.Listener
	slots chan struct{}
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newTrackingListener(ln net.Listener, max int) *trackingListener {
	return &trackingListener{Listener: ln, slots: make(chan struct{}, max), conns: map[net.Conn]struct{}{}}
}

func (l *trackingListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		l.mu.Lock()
		l.conns[c] = struct{}{}
		l.mu.Unlock()
		lc := &limitedConn{Conn: c}
		lc.release = func() {
			l.mu.Lock()
			delete(l.conns, c)
			l.mu.Unlock()
			<-l.slots
		}
		return lc, nil
	}
}

func (l *trackingListener) closeAll() {
	l.Listener.Close()
	l.mu.Lock()
	defer l.mu.Unlock()
	for c := range l.conns {
		c.Close()
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
