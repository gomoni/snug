package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/kubeproxy"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/sandbox"
)

// hostAddressesForResolve feeds identity.kubectl's host-owned-server refusal. It
// is a usability check, not the seal, so an interface enumeration that fails
// leaves it empty rather than refusing the run; the stage enumerates again and
// does refuse.
func hostAddressesForResolve() []string {
	a, err := sandbox.HostAddresses()
	if err != nil {
		return nil
	}
	return a
}

// kubeHostNets is sandbox.HostLinks; a test replaces it.
var kubeHostNets = sandbox.HostLinks

// kubeRoute is sandbox.RouteIface; a test replaces it.
var kubeRoute = sandbox.RouteIface

// kubePreflight is kubeproxy.Preflight; a test replaces it.
var kubePreflight = kubeproxy.Preflight

// kubeRun is identity.kubectl's run-time half: the credential the proxy
// presents — a client certificate or a static token — and, once the stage has handed over the relay socket, the proxy
// listening on it inside the sandbox's network namespace.
type kubeRun struct {
	pol    *policy.Policy
	token  *policy.Secret   // static token only; a pointer, so fmt never prints it
	cert   *tls.Certificate // client certificate only
	audit  func(string)
	mu     sync.Mutex
	proxy  *kubeproxy.Proxy
	closed bool
}

// startKubeIdentity is everything identity.kubectl needs before the sandbox
// starts: the server checked from the host and the credential loaded into
// snug's memory. A dry run starts nothing. The proxy itself starts in apply's relay callback, because its
// socket does not exist until the stage makes it. Nothing here writes a file.
func startKubeIdentity(pol *policy.Policy, verbose, dryRun bool) (*kubeRun, error) {
	k := pol.Kube
	if k == nil || dryRun {
		return nil, nil
	}
	if err := kubeServerIsRemote(k.Server); err != nil {
		return nil, err
	}
	audit := func(string) {}
	if verbose {
		audit = func(msg string) { fmt.Fprintln(os.Stderr, "snug: kubectl: "+policy.VisibleText(msg)) }
	}
	r := &kubeRun{pol: pol, audit: audit}
	server := policy.VisibleText(k.Server)
	switch k.Credential {
	case policy.KubeCredentialClientCert:
		// The clock is read here, not in Resolve: a certificate past its
		// notAfter would answer every request with a handshake failure.
		if time.Now().After(k.CertNotAfter) {
			return nil, fmt.Errorf("identity.kubectl: the client certificate of context %s (%s) expired on %s; "+
				"refresh it with your cloud's get-credentials command", policy.VisibleText(k.Context),
				k.CertSubject, k.CertNotAfter.UTC().Format(time.DateOnly))
		}
		c, err := tls.X509KeyPair(k.HostUser.ClientCertData, k.HostUser.ClientKeyData)
		if err != nil {
			return nil, fmt.Errorf("identity.kubectl: the client certificate of context %s: %w",
				policy.VisibleText(k.Context), err)
		}
		r.cert = &c
		audit(fmt.Sprintf("presenting client certificate %s (expires %s) to %s as context %s", k.CertSubject,
			k.CertNotAfter.UTC().Format(time.DateOnly), server, policy.VisibleText(k.Context)))
	case policy.KubeCredentialToken:
		tok := k.HostUser.Token
		r.token = &tok
		audit(fmt.Sprintf("presenting static token (%d chars) to %s as context %s", k.TokenLen, server,
			policy.VisibleText(k.Context)))
	default:
		return nil, fmt.Errorf("identity.kubectl: no credential resolved for context %s", policy.VisibleText(k.Context))
	}
	return r, nil
}

// kubeServerIsRemote resolves the pinned server on the host before the
// sandbox exists and refuses one on this host: Resolve refuses loopback and
// host-owned literals, and this is the same refusal for a name.
func kubeServerIsRemote(server string) error {
	u, err := url.Parse(server)
	if err != nil {
		return fmt.Errorf("identity.kubectl: server %s: %w", policy.VisibleText(server), err)
	}
	if _, err := kubeHostNets(); err != nil {
		return fmt.Errorf("identity.kubectl: listing this host's addresses to check server %s: %w",
			policy.VisibleText(server), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := kubePreflight(ctx, kubeproxy.Config{Server: u, HostNets: kubeHostNets, Route: kubeRoute}); err != nil {
		return fmt.Errorf("identity.kubectl: %w. Not starting", err)
	}
	return nil
}

// apply asks the stage for the proxy's one relay socket. A nil run — no kube
// identity, or a dry run — asks for none.
func (r *kubeRun) apply(o *sandbox.Options) {
	if r == nil {
		return
	}
	addRelaySockets(o, 1, r.listen)
}

// listen binds the relay socket to policy.KubeProxyGuest inside the sandbox's
// network namespace and starts the proxy on it. It runs before bwrap is
// forked, so nothing inside can hold the port first; and the socket is bound
// without SO_REUSEADDR or SO_REUSEPORT, so nothing inside can bind it beside
// the proxy afterwards either (measured: a payload bind on 127.0.0.1:6443 and
// on 0.0.0.0:6443 gets EADDRINUSE).
func (r *kubeRun) listen(fs []*os.File) error {
	f := fs[0]
	defer f.Close()
	// The dialer's host-owned refusal runs outside the seal, so an
	// enumeration that fails refuses the run rather than leaving it empty
	// (red team: it was swallowed into an empty list).
	if _, err := kubeHostNets(); err != nil {
		return fmt.Errorf("identity.kubectl: listing this host's addresses for the proxy's dialer: %w", err)
	}
	fd := int(f.Fd())
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: policy.KubeProxyGuestPort, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		return fmt.Errorf("identity.kubectl: binding the proxy to 127.0.0.1:%d inside the sandbox: %w",
			policy.KubeProxyGuestPort, err)
	}
	if err := unix.Listen(fd, 64); err != nil {
		return fmt.Errorf("identity.kubectl: listening on 127.0.0.1:%d inside the sandbox: %w",
			policy.KubeProxyGuestPort, err)
	}
	ln, err := net.FileListener(f)
	if err != nil {
		return fmt.Errorf("identity.kubectl: the proxy's listener: %w", err)
	}
	k := r.pol.Kube
	server, err := url.Parse(k.Server)
	if err != nil {
		ln.Close()
		return fmt.Errorf("identity.kubectl: server %s: %w", policy.VisibleText(k.Server), err)
	}
	var pool *x509.CertPool
	if len(k.CAData) > 0 {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(k.CAData) {
			ln.Close()
			return errors.New("identity.kubectl: the cluster's certificate-authority-data holds no certificate")
		}
	}
	cfg := kubeproxy.Config{
		Listener: ln, Server: server, CAs: pool, TLSName: k.TLSServerName,
		ClientCert: r.cert, HostNets: kubeHostNets, Route: kubeRoute, Audit: r.audit,
	}
	if r.token != nil {
		tok := *r.token
		cfg.Token = func(context.Context) (policy.Secret, error) { return tok, nil }
	}
	p, err := kubeproxy.New(cfg)
	if err != nil {
		ln.Close()
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		ln.Close()
		return errors.New("identity.kubectl: the run ended before the proxy started")
	}
	r.proxy = p
	go p.Serve()
	return nil
}

// close stops the proxy — every connection on both sides. Safe on a nil run.
func (r *kubeRun) close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	p := r.proxy
	r.mu.Unlock()
	if p != nil {
		p.Close()
	}
}
