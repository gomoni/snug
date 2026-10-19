package kubeproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/sandbox"
)

// recorder is a Lookup seam that logs the names it was asked for and answers
// from a function of the call number (1-based), plus a vet that logs every
// address the dialer checked.
type recorder struct {
	mu     sync.Mutex
	hosts  []string
	vetted []netip.Addr
	answer func(call int) []netip.Addr
}

func (r *recorder) lookup(_ context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hosts = append(r.hosts, host)
	return r.answer(len(r.hosts)), nil
}

func (r *recorder) calls() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.hosts) }

// startNamed runs a proxy whose pinned server is the NAME kube.example on the
// upstream's port. standIn is the one loopback address the vet lets through
// (the httptest upstream lives on it); every other address gets the real
// refusedAddr, with the host prefixes nets.
func startNamed(t *testing.T, up *upstream, rec *recorder, nets func() ([]netip.Prefix, error), mod func(*Config)) *pfix {
	t.Helper()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(up.srv.URL, "https://"))
	f := start(t, up, "", func(c *Config) {
		c.Server, _ = url.Parse("https://kube.example:" + port)
		c.Lookup = rec.lookup
		c.HostNets = nets
		if mod != nil {
			mod(c)
		}
	})
	stand := netip.MustParseAddr("127.0.0.1")
	f.p.vet = func(a netip.Addr) string {
		rec.mu.Lock()
		rec.vetted = append(rec.vetted, a)
		rec.mu.Unlock()
		if a == stand {
			return ""
		}
		return f.p.refusedAddr(a)
	}
	return f
}

const getClose = "GET /api HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"

// Fails if the dialer trusts the answer Preflight (or an earlier dial) saw:
// the name is resolved again on every connection, so a record that turns
// local after the check is still refused, and nothing is connected to.
// It does not cover a record that changes between the dialer's own vet and
// its connect; the dialer connects to the vetted IP, never the name, which
// this test does not observe.
func TestKubeProxyDialerRefusesAnAnswerThatChangesAfterPreflight(t *testing.T) {
	public := netip.MustParseAddr("203.0.113.7")
	for _, later := range []string{"127.0.0.1", "192.0.2.50", "::1", "169.254.169.254", "64:ff9b::7f00:1"} {
		t.Run(later, func(t *testing.T) {
			nets := hostNets("192.0.2.1/24")
			rec := &recorder{answer: func(call int) []netip.Addr {
				if call == 1 {
					return []netip.Addr{public}
				}
				return []netip.Addr{netip.MustParseAddr(later)}
			}}
			up := newUpstream(t, nil)
			f := startNamed(t, up, rec, nets, nil)
			f.p.vet = f.p.refusedAddr // the real vet: loopback is refused too
			if err := Preflight(context.Background(), f.p.cfg); err != nil {
				t.Fatalf("Preflight on the public first answer: %v", err)
			}
			if rec.calls() != 1 {
				t.Fatalf("positive control: %d lookups after Preflight, want 1", rec.calls())
			}
			status, _ := raw(t, f.addr, getClose)
			if !strings.HasPrefix(status, "502") {
				t.Errorf("answer turned %s after Preflight: %s, want 502", later, status)
			}
			if rec.calls() < 2 {
				t.Errorf("the dialer did not resolve again (%d lookups): the second answer was never seen", rec.calls())
			}
			if n := up.count(); n != 0 {
				t.Errorf("%d requests reached the upstream, want 0", n)
			}
		})
	}
}

// Fails if the dialer caches an answer: the name alternates between an
// address the vet admits and one on a host-attached subnet, and each
// connection must follow the CURRENT answer. The admitted request reaching
// the upstream is the positive control that the alternation is being read.
func TestKubeProxyDialerFollowsAnAlternatingAnswerPerConnection(t *testing.T) {
	nets := hostNets("198.51.100.1/24")
	rec := &recorder{answer: func(call int) []netip.Addr {
		if call%2 == 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")} // the vet's stand-in for the cluster
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.7")}
	}}
	up := newUpstream(t, nil)
	f := startNamed(t, up, rec, nets, nil)
	wantUp := 0
	for i := 1; i <= 6; i++ {
		f.p.tr.CloseIdleConnections()
		status, _ := raw(t, f.addr, getClose)
		if i%2 == 1 {
			wantUp++
			if !strings.HasPrefix(status, "200") {
				t.Errorf("request %d (admitted answer): %s, want 200", i, status)
			}
		} else if !strings.HasPrefix(status, "502") {
			t.Errorf("request %d (host-subnet answer): %s, want 502", i, status)
		}
		if n := up.count(); n != wantUp {
			t.Errorf("after request %d: %d upstream requests, want %d", i, n, wantUp)
		}
	}
}

// Fails if any of these names, which this machine's own resolver may map to
// itself, is accepted by Preflight. It runs the REAL resolver and the real
// host prefixes, so its outcome depends on this machine's /etc/hosts and
// resolv.conf; the per-name reason is logged (go test -v). A name that does
// not resolve is a refusal too, and the log says which of the two it was.
func TestKubeProxyPreflightRefusesNamesThisMachineResolvesLocally(t *testing.T) {
	names := []string{"localhost", "localhost.", "LOCALHOST", "x.localhost", "localhost.localdomain",
		"127.1", "0x7f.0.0.1", "2130706433", "127.0.0.1.", "127.0.0.1"}
	if h, err := os.Hostname(); err == nil && h != "" {
		names = append(names, h)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			server, err := url.Parse("https://" + name + ":6443")
			if err != nil {
				t.Skipf("url.Parse refuses the spelling, so it cannot reach the proxy: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			err = Preflight(ctx, Config{Server: server, HostNets: sandbox.HostPrefixes})
			if err == nil {
				t.Errorf("%q was ACCEPTED by Preflight", name)
				return
			}
			kind := "address check"
			if strings.Contains(err.Error(), "resolving ") {
				kind = "did not resolve"
			}
			t.Logf("%q refused by %s: %v", name, kind, err)
		})
	}
}

// Fails if Preflight stops refusing a literal that Resolve lets through. The
// table records which layer holds each one: Resolve (internal/policy/kube.go)
// refuses loopback, unspecified and host-owned literals and localhost names;
// the rest are Preflight's alone. The Resolve half is
// TestKubeLiteralServerFormsAreRefusedByOneLayer in internal/policy.
func TestKubeProxyPreflightRefusesLiteralServerForms(t *testing.T) {
	for _, host := range []string{"[::ffff:127.0.0.1]", "[fe80::1%25eth0]", "[64:ff9b::7f00:1]", "[::]", "0.0.0.0",
		"0.1.2.3", "[::ffff:0:7f00:1]", "[2002:7f00:1::1]", "LOCALHOST", "localhost.", "[::ffff:169.254.169.254]"} {
		server, err := url.Parse("https://" + host + ":6443")
		if err != nil {
			t.Errorf("%s: url.Parse: %v", host, err)
			continue
		}
		called := false
		err = Preflight(context.Background(), Config{Server: server, HostNets: noHostNets,
			Lookup: func(context.Context, string) ([]netip.Addr, error) { called = true; return nil, fmt.Errorf("nxdomain") }})
		if err == nil {
			t.Errorf("%s: Preflight accepted it", host)
			continue
		}
		t.Logf("%s: refused (lookup called: %v): %v", host, called, err)
	}
}

// Fails if the proxy looks up, or dials, anything but the pinned server's
// hostname: Config.TLSName is only the name the certificate is checked
// against, so a TLSName of "localhost" must not become a lookup. The
// vetted-address list is the dial target.
func TestKubeProxyLooksUpTheServerHostNeverTheTLSName(t *testing.T) {
	for _, tlsName := range []string{"example.com", "localhost", "127.0.0.1"} {
		t.Run(tlsName, func(t *testing.T) {
			rec := &recorder{answer: func(int) []netip.Addr { return []netip.Addr{netip.MustParseAddr("127.0.0.1")} }}
			up := newUpstream(t, nil)
			f := startNamed(t, up, rec, noHostNets, func(c *Config) { c.TLSName = tlsName })
			if err := Preflight(context.Background(), f.p.cfg); err != nil {
				t.Logf("Preflight (real vet, stand-in is loopback): %v", err)
			}
			raw(t, f.addr, getClose)
			if rec.calls() == 0 {
				t.Fatal("positive control: Lookup never called")
			}
			for _, h := range rec.hosts {
				if h != "kube.example" {
					t.Errorf("Lookup called with %q, want only kube.example", h)
				}
			}
			for _, a := range rec.vetted {
				if a != netip.MustParseAddr("127.0.0.1") {
					t.Errorf("vet saw %s, want only the looked-up answer", a)
				}
			}
			if len(rec.vetted) == 0 {
				t.Error("positive control: the dialer vetted nothing")
			}
		})
	}
}

// Fails if the proxy follows a redirect: a 3xx from the upstream with a
// Location on loopback or another host is relayed to the client as it is, and
// there is exactly one upstream connection and one lookup for it.
func TestKubeProxyRelaysARedirectWithoutFollowingIt(t *testing.T) {
	for _, loc := range []string{"https://127.0.0.1:1/x", "https://other.example/x", "/api/v1"} {
		t.Run(loc, func(t *testing.T) {
			rec := &recorder{answer: func(int) []netip.Addr { return []netip.Addr{netip.MustParseAddr("127.0.0.1")} }}
			up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, loc, http.StatusFound)
			})
			f := startNamed(t, up, rec, noHostNets, nil)
			status, _ := raw(t, f.addr, getClose)
			if !strings.HasPrefix(status, "302") {
				t.Fatalf("redirect not relayed: %s", status)
			}
			if n := up.count(); n != 1 {
				t.Errorf("%d upstream requests, want 1 (a redirect was followed)", n)
			}
			if n := rec.calls(); n != 1 {
				t.Errorf("%d lookups, want 1", n)
			}
		})
	}
}

// Fails if a request can steer the dial: an Upgrade request, a Host header
// naming 127.0.0.1, and an absolute-form target all leave the lookups and the
// vetted addresses at the pinned server's. The absolute-form ones are
// refused before any lookup at all.
func TestKubeProxyRequestCannotSteerTheDialTarget(t *testing.T) {
	rec := &recorder{answer: func(int) []netip.Addr { return []netip.Addr{netip.MustParseAddr("127.0.0.1")} }}
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	f := startNamed(t, up, rec, noHostNets, nil)

	// Absolute-form: refused, nothing resolved, nothing connected.
	for _, req := range []string{
		"GET http://127.0.0.1:1/api HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n",
		"GET https://127.0.0.1/api HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
	} {
		status, _ := raw(t, f.addr, req)
		if strings.HasPrefix(status, "2") {
			t.Errorf("%q: %s", strings.SplitN(req, "\r\n", 2)[0], status)
		}
	}
	if rec.calls() != 0 || up.count() != 0 {
		t.Fatalf("absolute-form reached the dialer: %d lookups, %d upstream requests", rec.calls(), up.count())
	}

	// Host header and Upgrade: forwarded, to the pinned server, with the
	// pinned server's Host. Positive control: the request did arrive.
	for _, req := range []string{
		"GET /api HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
		"GET /api HTTP/1.1\r\nHost: localhost:1\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n",
	} {
		f.p.tr.CloseIdleConnections()
		status, _ := raw(t, f.addr, req)
		if !strings.HasPrefix(status, "200") {
			t.Errorf("%q: %s, want 200 from the pinned upstream", strings.SplitN(req, "\r\n", 2)[0], status)
		}
	}
	if n := up.count(); n != 2 {
		t.Fatalf("%d upstream requests, want 2", n)
	}
	for i, h := range up.hosts {
		if !strings.HasPrefix(h, "kube.example:") {
			t.Errorf("upstream request %d saw Host %q, want the pinned kube.example", i, h)
		}
	}
	for _, h := range rec.hosts {
		if h != "kube.example" {
			t.Errorf("Lookup called with %q", h)
		}
	}
	for _, a := range rec.vetted {
		if a != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("vet saw %s", a)
		}
	}
}

// Fails if a hostname that merely LOOKS like a local name (a Cyrillic or
// full-width letter standing in for a Latin one, an xn-- label) gets past the
// resolver to a local address. The proxy does no IDNA mapping of its own, so
// the name reaches the resolver as written; the first case pins that with a
// recorder, the rest run the real resolver and log what it said.
func TestKubeProxyIDNNamesDoNotReachALocalAddress(t *testing.T) {
	for _, host := range []string{"lоcalhost", "ｌｏｃａｌｈｏｓｔ", "xn--localhost-9ea", "xn--calhost-hn5b"} {
		server, err := url.Parse("https://" + host + ":6443")
		if err != nil {
			t.Logf("%q: url.Parse refuses: %v", host, err)
			continue
		}
		var seen string
		err = Preflight(context.Background(), Config{Server: server, HostNets: noHostNets,
			Lookup: func(_ context.Context, h string) ([]netip.Addr, error) {
				seen = h
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}})
		if err == nil {
			t.Errorf("%q: loopback answer accepted", host)
		}
		if seen != server.Hostname() {
			t.Errorf("%q: resolver was asked for %q, want the name as written (%q)", host, seen, server.Hostname())
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = Preflight(ctx, Config{Server: server, HostNets: sandbox.HostPrefixes})
		cancel()
		if err == nil {
			t.Errorf("%q: ACCEPTED with the real resolver", host)
			continue
		}
		t.Logf("%q: real resolver: %v", host, err)
	}
}
