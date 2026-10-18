//go:build snugfixture

package kubeproxy

import (
	"context"
	"net/netip"
	"os"
	"strings"
)

// fixtureUpstreamEnv names "host=ip": the one server name this binary
// resolves to ip, and the one address its dialer reaches although it is
// loopback. Only a binary built with -tags snugfixture reads it — the
// integration suite's — because the API server it stands up is an httptest
// server on this host's loopback, which the real dialer refuses by design. No
// install or release target passes the tag.
const fixtureUpstreamEnv = "SNUG_FIXTURE_KUBE_UPSTREAM"

func init() {
	host, ip, ok := strings.Cut(os.Getenv(fixtureUpstreamEnv), "=")
	if !ok {
		return
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	fixture = func(p *Proxy) {
		if p.cfg.Server.Hostname() != host {
			return
		}
		p.cfg.Lookup = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{a}, nil }
		real := p.vet
		p.vet = func(x netip.Addr) string {
			if x == a {
				return ""
			}
			return real(x)
		}
	}
}
