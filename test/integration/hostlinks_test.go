//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/kubeproxy"
	"github.com/gomoni/snug/internal/sandbox"
)

type hostLinksPayload struct {
	Nets      []sandbox.HostNet
	Routes    map[string]sandbox.HostNet
	Preflight map[string]string
}

const hostLinksHelperEnv = "SNUG_HOSTLINKS_HELPER"

// TestHostLinksHelper is not a test: it is the payload TestHostLinksClassifiesVirtualKinds
// re-executes inside a user+net namespace, where it prints what the real
// classifier read as JSON on stdout.
func TestHostLinksHelper(t *testing.T) {
	if os.Getenv(hostLinksHelperEnv) == "" {
		t.Skip("payload of TestHostLinksClassifiesVirtualKinds")
	}
	nets, err := sandbox.HostLinks()
	if err != nil {
		t.Fatal(err)
	}
	out := hostLinksPayload{Nets: nets, Routes: map[string]sandbox.HostNet{}, Preflight: map[string]string{}}
	for _, a := range []string{"10.1.0.5", "10.2.0.5", "10.3.0.5", "10.4.0.5", "10.5.0.5", "10.6.0.5", "10.99.0.5", "8.8.8.8"} {
		r, err := sandbox.RouteIface(netip.MustParseAddr(a))
		if err != nil {
			t.Fatalf("RouteIface(%s): %v", a, err)
		}
		out.Routes[a] = r
	}
	for a := range out.Routes {
		addr := netip.MustParseAddr(a)
		server, _ := url.Parse("https://kube.example:6443")
		err := kubeproxy.Preflight(context.Background(), kubeproxy.Config{Server: server,
			HostNets: sandbox.HostLinks, Route: sandbox.RouteIface,
			Lookup: func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{addr}, nil }})
		if err != nil {
			out.Preflight[a] = err.Error()
		} else {
			out.Preflight[a] = ""
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		t.Fatal(err)
	}
}

// Fails if the classifier reads a kind wrong: each virtual link is created in
// a namespace of its own, and the real netlink reader must name it and refuse
// it, while the two layer-3 kinds it may trust (tun with POINTOPOINT,
// wireguard) are allowed. The allowed rows are the positive controls; a
// classifier that refused everything would pass every refusal.
//
// A physical NIC cannot be made in a namespace, and /sys/class/net shows the
// host's interfaces, so that row is covered by TestClassifyLink instead.
func TestHostLinksClassifiesVirtualKinds(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		skipOrFail(t, "no ip(8) on this host, so there are no links to create")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		skipOrFail(t, "no unshare(1) on this host")
	}
	if err := exec.Command("unshare", "-rn", "--", "ip", "link", "add", "probe0", "type", "wireguard").Run(); err != nil {
		skipOrFail(t, "cannot create a wireguard link in a user+net namespace (is the wireguard module available? "+
			"does this host allow unprivileged user namespaces?): %v", err)
	}
	const setup = `set -e
ip link add br0 type bridge
ip link add veth0 type veth peer name veth1
ip tuntap add tap0 mode tap
ip tuntap add tun0 mode tun
ip link add wg0 type wireguard
ip link add dummy0 type dummy
n=0
for l in br0 veth0 tap0 tun0 wg0 dummy0; do
  n=$((n+1))
  ip addr add 10.$n.0.1/24 dev $l
  ip link set $l up
done
ip route add 10.99.0.0/16 via 10.1.0.2 dev br0
ip route add default via 10.1.0.2 dev br0
exec "$0" -test.run '^TestHostLinksHelper$' -test.count=1
`
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "-rn", "--", "sh", "-c", setup, exe)
	cmd.Env = append(os.Environ(), hostLinksHelperEnv+"=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("payload: %v\n%s\n%s", err, raw, stderr.String())
	}
	var got hostLinksPayload
	if err := json.NewDecoder(strings.NewReader(string(raw))).Decode(&got); err != nil {
		t.Fatalf("payload printed no JSON (%v): %q", err, raw)
	}
	byIface := map[string]sandbox.HostNet{}
	for _, n := range got.Nets {
		if n.Prefix.IsValid() && strings.HasPrefix(n.Prefix.Addr().String(), "10.") {
			byIface[n.Iface] = n
		}
	}
	want := []struct {
		iface, kind string
		allowed     bool
		route       string
	}{
		{"br0", "bridge", false, "10.1.0.5"},
		{"veth0", "veth", false, "10.2.0.5"},
		{"tap0", "tap", false, "10.3.0.5"},
		{"tun0", "tun", true, "10.4.0.5"},
		{"wg0", "wireguard", true, "10.5.0.5"},
		{"dummy0", "dummy", false, "10.6.0.5"},
	}
	for _, w := range want {
		n, ok := byIface[w.iface]
		if !ok {
			t.Errorf("%s: no prefix read for it; read %v", w.iface, got.Nets)
			continue
		}
		if n.Kind != w.kind || n.Allowed != w.allowed {
			t.Errorf("%s: read as %q allowed=%v, want %q allowed=%v", w.iface, n.Kind, n.Allowed, w.kind, w.allowed)
		}
		r := got.Routes[w.route]
		if r.Iface != w.iface || r.Kind != w.kind || r.Allowed != w.allowed {
			t.Errorf("route to %s: %+v, want %s (%s) allowed=%v", w.route, r, w.iface, w.kind, w.allowed)
		}
	}

	// 10.99.0.0/16 is on no attached subnet: it is reached through a gateway
	// on the bridge, so only the route lookup sees the bridge, and the
	// matched entry is a /16. 8.8.8.8 is the default route through the same
	// bridge (an uplink enslaved to br0): the network beyond the gateway.
	specific, def := got.Routes["10.99.0.5"], got.Routes["8.8.8.8"]
	if specific.Iface != "br0" || specific.RouteBits != 16 || specific.Default {
		t.Errorf("route to 10.99.0.5: %+v, want br0, a /16, not default", specific)
	}
	if def.Iface != "br0" || def.RouteBits != 0 || !def.Default {
		t.Errorf("route to 8.8.8.8: %+v, want br0 as the default route (RouteBits 0)", def)
	}
	if why := got.Preflight["10.99.0.5"]; !strings.Contains(why, "leaves via br0 (bridge)") {
		t.Errorf("Preflight of 10.99.0.5 = %q, want the route-egress refusal", why)
	}
	if why := got.Preflight["8.8.8.8"]; why != "" {
		t.Errorf("Preflight of 8.8.8.8 through a default route via a bridge = %q, want it admitted", why)
	}
}
