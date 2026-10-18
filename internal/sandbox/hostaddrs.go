package sandbox

import (
	"fmt"
	"net"
	"net/netip"
)

// hostAddresses enumerates every address the HOST holds, on EVERY interface —
// not just the one carrying the default route. A bridge, a VPN interface or a
// second alias can carry a host-owned address that never touches the default
// route at all, and host-bridge's own measurement is what makes that matter
// here: a route-blackhole approach only ever covers the addresses it thinks
// to name, while pasta itself already copies the default-route interface's
// v4 primary and v6 globals onto snug0. This is P0's own contribution to the
// stage's seal (internal/stage/loopback.go's sealHostAddresses) — the
// addresses pasta does NOT copy there, chiefly the host's link-local, which
// pasta never touches and which a hostile process inside the sandbox can
// otherwise reach via the host's own snug0 link-local neighbour.
//
// Loopback, unspecified and multicast are excluded: loopback is the
// sandbox's OWN loopback once assigned there, not the host's; unspecified
// names no address at all; and multicast cannot be assigned to an interface
// as a unicast local address in the first place.
func hostAddresses() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerating host interfaces to seal their addresses in the "+
			"sandbox's network namespace: %w", err)
	}
	var out []string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			// Best-effort per interface: one disappearing between Interfaces()
			// and Addrs() (a hot-unplugged device, a torn-down VPN link) is not
			// a reason to refuse sealing every other one.
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out, nil
}
