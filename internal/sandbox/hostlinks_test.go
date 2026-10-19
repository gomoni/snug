package sandbox

import (
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The allow list is the whole list: each refused row has the allowed row that
// differs from it in the one attribute under test.
func TestClassifyLink(t *testing.T) {
	cases := []struct {
		name string
		in   linkInfo
		kind string
		ok   bool
	}{
		{"physical NIC", linkInfo{Name: "wlp3s0", Device: true}, "physical", true},
		{"physical, enslaved", linkInfo{Name: "enp3s0", Device: true, Master: 5}, "enslaved physical", false},
		{"no kind, no device", linkInfo{Name: "vboxnet0"}, "virtual", false},
		{"loopback", linkInfo{Name: "lo", Device: true, Flags: unix.IFF_LOOPBACK}, "loopback", false},
		{"wwan", linkInfo{Name: "wwan0", Kind: "wwan"}, "wwan", true},
		{"tun, point-to-point", linkInfo{Name: "tun0", Kind: "tun", Flags: unix.IFF_POINTOPOINT}, "tun", true},
		{"tap is tun without point-to-point", linkInfo{Name: "tap0", Kind: "tun"}, "tap", false},
		{"wireguard", linkInfo{Name: "wg0", Kind: "wireguard", Flags: unix.IFF_POINTOPOINT}, "wireguard", true},
		{"unknown kind", linkInfo{Name: "x0", Kind: "frobnicate", Device: true}, "frobnicate", false},
	}
	for _, k := range []string{"bridge", "veth", "tap", "macvlan", "macvtap", "ipvlan", "ipvtap", "vxlan",
		"geneve", "dummy", "vrf", "bond", "team", "vlan", "gre", "gretap", "ipip", "sit", "erspan"} {
		cases = append(cases, struct {
			name string
			in   linkInfo
			kind string
			ok   bool
		}{"named " + k, linkInfo{Name: "x0", Kind: k, Device: true, Flags: unix.IFF_POINTOPOINT}, k, false})
		if !IsNamedVirtualKind(k) {
			t.Errorf("%s is not in the named set", k)
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind, ok := classifyLink(c.in)
			if kind != c.kind || ok != c.ok {
				t.Errorf("classifyLink(%+v) = %q, %v; want %q, %v", c.in, kind, ok, c.kind, c.ok)
			}
		})
	}
}

// HostLinks keeps each address with its own subnet, unmapped: the kube
// dialer refuses an address inside one, so a v4 prefix that came back as a
// 4in6 /104 or a bare /32 would refuse nothing beside the host itself.
func TestHostLinksCarryTheAttachedSubnet(t *testing.T) {
	ps, err := HostLinks()
	if err != nil {
		t.Fatal(err)
	}
	var lo bool
	for _, p := range ps {
		if p.Prefix.Addr().Is4In6() || p.Prefix.Addr().Zone() != "" {
			t.Errorf("%s is mapped or zoned", p.Prefix)
		}
		if p.Prefix.Addr() == netip.MustParseAddr("127.0.0.1") {
			lo = true
			if p.Prefix.Bits() != 8 || !p.Prefix.Masked().Contains(netip.MustParseAddr("127.9.9.9")) {
				t.Errorf("loopback came back as %s, want 127.0.0.1/8", p.Prefix)
			}
			if p.Allowed || p.Kind != "loopback" {
				t.Errorf("lo classified as %q allowed=%v", p.Kind, p.Allowed)
			}
		}
	}
	if !lo {
		t.Skipf("no 127.0.0.1 on any interface here: %v", ps)
	}
}

func TestRouteIfaceOfLoopback(t *testing.T) {
	n, err := RouteIface(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Skipf("no route to 127.0.0.1 here: %v", err)
	}
	if n.Allowed || n.Kind != "loopback" {
		t.Errorf("route to 127.0.0.1 = %+v, want the loopback link, refused", n)
	}
}

func TestJoinAddrs(t *testing.T) {
	links := map[uint32]classifiedLink{2: {Iface: "wlp3s0", Kind: "physical", Allowed: true}}
	v4 := []byte{192, 168, 1, 5}

	got, err := joinAddrs(links, []addrRec{{Index: 2, Bits: 24, Raw: v4}})
	if err != nil || len(got) != 1 || got[0].Iface != "wlp3s0" || !got[0].Allowed {
		t.Fatalf("positive control: %+v, %v", got, err)
	}

	got, err = joinAddrs(links, []addrRec{{Index: 9, Bits: 24, Raw: v4}})
	if err != nil || len(got) != 1 || got[0].Kind != "unknown" || got[0].Allowed ||
		got[0].Prefix != netip.MustParsePrefix("192.168.1.5/24") {
		t.Errorf("address on an unlisted link: %+v, %v; want it kept, unknown, refused", got, err)
	}

	for name, r := range map[string]addrRec{
		"short address": {Index: 2, Bits: 24, Raw: []byte{1, 2, 3}},
		"no address":    {Index: 2, Bits: 24},
		"bad length":    {Index: 2, Bits: 99, Raw: v4},
	} {
		if got, err := joinAddrs(links, []addrRec{r}); err == nil {
			t.Errorf("%s: %+v, want an error naming the interface", name, got)
		} else if !strings.Contains(err.Error(), "interface 2") {
			t.Errorf("%s: %v does not name the interface index", name, err)
		}
	}
}
