package sandbox

import (
	"net/netip"
	"testing"
)

// HostPrefixes keeps each address with its own subnet, unmapped: the kube
// dialer refuses an address inside one, so a v4 prefix that came back as a
// 4in6 /104 or a bare /32 would refuse nothing beside the host itself.
func TestHostPrefixesCarryTheAttachedSubnet(t *testing.T) {
	ps, err := HostPrefixes()
	if err != nil {
		t.Fatal(err)
	}
	var lo bool
	for _, p := range ps {
		if p.Addr().Is4In6() || p.Addr().Zone() != "" {
			t.Errorf("%s is mapped or zoned", p)
		}
		if p.Addr() == netip.MustParseAddr("127.0.0.1") {
			lo = true
			if p.Bits() != 8 || !p.Masked().Contains(netip.MustParseAddr("127.9.9.9")) {
				t.Errorf("loopback came back as %s, want 127.0.0.1/8", p)
			}
		}
	}
	if !lo {
		t.Skipf("no 127.0.0.1 on any interface here: %v", ps)
	}
}
