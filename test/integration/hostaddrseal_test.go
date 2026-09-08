//go:build integration

package integration

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// hostDefaultIfaceLinkLocal6 returns the interface name and IPv6 link-local
// address of whichever host interface also carries hostOutboundAddr()'s
// address — the interface pasta actually attaches to. Matched by INTERFACE
// rather than returning the first link-local found anywhere: a host can
// carry an unrelated bridge or VPN device with its own link-local, and
// dialing that one from inside would say nothing about the interface pasta
// copies addresses from.
//
// (false, ...) when no interface could be matched — the caller's cue to skip
// rather than assert on an address that does not represent this host's
// actual network path.
func hostDefaultIfaceLinkLocal6(t *testing.T) (iface string, ll netip.Addr, ok bool) {
	t.Helper()
	v4, err := hostOutboundAddr()
	if err != nil {
		return "", netip.Addr{}, false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", netip.Addr{}, false
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		hasOutbound := false
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.String() == v4 {
				hasOutbound = true
			}
		}
		if !hasOutbound {
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
			if ip.Is6() && ip.IsLinkLocalUnicast() {
				return ifc.Name, ip, true
			}
		}
	}
	return "", netip.Addr{}, false
}

// hostHasV6Internet reports whether this host can reach a real IPv6 endpoint
// on the public internet — the precondition for this test's v6 EGRESS
// positive control, which is a separate fact from having an IPv6 link-local
// address at all (every Linux host with IPv6 enabled on an interface gets
// one regardless of whether it has a global route anywhere).
func hostHasV6Internet() bool {
	c, err := net.DialTimeout("tcp6", "[2001:4860:4860::8888]:53", 3*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// serveTokenCounting answers every TCP connection on ln with token and
// counts accepts, so a caller can tell "nothing connected" from "something
// connected and was refused a different way" — the distinction this file's
// test needs to say the host listener saw NO accept from inside the sandbox.
func serveTokenCounting(t *testing.T, ln net.Listener, token string) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return // closed
			}
			n.Add(1)
			c.SetDeadline(time.Now().Add(5 * time.Second))
			c.Write([]byte(token + "\n"))
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	return &n
}

// TestNetSealsHostOwnedAddressesFromInside is the named regression for the
// sev:high escape sealHostAddresses (internal/stage/loopback.go) closes: a
// host service bound to the IPv6 wildcard ("::") used to be reachable from
// inside an `@net` sandbox through the host's OWN link-local address. pasta
// copies only the default-route interface's v4 primary and its v6 GLOBAL
// addresses onto snug0 — never the interface's link-local one — so nothing
// in the sandbox's own routing table matched that address and a connect to
// it travelled out to pasta, and past it, onto the real host network, rather
// than being refused locally the way host loopback already was. The fix
// assigns every address the host owns onto snug0 as a /32 or /128, which
// turns a match into a LOCAL route the sandbox's own kernel refuses before
// the packet ever reaches pasta.
//
// RESIDUAL, stated rather than covered: the seal runs once, at the
// "netready" bring-up (internal/stage/serve.go), from addresses enumerated
// at that moment. A host address that starts existing afterward — a NIC
// hot-plugged, a VPN interface brought up mid-run — is never retroactively
// sealed. This test's own listener and address discovery both happen before
// the sandbox starts, which is exactly the bring-up window the seal covers;
// it asserts nothing about an address introduced later.
//
// Self-contained: the listener is this test's own, bound on an ephemeral
// port, and the host's addresses are enumerated at runtime rather than
// assumed or hardcoded.
func TestNetSealsHostOwnedAddressesFromInside(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)
	requirePasta(t)
	requirePython(t)
	requireInternet(t)

	iface, ll, ok := hostDefaultIfaceLinkLocal6(t)
	if !ok {
		t.Skip("could not find an IPv6 link-local address on this host's default-route " +
			"interface — there is nothing here for the seal to close, so this test cannot " +
			"exercise the fix")
	}
	haveV6Egress := hostHasV6Internet()

	proj, _ := target(t)

	ln, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Skipf("could not bind a dual-stack wildcard listener: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	token := fmt.Sprintf("SEAL-TOKEN-%d-%d", os.Getpid(), time.Now().UnixNano())
	accepts := serveTokenCounting(t, ln, token)

	// PRECONDITIONS, and they are fatal rather than skipped: without them
	// every refusal asserted below is equally what an unbound, unreachable, or
	// never-started listener would produce.
	//
	// Reads the token back rather than just connecting and closing: the
	// accept counter checked right after this is incremented by the
	// listener's OWN goroutine, so without waiting for the round trip to
	// finish, "the host's own connections were not both counted" is a race
	// against that goroutine rather than a fact about the listener.
	mustReach := func(label, host string) {
		t.Helper()
		c, err := net.DialTimeout("tcp6", net.JoinHostPort(host, strconv.Itoa(port)), 3*time.Second)
		if err != nil {
			t.Fatalf("precondition: the host cannot reach its own wildcard listener via %s "+
				"(%s): %v", label, host, err)
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, len(token)+1)
		n, err := c.Read(buf)
		if err != nil || !strings.HasPrefix(string(buf[:n]), token) {
			t.Fatalf("precondition: did not read the token back from the host's own wildcard "+
				"listener via %s (%s): n=%d err=%v", label, host, n, err)
		}
	}
	mustReach("::1", "::1")
	mustReach("its own link-local address", ll.String()+"%"+iface)
	if n := accepts.Load(); n < 2 {
		t.Fatalf("precondition: the host's own two connections were not both counted (saw "+
			"%d) — the accept counter this test relies on below is not trustworthy", n)
	}
	accepts.Store(0) // the preconditions' own accepts must not count against the assertion below

	probe := fmt.Sprintf(`import socket

def probe(label, family, host, port, scope=0):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        if family == socket.AF_INET6:
            s.connect((host, port, 0, scope))
        else:
            s.connect((host, port))
        print("RESULT", label, "REACHED", s.recv(64).decode(errors="replace").strip())
    except ConnectionRefusedError:
        print("RESULT", label, "REFUSED")
    except socket.timeout:
        print("RESULT", label, "TIMEDOUT")
    except OSError as e:
        print("RESULT", label, "ERROR", type(e).__name__, e)
    finally:
        s.close()

scope = socket.if_nametoindex("snug0")

# THE FINDING: the host's OWN link-local address, dialled with the SANDBOX's
# OWN interface as the zone. pasta never copies this address onto snug0, so
# before the seal nothing in the sandbox's routing table matched it and the
# connect reached pasta, and past it, the real host.
probe("host-ll", socket.AF_INET6, %[1]q, %[2]d, scope)

# ADJACENT NEGATIVES: loopback stays closed exactly as it did before the seal
# — the seal must not have loosened anything it did not exist to touch.
probe("v4-loop", socket.AF_INET, "127.0.0.1", %[2]d)
probe("v6-loop", socket.AF_INET6, "::1", %[2]d, scope)

# POSITIVE: the seal must not have blanket-closed ordinary egress along with
# the host's own addresses.
probe("egress-v4", socket.AF_INET, "8.8.8.8", 53)
if %[3]s:
    probe("egress-v6", socket.AF_INET6, "2001:4860:4860::8888", 53)
    try:
        info = socket.getaddrinfo("dns.google", 53, socket.AF_INET6)
        print("RESULT", "v6-name", info[0][4][0])
    except OSError as e:
        print("RESULT", "v6-name", "ERROR", e)

print("PROBE-COMPLETE")
`, ll.String(), port, map[bool]string{true: "True", false: "False"}[haveV6Egress])

	if err := os.WriteFile(filepath.Join(proj, "seal.py"), []byte(probe), 0o644); err != nil {
		t.Fatal(err)
	}
	r := run(t, []string{"-p", "@net"}, proj, `python3 seal.py`).mustRun(t)

	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the probe did not run to the end, so every verdict below is missing "+
			"rather than negative:\n%s", r.out)
	}

	verdicts := map[string]string{}
	for _, line := range strings.Split(r.out, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "RESULT" {
			verdicts[f[1]] = strings.Join(f[2:], " ")
		}
	}

	// THE SEAL ITSELF: the token must never come back, and the host listener
	// must record no accept at all from inside — a REFUSED verdict alone
	// would not rule out a race where the connection was accepted and then
	// dropped for an unrelated reason.
	if strings.Contains(r.out, token) {
		t.Errorf("the sandbox READ the token from a host service bound on the host's own "+
			"link-local address %s%%%s — sealHostAddresses did not close it:\n%s",
			ll, iface, r.out)
	}
	if got := verdicts["host-ll"]; !strings.HasPrefix(got, "REFUSED") {
		t.Errorf("host-ll = %q, want REFUSED — the seal assigns this address onto snug0 as "+
			"a local route, which the sandbox's own kernel is supposed to refuse before the "+
			"packet ever reaches pasta:\n%s", got, r.out)
	}
	if n := accepts.Load(); n != 0 {
		t.Errorf("the host listener recorded %d accept(s) from inside the sandbox — the "+
			"seal exists to keep the connection from ever leaving the sandbox's own network "+
			"namespace:\n%s", n, r.out)
	}

	// ADJACENT: host loopback, both families — unrelated to the seal, but a
	// regression here would mean the seal's own address assignment disturbed
	// bwrap/pasta's separate loopback closure (--map-host-loopback none).
	for _, label := range []string{"v4-loop", "v6-loop"} {
		if got := verdicts[label]; got != "REFUSED" {
			t.Errorf("%s = %q, want REFUSED (host loopback must stay closed regardless of "+
				"the seal):\n%s", label, got, r.out)
		}
	}

	// POSITIVE: ordinary egress still works, so every refusal above is a
	// closed HOLE rather than a sandbox with no network at all.
	if got := verdicts["egress-v4"]; !strings.HasPrefix(got, "REACHED") {
		t.Errorf("egress-v4 = %q, want REACHED — the seal must not have closed ordinary "+
			"egress along with the host's own addresses:\n%s", got, r.out)
	}
	if haveV6Egress {
		if got := verdicts["egress-v6"]; !strings.HasPrefix(got, "REACHED") {
			t.Errorf("egress-v6 = %q, want REACHED — the v6 default route, via the "+
				"GATEWAY's own link-local (distinct from the host's, which stays sealed), "+
				"must still work after the seal:\n%s", got, r.out)
		}
		if got, ok := verdicts["v6-name"]; !ok || strings.HasPrefix(got, "ERROR") {
			t.Errorf("a v6 AAAA lookup did not resolve inside the sandbox after the seal "+
				"(v6-name = %q):\n%s", got, r.out)
		}
	} else {
		t.Log("this host has no IPv6 internet reachability; skipping the v6 egress and " +
			"name-resolution positive controls (the link-local seal negative above still ran)")
	}
}
