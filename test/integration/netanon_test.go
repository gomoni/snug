//go:build integration

package integration

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// hostGlobalAddrs returns every GLOBAL unicast address (both families) bound
// to a host interface — the addresses @net-anon exists to hide. Loopback and
// link-local are excluded deliberately: they are never what pasta copies onto
// the sandbox's own interface, so their presence or absence proves nothing
// about anonymisation.
func hostGlobalAddrs(t *testing.T) []string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate host interfaces: %v", err)
	}
	var out []string
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out
}

// TestAnonymisedSandboxCarriesNoHostAddressInEitherFamily is issue #165's
// central regression: @net-anon existed to hide the host's address, and
// pasta's IPv6 default — copy the interface holding the default route — left
// the host's own GLOBAL v6 addresses on the sandbox's interface verbatim,
// privacy-extension temporary one included, while only the (RFC1918, low-
// value) v4 address was actually hidden.
//
// The control is what makes this test able to fail: under @net the host's
// addresses DO appear on snug0, so a version of this test that always passes
// (a sandbox that never started, or a host with no addresses at all) is
// caught before the real assertion runs.
func TestAnonymisedSandboxCarriesNoHostAddressInEitherFamily(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePasta(t)

	hostAddrs := hostGlobalAddrs(t)
	if len(hostAddrs) == 0 {
		t.Skip("no global host address discovered on this host")
	}
	proj, _ := target(t)

	addrShow := func(prof string) string {
		t.Helper()
		r := run(t, []string{"-p", prof}, proj, `command -v ip >/dev/null && ip -br addr show snug0 || echo NO-IP`).mustRun(t)
		return r.out
	}

	// POSITIVE CONTROL, and it is the whole test: @net copies the host's
	// addresses, so at least one of them must appear on snug0.
	netOut := addrShow("@net")
	if strings.Contains(netOut, "NO-IP") {
		t.Skip("iproute2 is not available inside the sandbox; this test needs `ip`")
	}
	if !strings.Contains(netOut, "snug0") {
		t.Fatalf("control: snug0 does not exist under @net, so the sandbox never got a "+
			"network namespace with pasta attached:\n%s", netOut)
	}
	named := 0
	for _, a := range hostAddrs {
		if strings.Contains(netOut, a) {
			named++
		}
	}
	if named == 0 {
		t.Fatalf("control: @net's snug0 carries none of the host's global addresses %v, so "+
			"the absence asserted below proves nothing:\n%s", hostAddrs, netOut)
	}

	anonOut := addrShow("@net-anon")
	if !strings.Contains(anonOut, "snug0") {
		t.Fatalf("snug0 does not exist under @net-anon:\n%s", anonOut)
	}
	if !strings.Contains(anonOut, "10.13.13.2/24") {
		t.Errorf("@net-anon's snug0 does not carry the expected synthetic v4 address:\n%s", anonOut)
	}
	if !strings.Contains(anonOut, "fd00:5e79:1::2/64") {
		t.Errorf("@net-anon's snug0 does not carry the expected synthetic v6 address (issue #165):\n%s", anonOut)
	}
	for _, a := range hostAddrs {
		if strings.Contains(anonOut, a) {
			t.Errorf("@net-anon's snug0 carries the host's own global address %s, which "+
				"anonymisation exists to hide:\n%s", a, anonOut)
		}
	}
}

// TestAnonymisedSandboxHasNoHostRouteOrRouterMAC is the route-table half of
// issue #165: `-a` with no matching `-g` (or an unset v6 pair) left pasta's
// IPv6 default in place — a route through the ROUTER's own link-local
// address, which carries the router's MAC (a stable, geolocatable hardware
// identifier) even though the address on the interface was synthetic.
//
// Control: under @net, a `proto ra` default route through the router's own
// link-local address IS present, distinguishing "no route at all" from "the
// route was anonymised".
func TestAnonymisedSandboxHasNoHostRouteOrRouterMAC(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	routeShow := func(prof string) string {
		t.Helper()
		r := run(t, []string{"-p", prof}, proj, `command -v ip >/dev/null && ip -6 route show default || echo NO-IP`).mustRun(t)
		return r.out
	}

	netOut := routeShow("@net")
	if strings.Contains(netOut, "NO-IP") {
		t.Skip("iproute2 is not available inside the sandbox; this test needs `ip`")
	}
	if !strings.Contains(netOut, "proto ra") {
		t.Skip("this host's @net sandbox has no IPv6 RA default route to compare against " +
			"(no IPv6 default route on the host, or pasta did not copy one)")
	}

	anonOut := routeShow("@net-anon")
	if strings.Contains(anonOut, "proto ra") {
		t.Errorf("@net-anon's default route still carries 'proto ra' — pasta's own IPv6 "+
			"default (copy the host's route) was not overridden by the synthetic gateway:\n%s", anonOut)
	}
	if !strings.Contains(anonOut, "fd00:5e79:1::1") {
		t.Errorf("@net-anon's default route is not via the synthetic gateway fd00:5e79:1::1:\n%s", anonOut)
	}
}

// loopbackProbePy is a minimal, dependency-free (no iproute2, no requests)
// probe: one RESULT line per family, so a verdict is RECORDED rather than
// inferred from silence — the same discipline TestHostLoopbackIsUnreachable
// uses.
const loopbackProbePy = `import socket, sys

def probe(label, fam, host, port):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        if fam == socket.AF_INET6:
            s.connect((host, port, 0, 0))
        else:
            s.connect((host, port))
        print("RESULT", label, "REACHED")
    except ConnectionRefusedError:
        print("RESULT", label, "REFUSED")
    except socket.timeout:
        print("RESULT", label, "TIMEDOUT")
    except OSError as e:
        print("RESULT", label, "ERROR", e)
    finally:
        s.close()

probe("v4", socket.AF_INET, "127.0.0.1", int(sys.argv[1]))
if len(sys.argv) > 2:
    probe("v6", socket.AF_INET6, "::1", int(sys.argv[2]))
`

// TestHostLoopbackIsUnreachableUnderEveryNetProfile extends the loopback
// guarantee to @net-anon. TestHostLoopbackIsUnreachable exercises exactly one
// profile (@net), and its own LAN-address/gateway probes do not apply
// unchanged to an anonymising profile — see
// TestAnonymisingReachesTheHostsOwnAddressAndThatIsDocumented for that
// widening, which is a disclosure rather than a regression — so this test is
// scoped to the property that must hold under EVERY net profile without
// exception: host loopback, both families, closed. It runs one profile
// today, which is why the widening in issue #176 was never caught.
func TestHostLoopbackIsUnreachableUnderEveryNetProfile(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	ln4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveBanner(t, ln4)
	tcpPort := ln4.Addr().(*net.TCPAddr).Port

	haveV6 := true
	v6Port := 0
	if ln6, err := net.Listen("tcp6", "[::1]:0"); err != nil {
		haveV6 = false
	} else {
		serveBanner(t, ln6)
		v6Port = ln6.Addr().(*net.TCPAddr).Port
	}

	if err := os.WriteFile(filepath.Join(proj, "loopbackevery.py"), []byte(loopbackProbePy), 0o644); err != nil {
		t.Fatal(err)
	}

	args := shellArgs(tcpPort, v6Port, haveV6)

	for _, prof := range []string{"@net", "@net-anon"} {
		t.Run(prof, func(t *testing.T) {
			r := run(t, []string{"-p", prof}, proj, "python3 loopbackevery.py "+args).mustRun(t)
			if !strings.Contains(r.out, "RESULT v4") {
				t.Fatalf("the v4 loopback probe produced no verdict at all under %s:\n%s", prof, r.out)
			}
			if strings.Contains(r.out, "RESULT v4 REACHED") {
				t.Errorf("host v4 loopback was REACHED under %s:\n%s", prof, r.out)
			}
			if haveV6 {
				if !strings.Contains(r.out, "RESULT v6") {
					t.Fatalf("the v6 loopback probe produced no verdict at all under %s:\n%s", prof, r.out)
				}
				if strings.Contains(r.out, "RESULT v6 REACHED") {
					t.Errorf("host v6 loopback was REACHED under %s:\n%s", prof, r.out)
				}
			}
		})
	}
}

// TestAnonymisingReachesTheHostsOwnAddressAndThatIsDocumented is issue
// #176's regression test and the honest half of the widening §A accepted:
// hiding the host's address is what makes the host's OWN services reachable
// from inside, in both families now that #165's v6 pair ships, because the
// packet stops being refused by the sandbox's own stack (the address is no
// longer its own) and instead leaves the netns for pasta to open on the
// host. Host LOOPBACK stays closed throughout — that is the property this
// project promises — and this test's own control is @net, where the host's
// own address is refused exactly as loopback is.
//
// A future change that closes this reach must update BOTH this test and the
// --dry-run text it also checks, which is the point of asserting both here.
func TestAnonymisingReachesTheHostsOwnAddressAndThatIsDocumented(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePasta(t)

	lanAddr, err := hostOutboundAddr()
	if err != nil {
		t.Skipf("could not discover this host's own outbound address: %v", err)
	}
	ln, err := net.Listen("tcp4", lanAddr+":0")
	if err != nil {
		t.Skipf("could not bind a listener on %s: %v", lanAddr, err)
	}
	serveBanner(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port

	// PRECONDITION: the host can reach its own listener.
	c, err := net.DialTimeout("tcp4", net.JoinHostPort(lanAddr, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatalf("precondition: the host cannot reach its own listener on %s: %v", lanAddr, err)
	}
	c.Close()

	proj, _ := target(t)
	probePy := `import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(("` + lanAddr + `", ` + strconv.Itoa(port) + `))
    print("REACHED", s.recv(64).decode(errors="replace").strip())
except ConnectionRefusedError:
    print("REFUSED")
except socket.timeout:
    print("TIMEDOUT")
except OSError as e:
    print("ERROR", e)
`
	if err := os.WriteFile(filepath.Join(proj, "lanreach.py"), []byte(probePy), 0o644); err != nil {
		t.Fatal(err)
	}

	// CONTROL: under @net the host's own address is on the sandbox's own
	// interface, so the connection never leaves the netns and the sandbox's
	// own kernel refuses it — exactly like loopback.
	netResult := run(t, []string{"-p", "@net"}, proj, "python3 lanreach.py").mustRun(t)
	if strings.Contains(netResult.out, "REACHED") {
		t.Fatalf("control: @net reached the host's own address %s — the address is copied "+
			"onto the sandbox's own interface under @net, so this should be refused "+
			"exactly like loopback:\n%s", lanAddr, netResult.out)
	}

	anonResult := run(t, []string{"-p", "@net-anon"}, proj, "python3 lanreach.py").mustRun(t)
	if !strings.Contains(anonResult.out, "REACHED") {
		t.Errorf("@net-anon did NOT reach the host's own address %s — if this reach has been "+
			"closed, that is real hardening, but it must be deliberate: update this test AND "+
			"the --dry-run text (dryrun.go's describeNetwork, 'host's own IPs' row):\n%s",
			lanAddr, anonResult.out)
	}

	// The screen must say so, in both directions: @net-anon documents the
	// reach, @net documents the refusal.
	screenAnon, code := cli(t, nil, "--dry-run", "-p", "@net-anon", proj, "--", "true")
	if code != 0 {
		t.Fatalf("--dry-run -p @net-anon exited %d:\n%s", code, screenAnon)
	}
	if !strings.Contains(screenAnon, "REACHABLE") {
		t.Errorf("--dry-run -p @net-anon does not document that the host's own addresses "+
			"become reachable:\n%s", screenAnon)
	}
	screenNet, code := cli(t, nil, "--dry-run", "-p", "@net", proj, "--", "true")
	if code != 0 {
		t.Fatalf("--dry-run -p @net exited %d:\n%s", code, screenNet)
	}
	if !strings.Contains(screenNet, "unreachable") {
		t.Errorf("--dry-run -p @net does not document that the host's own addresses stay "+
			"unreachable:\n%s", screenNet)
	}
}

// shellArgs builds the argv tail for loopbackProbePy: the v4 port always, the
// v6 port only when this host has an IPv6 loopback to test against.
func shellArgs(tcpPort, v6Port int, haveV6 bool) string {
	if !haveV6 {
		return strconv.Itoa(tcpPort)
	}
	return strconv.Itoa(tcpPort) + " " + strconv.Itoa(v6Port)
}
