package policy

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// NetMode is a total order joined by max, like Access: more reachability wins,
// so composing profiles can only ever open the network further.
type NetMode uint8

const (
	// NetIsolated is the floor: bwrap's own netns, loopback only, no helper
	// process. Offline is the ABSENCE of a net profile, not a setting — so it
	// cannot be switched back on by accident.
	NetIsolated NetMode = iota

	// NetEgress is a private netns with a pasta helper: full internet in and
	// out, host loopback unreachable.
	NetEgress

	// NetHost shares the HOST network namespace. Everything on 127.0.0.1, every
	// abstract AF_UNIX socket (X11, D-Bus), the LAN as the host. Requires
	// --i-know on the command line.
	NetHost
)

func (m NetMode) Join(o NetMode) NetMode {
	if o > m {
		return o
	}
	return m
}

func (m NetMode) String() string {
	switch m {
	case NetEgress:
		return "egress"
	case NetHost:
		return "host"
	default:
		return "isolated"
	}
}

func ParseNetMode(s string) (NetMode, error) {
	switch s {
	case "isolated":
		return NetIsolated, nil
	case "egress":
		return NetEgress, nil
	case "host":
		return NetHost, nil
	default:
		return 0, fmt.Errorf("unknown network mode %q (want isolated, egress or host)", s)
	}
}

type NetPolicy struct {
	Mode NetMode

	// Publish names ports the HOST's 127.0.0.1 should forward into the sandbox.
	// A human names each one; there is no "whatever the sandbox binds" form.
	Publish []int

	// DNS installs a generated /etc/resolv.conf, and pasta's --dns-forward when
	// the host has no nameserver the sandbox could reach directly.
	DNS bool

	// Nameservers are the host's resolvers that are actually routable from the
	// sandbox. Empty means "none usable" and forces the interception path.
	Nameservers []string

	// Address, when set, gives the sandbox a synthetic address instead of
	// copying the host's — so the agent does not learn your LAN IP.
	Address string // "10.13.13.2/24"
	Gateway string
	MTU     int
}

// dnsForwardAddr is the link-local address the sandbox is told to use as its
// nameserver. It does not exist; pasta intercepts traffic to it and re-issues
// the query from the HOST side, where the real resolver lives.
//
// This is what makes one sandbox-side configuration work on both a plain
// resolv.conf host and a systemd-resolved host. On the latter the real
// nameserver is 127.0.0.53, which the sandbox must NOT be able to reach — and
// does not: it talks to a link-local address that goes nowhere, and pasta
// answers on its behalf from outside.
const dnsForwardAddr = "169.254.1.1"

// ResolvConf is the generated /etc/resolv.conf content — generated, never a
// bind of the host's, which may name an address the sandbox must not reach.
//
// Two cases, and the choice is forced by how resolvers actually behave:
//
//   - The host's nameservers are ROUTABLE (a LAN router, a public resolver).
//     Name them directly. They reach the sandbox through pasta's ordinary
//     egress, exactly as any other address does.
//   - The host's nameservers are all LOOPBACK (systemd-resolved on 127.0.0.53).
//     The sandbox must not be able to reach host loopback — that is the whole
//     point — so point it at a link-local address that does not exist and let
//     pasta's --dns-forward intercept and re-issue the query from the host side.
//
// The design originally specified the second form unconditionally, on the
// grounds that one sandbox-side configuration then works everywhere. It does
// not: pasta's interception satisfies glibc's resolver but NOT c-ares, which
// curl on this host uses (`curl --version` reports AsynchDNS). With
// `nameserver 169.254.1.1`, `getent hosts example.com` resolved and `curl
// https://example.com` returned 000 with a resolver timeout. Preferring the
// host's real nameservers where they are usable avoids depending on
// interception at all.
//
// Residual limitation, documented rather than hidden: on a systemd-resolved
// host there IS no routable nameserver, so the interception path is the only
// option and c-ares-based clients may still fail there. Pin a routable resolver
// in a profile if that bites.
//
// `search .` rather than the host's search domains, so the sandbox does not
// learn your internal domain names and a bare hostname cannot accidentally
// resolve against a corporate suffix.
func (n NetPolicy) ResolvConf() []byte {
	if n.Mode == NetIsolated {
		return []byte("# snug: no network profile selected; DNS is intentionally unavailable.\n" +
			"# Resolver libraries will fail immediately rather than hang.\n")
	}
	servers := n.Nameservers
	if len(servers) == 0 {
		servers = []string{dnsForwardAddr}
	}
	var b strings.Builder
	for _, s := range servers {
		fmt.Fprintf(&b, "nameserver %s\n", s)
	}
	b.WriteString("search .\noptions edns0\n")
	return []byte(b.String())
}

// NeedsDNSForward reports whether pasta must intercept DNS, which is only true
// when the host has no nameserver the sandbox could reach on its own.
func (n NetPolicy) NeedsDNSForward() bool {
	return n.DNS && len(n.Nameservers) == 0
}

// RoutableNameservers filters a host nameserver list down to the ones a sandbox
// can actually reach. Loopback addresses are dropped precisely because the
// sandbox must not reach host loopback.
func RoutableNameservers(hostServers []string) []string {
	var out []string
	for _, s := range hostServers {
		ip := net.ParseIP(s)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		out = append(out, s)
	}
	return out
}

// PastaTarget is what pasta must be aimed at: the paths it opens for --netns
// and --userns. A single pid cannot always produce both — under the stage
// topology, no process is both IN the sandbox's network namespace N and IN the
// user namespace U that owns it (bwrap's child is in N but its own userns is a
// descendant of U with no authority over it) — so the two paths are named
// separately rather than derived from one pid.
//
// SUPERVISOR-DESIGN.md §3.4 measured (0b) that a pid alone cannot express
// the stage case: after P1 leaves N, /proc/<P1>/ns/net names P1's own empty
// namespace, and pasta accepts that path SILENTLY and attaches to the wrong
// one. Handing pasta the descriptor P1 pinned before it moved is refused
// outright — pasta drops privileges before it opens /proc/self/fd/<n> — so the
// only reference that works is P1's OWN fd table, named from outside as
// /proc/<P1>/fd/<n>.
type PastaTarget struct {
	NetnsPath  string // what pasta opens for --netns
	UsernsPath string // what pasta opens for --userns
}

// PastaTargetChild is today's shape: bwrap's own child owns both N (which
// bwrap's --unshare-net created) and the userns that owns it, so one pid names
// both paths.
func PastaTargetChild(childPID int) PastaTarget {
	return PastaTarget{
		NetnsPath:  fmt.Sprintf("/proc/%d/ns/net", childPID),
		UsernsPath: fmt.Sprintf("/proc/%d/ns/user", childPID),
	}
}

// PastaTargetStage is the stage shape: netnsFD is the descriptor P1 pinned on N
// BEFORE it left — never P1's own /proc/<pid>/ns/net, which after the move
// names the wrong (empty) namespace and which pasta will accept without
// complaint.
func PastaTargetStage(stagePID, netnsFD int) PastaTarget {
	return PastaTarget{
		NetnsPath:  fmt.Sprintf("/proc/%d/fd/%d", stagePID, netnsFD),
		UsernsPath: fmt.Sprintf("/proc/%d/ns/user", stagePID),
	}
}

// PastaArgs builds the pasta invocation for a sandbox whose netns and userns
// are named by t.
//
// EVERY security-relevant flag is passed explicitly, even where it matches the
// current default. pasta is tuned for "make the container work like the host",
// which is the opposite of what snug wants, and a default flipping upstream
// must not silently change our posture. The two that matter most:
//
//   - --map-host-loopback none. pasta's default is THE GATEWAY ADDRESS, which
//     translates to the host's loopback — the exact hole a private netns exists
//     to close.
//   - -T none -U none. These are ns->host forwards and BOTH DEFAULT TO auto,
//     which splices host loopback services into the namespace's own loopback.
//     The previous generation of this project passed the first flag and not
//     these, and its "private" netns could reach every host loopback service.
//     Verified: with only --map-host-loopback none, cups on 127.0.0.1:631 was
//     reachable from inside.
//
// TestPastaArgsAlwaysCloseHostLoopback asserts these by name, and an
// integration test asserts the BEHAVIOUR — because a golden argv test would
// have passed on the buggy configuration.
func (p *Policy) PastaArgs(t PastaTarget) []string {
	n := p.Net
	a := []string{
		// Configure address/routes/MTU inside the netns. NOT implied when
		// joining via --netns: without it the tap interface exists but stays
		// down with no address.
		"--config-net",

		"--map-host-loopback", "none",

		// host -> ns forwards
		"-t", publishSpec(n),
		"-u", "none",

		// ns -> host forwards. THE FIX. Never remove these.
		"-T", "none",
		"-U", "none",

		// Stable, recognisable interface name inside the sandbox.
		"--ns-ifname", "snug0",

		// Mandatory for a /proc/<pid>/ns/net target: without it pasta tries to
		// watch the netns *directory* and exits.
		"--no-netns-quit",

		// snug owns the diagnostics.
		"--quiet",

		// Stay OUR child. pasta daemonises by default, which would break
		// Pdeathsig, early-failure detection through Wait(), and deterministic
		// teardown all at once.
		"--foreground",
	}

	if n.NeedsDNSForward() {
		a = append(a, "--dns-forward", dnsForwardAddr)
	}
	if n.Address != "" {
		addr, prefix, _ := strings.Cut(n.Address, "/")
		a = append(a, "-a", addr)
		if prefix != "" {
			a = append(a, "-n", prefix)
		}
		if n.Gateway != "" {
			a = append(a, "-g", n.Gateway)
		}
	}
	if n.MTU > 0 {
		a = append(a, "--mtu", strconv.Itoa(n.MTU))
	}

	return append(a,
		"--netns", t.NetnsPath,
		// Joining a netns needs CAP_SYS_ADMIN in the userns that owns it.
		"--userns", t.UsernsPath,
	)
}

// publishSpec renders the host->sandbox forwarding rule.
//
// Every form is scoped to 127.0.0.1. The unscoped form binds on ALL host
// addresses, which would publish the agent's dev server to the LAN — a thing
// the human did not ask for and would not see.
func publishSpec(n NetPolicy) string {
	if len(n.Publish) == 0 {
		return "none"
	}
	ports := append([]int(nil), n.Publish...)
	sort.Ints(ports)
	seen := map[int]bool{}
	var out []string
	for _, p := range ports {
		if !seen[p] {
			seen[p] = true
			out = append(out, strconv.Itoa(p))
		}
	}
	return "127.0.0.1/" + strings.Join(out, ",")
}
