package policy

import (
	"fmt"
	"net"
	"net/netip"
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

	// NetEgress IS THE TOP. No mode shares the host's network namespace, so
	// host loopback and the host's abstract AF_UNIX sockets (X11, D-Bus) are
	// unreachable under every selection — see pastaArgs' --map-host-loopback
	// and -T/-U.
	//
	// Reaching ONE host-local service is an enumerated grant (invariant 2's
	// corollary), spelled `-T <port>` where pastaArgs passes `-T none`. It is not
	// built. A mode that hands over the whole namespace is not the fallback for
	// it — a capability whose only bound is a CLI flag is one that gets used
	// (CLAUDE.md, working agreement).
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
	default:
		return 0, fmt.Errorf("unknown network mode %q (want isolated or egress)", s)
	}
}

type NetPolicy struct {
	Mode NetMode

	// DNS installs a generated /etc/resolv.conf, and pasta's --dns-forward when
	// the host has no nameserver the sandbox could reach directly.
	DNS bool

	// Nameservers is the host's resolver list, RAW and unfiltered — every
	// address its /etc/resolv.conf names, loopback included.
	//
	// It used to arrive already filtered by RoutableNameservers, and that was
	// the loopback rule being decided in Resolve while the interception rule
	// was decided in Resolver: two authors for one question (invariant 6), and
	// the reason a sandbox was once handed an address nothing answers (issue
	// #164). The filter's premise is that the sandbox has a netns of its OWN,
	// where host loopback is unreachable by design — so it belongs where the
	// mode is known. Resolver applies it, per arm. Every mode that remains
	// satisfies that premise; the rule stays because the premise is what makes
	// it correct, not the count of modes.
	Nameservers []string

	MTU int
}

// dnsForwardAddr is the link-local address the sandbox is told to use as its
// nameserver. pasta intercepts traffic to it and re-issues the query from the
// HOST side, where the real resolver lives.
//
// This comment used to say "it does not exist", and a red team round falsified
// that on this very network: `ping 169.254.1.1` answers in 8.6 ms and
// `/dev/tcp/169.254.1.1/22` returns `SSH-2.0-dropbear_2017.75`. 169.254.0.0/16
// is link-local, not reserved-unroutable, and any device on the LAN may claim
// an address in it. What is true is narrower and is the thing the design
// actually relies on: INSIDE a sandbox pasta is configured for, traffic to
// this address is intercepted before it can leave, so nothing on the LAN sees
// it. Where no pasta is configured the sandbox really would send its queries at
// whatever answers that address — which is what issue #164 was — so naming the
// fallback honestly matters more than it looks.
//
// This is what makes one sandbox-side configuration work on both a plain
// resolv.conf host and a systemd-resolved host. On the latter the real
// nameserver is 127.0.0.53, which the sandbox must NOT be able to reach — and
// does not: it talks to a link-local address that goes nowhere, and pasta
// answers on its behalf from outside.
const dnsForwardAddr = "169.254.1.1"

// dnsForwardAddr6 is the IPv6 interception address, and it exists because
// pasta re-issues a query only to a --dns-host of the SAME family — measured:
// on a host whose only resolver is 2a00:ca8::100, `--dns-forward 169.254.1.1
// --dns-host 2a00:ca8::100` times out for A and AAAA alike, with or without
// the flag, while `--dns-forward fd00:5e79:1::53` answers both (issue #162's
// remnant).
//
// A ULA (RFC 4193 fd00::/8) rather than link-local: glibc will not use a
// link-local nameserver without a %scope suffix, and this address is never
// globally routed, so a query to it cannot leave even where no pasta
// intercepts.
const dnsForwardAddr6 = "fd00:5e79:1::53"

// ResolvConf is the generated /etc/resolv.conf content — generated, never a
// bind of the host's, which may name an address the sandbox must not reach.
//
// Two cases, forced by how resolvers actually behave:
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
// grounds that one sandbox-side configuration then works everywhere. This
// comment then carried a measurement saying it does not — that pasta's
// interception satisfied glibc's resolver but not c-ares, with `getent hosts
// example.com` resolving while `curl https://example.com` returned 000 on a
// resolver timeout. **That diagnosis was wrong, and it is re-measured here
// rather than deleted, because the wrong version is the more instructive
// one.** It was wrong twice over:
//
//   - `curl --version` printing AsynchDNS does not mean c-ares. It means
//     asynchronous resolution, which libcurl also provides with a THREADED
//     resolver. Measured on this host: `ldd /lib64/libcurl.so.4` names no
//     libcares at all, so the library blamed was never in the process.
//   - getent-resolves-but-curl-times-out is the exact signature of the
//     seccomp `clone3` defect CLAUDE.md records — a threaded resolver calls
//     `pthread_create`, glibc falls back from `clone3` to `clone` only on
//     ENOSYS, and denying it with EPERM surfaced as a DNS timeout that looked
//     precisely like a networking bug. That was fixed by returning the errno
//     callers have a tested fallback for.
//
// Re-measured on the interception arm after the fix (issue #162's branch, on
// a host whose only resolver is loopback): `getent hosts example.com`
// resolves, and `curl -w %{http_code} https://example.com` returns 200, three
// runs out of three. Interception costs the payload nothing observable here.
//
// The routable-nameserver arm is kept anyway, and deliberately: this is one
// host and one libcurl, "no cost measured here" is not "no cost anywhere",
// and naming a resolver the sandbox can reach directly depends on strictly
// less machinery than routing DNS through a helper process.
//
// `search .` rather than the host's search domains, so the sandbox does not
// learn your internal domain names and a bare hostname cannot accidentally
// resolve against a corporate suffix.
func (n NetPolicy) ResolvConf() []byte {
	r := n.Resolver()
	if len(r.Servers) == 0 {
		// THREE states reach here and the text must fit all of them: no
		// network profile at all; a profile granting egress that never asked
		// for DNS (`network = "egress"` with no `dns = true`); and — since
		// issue #162's remnant — a profile that DID ask for DNS on a host
		// that names no nameserver snug could parse and forward to at all.
		// The old wording named only the first two, so the third used to fall
		// through to naming dnsForwardAddr with nothing behind it: every
		// lookup inside waited out a five-second timeout instead of failing
		// immediately, measured at 40s for a single `getent` call. Naming
		// none here is what turns that into a 2ms failure — see the warning
		// internal/cli/main.go prints on the host side when this is why.
		return []byte("# snug: this sandbox has no resolver; DNS is intentionally unavailable.\n" +
			"# Either no network profile was selected, the one that was did not ask for DNS,\n" +
			"# or this host has no usable resolver for snug to forward to. Resolver\n" +
			"# libraries will fail immediately rather than hang.\n")
	}
	var b strings.Builder
	for _, s := range r.Servers {
		fmt.Fprintf(&b, "nameserver %s\n", s)
	}
	fmt.Fprintf(&b, "search %s\n", strings.Join(r.Searches, " "))
	fmt.Fprintf(&b, "options %s\n", strings.Join(r.Options, " "))
	return []byte(b.String())
}

// ResolverConfig is the DNS decision above expressed as VALUES rather than as
// /etc/resolv.conf syntax, so a second consumer can render it into its own
// format without re-deriving — or, worse, re-parsing — the decision.
//
// The second consumer is the container engine (issue #126). podman generates
// every container's /etc/resolv.conf from the ENGINE's own unless its
// containers.conf names DNS explicitly, and containers.conf spells the same
// three facts as three TOML lists rather than as resolver directives. Feeding
// that from ResolvConf's rendered bytes would mean parsing them back — which
// makes the rendered file a second author of a fact the policy already owns,
// against invariant 6 ("one Policy, one author"). Both renderers now read this
// one struct instead.
//
// Servers is empty exactly when the sandbox is offline. That is a real state
// with no /etc/resolv.conf spelling other than "name no nameserver", and each
// renderer says it in its own way — see ResolvConf above, and the engine's
// generated containers.conf.
type ResolverConfig struct {
	Servers  []string
	Searches []string
	Options  []string
}

// Resolver is the single derivation of what the sandbox is told about DNS.
// See ResolvConf for why the nameserver choice is what it is, and
// ResolverConfig for why the values are exposed separately from the file.
func (n NetPolicy) Resolver() ResolverConfig {
	r := ResolverConfig{
		// `search .` rather than the host's search domains, and `options
		// edns0`; both are part of the policy, not of the file format, so
		// they live here rather than in either renderer.
		Searches: []string{"."},
		Options:  []string{"edns0"},
	}
	// NAME NO RESOLVER AT ALL, and these are one state rather than two: "there
	// is no network" and "snug was not asked to configure DNS" both mean snug
	// has no resolver to name. Naming the interception address in either is
	// what issue #164 looked like from inside — a sandbox pointed at an
	// address with no forwarder behind it, so every lookup waits out a
	// five-second timeout instead of failing immediately, which is the exact
	// failure the offline file was written to avoid.
	//
	// !n.DNS is the half that used not to be here. A profile writing
	// `network = "egress"` without `dns = true` produced a resolv.conf naming
	// the interception address and a pasta argv with no --dns-forward — and
	// --dry-run printed no dns line at all, because the SCREEN consulted DNS
	// and this function did not.
	if n.Mode == NetIsolated || !n.DNS {
		return r
	}

	// EGRESS. The sandbox has a netns of its own, so a host resolver is usable
	// only if it is routable from there — this is where the filter belongs,
	// because this is the arm whose premise it encodes.
	r.Servers = RoutableNameservers(n.Nameservers)
	if len(r.Servers) == 0 {
		// THE FORWARDER, CHOSEN BY FAMILY (issue #162's remnant). Empty when
		// the host names no nameserver snug could parse — two states share
		// this branch (offline is excluded above already): a routable
		// resolver that turned out to be unparseable text, and a host with
		// only loopback resolvers (systemd-resolved).
		// See ResolvConf's doc comment for what an empty result means to the
		// generated file, and internal/cli/main.go for the host-side warning
		// when it is the no-nameserver-at-all case.
		if f := n.forwardAddr(); f != "" {
			r.Servers = []string{f}
		}
	}
	return r
}

// parsedNameservers parses n.Nameservers (RAW host text) into netip.Addr, in
// order, dropping anything that does not parse and anything carrying a ZONE.
//
// This is not a refusal — Nameservers is the host's own /etc/resolv.conf,
// invariant 3's trust class, not profile text a hostile payload can reach —
// so a line snug cannot use is silently skipped rather than fatal, the same
// way a malformed line is not a proof of anything. Dropping a ZONE rather
// than rendering it is V7's argument applied to host text (issue #177):
// netip.ParseAddr("fe80::1%<anything>") succeeds and String() re-emits the
// zone verbatim, so parsing alone is not escaping, and a link-local resolver
// is unusable inside the sandbox regardless of the zone's contents.
//
// Unmap()'d before it is kept (red team F3): a host naming a 4-in-6 mapped
// resolver (`::ffff:8.8.8.8`) classifies as Is4()||Is4In6() everywhere this
// file picks a family from it (forwardAddr, DNSHost), but String() on the
// UNmapped value still renders the v6-mapped spelling — so @net's DNS
// interception path on such a host emitted `--dns-forward 169.254.1.1 --dns-host
// ::ffff:8.8.8.8`: a v4 forwarder paired with a v6-spelled --dns-host, which
// pasta cannot answer (this file's own measured rule: pasta never crosses
// families when forwarding). Unmapping here makes the RENDERED value agree
// with the family the classifier already chose. Host text, not profile
// text, so it is fixed by coping (Unmap) rather than refused — the opposite
// of parseNetPrefix/parseNetGateway's treatment of the same shape in a
// profile's own address/gateway keys, where a wrong rendering is not the
// risk; a wrong ACCEPTANCE is (see their doc comments).
func (n NetPolicy) parsedNameservers() []netip.Addr {
	var out []netip.Addr
	for _, s := range n.Nameservers {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			continue
		}
		out = append(out, a.Unmap())
	}
	return out
}

// forwardAddr picks WHICH interception address to arm, by the family of the
// host's nameservers (issue #162's remnant) — empty when the host names none
// snug could parse.
//
// IPv4 preferred when the host has one, for a measured reason: the sandbox
// always has a v4 address and a v4 default route, whereas on a v4-only host
// pasta's v6 default is a local-mode stub via fe80::1, so a v4 forwarder is
// never stranded. Loopback nameservers count as "has a family" here — pasta
// runs on the HOST, where loopback is reachable, exactly DNSHost's own
// reasoning.
func (n NetPolicy) forwardAddr() string {
	var haveV4, haveV6 bool
	for _, a := range n.parsedNameservers() {
		if a.Is4() || a.Is4In6() {
			haveV4 = true
		} else {
			haveV6 = true
		}
	}
	switch {
	case haveV4:
		return dnsForwardAddr
	case haveV6:
		return dnsForwardAddr6
	default:
		return ""
	}
}

// DNSHost is the host-side resolver pasta is told to send intercepted queries
// to: the host's FIRST nameserver OF THE ARMED FORWARDER'S FAMILY, loopback
// included.
//
// Family-matched because pasta never crosses families when forwarding
// (measured, dnsForwardAddr6's doc comment): a v4-forwarded query re-issued
// to a v6 --dns-host times out, with or without a live v6 resolver behind it,
// and the reverse. Passed explicitly rather than left to pasta's default,
// which is documented as "first nameserver from host's /etc/resolv.conf" and
// would therefore READ THE SAME FILE A SECOND TIME with a second selection
// rule that additionally does not know about family (issue #166). CLAUDE.md's
// standing rule is to pass every security-relevant flag explicitly even when
// it matches the current default, because a default that changes upstream is
// a silent regression.
//
// Loopback INCLUDED is the deliberate half. pasta runs on the HOST, where
// 127.0.0.53 is reachable; RoutableNameservers exists to keep the SANDBOX off
// host loopback and its premise does not apply to the forwarder. Filtering
// here would break the systemd-resolved host that interception exists for.
//
// PARSED and re-rendered through netip, never the host's raw bytes (issue
// #177) — see parsedNameservers. Empty when no forwarder is armed, or none of
// the host's nameservers are of the armed family (which forwardAddr already
// guarantees cannot happen when it returned non-empty).
func (n NetPolicy) DNSHost() string {
	fam := n.forwardAddr()
	for _, a := range n.parsedNameservers() {
		is4 := a.Is4() || a.Is4In6()
		if (fam == dnsForwardAddr && is4) || (fam == dnsForwardAddr6 && !is4) {
			return a.String()
		}
	}
	return ""
}

// NeedsDNSForward reports whether pasta must be given --dns-forward: exactly
// when the file the sandbox will read names an interception address rather
// than a real resolver.
//
// It is DERIVED from Resolver rather than re-deciding the same question from
// the same fields, and that is the point rather than a style choice. The two
// used to test different conditions that happened to agree, and issue #162 is
// what disagreement looks like from the outside: one half of the DNS decision
// changing while the other keeps its old answer produces a sandbox told to
// talk to an address nothing is listening on — or, in #162's direction, a
// screen describing an interception that never happened. One derivation, one
// author (invariant 6).
func (n NetPolicy) NeedsDNSForward() bool {
	if !n.DNS {
		return false
	}
	s := n.Resolver().Servers
	return len(s) == 1 && (s[0] == dnsForwardAddr || s[0] == dnsForwardAddr6)
}

// HostAddressesSealed reports whether every address the host owns is sealed as
// a local route inside the sandbox's own network namespace — armed exactly
// when a pasta helper attaches to that namespace, since sealing is what closes
// the addresses pasta itself does not copy onto snug0 (the host's own
// link-local, and any second alias on another interface). The seal itself is
// host and stage work (internal/sandbox's host address enumeration,
// internal/stage/loopback.go's sealHostAddresses) — this predicate exists so
// --dry-run can describe the fact without either package reaching back into
// this pure one.
func (n NetPolicy) HostAddressesSealed() bool { return n.Mode == NetEgress }

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

// PastaTargetChild is the pre-stage shape: bwrap's own child owns both N (which
// bwrap's --unshare-net created) and the userns that owns it, so one pid names
// both paths.
//
// No run reaches it today — deriveTopology maps NetEgress, the only mode that
// starts pasta at all, to NetnsStage — so its only live caller is dryrun.go's
// else branch, which keeps the screen honest if that ever stops being true.
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
//     to close. ONE occurrence closes BOTH families — measured: the v4 gateway
//     maps to the host's 127.0.0.1 and the v6 gateway to ::1, but it is one
//     flag value, not two, so a second "--map-host-loopback none" for the v6
//     pair is not hardening. There is no second pasta default to close here.
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

		// host -> ns forwards. Nothing is forwarded INTO the namespace: a
		// listener a human wants to reach is served by `snug proxy`, which holds
		// a descriptor snug created and can check who is asking. A raw forward
		// here would be bound for the whole run, reachable by every uid on the
		// machine, and unable to inspect anything.
		"-t", "none",
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
		// The forwarder and its destination are ONE decision in TWO flags and
		// must agree on family: pasta re-issues a v4-forwarded query only to
		// a v4 --dns-host (measured — a live v6 --dns-host does not rescue
		// it, and neither does pasta's own default). Both come from
		// forwardAddr/DNSHost's shared family choice, so the file the sandbox
		// reads and the flags pasta gets cannot disagree.
		a = append(a, "--dns-forward", n.forwardAddr(), "--dns-host", n.DNSHost())
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
