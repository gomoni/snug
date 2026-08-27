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

	// Address/Gateway (v4) and Address6/Gateway6 (v6), when set, give the
	// sandbox a synthetic address instead of copying the host's — so the
	// agent does not learn your LAN IP. Typed as netip rather than string:
	// Resolve is the only place profile TEXT is parsed into these, and the
	// parse is a structural refusal of most of the forging-rune hazard for
	// free (a prefix or address literal contains only hex digits, dots,
	// colons and a slash). It is NOT a complete one — an IPv6 ZONE is
	// arbitrary text and Addr.String() re-emits it verbatim, so Gateway and
	// Gateway6 still need V7's explicit check (checkAddressPair). See
	// addrPairs for why every rule about these four fields is written once
	// over the pair rather than twice over the fields.
	//
	// V6 (checkAddressPair) requires all four or none: pasta assigns
	// addresses PER FAMILY, so a policy naming only one leaves the other at
	// the host's own (issue #165).
	Address  netip.Prefix // v4; !IsValid() means "copy the host's"
	Gateway  netip.Addr
	Address6 netip.Prefix // v6; !IsValid() means "copy the host's"
	Gateway6 netip.Addr
	MTU      int
}

// netAddrPair is one family's (address, gateway) with the TOML key names that
// spell it. Every rule about these fields is written ONCE over addrPairs()
// and never twice over four fields, because "a rule written once and applied
// to one of its two halves" is this project's named recurring defect and it
// has already produced #162 (search domain anonymised, nameserver not) and
// #165 (v4 anonymised, v6 not) in the same subsystem. Adding a family later —
// there is no third one on the horizon, but the shape should not assume that —
// is one element here, not a sweep for every site that said "v4".
type netAddrPair struct {
	keyAddr, keyGW string
	addr           netip.Prefix
	gw             netip.Addr
	want4          bool
}

// addrPairs is the one place that knows there are two families.
func (n NetPolicy) addrPairs() [2]netAddrPair {
	return [2]netAddrPair{
		{keyAddr: "address", keyGW: "gateway", addr: n.Address, gw: n.Gateway, want4: true},
		{keyAddr: "address6", keyGW: "gateway6", addr: n.Address6, gw: n.Gateway6, want4: false},
	}
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
// intercepts. Inside @net-anon's own /64 (issue #165) so it is on-link there;
// MEASURED to be intercepted off-link too, under plain @net, so one constant
// serves both arms.
const dnsForwardAddr6 = "fd00:5e79:1::53"

// ResolvConf is the generated /etc/resolv.conf content — generated, never a
// bind of the host's, which may name an address the sandbox must not reach.
//
// Three cases, and the first two are forced by how resolvers actually behave:
//
//   - The host's nameservers are ROUTABLE (a LAN router, a public resolver).
//     Name them directly. They reach the sandbox through pasta's ordinary
//     egress, exactly as any other address does.
//   - The host's nameservers are all LOOPBACK (systemd-resolved on 127.0.0.53).
//     The sandbox must not be able to reach host loopback — that is the whole
//     point — so point it at a link-local address that does not exist and let
//     pasta's --dns-forward intercept and re-issue the query from the host side.
//   - The profile ANONYMISES the sandbox (Address is set, i.e. @net-anon).
//     Interception, whatever the host's nameservers are — because naming them
//     hands back the thing the synthetic address exists to withhold. See
//     Resolver for the argument and the measurement (issue #162).
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
// Re-measured on the interception arm after the fix (issue #162's branch, via
// @net-anon, which now always intercepts): `getent hosts example.com`
// resolves, and `curl -w %{http_code} https://example.com` returns 200, three
// runs out of three. Interception costs the payload nothing observable here.
//
// The routable-nameserver arm is kept anyway, and deliberately: this is one
// host and one libcurl, "no cost measured here" is not "no cost anywhere",
// and naming a resolver the sandbox can reach directly depends on strictly
// less machinery than routing DNS through a helper process. What changes is
// that the arm is no longer justified by a client incompatibility that does
// not reproduce — so an anonymising profile can be moved onto interception
// (above) without trading a disclosure for a broken resolver, which is the
// trade issue #162 thought it was proposing.
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
	if n.Anonymised() {
		// AN ANONYMISING PROFILE, and the reason this branch exists at all
		// (issue #162). Address is set only by a profile whose whole purpose
		// is that the sandbox does not learn where the host sits — @net-anon
		// is the one that ships. Naming the host's own resolvers inside such
		// a sandbox gives that away on the adjacent line of the same
		// generated file: a LAN resolver is normally the router, so
		// 192.168.1.1 discloses the /24 the hidden host address sits in, and
		// an IPv6 ULA resolver discloses a randomly-generated, stable
		// per-site prefix. The search domain was already anonymised here and
		// the nameserver was not — one rule applied to one of its two halves,
		// which is the shape CLAUDE.md says to watch for.
		//
		// So: fall through to interception. pasta re-issues the query from
		// the HOST side, and no host address appears in the file at all.
		// Verified by execution, not reasoned about: with `-a 10.13.13.2 -n
		// 24 -g 10.13.13.1 --dns-forward 169.254.1.1`, the sandbox resolves
		// and /etc/resolv.conf names only the link-local address.
		//
		// This is deliberately keyed on Address rather than on the profile
		// NAME, so a future anonymising profile — or a human's own, in
		// ~/.config/snug/profiles.d — inherits the property instead of
		// re-opening the hole under a different name.
		//
		// It is reached only from this arm, and that is a fix rather than a
		// tidy-up: gating it on the mode was once missing, and a selection
		// pairing the anonymising profile with a mode no pasta applies it to
		// then stopped resolving — anonymising DNS there withheld a working
		// resolver and substituted nothing. That mode is gone; the gate stays,
		// because the rule is about which arm's premise holds.
		r.Servers = nil
	}
	if len(r.Servers) == 0 {
		// THE FORWARDER, CHOSEN BY FAMILY (issue #162's remnant). Empty when
		// the host names no nameserver snug could parse — three states share
		// this branch (offline is excluded above already): a routable
		// resolver that turned out to be unparseable text, a host with only
		// loopback resolvers (systemd-resolved), and an anonymising profile.
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
// UNmapped value still renders the v6-mapped spelling — so an anonymising
// policy on such a host emitted `--dns-forward 169.254.1.1 --dns-host
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

// renderAddrs renders a list of parsed addresses back to strings, through
// netip's own String() — the belt half of "parse, then render", never the
// host's original bytes.
func renderAddrs(addrs []netip.Addr) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
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

// Anonymised reports whether this sandbox withholds the HOST's network
// position from the payload, in EITHER family — not the v4 one, and not both.
// Every consumer withholds MORE when this is true (Resolver drops the host's
// resolvers entirely), so the safe direction under an incomplete NetPolicy is
// true: NOT `&&`, because AND would report a half-set policy as NOT
// anonymising, re-opening #162 for that configuration (the host's real
// resolvers named inside a sandbox whose author asked for anonymity).
//
// checkAddressPair's V6 makes the incomplete case unreachable through Resolve
// and Validate, which is exactly why this predicate must not DEPEND on V6: a
// correctness argument enforced two functions away is the shape that produced
// #165.
func (n NetPolicy) Anonymised() bool { return n.Address.IsValid() || n.Address6.IsValid() }

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

// familyWord names the family of an already-parsed address, for a V2 refusal.
func familyWord(is4 bool) string {
	if is4 {
		return "IPv4"
	}
	return "IPv6"
}

// siblingNetKey names the OTHER family's spelling of a network scalar key, so
// a V2 refusal can say "you probably meant %s" rather than just "wrong".
func siblingNetKey(key string) string {
	switch key {
	case "address":
		return "address6"
	case "address6":
		return "address"
	case "gateway":
		return "gateway6"
	case "gateway6":
		return "gateway"
	}
	return ""
}

// checkAddrIsUsable is V5: no unspecified, loopback or multicast address in
// ANY of the four network scalars. pasta may accept one of these silently and
// let the sandbox do something no profile author meant — an unspecified
// address is not a real synthetic one, a loopback address is the one thing a
// private netns exists to keep unreachable, and a multicast address cannot be
// assigned to an interface at all.
func checkAddrIsUsable(a netip.Addr) string {
	switch {
	case a.IsUnspecified():
		return "is unspecified"
	case a.IsLoopback():
		return "is a loopback address"
	case a.IsMulticast():
		return "is a multicast address"
	}
	return ""
}

// mappedV4Error is part of V2, split out because it is checked identically
// in all four keys and its message must name the real problem rather than
// "wrong family" (red team F1). A 4-in-6 mapped literal (::ffff:a.b.c.d)
// satisfies Is4()||Is4In6() as though it were an ordinary v4 value — which
// is exactly the shortcut this file used to take — but pasta does not agree
// with itself about it: measured, `-a ::ffff:10.13.13.2/120` is read as an
// IPv4 address (so V2's old check saw a match and let it through), while `-g
// ::ffff:10.13.13.1` is silently DISCARDED, and pasta falls back to its OWN
// default gateway — the host's real router. The result was accepted by V2,
// left V3/V4/V6 nothing to object to (the pair "matched"), and reached
// `--dry-run` as an ordinary synthetic address: `default via 192.168.1.1`
// appeared inside, no warning, exit 0 — precisely the half-anonymised state
// V6 exists to forbid, produced without tripping it.
//
// Refused in EITHER family's keys, unconditionally: it is never the
// spelling a profile author meant, in address/gateway (where it silently
// re-admits the host's router) or in address6/gateway6 (where it is not a
// real v6 address either). suggestion is the bare literal to write instead.
func mappedV4Error(name ProfileName, key, raw, suggestion string) error {
	return fmt.Errorf("profile %q: network %s %s is a 4-in-6 mapped address (::ffff:a.b.c.d). "+
		"pasta treats a mapped ADDRESS as IPv4 but silently DISCARDS a mapped GATEWAY, falling "+
		"back to its own default — the host's real router — which is exactly the "+
		"half-anonymised state this profile's own address key exists to forbid (measured: "+
		"`default via <host router>` appeared inside, exit 0, no warning). "+
		"Write the bare literal instead: %s",
		name, key, VisibleText(raw), suggestion)
}

// parseNetPrefix parses a profile's address/address6 value: V1 (parses as a
// netip.Prefix — ParsePrefix refuses a v6 ZONE outright, measured, and
// refuses trailing junk after the prefix, which is why the pre-netip forging
// refusal in validate.go could be retired for this half of the pair at all —
// see checkAddressPair for the half it could NOT retire), V2 (the value's
// family must match the key it was written under, and must not be a 4-in-6
// mapped spelling of either family — mappedV4Error), and V5.
//
// err's own text is escaped too (VisibleText, not %v) even though it is
// SAFE today — measured: netip.ParsePrefix/ParseAddr already quote the raw
// input inside their own error (`‮`, not the raw byte) — because this
// refusal must not depend on a standard-library error format staying that
// way, which is the same reasoning that keeps visibleValue on a Prefix's own
// String() even though String() cannot forge either.
func parseNetPrefix(name ProfileName, key, raw string, want4 bool) (netip.Prefix, error) {
	pfx, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("profile %q: network %s %s does not parse as an "+
			"address/prefix (e.g. \"10.13.13.2/24\"): %s", name, key, VisibleText(raw), VisibleText(err.Error()))
	}
	a := pfx.Addr()
	// Checked BEFORE the family-mismatch message below, on purpose: a mapped
	// value satisfies want4's check today, and moving straight to "wrong
	// family, use %s instead" would send the author to address6/gateway6
	// with a value that is not a real v6 literal there either.
	if a.Is4In6() {
		bits := pfx.Bits() - 96
		suggestion := a.Unmap().String()
		if bits >= 0 {
			suggestion = fmt.Sprintf("%s/%d", a.Unmap(), bits)
		}
		return netip.Prefix{}, mappedV4Error(name, key, raw, suggestion)
	}
	if is4 := a.Is4(); is4 != want4 {
		return netip.Prefix{}, fmt.Errorf("profile %q: network %s is %s (%s), which is an %s "+
			"value; write it as %s instead", name, key, VisibleText(raw), a, familyWord(is4), siblingNetKey(key))
	}
	if reason := checkAddrIsUsable(a); reason != "" {
		return netip.Prefix{}, fmt.Errorf("profile %q: network %s %s %s (%s); pasta may accept "+
			"it silently and the sandbox would do something no profile author meant",
			name, key, VisibleText(raw), reason, a)
	}
	return pfx, nil
}

// parseNetGateway parses a profile's gateway/gateway6 value: V1, V2 (family
// match, and no 4-in-6 mapped spelling — mappedV4Error, same reasoning as
// parseNetPrefix and the more dangerous half of the pair: pasta silently
// DISCARDS a mapped gateway rather than merely mis-filing it), V5, and V7 —
// no ZONE. Unlike a Prefix, ParseAddr does NOT refuse a zoned literal, and
// Addr.String() re-emits the zone verbatim wherever this value is later
// shown, which is the corrected half of the netip claim (a zoned link-local
// gateway is the shape of a real v6 default route, not a contrived one).
func parseNetGateway(name ProfileName, key, raw string, want4 bool) (netip.Addr, error) {
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("profile %q: network %s %s does not parse as an "+
			"address: %s", name, key, VisibleText(raw), VisibleText(err.Error()))
	}
	if a.Is4In6() {
		return netip.Addr{}, mappedV4Error(name, key, raw, a.Unmap().String())
	}
	if is4 := a.Is4(); is4 != want4 {
		return netip.Addr{}, fmt.Errorf("profile %q: network %s is %s, which is an %s value; "+
			"write it as %s instead", name, key, VisibleText(raw), familyWord(is4), siblingNetKey(key))
	}
	if a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("profile %q: network %s %s carries a zone (%s); a "+
			"zoned address re-emits the zone verbatim wherever this value is later shown — in "+
			"`snug --dry-run` and in the pasta command below it — so write the bare address",
			name, key, VisibleText(raw), VisibleText(a.Zone()))
	}
	if reason := checkAddrIsUsable(a); reason != "" {
		return netip.Addr{}, fmt.Errorf("profile %q: network %s %s %s (%s); pasta may accept "+
			"it silently and the sandbox would do something no profile author meant",
			name, key, VisibleText(raw), reason, a)
	}
	return a, nil
}

// checkAddressPair enforces V3, V4, V6 and V7 over the RESOLVED values — see
// addrPairs for why this is written once over the pair rather than twice over
// four fields. Called from Resolve, post-fold, with the owning profile for
// each present key so the refusal can name it; and from Validate with a nil
// map, as the backstop for a Policy built by hand, which never ran the
// per-value parse above that ALSO enforces V7 — one body, because two
// spellings of this rule are exactly what a reader would have to diff to
// trust either.
//
// V1, V2 and V5 are NOT re-checked here: they are properties of a single
// profile-supplied value, already enforced at parse time in Resolve, and a
// hand-built Policy's netip fields cannot fail to "parse" (they already are
// the typed value) — see net_test.go's own note on what that leaves
// uncovered for V2 specifically.
func (n NetPolicy) checkAddressPair(owners map[string]ProfileName) error {
	pairs := n.addrPairs()
	var present, missing []string
	for _, pr := range pairs {
		if pr.addr.IsValid() {
			present = append(present, pr.keyAddr)
		} else {
			missing = append(missing, pr.keyAddr)
		}
		if pr.gw.IsValid() {
			present = append(present, pr.keyGW)
		} else {
			missing = append(missing, pr.keyGW)
		}
		// V7, ADDRESS role. A Prefix built by ParsePrefix cannot carry a
		// zone (measured). This branch's own doc comment used to claim a
		// hand-built netip.PrefixFrom(zonedAddr, bits) could smuggle one in
		// — MEASURED FALSE, and it is worth naming the error rather than
		// quietly fixing it (red team F2): PrefixFrom(zonedAddr, bits)
		// STRIPS the zone (`PrefixFrom(fe80::1%eth0, 64) -> addrZone=""`),
		// so this branch is UNREACHABLE today — every zoned Prefix a Go
		// program can construct through the stdlib loses the zone before it
		// ever reaches here. It stays anyway, as belt-and-braces against a
		// future netip release changing that behaviour, and because a
		// Prefix built through some OTHER means (a third-party library, an
		// unsafe cast) is not something this package can rule out by
		// reading net/netip's current source. See
		// TestAZonedAddressIsRefusedEverywhereItCanBeBuilt for why its own
		// "ADDRESS role" subtest could not actually exercise this branch
		// either, and what asserting that honestly requires.
		if pr.addr.IsValid() && pr.addr.Addr().Zone() != "" {
			return fmt.Errorf("network %s %s carries a zone (%s): a zoned address re-emits the "+
				"zone verbatim wherever this value is later shown — in `snug --dry-run` and in "+
				"the pasta command below it — so write the bare prefix",
				pr.keyAddr, VisibleText(pr.addr.String()), VisibleText(pr.addr.Addr().Zone()))
		}
		if pr.gw.IsValid() && pr.gw.Zone() != "" {
			return fmt.Errorf("network %s %s carries a zone (%s): a zoned address re-emits the "+
				"zone verbatim wherever this value is later shown — in `snug --dry-run` and in "+
				"the pasta command below it — so write the bare address",
				pr.keyGW, VisibleText(pr.gw.String()), VisibleText(pr.gw.Zone()))
		}
		// V8, IPv6 ONLY: pasta PARSES the inline v6 prefix and then throws it
		// away. There is no c->ip6.prefix_len field; the namespace address is
		// configured with a literal 64 (`nl_addr_set(..., AF_INET6, &c->ip6.addr,
		// 64)`) and the RA's Prefix Information option carries a hardcoded
		// .prefix_len = 64. pasta's own man page says so under `-a`: "If a prefix
		// length is assigned to an IPv6 address using this method, it will in the
		// current code version be overridden by the default value of 64."
		//
		// So `address6 = "fd00::2/112"` used to resolve and hand the sandbox a
		// /64 — a WIDER on-link set than the author wrote, silently, which is the
		// silent downgrade invariant 5 forbids. Refusing is the only honest
		// answer: snug cannot deliver the narrower prefix, and narrowing the
		// author's value to the nearest thing pasta accepts is what an
		// unrecognised value must never be read as.
		//
		// The v4 half needs no such rule — pasta keeps it
		// (`c->ip4.prefix_len = prefix_len - 96`) — which is why this is keyed on
		// want4 rather than applied to the pair.
		if pr.addr.IsValid() && !pr.want4 && pr.addr.Bits() != 64 {
			return fmt.Errorf("network %s %s is a /%d: pasta discards an inline IPv6 prefix and "+
				"configures the address as a /64 regardless (its own man page says so under "+
				"`-a`), so the sandbox would treat a WIDER set of addresses as on-link than "+
				"this profile asks for. Write %s/64, or pick a narrower ADDRESS",
				pr.keyAddr, VisibleText(pr.addr.String()), pr.addr.Bits(), pr.addr.Addr())
		}
		if pr.addr.IsValid() && pr.gw.IsValid() {
			// V3: pasta refuses a gateway outside its address's prefix
			// ("No route to host", measured).
			if !pr.addr.Contains(pr.gw) {
				return fmt.Errorf("network %s %s is not inside %s %s: pasta refuses this "+
					"combination (\"No route to host\")", pr.keyGW, pr.gw, pr.keyAddr, pr.addr)
			}
			// V4: pasta refuses a gateway equal to the address itself
			// ("Invalid argument", measured).
			if pr.gw == pr.addr.Addr() {
				return fmt.Errorf("network %s %s equals the %s address %s: pasta refuses this "+
					"combination (\"Invalid argument\"); pick a different address inside the prefix",
					pr.keyGW, pr.gw, pr.keyAddr, pr.addr)
			}
		}
	}
	// V6: all four, or none.
	if len(present) == 0 || len(missing) == 0 {
		return nil
	}
	return halfAnonymisedError(present, missing, pairs, owners)
}

// halfAnonymisedError is V6's refusal. Subject is the RESOLVED policy, not
// one profile — a pair legitimately split across two profiles (one naming
// `address`/`gateway`, another `address6`/`gateway6`) must not be blamed on
// either alone — but the owning profile(s) are named when known, because
// "it broke" should become "I know which line to change".
//
// snug REFUSES here rather than warning, and that asymmetry with the
// no-resolver case (internal/cli/main.go) is one rule, not two moods: warn
// when the missing thing makes the sandbox do LESS (a payload with no DNS is
// strictly less capable, and the absence is loudly visible from inside in
// milliseconds); refuse when it makes the sandbox LEAK MORE. A
// half-anonymised sandbox WORKS PERFECTLY and discloses exactly what the
// profile's own name says it hides — invisible from inside, and invisible in
// --dry-run until a human reads this refusal.
func halfAnonymisedError(present, missing []string, pairs [2]netAddrPair, owners map[string]ProfileName) error {
	subject := "the resolved policy"
	if owners != nil {
		seen := map[ProfileName]bool{}
		var who []string
		for _, key := range present {
			if o := owners[key]; o != "" && !seen[o] {
				seen[o] = true
				who = append(who, string(o))
			}
		}
		if len(who) > 0 {
			subject = "profile " + strings.Join(who, "+")
		}
	}
	var have []string
	for _, pr := range pairs {
		if pr.addr.IsValid() {
			have = append(have, fmt.Sprintf("%s = %q", pr.keyAddr, pr.addr))
		}
		if pr.gw.IsValid() {
			have = append(have, fmt.Sprintf("%s = %q", pr.keyGW, pr.gw))
		}
	}
	return fmt.Errorf("network anonymisation is half-applied: %s sets %s but not %s.\n"+
		"       pasta assigns addresses PER FAMILY, so the family you did not name keeps the\n"+
		"       HOST's own addresses. Measured on a dual-stack host: `-a 10.13.13.2/24` alone left\n"+
		"       BOTH of the host's global IPv6 addresses on the sandbox's interface, the privacy-\n"+
		"       extension temporary one included, plus a default route through the router's\n"+
		"       link-local address. Those are globally routable, geolocatable and ISP-attributable;\n"+
		"       the IPv4 address you withheld is RFC1918 (issue #165). An `address` with no\n"+
		"       `gateway` is the same shape one step further in: pasta then keeps the host's own\n"+
		"       default route, so the ROUTE TABLE discloses the router and the LAN prefix even\n"+
		"       though the address itself is synthetic.\n"+
		"       snug refuses rather than warns because this is a guarantee that no longer holds,\n"+
		"       not a capability that is missing: the sandbox works perfectly and discloses\n"+
		"       exactly what the profile's own name says it hides.\n"+
		"       Currently set: %s\n"+
		"       Fix: write all four keys, or none. These are @net-anon's, and they work:\n"+
		"           address  = \"10.13.13.2/24\"          gateway  = \"10.13.13.1\"\n"+
		"           address6 = \"fd00:5e79:1::2/64\"      gateway6 = \"fd00:5e79:1::1\"\n"+
		"       Or drop your own profile and select @net-anon.",
		subject, strings.Join(present, ", "), strings.Join(missing, ", "), strings.Join(have, ", "))
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
	for _, pair := range n.addrPairs() {
		if !pair.addr.IsValid() {
			continue
		}
		// ONE -a per family, and the prefix INLINE in both. pasta's -n is a
		// single GLOBAL netmask, not a per-family one: with -n present, an
		// inline prefix in ANY -a is "Redundant prefix length specification"
		// and exit 1 (`conf.c` dies in both orders, exact string), and there is
		// no v6 -n at all.
		//
		// The v6 prefix travels inline and is DISCARDED: pasta parses it, keeps
		// no c->ip6.prefix_len, and configures a literal 64. snug does not
		// inherit that as a default — checkAddressPair's V8 refuses any v6
		// address that is not a /64, so the only value reaching this line is the
		// one pasta will actually deliver. The v4 prefix IS honoured
		// (`c->ip4.prefix_len = prefix_len - 96`), which is why V8 is v6-only.
		//
		// pair.gw is always valid here too: checkAddressPair's V6 (all four
		// values or none) has already run by the time a Policy reaches this
		// point, in Resolve or in Validate for a hand-built one — see net.go
		// and validate.go.
		a = append(a, "-a", pair.addr.String(), "-g", pair.gw.String())
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
