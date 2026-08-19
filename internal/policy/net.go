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
// it. Where there is no pasta — @net-host today, issue #164 — the sandbox
// really does send its queries at whatever answers that address, which is why
// naming the fallback honestly matters more than it looks.
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
		return []byte("# snug: no network profile selected; DNS is intentionally unavailable.\n" +
			"# Resolver libraries will fail immediately rather than hang.\n")
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
	if n.Mode == NetIsolated {
		return r
	}
	r.Servers = n.Nameservers
	if n.Mode == NetEgress && n.Anonymised() {
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
		// AND GATED ON NetEgress, which is not belt-and-braces — it is a
		// regression this branch caused and a review caught. pasta runs only
		// in egress mode, so under `-p @net-host -p @net-anon --i-know` there
		// is nothing to intercept: Mode joins permissive-ward to host, DNS
		// ORs true, Address is set, and the sandbox was handed a link-local
		// address with no forwarder behind it. Measured on this host, both
		// binaries, same command: before the branch `getent hosts
		// example.com` RESOLVED, after it RESOLVE-FAILED. "Adding a profile
		// made a capability stop working" is the shape invariant 1 exists to
		// keep out of the model, and an anonymising profile cannot anonymise
		// a sandbox that is sharing the host's namespace anyway — Address has
		// no effect at all in host mode.
		//
		// What this gate does NOT fix is @net-host on its own, which names
		// the same dead address for a different reason (it sets no `dns`, so
		// Nameservers is empty and the fallback below fires). That is issue
		// #164, it predates this change, and it is deliberately not repaired
		// here: the fix needs RoutableNameservers' loopback filter to become
		// mode-dependent, which is a decision of its own.
		r.Servers = nil
	}
	if len(r.Servers) == 0 {
		r.Servers = []string{dnsForwardAddr}
	}
	return r
}

// Anonymised reports whether this sandbox withholds the HOST's network position
// from the payload. Today `address` is the only profile key that says so — it
// replaces pasta's default of copying the host's addresses into the namespace —
// and every withholding that follows from that intent keys off this predicate
// rather than off the field, so the next one does not have to re-decide which
// field meant "anonymous".
func (n NetPolicy) Anonymised() bool { return n.Address != "" }

// NeedsDNSForward reports whether pasta must be given --dns-forward: exactly
// when the file the sandbox will read names the link-local address rather than
// a real resolver.
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
	return len(s) == 1 && s[0] == dnsForwardAddr
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
