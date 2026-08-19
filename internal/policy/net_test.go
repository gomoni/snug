package policy

import (
	"slices"
	"strings"
	"testing"
)

// THE test for this milestone.
//
// pasta's defaults are tuned for "make the container work like the host", which
// is the opposite of what snug wants, and TWO independent defaults re-open the
// host loopback:
//
//   - --map-host-loopback defaults to the gateway address
//   - -T/-U (ns->host forwards) BOTH default to auto
//
// The previous generation of this project passed the first and not the second,
// and its "private" netns could reach every host loopback service. Its own probe
// notes recorded the symptom and dismissed it as a procfs artifact.
//
// This asserts the flags are present. It is necessary and NOT sufficient: only
// the behavioural check in VERIFY.md §7 can catch an upstream default
// changing under us, which is exactly how the original bug survived review.
func TestPastaArgsAlwaysCloseHostLoopback(t *testing.T) {
	for _, tc := range []struct {
		name string
		net  NetPolicy
	}{
		{"plain", NetPolicy{Mode: NetEgress}},
		{"dns", NetPolicy{Mode: NetEgress, DNS: true}},
		{"publish", NetPolicy{Mode: NetEgress, Publish: []int{3000}}},
		{"many ports", NetPolicy{Mode: NetEgress, Publish: []int{3000, 8080, 9229}}},
		{"anon", NetPolicy{Mode: NetEgress, Address: "10.13.13.2/24", Gateway: "10.13.13.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := (&Policy{Net: tc.net}).PastaArgs(PastaTargetChild(1234))

			for _, pair := range [][2]string{
				{"--map-host-loopback", "none"},
				{"-T", "none"},
				{"-U", "none"},
				{"-u", "none"},
			} {
				i := slices.Index(args, pair[0])
				if i < 0 {
					t.Fatalf("%s is missing — the host loopback would be reachable", pair[0])
				}
				if args[i+1] != pair[1] {
					t.Errorf("%s = %q, want %q", pair[0], args[i+1], pair[1])
				}
			}
		})
	}
}

// Every host->sandbox forward must be scoped to 127.0.0.1. The unscoped form
// binds on ALL host addresses, publishing the agent's dev server to the LAN —
// something the human did not ask for and would not see.
func TestPublishIsScopedToLoopback(t *testing.T) {
	for _, tc := range []struct {
		name string
		net  NetPolicy
		want string
	}{
		{"closed by default", NetPolicy{Mode: NetEgress}, "none"},
		{"named ports", NetPolicy{Mode: NetEgress, Publish: []int{8080, 3000}}, "127.0.0.1/3000,8080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := (&Policy{Net: tc.net}).PastaArgs(PastaTargetChild(1))
			i := slices.Index(args, "-t")
			if i < 0 {
				t.Fatal("-t missing")
			}
			if args[i+1] != tc.want {
				t.Errorf("-t %q, want %q", args[i+1], tc.want)
			}
			if strings.Contains(args[i+1], "/") && !strings.HasPrefix(args[i+1], "127.0.0.1/") {
				t.Errorf("-t %q is not scoped to loopback; the LAN would see the sandbox", args[i+1])
			}
		})
	}
}

// Ports are sorted and deduplicated so the argv is a pure function of the
// resolved policy, not of the order profiles happened to contribute them.
func TestPublishPortsAreCanonical(t *testing.T) {
	a := (&Policy{Net: NetPolicy{Mode: NetEgress, Publish: []int{8080, 3000, 8080}}}).PastaArgs(PastaTargetChild(1))
	b := (&Policy{Net: NetPolicy{Mode: NetEgress, Publish: []int{3000, 8080}}}).PastaArgs(PastaTargetChild(1))
	if strings.Join(a, " ") != strings.Join(b, " ") {
		t.Error("publish port order or duplicates changed the pasta argv")
	}
}

// A loopback nameserver is exactly what the sandbox must not be able to reach,
// so it can never appear in the generated resolv.conf.
func TestLoopbackNameserversAreNeverUsed(t *testing.T) {
	got := RoutableNameservers([]string{"127.0.0.53", "::1", "192.168.1.1", "0.0.0.0"})
	if len(got) != 1 || got[0] != "192.168.1.1" {
		t.Fatalf("routable nameservers = %v, want only 192.168.1.1", got)
	}

	n := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: got}
	rc := string(n.ResolvConf())
	if strings.Contains(rc, "127.0.0.53") || strings.Contains(rc, "::1") {
		t.Errorf("resolv.conf names a loopback resolver the sandbox cannot reach:\n%s", rc)
	}
	if n.NeedsDNSForward() {
		t.Error("a routable nameserver exists, so pasta interception is unnecessary")
	}
}

// When the host has ONLY loopback resolvers (systemd-resolved), interception is
// the only option left.
func TestSystemdResolvedHostFallsBackToInterception(t *testing.T) {
	n := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: RoutableNameservers([]string{"127.0.0.53"})}
	if !n.NeedsDNSForward() {
		t.Fatal("no routable nameserver, so pasta must intercept DNS")
	}
	if !strings.Contains(string(n.ResolvConf()), dnsForwardAddr) {
		t.Error("resolv.conf should name the link-local address pasta intercepts")
	}
	if !slices.Contains((&Policy{Net: n}).PastaArgs(PastaTargetChild(1)), "--dns-forward") {
		t.Error("--dns-forward missing; the sandbox would have no working resolver")
	}
}

// Offline must produce a resolv.conf that fails FAST rather than one that hangs
// for five seconds on every lookup.
func TestOfflineResolvConfFailsFast(t *testing.T) {
	rc := string(NetPolicy{Mode: NetIsolated}.ResolvConf())
	if strings.Contains(rc, "nameserver") {
		t.Errorf("offline resolv.conf names a server:\n%s", rc)
	}
	if !strings.Contains(rc, "intentionally") {
		t.Error("offline resolv.conf should say the absence is deliberate")
	}
}

// NetMode joins permissive-ward like Access, so composing profiles can only
// open the network further.
func TestNetModeJoinsPermissiveWard(t *testing.T) {
	for _, tc := range []struct{ a, b, want NetMode }{
		{NetIsolated, NetEgress, NetEgress},
		{NetEgress, NetIsolated, NetEgress},
		{NetEgress, NetHost, NetHost},
		{NetHost, NetIsolated, NetHost},
	} {
		if got := tc.a.Join(tc.b); got != tc.want {
			t.Errorf("%s.Join(%s) = %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

// Host networking must be the ONLY mode that inherits the host netns, and it
// must be visible in the bwrap argv rather than implied.
func TestShareNetOnlyForHostMode(t *testing.T) {
	for _, tc := range []struct {
		mode NetMode
		want bool
	}{
		{NetIsolated, false},
		{NetEgress, false},
		{NetHost, true},
	} {
		p := &Policy{Net: NetPolicy{Mode: tc.mode}, Hostname: "snug", Mounts: map[string]Mount{}}
		got := slices.Contains(p.BwrapFlags(1000, 1000, func(string) int { return 9 }), "--share-net")
		if got != tc.want {
			t.Errorf("mode %s: --share-net present = %v, want %v", tc.mode, got, tc.want)
		}
	}
}

// AN ANONYMISING PROFILE MUST NOT NAME A HOST RESOLVER. @net-anon exists for
// one reason — the sandbox does not learn where the host sits — and it used to
// hide the host's address and then hand back the host's LAN resolver on the
// next line of the same generated file (issue #162). A LAN resolver is
// normally the router, so its address discloses the prefix the hidden host
// address sits in; an IPv6 ULA resolver discloses a stable per-site prefix.
//
// The condition is Address, never the profile NAME, so a future anonymising
// profile inherits this instead of re-opening the hole under a new name.
func TestAnAnonymisedSandboxNamesNoHostResolver(t *testing.T) {
	const hostNS = "192.168.1.1"
	const hostNS6 = "fdde:4e97:189::1"
	servers := RoutableNameservers([]string{hostNS, hostNS6})

	anon := NetPolicy{
		Mode: NetEgress, DNS: true, Nameservers: servers,
		Address: "10.13.13.2/24", Gateway: "10.13.13.1",
	}

	// CONTROL, and it is the whole test: the SAME policy without Address does
	// name both host resolvers. Without this, "no host resolver appears"
	// passes equally on a fixture that never had one — and on a ResolvConf
	// that stopped naming any resolver at all, which would be a broken
	// sandbox rather than a private one.
	plain := anon
	plain.Address, plain.Gateway = "", ""
	control := string(plain.ResolvConf())
	for _, ns := range []string{hostNS, hostNS6} {
		if !strings.Contains(control, ns) {
			t.Fatalf("control: a non-anonymised sandbox does not name the host resolver %s "+
				"either, so the assertion below distinguishes nothing:\n%s", ns, control)
		}
	}

	rc := string(anon.ResolvConf())
	for _, ns := range []string{hostNS, hostNS6} {
		if strings.Contains(rc, ns) {
			t.Errorf("an anonymised sandbox is told to use the host's own resolver %s, which "+
				"discloses the network the synthetic address exists to hide:\n%s", ns, rc)
		}
	}
	if !strings.Contains(rc, dnsForwardAddr) {
		t.Errorf("an anonymised sandbox names no interception address, so it has no resolver "+
			"at all — the fix must withhold the host's resolver, not DNS:\n%s", rc)
	}
	if !slices.Contains((&Policy{Net: anon}).PastaArgs(PastaTargetChild(1)), "--dns-forward") {
		t.Error("--dns-forward missing for an anonymised sandbox, so it is pointed at a " +
			"link-local address with nothing behind it")
	}
}

// THE TWO HALVES OF THE DNS DECISION CANNOT DISAGREE. NeedsDNSForward decides
// whether pasta is given --dns-forward; Resolver decides what the sandbox is
// told to use. They used to test different conditions over the same fields,
// and issue #28 is what that looks like from outside: the screen described an
// interception the sandbox was not doing.
//
// Asserted as an identity over every combination rather than at either site,
// because the failure mode is not a wrong answer at one site — it is the two
// sites answering differently.
func TestDNSForwardingAgreesWithTheGeneratedResolvConf(t *testing.T) {
	routable := []string{"192.168.1.1"}
	for _, tc := range []struct {
		name string
		net  NetPolicy
	}{
		{"routable host resolver", NetPolicy{Mode: NetEgress, DNS: true, Nameservers: routable}},
		{"systemd-resolved host", NetPolicy{Mode: NetEgress, DNS: true}},
		{"anonymised, routable host resolver", NetPolicy{Mode: NetEgress, DNS: true, Nameservers: routable, Address: "10.13.13.2/24"}},
		{"anonymised, systemd-resolved host", NetPolicy{Mode: NetEgress, DNS: true, Address: "10.13.13.2/24"}},
		{"host netns, anonymised too", NetPolicy{Mode: NetHost, DNS: true, Nameservers: routable, Address: "10.13.13.2/24"}},
		{"offline", NetPolicy{Mode: NetIsolated}},
		{"egress without dns", NetPolicy{Mode: NetEgress, Nameservers: routable}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intercepting := strings.Contains(string(tc.net.ResolvConf()), dnsForwardAddr)
			forwarding := slices.Contains((&Policy{Net: tc.net}).PastaArgs(PastaTargetChild(1)), "--dns-forward")

			if tc.net.DNS && intercepting != forwarding {
				t.Errorf("the sandbox is told %s but pasta --dns-forward is %v: one half of the "+
					"DNS decision changed and the other did not",
					map[bool]string{true: "to use the interception address", false: "to use a real resolver"}[intercepting],
					forwarding)
			}
			if tc.net.NeedsDNSForward() != forwarding {
				t.Errorf("NeedsDNSForward() = %v but the pasta argv %s --dns-forward",
					tc.net.NeedsDNSForward(),
					map[bool]string{true: "carries", false: "does not carry"}[forwarding])
			}
		})
	}
}

// AN ANONYMISING PROFILE MUST NOT BREAK DNS WHERE NO PASTA RUNS.
//
// This is a regression this file's own anonymising branch caused, caught in
// review and measured on both binaries before being fixed: `-p @net-host -p
// @net-anon --i-know` resolved on main and returned RESOLVE-FAILED with the
// branch ungated. Mode joins permissive-ward to host, DNS ORs true, Address is
// set — and pasta runs only in egress mode, so the interception address the
// branch installs has nothing behind it.
//
// "Adding a profile made a capability stop working" is the shape invariant 1
// exists to keep out of the model. Address has no effect in host mode anyway:
// there is nothing to anonymise about a sandbox sharing the host's namespace.
func TestAnonymisingDoesNotBreakDNSWhereNoPastaRuns(t *testing.T) {
	const hostNS = "192.168.1.1"
	n := NetPolicy{Mode: NetHost, DNS: true, Nameservers: []string{hostNS}, Address: "10.13.13.2/24"}

	rc := string(n.ResolvConf())
	if strings.Contains(rc, dnsForwardAddr) {
		t.Errorf("a host-netns sandbox is told to use pasta's interception address, and "+
			"no pasta runs in host mode, so every lookup inside waits out a timeout:\n%s", rc)
	}
	if !strings.Contains(rc, hostNS) {
		t.Errorf("a host-netns sandbox is not told the resolvers it can actually reach:\n%s", rc)
	}
	if n.NeedsDNSForward() {
		t.Error("NeedsDNSForward() is true in host mode, where there is no pasta to give " +
			"the flag to")
	}

	// CONTROL: the same anonymising address in EGRESS mode still intercepts.
	// Without it, this test passes equally on a build where the anonymising
	// branch was deleted outright rather than gated — which would reopen
	// issue #162.
	e := n
	e.Mode = NetEgress
	if !strings.Contains(string(e.ResolvConf()), dnsForwardAddr) {
		t.Errorf("control: an anonymised EGRESS sandbox no longer intercepts, so the gate "+
			"above removed the #162 fix rather than scoping it:\n%s", e.ResolvConf())
	}
	if strings.Contains(string(e.ResolvConf()), hostNS) {
		t.Errorf("control: an anonymised EGRESS sandbox names the host resolver again:\n%s",
			e.ResolvConf())
	}
}

// A NETWORK ADDRESS IS PROFILE TEXT, AND IT REACHES THE SCREEN A HUMAN READS.
//
// `address` and `gateway` were the only profile-supplied scalars never asked
// whether they could forge a row. A red team round put an ESC/CR payload
// through `address` and rewrote the `host loopback UNREACHABLE` line of
// --dry-run's own NETWORK block — while the sandbox RAN NORMALLY, because
// pasta's `-n` parser tolerates the trailing junk, which removes the one
// signal that would otherwise give a forged profile away.
//
// Both fields, and every rune in IsForgingRune's set rather than the ESC that
// happened to be demonstrated: the predicate owns the question, so a test that
// pins one spelling is the drift this project has now had four times. The C1
// and bidi probes are written as escapes for the same reason they are
// elsewhere in this tree — a raw one in source is a trap for the next reader
// rather than an illustration.
func TestNetworkAddressAndGatewayRefuseAForgingRune(t *testing.T) {
	for _, probe := range []struct{ name, payload string }{
		{"ESC", "\x1b[1A\r         host loopback   REACHABLE"},
		{"newline", "\n         host loopback   REACHABLE"},
		{"CSI (C1, U+009B)", "\u009b1A"},
		{"NEL (C1, U+0085)", "\u0085forged"},
		{"LINE SEPARATOR (U+2028)", "\u2028  forged"},
		{"RIGHT-TO-LEFT OVERRIDE (U+202E)", "\u202eDEGROF"},
	} {
		for _, field := range []string{"address", "gateway"} {
			t.Run(field+"/"+probe.name, func(t *testing.T) {
				p := resolveDefaults(t)
				// Topology is derived from Net.Mode and is CHECKED by
				// Validate, so setting the mode by hand without it makes
				// every Validate below fail for an unrelated reason — a
				// fixture that refuses for the wrong cause, which is the
				// failure mode this project has been bitten by twice. Caught
				// here only because the assertion checks the message names
				// the field.
				p.Net.Mode = NetEgress
				p.Topology = deriveTopology(p.Net.Mode, p.Podman)
				p.Net.Address, p.Net.Gateway = "10.5.5.2/24", "10.5.5.1"
				switch field {
				case "address":
					p.Net.Address += probe.payload
				case "gateway":
					p.Net.Gateway += probe.payload
				}

				err := p.Validate(newFakeEnv())
				if err == nil {
					t.Fatalf("a network %s containing %s was accepted; the NETWORK block and the "+
						"pasta command below it are one row per fact, and such a rune forges or "+
						"erases a row a human reads to decide whether the sandbox leaks its "+
						"network position", field, probe.name)
				}
				if !strings.Contains(err.Error(), field) {
					t.Errorf("the refusal does not name which field was at fault (%s): %v", field, err)
				}
			})
		}
	}

	// CONTROL: the ordinary values @net-anon ships still validate. Without it
	// every assertion above is satisfied by a Validate that refuses every
	// network address, which would be a broken profile rather than a guarded
	// one.
	p := resolveDefaults(t)
	p.Net.Mode = NetEgress
	p.Topology = deriveTopology(p.Net.Mode, p.Podman)
	p.Net.Address, p.Net.Gateway = "10.13.13.2/24", "10.13.13.1"
	if err := p.Validate(newFakeEnv()); err != nil {
		t.Fatalf("control: a clean synthetic address is refused, so the checks above prove "+
			"nothing about forging runes specifically: %v", err)
	}
}
