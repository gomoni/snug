package policy

import (
	"net"
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

			// EXACTLY ONCE (B.3, measured): the v4 gateway maps to the host's
			// 127.0.0.1 and the v6 gateway to ::1 -- one flag VALUE closes
			// both families, so a second occurrence is not hardening, it is
			// a sign someone "helpfully" added one per family.
			n := 0
			for _, a := range args {
				if a == "--map-host-loopback" {
					n++
				}
			}
			if n != 1 {
				t.Errorf("--map-host-loopback appears %d times, want exactly 1: %v", n, args)
			}
		})
	}
}

// A loopback nameserver is exactly what the sandbox must not be able to reach,
// so it can never appear in the generated resolv.conf.
// Renamed when Resolver became mode-aware (issue #164). The body is unchanged
// and still true; the NAME was the part that stopped being true, because a
// sandbox sharing the HOST's netns is now told the host's loopback resolvers
// deliberately — they are reachable there, which is that profile's whole abuse
// sentence. The claim this test makes is about a PRIVATE netns, and saying so
// is what stops the next reader believing the sweep covers every mode.
func TestLoopbackNameserversAreNeverUsedInAPrivateNetns(t *testing.T) {
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
	// Nameservers is RAW and unfiltered (net.go's own field comment) — that is
	// what lets forwardAddr() see the host's nameserver at all to pick a
	// FAMILY from. Pre-filtering it with RoutableNameservers here, as this
	// fixture used to, throws that text away before NetPolicy ever sees it,
	// which is not what a real caller does (resolve.go assigns
	// ctx.HostNameservers straight through) and left this test passing by
	// accident: the pre-#162-remnant code fell back to dnsForwardAddr
	// unconditionally on an EMPTY list too, for the wrong reason.
	n := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: []string{"127.0.0.53"}}
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
	} {
		if got := tc.a.Join(tc.b); got != tc.want {
			t.Errorf("%s.Join(%s) = %s, want %s", tc.a, tc.b, got, tc.want)
		}
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

// NO SANDBOX WITH A PRIVATE NETNS MAY BE TOLD A LOOPBACK RESOLVER. The sweep
// the renamed test above no longer makes on its own: asserted over the whole
// state space rather than at one fixture, so the claim covers every mode
// instead of the one that was written down.
func TestNoPrivateNetnsPolicyNamesALoopbackResolver(t *testing.T) {
	hosts := [][]string{
		nil,
		{"127.0.0.53"},
		{"127.0.0.53", "192.168.1.1"},
		{"192.168.1.1"},
		{"::1", "fdde:4e97:189::1"},
	}
	for _, mode := range []NetMode{NetIsolated, NetEgress} {
		for _, dns := range []bool{false, true} {
			for _, ns := range hosts {
				n := NetPolicy{Mode: mode, DNS: dns, Nameservers: ns}
				for _, s := range n.Resolver().Servers {
					if ip := net.ParseIP(s); ip != nil && ip.IsLoopback() {
						t.Errorf("mode=%v dns=%v nameservers=%v names loopback "+
							"resolver %s, which a private netns cannot reach",
							mode, dns, ns, s)
					}
				}
			}
		}
	}
}

// THE FORWARDER'S DESTINATION IS CHOSEN BY THE POLICY, NOT BY PASTA (issue
// #166). pasta's --dns-host default is "first nameserver from host's
// /etc/resolv.conf", which is the same file snug already read with a different
// rule — two authors for one fact, and they disagree on a host that lists a
// local resolver first and a router second.
//
// Loopback is INCLUDED here on purpose, and that is the assertion with
// content: pasta runs on the HOST, where 127.0.0.53 is reachable, so applying
// the sandbox-side filter to the forwarder's destination would break the very
// host configuration interception exists for.
func TestTheDNSForwardDestinationIsNamedAndIncludesLoopback(t *testing.T) {
	// A host whose nameservers are ALL loopback (systemd-resolved, with a
	// fallback line), which is the case where the two selection rules would
	// actually disagree if either forgot loopback: snug's own filter
	// (RoutableNameservers) drops every one of these, so the sandbox is told
	// no resolver at all unless pasta intercepts — and the destination pasta
	// is told to re-issue the query to is still the FIRST line of this list,
	// loopback included, because pasta runs on the HOST where it is
	// reachable.
	n := NetPolicy{
		Mode: NetEgress, DNS: true,
		Nameservers: []string{"127.0.0.53", "127.0.0.1"},
	}
	if !n.NeedsDNSForward() {
		t.Fatalf("fixture: a loopback-only-resolver host must intercept; resolv.conf is\n%s",
			n.ResolvConf())
	}
	if got := n.DNSHost(); got != "127.0.0.53" {
		t.Errorf("DNSHost() = %q, want the host's first nameserver 127.0.0.53 — pasta runs on "+
			"the host, where a loopback resolver is exactly what it must be able to use", got)
	}

	args := (&Policy{Net: n}).PastaArgs(PastaTargetChild(1))
	if i := slices.Index(args, "--dns-host"); i < 0 || i+1 >= len(args) || args[i+1] != "127.0.0.53" {
		t.Errorf("the pasta argv does not pin --dns-host, so the destination is pasta's own "+
			"default and snug's screen cannot name it: %v", args)
	}

	// CONTROL: no interception, no --dns-host. A flag passed on an arm that
	// does not forward would be describing a path that does not exist.
	c := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: []string{"192.168.1.1"}}
	if slices.Contains((&Policy{Net: c}).PastaArgs(PastaTargetChild(1)), "--dns-host") {
		t.Error("control: --dns-host is passed on a run that does not intercept DNS")
	}
}

// TestParseNetModeAcceptsTwoModesAndNothingElse states the accepted set as the
// WHOLE set.
//
// snug has two network modes. The interesting assertion is the closed one — a
// value the parser has not been taught about fails rather than being read as
// the nearest thing it resembles, so a profile can never resolve to a sandbox
// it does not describe (invariant 5).
//
// The unknown values below are a sample, not a catalogue: there is no
// per-spelling arm in the parser to keep them in step with, which is exactly
// what lets the accepted set be read as the whole set. `EGRESS` is in the list
// because the match is case-sensitive, and `""` because resolve.go guards
// `prof.Network != ""` before calling — an unset key never reaches here, so
// this function refusing it is correct.
func TestParseNetModeAcceptsTwoModesAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		text string
		want NetMode
	}{
		{"isolated", NetIsolated},
		{"egress", NetEgress},
	} {
		got, err := ParseNetMode(tc.text)
		if err != nil || got != tc.want {
			t.Errorf("ParseNetMode(%q) = %v, %v; want %v, nil", tc.text, got, err, tc.want)
		}
	}

	for _, text := range []string{"bridge", "slirp4netns", "none", "EGRESS", ""} {
		got, err := ParseNetMode(text)
		if err == nil {
			t.Errorf("ParseNetMode(%q) = %v, nil — an unknown mode must fail rather than "+
				"resolve as the nearest thing it resembles", text, got)
			continue
		}
		// The message names the accepted set, which is what a reader needs and
		// the only thing it should name.
		for _, says := range []string{"isolated", "egress"} {
			if !strings.Contains(err.Error(), says) {
				t.Errorf("ParseNetMode(%q) does not name %q as an accepted mode: %v",
					text, says, err)
			}
		}
	}
}
