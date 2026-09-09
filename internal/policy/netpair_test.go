package policy

import (
	"slices"
	"strings"
	"testing"
)

// THE FORWARDER AND ITS DESTINATION AGREE ON FAMILY, AND THE DESTINATION IS
// NOT ALWAYS Nameservers[0] (the #166 regression, alive again in family-aware
// clothing). Every case here is a host whose nameservers are ALL loopback —
// the one remaining trigger for interception now that network anonymisation
// is gone — which is what forces interception regardless of whether a
// routable resolver would otherwise be used directly. Assert the generated
// FILE and the ARGV in the SAME subtest, because the defect class this
// guards is the two disagreeing.
func TestTheDNSForwarderMatchesTheFamilyOfTheHostsResolvers(t *testing.T) {
	for _, tc := range []struct {
		name          string
		ns            []string
		wantForward   string
		wantDNSHost   string
		wantNoForward bool
	}{
		{"v4 loopback alone", []string{"127.0.0.53"}, dnsForwardAddr, "127.0.0.53", false},
		{"v6 loopback alone", []string{"::1"}, dnsForwardAddr6, "::1", false},
		{"mixed loopback, v4 wins and is not necessarily first", []string{"::1", "127.0.0.53"}, dnsForwardAddr, "127.0.0.53", false},
		{"none", nil, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: tc.ns}
			rc := string(n.ResolvConf())
			args := (&Policy{Net: n}).PastaArgs(PastaTargetChild(1))

			if tc.wantNoForward {
				if slices.Contains(args, "--dns-forward") {
					t.Errorf("--dns-forward present with no usable resolver at all: %v", args)
				}
				if slices.Contains(args, "--dns-host") {
					t.Errorf("--dns-host present with no usable resolver at all: %v", args)
				}
				if len(n.Resolver().Servers) != 0 {
					t.Errorf("Resolver().Servers is non-empty with no usable resolver: %v", n.Resolver().Servers)
				}
				return
			}

			if !strings.Contains(rc, tc.wantForward) {
				t.Errorf("resolv.conf does not name the forwarder %s:\n%s", tc.wantForward, rc)
			}
			if got := n.DNSHost(); got != tc.wantDNSHost {
				t.Errorf("DNSHost() = %q, want %q", got, tc.wantDNSHost)
			}
			if i := slices.Index(args, "--dns-forward"); i < 0 || args[i+1] != tc.wantForward {
				t.Errorf("--dns-forward = %v, want %s: %v", args, tc.wantForward, args)
			}
			if i := slices.Index(args, "--dns-host"); i < 0 || args[i+1] != tc.wantDNSHost {
				t.Errorf("--dns-host = %v, want %s: %v", args, tc.wantDNSHost, args)
			}
		})
	}
}

// A 4-IN-6 MAPPED HOST RESOLVER GETS A FAMILY-MATCHED FORWARDER, NOT A
// MISMATCHED PAIR (red team F3). A resolver spelled as ::ffff:8.8.8.8
// classifies as Is4()||Is4In6() everywhere this file picks a family from it
// (forwardAddr, DNSHost) — that half was already right — but before this
// fix the RENDERED value stayed in its v6-mapped spelling, so a host whose
// only resolver was such a mapped literal emitted `--dns-forward 169.254.1.1
// --dns-host ::ffff:8.8.8.8`: a v4 forwarder paired with a v6-spelled
// --dns-host, which pasta cannot answer (this file's own measured rule:
// pasta never crosses families when forwarding). parsedNameservers now
// Unmap()s, so the rendered value agrees with the family the classifier
// already chose. The host's ONLY resolver is loopback here, which is what
// forces interception in the first place.
func TestMappedHostResolverGetsAFamilyMatchedDNSHost(t *testing.T) {
	n := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: []string{"::ffff:127.0.0.1"}}

	if got := n.DNSHost(); got != "127.0.0.1" {
		t.Errorf("DNSHost() = %q, want the UNmapped bare literal \"127.0.0.1\" — a v4 forwarder "+
			"paired with a v6-spelled --dns-host cannot be answered (pasta never crosses "+
			"families when forwarding)", got)
	}
	args := (&Policy{Net: n}).PastaArgs(PastaTargetChild(1))
	if i := slices.Index(args, "--dns-forward"); i < 0 || args[i+1] != dnsForwardAddr {
		t.Fatalf("fixture: --dns-forward is not the v4 constant: %v", args)
	}
	if i := slices.Index(args, "--dns-host"); i < 0 || args[i+1] != "127.0.0.1" {
		t.Errorf("--dns-host = %v, want the v4 forwarder paired with the UNmapped v4 literal: %v", args, args)
	}
	if strings.Contains(strings.Join(args, " "), "::ffff") {
		t.Errorf("the pasta argv still carries a v6-mapped spelling: %v", args)
	}

	// CONTROL: an ordinary (non-mapped) v4 resolver behaves identically —
	// Unmap() is a no-op on a value that was never mapped, so this is not a
	// behaviour change for the common case.
	plain := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: []string{"127.0.0.1"}}
	if got := plain.DNSHost(); got != "127.0.0.1" {
		t.Errorf("control: an ordinary v4 resolver changed under Unmap(): %q", got)
	}
}

// NO USABLE RESOLVER IS NAMED WHEN NOTHING CAN ANSWER IT (issue #162's
// remnant). The behavioural 40s-vs-2ms measurement is an integration
// concern (test/integration); this is the unit-level shape: DNS was asked
// for, the mode actually runs (or could run) a resolver, and the host names
// nothing snug could parse and forward to — the file must name NO resolver
// rather than the interception address with nothing behind it.
func TestNoResolverIsNamedWhenNothingCanAnswerIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		ns   []string
	}{
		{"host names nothing", nil},
		{"host names only unparseable text", []string{"not-an-address"}},
		{"host names only a zoned address", []string{"fe80::1%eth0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: tc.ns}
			rc := string(n.ResolvConf())
			if strings.Contains(rc, dnsForwardAddr) || strings.Contains(rc, dnsForwardAddr6) {
				t.Errorf("resolv.conf names an interception address with nothing behind it:\n%s", rc)
			}
			if n.NeedsDNSForward() {
				t.Error("NeedsDNSForward() is true with no usable resolver at all")
			}
			if len(n.Resolver().Servers) != 0 {
				t.Errorf("Resolver().Servers is non-empty: %v", n.Resolver().Servers)
			}
		})
	}
}

// DNSHost() NAMES NO UNPARSED HOST TEXT (issue #177). hostNameservers()
// splits on unicode.IsSpace, which does not include ESC, so a line like
// "nameserver 1.1.1.1<ESC>[2Kfoo" used to land verbatim in Nameservers and
// from there raw into --dns-host and the pasta argv. Parsed and re-rendered
// through netip now; a zoned address is DROPPED rather than rendered
// (parsing alone is not escaping — netip.ParseAddr accepts a zone and
// String() re-emits it verbatim).
func TestDNSHostNamesNoUnparsedHostText(t *testing.T) {
	// A loopback-only list, so interception is forced and DNSHost() actually
	// names something — the arm the ESC/zone payloads have to survive.
	dirty := []string{"127.0.0.1\x1b[2Kfoo", "fe80::1%eth0\x1b[2K"}

	n := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: dirty}
	if got := n.DNSHost(); strings.ContainsAny(got, "\x1b%") {
		t.Errorf("DNSHost() carries unparsed host text: %q", got)
	}
	for _, s := range n.Resolver().Servers {
		if strings.ContainsAny(s, "\x1b%") {
			t.Errorf("Resolver().Servers carries unparsed host text: %q", s)
		}
	}
	if rc := string(n.ResolvConf()); strings.ContainsAny(rc, "\x1b") || strings.Contains(rc, "%") {
		t.Errorf("ResolvConf() carries unparsed host text:\n%s", rc)
	}

	// POSITIVE CONTROL: a clean list comes through unchanged, so the checks
	// above are not vacuously true on a function that drops everything.
	clean := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: []string{"8.8.8.8", "1.1.1.1"}}
	got := clean.Resolver().Servers
	if len(got) != 2 || got[0] != "8.8.8.8" || got[1] != "1.1.1.1" {
		t.Errorf("control: a clean nameserver list was altered: %v", got)
	}
}
