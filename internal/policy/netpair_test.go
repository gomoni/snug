package policy

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// V6: ALL FOUR NETWORK-ADDRESS KEYS, OR NONE. pasta assigns addresses PER
// FAMILY, so naming only one leaves the other at the host's own — issue #165.
// It is a hard refusal, not a warning, because it is the shape invariant 5
// names: a half-anonymised sandbox WORKS PERFECTLY and discloses exactly what
// the profile's own name says it hides, invisible from inside.
//
// Every one of the 14 non-empty proper subsets of {address, gateway,
// address6, gateway6} is refused, and the refusal must name every MISSING key
// and hand over all four WORKING values (@net-anon's own), so a human hitting
// this can copy-paste the fix rather than re-derive it.
func TestHalfAnonymisedIsRefusedAndTheRefusalHandsOverTheFourValues(t *testing.T) {
	keys := []string{"address", "gateway", "address6", "gateway6"}
	// The four "working" values a passing message must hand over, regardless
	// of which subset was actually set — @net-anon's own, quoted exactly as
	// halfAnonymisedError's Fix block renders them.
	workingValues := []string{`"10.13.13.2/24"`, `"10.13.13.1"`, `"fd00:5e79:1::2/64"`, `"fd00:5e79:1::1"`}

	// Every non-empty PROPER subset: 2^4-2 = 14, enumerated by bitmask 1..14
	// (0 = none, 15 = all four, neither of which V6 refuses).
	for mask := 1; mask < 15; mask++ {
		var present, missing []string
		p := &Profile{Name: "myanon", Network: "egress"}
		for i, k := range keys {
			if mask&(1<<i) == 0 {
				missing = append(missing, k)
				continue
			}
			present = append(present, k)
			switch k {
			case "address":
				p.Address = "10.13.13.2/24"
			case "gateway":
				p.Gateway = "10.13.13.1"
			case "address6":
				p.Address6 = "fd00:5e79:1::2/64"
			case "gateway6":
				p.Gateway6 = "fd00:5e79:1::1"
			}
		}
		reg := testRegistry()
		reg["myanon"] = p

		t.Run(strings.Join(present, "+"), func(t *testing.T) {
			_, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "myanon"), testCtx(), newFakeEnv())
			if err == nil {
				t.Fatalf("a half-anonymised profile (%v set, %v missing) was accepted", present, missing)
			}
			for _, m := range missing {
				if !strings.Contains(err.Error(), m) {
					t.Errorf("refusal does not name missing key %q: %v", m, err)
				}
			}
			for _, want := range workingValues {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal does not hand over the working value %s: %v", want, err)
				}
			}
		})
	}

	// CONTROL: all four accepted.
	regAll := testRegistry()
	regAll["allfour"] = &Profile{Name: "allfour", Network: "egress",
		Address: "10.13.13.2/24", Gateway: "10.13.13.1",
		Address6: "fd00:5e79:1::2/64", Gateway6: "fd00:5e79:1::1"}
	if _, err := Resolve(regAll, append(append([]ProfileName{}, testDefaults...), "allfour"), testCtx(), newFakeEnv()); err != nil {
		t.Errorf("control: all four keys present was refused: %v", err)
	}

	// CONTROL: none present (an ordinary @net-shaped profile) accepted.
	regNone := testRegistry()
	regNone["plain"] = &Profile{Name: "plain", Network: "egress"}
	if _, err := Resolve(regNone, append(append([]ProfileName{}, testDefaults...), "plain"), testCtx(), newFakeEnv()); err != nil {
		t.Errorf("control: no network-address keys at all was refused: %v", err)
	}
}

// V6 IS A POST-FOLD CHECK, not a per-profile one — the load-bearing ordering
// constraint J.3 identifies. Checking it inside the fold loop would make
// resolve([a,b]) depend on which profile the SORTED fold reaches first:
// resolve([a]) and resolve([b]) must each refuse (a half-set pair alone), and
// resolve([a,b]) and resolve([b,a]) must both SUCCEED and be EQUAL — the
// commutativity guard, and the test that fails if V6 is ever moved into the
// fold.
func TestTheAddressPairRuleIsCheckedAfterTheFold(t *testing.T) {
	reg := testRegistry()
	reg["v4half"] = &Profile{Name: "v4half", Network: "egress", Address: "10.13.13.2/24", Gateway: "10.13.13.1"}
	reg["v6half"] = &Profile{Name: "v6half", Network: "egress", Address6: "fd00:5e79:1::2/64", Gateway6: "fd00:5e79:1::1"}

	if _, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "v4half"), testCtx(), newFakeEnv()); err == nil {
		t.Error("resolve([v4half alone]) must refuse — it sets only the v4 half of the pair")
	}
	if _, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "v6half"), testCtx(), newFakeEnv()); err == nil {
		t.Error("resolve([v6half alone]) must refuse — it sets only the v6 half of the pair")
	}

	ab, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "v4half", "v6half"), testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("resolve([v4half, v6half]) must succeed — the pair is complete once combined: %v", err)
	}
	ba, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "v6half", "v4half"), testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("resolve([v6half, v4half]) must succeed: %v", err)
	}
	if canon(ab) != canon(ba) {
		t.Errorf("order changed the result — V6 is depending on fold order\n--- a,b\n%s\n--- b,a\n%s",
			canon(ab), canon(ba))
	}
}

// TWO SPELLINGS OF ONE ADDRESS ARE NOT A CONFLICT. netip compares MEANING,
// not the literal bytes a human typed — measured: "fd00:5e79:1::2/64" and
// "fd00:5e79:0001::2/64" compare equal as netip.Prefix, and this was a
// SPURIOUS conflict when the fields were raw strings compared with `!=`.
func TestTwoSpellingsOfTheSameAddressAreNotAConflict(t *testing.T) {
	reg := testRegistry()
	reg["spell-a"] = &Profile{Name: "spell-a", Network: "egress",
		Address: "10.13.13.2/24", Gateway: "10.13.13.1",
		Address6: "fd00:5e79:1::2/64", Gateway6: "fd00:5e79:1::1"}
	reg["spell-b"] = &Profile{Name: "spell-b", Network: "egress",
		Address: "10.13.13.2/24", Gateway: "10.13.13.1",
		Address6: "fd00:5e79:0001::2/64", Gateway6: "FD00:5E79:1::1"}

	if _, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "spell-a", "spell-b"), testCtx(), newFakeEnv()); err != nil {
		t.Errorf("two spellings of the SAME address were reported as a conflict: %v", err)
	}
}

// Anonymised() IS TRUE FOR EITHER FAMILY ALONE, not just v4 and not only when
// both are set (J.4(a)). AND, not OR, would report a half-set policy as NOT
// anonymising — re-opening #162 for that shape, since Resolver()'s egress arm
// keys off Anonymised() to decide whether to name the host's real resolvers.
// This predicate must not depend on V6 having run: a hand-built Policy that
// skipped Resolve can still carry a half-set pair, and it is exactly there
// that under-withholding would be worst.
func TestAnonymisedIsTrueForEitherFamilyAlone(t *testing.T) {
	v4only := NetPolicy{Address: netip.MustParsePrefix("10.13.13.2/24")}
	if !v4only.Anonymised() {
		t.Error("Anonymised() is false with only Address set")
	}
	v6only := NetPolicy{Address6: netip.MustParsePrefix("fd00:5e79:1::2/64")}
	if !v6only.Anonymised() {
		t.Error("Anonymised() is false with only Address6 set")
	}
	both := NetPolicy{Address: netip.MustParsePrefix("10.13.13.2/24"), Address6: netip.MustParsePrefix("fd00:5e79:1::2/64")}
	if !both.Anonymised() {
		t.Error("Anonymised() is false with both set")
	}
	neither := NetPolicy{}
	if neither.Anonymised() {
		t.Error("Anonymised() is true with neither address set")
	}
}

// EVERY -a CARRIES AN INLINE PREFIX, AND -n NEVER APPEARS. pasta's -n is a
// single GLOBAL netmask, not per-family: with -n present, an inline prefix in
// ANY -a is "Redundant prefix length specification" and exits 1 (measured),
// and there is no v6 -n at all. Encodes that measurement so a later
// "tidy-up" reintroducing -n fails here rather than at a live pasta.
func TestPastaArgsNeverPassNWithAnInlinePrefix(t *testing.T) {
	n := NetPolicy{
		Mode:    NetEgress,
		Address: netip.MustParsePrefix("10.13.13.2/24"), Gateway: netip.MustParseAddr("10.13.13.1"),
		Address6: netip.MustParsePrefix("fd00:5e79:1::2/64"), Gateway6: netip.MustParseAddr("fd00:5e79:1::1"),
	}
	args := (&Policy{Net: n}).PastaArgs(PastaTargetChild(1))
	if slices.Contains(args, "-n") {
		t.Errorf("-n present alongside an inline prefix — pasta exits 1 on this combination: %v", args)
	}
	for i, a := range args {
		if a == "-a" && i+1 < len(args) && !strings.Contains(args[i+1], "/") {
			t.Errorf("-a %s has no inline prefix: %v", args[i+1], args)
		}
	}
}

// THE FORWARDER AND ITS DESTINATION AGREE ON FAMILY, AND THE DESTINATION IS
// NOT ALWAYS Nameservers[0] (the #166 regression, alive again in family-aware
// clothing). All five cases anonymise (Address is set), which is what forces
// interception regardless of whether the raw resolver would otherwise be
// used directly — the shape that isolates forwardAddr()/DNSHost() from
// Resolver()'s other branches. Assert the generated FILE and the ARGV in the
// SAME subtest, because the defect class this guards is the two disagreeing.
func TestTheDNSForwarderMatchesTheFamilyOfTheHostsResolvers(t *testing.T) {
	anonAddr := netip.MustParsePrefix("10.13.13.2/24")
	for _, tc := range []struct {
		name          string
		ns            []string
		wantForward   string
		wantDNSHost   string
		wantNoForward bool
	}{
		{"v4 alone", []string{"192.168.1.1"}, dnsForwardAddr, "192.168.1.1", false},
		{"v4 loopback alone", []string{"127.0.0.53"}, dnsForwardAddr, "127.0.0.53", false},
		{"v6 alone", []string{"2a00:ca8::100"}, dnsForwardAddr6, "2a00:ca8::100", false},
		{"mixed, v4 wins and is not necessarily first", []string{"2a00:ca8::100", "192.168.1.1"}, dnsForwardAddr, "192.168.1.1", false},
		{"none", nil, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: tc.ns, Address: anonAddr}
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
// fix the RENDERED value stayed in its v6-mapped spelling, so an
// anonymising policy on such a host emitted `--dns-forward 169.254.1.1
// --dns-host ::ffff:8.8.8.8`: a v4 forwarder paired with a v6-spelled
// --dns-host, which pasta cannot answer (this file's own measured rule:
// pasta never crosses families when forwarding). parsedNameservers now
// Unmap()s, so the rendered value agrees with the family the classifier
// already chose.
func TestMappedHostResolverGetsAFamilyMatchedDNSHost(t *testing.T) {
	n := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: []string{"::ffff:8.8.8.8"}, Address: netip.MustParsePrefix("10.13.13.2/24")}

	if got := n.DNSHost(); got != "8.8.8.8" {
		t.Errorf("DNSHost() = %q, want the UNmapped bare literal \"8.8.8.8\" — a v4 forwarder "+
			"paired with a v6-spelled --dns-host cannot be answered (pasta never crosses "+
			"families when forwarding)", got)
	}
	args := (&Policy{Net: n}).PastaArgs(PastaTargetChild(1))
	if i := slices.Index(args, "--dns-forward"); i < 0 || args[i+1] != dnsForwardAddr {
		t.Fatalf("fixture: --dns-forward is not the v4 constant: %v", args)
	}
	if i := slices.Index(args, "--dns-host"); i < 0 || args[i+1] != "8.8.8.8" {
		t.Errorf("--dns-host = %v, want the v4 forwarder paired with the UNmapped v4 literal: %v", args, args)
	}
	if strings.Contains(strings.Join(args, " "), "::ffff") {
		t.Errorf("the pasta argv still carries a v6-mapped spelling: %v", args)
	}

	// CONTROL: an ordinary (non-mapped) v4 resolver behaves identically —
	// Unmap() is a no-op on a value that was never mapped, so this is not a
	// behaviour change for the common case.
	plain := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: []string{"8.8.8.8"}, Address: netip.MustParsePrefix("10.13.13.2/24")}
	if got := plain.DNSHost(); got != "8.8.8.8" {
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
	dirty := []string{"1.1.1.1\x1b[2Kfoo", "fe80::1%eth0\x1b[2K", "8.8.8.8"}

	egress := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: dirty, Address: netip.MustParsePrefix("10.13.13.2/24")}
	if got := egress.DNSHost(); strings.ContainsAny(got, "\x1b%") {
		t.Errorf("DNSHost() (egress) carries unparsed host text: %q", got)
	}
	for _, s := range egress.Resolver().Servers {
		if strings.ContainsAny(s, "\x1b%") {
			t.Errorf("Resolver().Servers (egress) carries unparsed host text: %q", s)
		}
	}

	// The same, through the arm that actually NAMES a host resolver inside.
	// The egress fixture above carries an Address, so it anonymises and its
	// Servers are replaced by the forwarder — which is snug's own constant and
	// could never carry host text. Without a second fixture the assertions
	// above are about a list nothing put host bytes into.
	named := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: dirty}
	for _, s := range named.Resolver().Servers {
		if strings.ContainsAny(s, "\x1b%") {
			t.Errorf("Resolver().Servers (named host resolvers) carries unparsed host text: %q", s)
		}
	}
	if rc := string(named.ResolvConf()); strings.ContainsAny(rc, "\x1b") || strings.Contains(rc, "%") {
		t.Errorf("ResolvConf() (named host resolvers) carries unparsed host text:\n%s", rc)
	}

	// POSITIVE CONTROL: a clean list comes through unchanged, so the checks
	// above are not vacuously true on a function that drops everything.
	clean := NetPolicy{Mode: NetEgress, DNS: true, Nameservers: []string{"8.8.8.8", "1.1.1.1"}}
	got := clean.Resolver().Servers
	if len(got) != 2 || got[0] != "8.8.8.8" || got[1] != "1.1.1.1" {
		t.Errorf("control: a clean nameserver list was altered: %v", got)
	}
}

// A ZONED ADDRESS IS REFUSED EVERYWHERE IT CAN BE BUILT (V7). Through
// RESOLVE, only the GATEWAY role is reachable by profile TEXT — ParsePrefix
// refuses a zone outright, so the ADDRESS role cannot carry one via a string.
// Through VALIDATE, a hand-built Policy can put a zoned Addr into EITHER role
// (a Prefix can be built directly from a zoned Addr via netip.PrefixFrom,
// bypassing ParsePrefix's own refusal), so both roles are checked there.
func TestAZonedAddressIsRefusedEverywhereItCanBeBuilt(t *testing.T) {
	zonedGW := "fe80::1%eth0"

	t.Run("Resolve refuses a zoned gateway, v4 key", func(t *testing.T) {
		reg := testRegistry()
		reg["z"] = &Profile{Name: "z", Network: "egress", Address: "10.13.13.2/24", Gateway: zonedGW}
		_, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "z"), testCtx(), newFakeEnv())
		if err == nil {
			t.Fatal("a zoned gateway was accepted through Resolve")
		}
	})
	t.Run("Resolve refuses a zoned gateway6", func(t *testing.T) {
		reg := testRegistry()
		reg["z"] = &Profile{Name: "z", Network: "egress", Address6: "fd00:5e79:1::2/64", Gateway6: zonedGW}
		_, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "z"), testCtx(), newFakeEnv())
		if err == nil {
			t.Fatal("a zoned gateway6 was accepted through Resolve")
		}
	})

	buildZonedPrefix := func() netip.Prefix {
		a := netip.MustParseAddr("fe80::1")
		zoned := netip.AddrFrom16(a.As16()).WithZone("eth0")
		return netip.PrefixFrom(zoned, 64)
	}

	// This subtest used to claim to exercise checkAddressPair's ADDRESS-role
	// zone check via Validate, and it PASSED — but for the wrong reason
	// (red team F2). buildZonedPrefix's own construction, netip.PrefixFrom,
	// STRIPS the zone (measured below), so p.Net.Address6 held an ordinary
	// unzoned fe80::1/64, Address/Gateway were never set, and the refusal
	// this subtest observed was V6 (half-set pair) — its message reads
	// "sets address6, gateway6 but not address, gateway", naming nothing
	// about a zone. That is exactly CLAUDE.md's "a test that cannot fail"
	// shape, in the file added to prove the zone rule.
	//
	// Made honest rather than deleted: every public netip construction path
	// strips a Prefix's zone (PrefixFrom, Addr.Prefix(), and
	// ParsePrefix/UnmarshalText refuse a zoned literal outright, measured
	// here and in net.go's checkAddressPair comment), so there is currently
	// no way to build the case this subtest's name claims to test. The
	// PRECONDITION below asserts that measurement explicitly and SKIPS
	// rather than silently passing on a different rule — and Address/
	// Gateway ARE set here (unlike the original), so that if a future
	// netip version stops stripping the zone, V6 cannot be what fires and
	// this subtest starts exercising the real branch automatically instead
	// of needing to be rediscovered.
	t.Run("Validate refuses a zoned ADDRESS (hand-built Prefix)", func(t *testing.T) {
		built := buildZonedPrefix()
		if built.Addr().Zone() == "" {
			t.Skip("PRECONDITION: netip's Prefix construction (PrefixFrom, Addr.Prefix()) " +
				"strips the zone before this test ever sees it, so there is no public API " +
				"that builds a Prefix carrying one — the ADDRESS-role branch in " +
				"checkAddressPair is unreachable today and this subtest cannot exercise it. " +
				"It stays here, skipping rather than passing on a different rule, so a future " +
				"netip change that stops stripping the zone re-enables this test rather than " +
				"leaving the branch untested silently.")
		}
		p := resolveDefaults(t)
		p.Net.Mode = NetEgress
		p.Topology = deriveTopology(p.Net.Mode, p.Podman)
		p.Net.Address = netip.MustParsePrefix("10.13.13.2/24")
		p.Net.Gateway = netip.MustParseAddr("10.13.13.1")
		p.Net.Address6 = built
		p.Net.Gateway6 = netip.MustParseAddr("fe80::2")
		if err := p.Validate(newFakeEnv()); err == nil {
			t.Fatal("a hand-built Prefix carrying a zoned Addr was accepted by Validate")
		} else if !strings.Contains(err.Error(), "zone") {
			t.Errorf("Validate refused, but not for the zone — V6 or another rule may have "+
				"fired instead, which is the exact failure mode this subtest exists to catch: %v", err)
		}
	})
	t.Run("Validate refuses a zoned GATEWAY", func(t *testing.T) {
		p := resolveDefaults(t)
		p.Net.Mode = NetEgress
		p.Topology = deriveTopology(p.Net.Mode, p.Podman)
		p.Net.Address6 = netip.MustParsePrefix("fd00:5e79:1::/64")
		p.Net.Gateway6 = netip.MustParseAddr(zonedGW)
		if err := p.Validate(newFakeEnv()); err == nil {
			t.Fatal("a zoned Gateway6 was accepted by Validate")
		}
	})

	// NEGATIVE CONTROL: the unzoned equivalent is accepted by Validate, so
	// the refusals above are about the ZONE specifically.
	t.Run("control: unzoned accepted", func(t *testing.T) {
		p := resolveDefaults(t)
		p.Net.Mode = NetEgress
		p.Topology = deriveTopology(p.Net.Mode, p.Podman)
		p.Net.Address = netip.MustParsePrefix("10.13.13.2/24")
		p.Net.Gateway = netip.MustParseAddr("10.13.13.1")
		p.Net.Address6 = netip.MustParsePrefix("fd00:5e79:1::2/64")
		p.Net.Gateway6 = netip.MustParseAddr("fd00:5e79:1::1")
		if err := p.Validate(newFakeEnv()); err != nil {
			t.Fatalf("control: unzoned values refused: %v", err)
		}
	})
}

// V1-V5 EACH REFUSE, AND NAME THE KEY AT FAULT. V6 (all four, or none) has
// its own dedicated tests (TestHalfAnonymisedIsRefusedAndTheRefusalHandsOverTheFourValues,
// TestTheAddressPairRuleIsCheckedAfterTheFold) because it carries a security
// argument distinct from a usability one; included here as one more case for
// completeness of the table.
func TestNetworkAddressKeysRefuseUnusableValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		prof *Profile
		key  string
	}{
		{"V1 address does not parse", &Profile{Name: "v1", Network: "egress", Address: "not-an-address"}, "address"},
		{"V1 gateway does not parse", &Profile{Name: "v1g", Network: "egress", Address: "10.13.13.2/24", Gateway: "not-an-address"}, "gateway"},
		{"V2 a v6 value in address", &Profile{Name: "v2", Network: "egress", Address: "fd00:5e79:1::2/64"}, "address"},
		{"V2 a v4 value in address6", &Profile{Name: "v2b", Network: "egress", Address6: "10.13.13.2/24"}, "address6"},
		{"V5 unspecified address", &Profile{Name: "v5a", Network: "egress", Address: "0.0.0.0/24", Gateway: "0.0.0.1"}, "address"},
		{"V5 loopback address", &Profile{Name: "v5b", Network: "egress", Address: "127.0.0.2/24", Gateway: "127.0.0.1"}, "address"},
		{"V5 multicast gateway", &Profile{Name: "v5c", Network: "egress", Address: "10.13.13.2/24", Gateway: "224.0.0.1"}, "gateway"},
		{"V3 gateway outside prefix", &Profile{Name: "v3", Network: "egress", Address: "10.13.13.2/24", Gateway: "10.14.14.1"}, "gateway"},
		{"V4 gateway equals address", &Profile{Name: "v4", Network: "egress", Address: "10.13.13.2/24", Gateway: "10.13.13.2"}, "gateway"},
		{"V6 half-set", &Profile{Name: "v6", Network: "egress", Address: "10.13.13.2/24", Gateway: "10.13.13.1"}, "address6"},
		// Red team F1: a 4-in-6 mapped literal (::ffff:a.b.c.d) satisfies
		// Is4()||Is4In6() as though it were an ordinary v4 value — the
		// shortcut this file used to take — but pasta does not agree with
		// itself about it: it reads a mapped ADDRESS as IPv4 (so this used
		// to be ACCEPTED) and silently DISCARDS a mapped GATEWAY, falling
		// back to its own default (the host's real router). Refused in
		// every key now, both families, both roles.
		{"F1 4-in-6 mapped address (v4 key)", &Profile{Name: "f1a", Network: "egress", Address: "::ffff:10.13.13.2/120", Gateway: "10.13.13.1"}, "address"},
		{"F1 4-in-6 mapped gateway (v4 key)", &Profile{Name: "f1g", Network: "egress", Address: "10.13.13.2/24", Gateway: "::ffff:10.13.13.1"}, "gateway"},
		{"F1 4-in-6 mapped address6 (v6 key)", &Profile{Name: "f1a6", Network: "egress", Address6: "::ffff:10.13.13.2/120", Gateway6: "fd00:5e79:1::1"}, "address6"},
		{"F1 4-in-6 mapped gateway6 (v6 key)", &Profile{Name: "f1g6", Network: "egress", Address6: "fd00:5e79:1::/64", Gateway6: "::ffff:10.13.13.1"}, "gateway6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := testRegistry()
			reg[tc.prof.Name] = tc.prof
			_, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), tc.prof.Name), testCtx(), newFakeEnv())
			if err == nil {
				t.Fatalf("%s: accepted, want a refusal naming %q", tc.name, tc.key)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Errorf("%s: refusal does not name %q: %v", tc.name, tc.key, err)
			}
		})
	}
}

// TestFourInSixMappedAddressIsRefusedNotAcceptedAsHalfAnonymised is issue
// #165's red team finding F1, reproduced exactly: a profile spelling its v4
// pair as 4-in-6 mapped literals used to be ACCEPTED — Is4()||Is4In6()
// treats ::ffff:10.13.13.2/120 as an ordinary v4 address — and reached
// pasta as `-a ::ffff:10.13.13.2/120 -g ::ffff:10.13.13.1`. Measured at the
// helper level: pasta reads the mapped ADDRESS as IPv4 (so the sandbox got
// 10.13.13.2/24 as intended) but silently DISCARDS the mapped GATEWAY,
// falling back to its OWN default — the host's real router — so
// `default via 192.168.1.1` and the host's `/24` appeared inside, exit 0,
// no warning: precisely the half-anonymised state V6 exists to forbid,
// reached without ever tripping it.
//
// The message must name the REAL problem (the mapped spelling), not just
// "wrong family" — a user told to move the value to address6 would still
// not have a real v6 literal there.
func TestFourInSixMappedAddressIsRefusedNotAcceptedAsHalfAnonymised(t *testing.T) {
	reg := testRegistry()
	reg["f1"] = &Profile{Name: "f1", Network: "egress",
		Address: "::ffff:10.13.13.2/120", Gateway: "::ffff:10.13.13.1",
		Address6: "fd00:5e79:1::2/64", Gateway6: "fd00:5e79:1::1"}

	_, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), "f1"), testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("a 4-in-6 mapped address/gateway pair was accepted — this is exactly the " +
			"half-anonymised state V6 exists to forbid, reached without tripping it")
	}
	for _, want := range []string{"address", "4-in-6", "mapped"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q, so it may be naming the wrong problem "+
				"(e.g. \"wrong family, use address6\" — which is not a fix, since a mapped "+
				"value is not a real v6 literal either): %v", want, err)
		}
	}

	// CONTROL: the same profile with a bare v4 literal instead is accepted —
	// the refusal above is about the MAPPED SPELLING specifically, not about
	// something else in the fixture.
	regOK := testRegistry()
	regOK["f1ok"] = &Profile{Name: "f1ok", Network: "egress",
		Address: "10.13.13.2/24", Gateway: "10.13.13.1",
		Address6: "fd00:5e79:1::2/64", Gateway6: "fd00:5e79:1::1"}
	if _, err := Resolve(regOK, append(append([]ProfileName{}, testDefaults...), "f1ok"), testCtx(), newFakeEnv()); err != nil {
		t.Errorf("control: the bare-literal equivalent was refused too: %v", err)
	}
}
