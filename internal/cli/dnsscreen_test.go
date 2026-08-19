package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// The host resolver addresses these tests pretend the host has. Deliberately
// documentation-range (RFC 5737 / RFC 3849) and deliberately NOT this
// developer's real 192.168.1.1: a test that passes only where the fixture
// happens to match the host tells the next reader nothing.
var testHostNameservers = []string{"203.0.113.53", "2001:db8::53"}

func dnsPolicy(t *testing.T, profiles ...policy.ProfileName) *policy.Policy {
	t.Helper()
	reg := loadTestRegistry(t)
	home, target := testTree(t)
	ctx := policy.Context{
		Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"},
		HostNameservers: testHostNameservers,
	}
	sel := append([]policy.ProfileName{"@sys", "@home", "@cwd-rw"}, profiles...)
	p, err := policy.Resolve(reg, sel, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve %v: %v", sel, err)
	}
	return p
}

func networkBlock(t *testing.T, p *policy.Policy) string {
	t.Helper()
	return captureFile(t, func(f *os.File) { describeNetwork(f, p) })
}

// TestTheDNSLineRendersTheResolvedPolicy is issue #28's review artifact.
//
// The line was a hardcoded literal — `169.254.1.1 -> pasta -> host resolver`,
// printed whenever DNS was on — so on an ordinary LAN host it described an
// interception that was not happening while the sandbox was handed the host's
// real resolvers. --dry-run is the artifact a human uses to decide whether a
// sandbox leaks its network position, and this line said the opposite of what
// the sandbox did.
//
// Both arms are asserted against the RESOLVED POLICY rather than against a
// literal, which is what makes the test able to fail: the fixture's
// nameservers are documentation-range addresses that appear nowhere in the
// source, so a hardcoded line cannot satisfy the first arm by coincidence.
func TestTheDNSLineRendersTheResolvedPolicy(t *testing.T) {
	t.Run("routable host resolvers are named, not an interception that is not happening", func(t *testing.T) {
		p := dnsPolicy(t, "@net")
		if p.Net.NeedsDNSForward() {
			t.Fatalf("fixture: the resolved policy intercepts DNS even though the host has "+
				"routable nameservers %v, so this arm is not the arm it claims to be",
				testHostNameservers)
		}
		got := networkBlock(t, p)
		for _, ns := range testHostNameservers {
			if !strings.Contains(got, ns) {
				t.Errorf("the dns line does not name %s, which is what the sandbox will "+
					"actually read out of /etc/resolv.conf:\n%s", ns, got)
			}
		}
		if strings.Contains(got, "169.254.1.1") {
			t.Errorf("the dns line claims pasta intercepts, which is false for this run:\n%s", got)
		}
	})

	t.Run("interception is described only when it happens", func(t *testing.T) {
		p := dnsPolicy(t, "@net-anon")
		if !p.Net.NeedsDNSForward() {
			t.Fatalf("fixture: @net-anon does not intercept DNS, so this arm proves nothing")
		}
		got := networkBlock(t, p)
		if !strings.Contains(got, "169.254.1.1") {
			t.Errorf("the dns line does not name the interception address:\n%s", got)
		}
		for _, ns := range testHostNameservers {
			if strings.Contains(got, ns) {
				t.Errorf("the dns line names the host resolver %s for a run that does not "+
					"use it:\n%s", ns, got)
			}
		}
	})

	// CONTROL: offline prints no dns line at all. Without it, "the right
	// addresses appear" is satisfied by a block that prints every arm.
	t.Run("offline names no resolver", func(t *testing.T) {
		got := networkBlock(t, dnsPolicy(t))
		if strings.Contains(got, "dns  ") {
			t.Errorf("an offline sandbox has a dns line:\n%s", got)
		}
	})
}

// NO PROFILE THAT ANONYMISES THE SANDBOX MAY HAND IT A HOST RESOLVER ADDRESS.
//
// Asserted over the SET of builtin profiles that set an address rather than at
// the @net-anon site, which is what issue #162 asked for: a future anonymising
// profile inherits the property instead of re-opening the hole under a new
// name. It reads the generated /etc/resolv.conf mount out of the resolved
// policy — the bytes the sandbox will really read — not NetPolicy's fields.
func TestNoAnonymisingProfileNamesAHostResolver(t *testing.T) {
	reg := loadTestRegistry(t)

	var anonymising []policy.ProfileName
	for name, prof := range reg {
		if prof.Address != "" {
			anonymising = append(anonymising, policy.ProfileName(name))
		}
	}
	if len(anonymising) == 0 {
		t.Fatal("no builtin profile sets an address, so this test sweeps nothing — if " +
			"@net-anon was renamed or retired, this test must follow it rather than " +
			"silently pass over an empty set")
	}

	for _, name := range anonymising {
		t.Run(string(name), func(t *testing.T) {
			p := dnsPolicy(t, name)
			if p.Net.Address == "" {
				t.Fatalf("fixture: %s resolved to no synthetic address, so this is not an "+
					"anonymised sandbox", name)
			}
			m, ok := p.Mounts["/etc/resolv.conf"]
			if !ok {
				t.Fatalf("no generated /etc/resolv.conf in the resolved policy for %s", name)
			}
			rc := string(m.Content)
			for _, ns := range testHostNameservers {
				if strings.Contains(rc, ns) {
					t.Errorf("%s hides the host's address and then names the host's resolver "+
						"%s, which discloses the network the host sits on — the disclosure "+
						"this profile exists to prevent:\n%s", name, ns, rc)
				}
			}
			if !strings.Contains(rc, "nameserver") {
				t.Errorf("%s leaves the sandbox with no resolver at all; the property is "+
					"withholding the HOST's resolver, not withholding DNS:\n%s", name, rc)
			}
		})
	}

	// CONTROL: the non-anonymising @net, resolved through the identical path,
	// DOES name them. Without it every assertion above passes on a fixture
	// whose nameservers never reached the policy.
	rc := string(dnsPolicy(t, "@net").Mounts["/etc/resolv.conf"].Content)
	for _, ns := range testHostNameservers {
		if !strings.Contains(rc, ns) {
			t.Fatalf("control: @net does not name the host resolver %s either, so the "+
				"fixture's nameservers never reached the generated file and the sweep "+
				"above distinguishes nothing:\n%s", ns, rc)
		}
	}
}
