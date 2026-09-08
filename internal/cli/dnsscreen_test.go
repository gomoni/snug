package cli

import (
	"io"
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
	return captureFile(t, func(f io.Writer) { describeNetwork(f, p) })
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
		// A host whose ONLY resolver is loopback (systemd-resolved) — the one
		// remaining trigger for interception now that network anonymisation
		// is gone.
		reg := loadTestRegistry(t)
		home, target := testTree(t)
		ctx := policy.Context{
			Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"},
			HostNameservers: []string{"127.0.0.53"},
		}
		p, err := policy.Resolve(reg, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@net"}, ctx, policy.OSEnviron{})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if !p.Net.NeedsDNSForward() {
			t.Fatalf("fixture: a loopback-only-resolver host does not intercept DNS, so this " +
				"arm proves nothing")
		}
		got := networkBlock(t, p)
		if !strings.Contains(got, "169.254.1.1") {
			t.Errorf("the dns line does not name the interception address:\n%s", got)
		}

		// WHAT THE SANDBOX IS TOLD, versus what the SCREEN says — and the
		// distinction is the whole of issue #162 against issue #166.
		//
		// Since #166 the line reads `169.254.1.1 -> pasta -> 127.0.0.53`:
		// the destination is named because snug now chooses it (--dns-host)
		// rather than leaving it to pasta's default, and a reader deciding
		// whether to trust this sandbox needs to know where its queries end
		// up. That is not a disclosure — --dry-run runs on the host and is
		// read by the person whose resolver it is.
		//
		// So this checks the half of the line that describes the sandbox's
		// own configuration — everything before the first arrow — rather
		// than the whole string, which would forbid the destination #166
		// exists to print.
		inside, _, _ := strings.Cut(got[strings.Index(got, "dns "):], "->")
		if strings.Contains(inside, "127.0.0.53") {
			t.Errorf("the dns line says the sandbox itself is configured with the host "+
				"resolver 127.0.0.53, for a run that intercepts:\n%s", got)
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

	// EGRESS WITHOUT DNS: the screen must SAY there is no resolver, rather
	// than printing nothing (issue #166's second half). The line used to be
	// gated on p.Net.DNS while the generated file consulted no such field, so
	// this selection produced a NETWORK block silent about DNS beside a
	// sandbox that had a resolv.conf — and a block that is silent about DNS is
	// not the same as a sandbox that has no DNS.
	//
	// No shipped profile has this shape; a human writing `network = "egress"`
	// with no `dns = true` in profiles.d does, which is why the fixture builds
	// one rather than selecting a builtin.
	t.Run("egress without dns says so rather than saying nothing", func(t *testing.T) {
		reg := loadTestRegistry(t)
		reg["egressnodns"] = &policy.Profile{Name: "egressnodns", Network: "egress"}
		home, target := testTree(t)
		p, err := policy.Resolve(reg,
			[]policy.ProfileName{"@sys", "@home", "@cwd-rw", "egressnodns"},
			policy.Context{
				Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"},
				HostNameservers: testHostNameservers,
			}, policy.OSEnviron{})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if p.Net.DNS {
			t.Fatalf("fixture: the profile asked for DNS after all, so this is not the arm " +
				"it claims to be")
		}
		if p.Net.Mode != policy.NetEgress {
			t.Fatalf("fixture: the profile did not resolve to egress mode")
		}

		got := networkBlock(t, p)
		if !strings.Contains(got, "dns ") {
			t.Errorf("a sandbox with egress and no DNS prints no dns line at all, so the "+
				"screen is silent about a fact the generated resolv.conf has an answer "+
				"for:\n%s", got)
		}
		if !strings.Contains(got, "NONE") {
			t.Errorf("the dns line does not say plainly that no resolver is named inside:\n%s", got)
		}
		for _, ns := range testHostNameservers {
			if strings.Contains(got, ns) {
				t.Errorf("the dns line names host resolver %s for a run that was never given "+
					"any:\n%s", ns, got)
			}
		}
	})
}
