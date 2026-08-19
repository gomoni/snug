//go:build integration

package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// hostRoutableNameservers reads the host's own /etc/resolv.conf and returns the
// resolvers a sandbox could reach directly — the same filter Resolve applies,
// called rather than reimplemented so the test cannot disagree with the policy
// about what "routable" means.
//
// Returns nil on a systemd-resolved host (every resolver on loopback), where
// @net and @net-anon both intercept and the comparison below distinguishes
// nothing.
func hostRoutableNameservers(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Skipf("cannot read the host's /etc/resolv.conf: %v", err)
	}
	var servers []string
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "nameserver" {
			servers = append(servers, f[1])
		}
	}
	return policy.RoutableNameservers(servers)
}

// TestAnonymisedSandboxIsNeverToldTheHostsResolver is issue #162's regression
// test, end to end in a live sandbox.
//
// @net-anon exists for one reason — the sandbox does not learn where the host
// sits — and it used to hide the host's address and then name the host's LAN
// resolver in the sandbox's own /etc/resolv.conf. A LAN resolver is normally
// the router, so its address gives back the prefix the synthetic address was
// hiding; an IPv6 ULA resolver gives back a stable per-site prefix.
//
// The property is asserted on the bytes the payload actually reads, not on the
// policy's fields, because that file is what a payload greps.
func TestAnonymisedSandboxIsNeverToldTheHostsResolver(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePasta(t)

	hostNS := hostRoutableNameservers(t)
	if len(hostNS) == 0 {
		t.Skip("this host has no routable nameserver (systemd-resolved?), so @net and " +
			"@net-anon both intercept and this comparison distinguishes nothing")
	}
	proj, _ := target(t)

	// CONTROL, and it carries the whole test. @net — the non-anonymising
	// profile — DOES name the host's resolvers inside the sandbox. Without
	// this, "no host resolver appears under @net-anon" is equally true of a
	// snug that stopped passing nameservers through at all, of a host whose
	// resolvers are not routable, and of a payload whose cat printed nothing.
	c := run(t, []string{"-p", "@net"}, proj, `cat /etc/resolv.conf`).mustRun(t)
	named := 0
	for _, ns := range hostNS {
		if strings.Contains(c.out, ns) {
			named++
		}
	}
	if named == 0 {
		t.Fatalf("control: @net does not name any of the host's routable resolvers %v "+
			"inside the sandbox, so the absence asserted below proves nothing:\n%s",
			hostNS, c.out)
	}

	r := run(t, []string{"-p", "@net-anon"}, proj, `cat /etc/resolv.conf`).mustRun(t)
	for _, ns := range hostNS {
		if strings.Contains(r.out, ns) {
			t.Errorf("@net-anon hides the host's address and then hands the sandbox the "+
				"host's own resolver %s, which discloses the network the host sits on:\n%s",
				ns, r.out)
		}
	}
	if !strings.Contains(r.out, "nameserver") {
		t.Errorf("@net-anon left the sandbox with no resolver line at all; the property is "+
			"withholding the HOST's resolver, not withholding DNS:\n%s", r.out)
	}

	// POSITIVE CONTROL for the fix itself: interception must actually work.
	// Otherwise this whole test is satisfied by a profile that simply broke
	// DNS, which trades a disclosure for an unusable sandbox rather than
	// fixing anything.
	requireInternet(t)
	res := run(t, []string{"-p", "@net-anon"}, proj,
		`getent hosts example.com >/dev/null && echo RESOLVED || echo RESOLVE-FAILED`).mustRun(t)
	if !strings.Contains(res.out, "RESOLVED") {
		t.Errorf("an anonymised sandbox cannot resolve at all, so pasta's interception is "+
			"not working and the disclosure was traded for a broken resolver:\n%s", res.out)
	}
}

// TestTheDNSLineOnScreenMatchesTheFileInsideTheSandbox is issue #28's
// regression test, and it is deliberately a CROSS-CHECK of two artifacts
// rather than an assertion about either one.
//
// The defect was that --dry-run printed a hardcoded `169.254.1.1 -> pasta ->
// host resolver` whenever DNS was on, while the sandbox was handed the host's
// real resolvers. Unit tests cover each renderer; what neither can see is the
// two disagreeing about the same run. Here the screen and the file are
// produced by two separate invocations of the real binary and compared.
func TestTheDNSLineOnScreenMatchesTheFileInsideTheSandbox(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	for _, prof := range []string{"@net", "@net-anon"} {
		t.Run(prof, func(t *testing.T) {
			screen, code := cli(t, nil, "--dry-run", "-p", prof, proj, "--", "true")
			if code != 0 {
				t.Fatalf("--dry-run -p %s exited %d:\n%s", prof, code, screen)
			}
			var dns string
			for _, line := range strings.Split(screen, "\n") {
				if f := strings.Fields(line); len(f) >= 2 && f[0] == "dns" {
					dns = strings.Join(f[1:], " ")
					break
				}
			}
			if dns == "" {
				t.Fatalf("--dry-run printed no dns line for %s, so there is nothing to "+
					"cross-check:\n%s", prof, screen)
			}

			r := run(t, []string{"-p", prof}, proj, `cat /etc/resolv.conf`).mustRun(t)
			var inside []string
			for _, line := range strings.Split(r.out, "\n") {
				if f := strings.Fields(line); len(f) == 2 && f[0] == "nameserver" {
					inside = append(inside, f[1])
				}
			}
			if len(inside) == 0 {
				t.Fatalf("the sandbox's /etc/resolv.conf names no resolver at all:\n%s", r.out)
			}
			for _, ns := range inside {
				if !strings.Contains(dns, ns) {
					t.Errorf("--dry-run's dns line says %q, but the sandbox is actually told "+
						"to use %s. The screen a human uses to decide whether a sandbox leaks "+
						"its network position does not describe the sandbox they ran:\n%s",
						dns, ns, r.out)
				}
			}
		})
	}
}

// ADDING A PROFILE MUST NOT TAKE A CAPABILITY AWAY. This is the live half of a
// regression the anonymising branch caused and a review caught before it
// landed: `-p @net-host -p @net-anon --i-know` resolved on main and stopped
// resolving with the branch ungated, because Mode joins permissive-ward to
// host, DNS ORs true, Address is set — and pasta, the thing that implements
// the interception the generated file then demanded, runs only in egress mode.
//
// Measured on both binaries at the time: RESOLVED before, RESOLVE-FAILED
// after. Composition going backwards is the property profiles are sold on, so
// this gets a named test rather than a comment.
//
// Note what this test does NOT assert: that `@net-host` alone resolves. It
// does not, on main or here — that is issue #164, a different and older defect
// (the profile sets no `dns`, so it is handed the interception address with no
// pasta behind it), deliberately not repaired in this change.
func TestAddingAnAnonymisingProfileDoesNotBreakDNSInHostMode(t *testing.T) {
	budget(t)
	requireSandbox(t)
	// The positive control this test rests on: the HOST can resolve. @net-host
	// shares the host's network namespace, so if the host cannot resolve then
	// neither can the sandbox and a failure here would say nothing about snug.
	requireInternet(t)

	// This test once skipped on a host whose resolvers are all loopback,
	// because @net-host had no working DNS there to begin with — issue #164,
	// now fixed in this same milestone: host mode names the host's own
	// resolvers, loopback included, since the netns IS the host's. The skip
	// is therefore gone, and deliberately: a guard whose stated reason has
	// stopped being true is how folklore starts.
	//
	// What survives from that episode is the `timeout` below. A resolver
	// pointed at an address nothing answers BLOCKS, and a hung payload trips
	// the per-test watchdog with a panic that names no assertion — which is
	// exactly what this test did on a GitHub runner before the guard existed.
	proj, _ := target(t)

	r := run(t, []string{"-p", "@net-host", "-p", "@net-anon", "--i-know"}, proj,
		`grep ^nameserver /etc/resolv.conf
timeout 5 getent hosts example.com >/dev/null && echo RESOLVED || echo RESOLVE-FAILED`).mustRun(t)

	if strings.Contains(r.out, "169.254.1.1") {
		t.Errorf("a sandbox sharing the HOST's network namespace is told to use pasta's "+
			"interception address, and no pasta runs in host mode, so every lookup inside "+
			"waits out a timeout:\n%s", r.out)
	}
	if !strings.Contains(r.out, "RESOLVED") {
		t.Errorf("adding @net-anon to a working @net-host selection broke DNS — adding a "+
			"profile took a capability away:\n%s", r.out)
	}
}

// TestNetHostResolvesThroughTheHostsOwnResolvers is issue #164's regression
// test.
//
// @net-host shares the host's network namespace and runs no pasta, and it was
// handed `nameserver 169.254.1.1` anyway — the address pasta intercepts, with
// no pasta behind it — so DNS did not work at all inside the one profile whose
// purpose is reaching host services. Nothing on screen said so either: the
// NetHost arm of the NETWORK block printed no dns line.
//
// The fix names the host's own resolvers there, loopback ones included,
// because the filter that drops them exists to keep a PRIVATE netns off host
// loopback and this namespace is the host's. So the assertion is deliberately
// not "no loopback address appears" — in this mode a loopback resolver is the
// correct answer.
func TestNetHostResolvesThroughTheHostsOwnResolvers(t *testing.T) {
	budget(t)
	requireSandbox(t)
	// @net-host shares the host's namespace, so if the host cannot resolve
	// then neither can the sandbox and a failure here would be about the
	// runner rather than about snug.
	requireInternet(t)
	proj, _ := target(t)

	r := run(t, []string{"-p", "@net-host", "--i-know"}, proj,
		`grep ^nameserver /etc/resolv.conf
timeout 5 getent hosts example.com >/dev/null && echo RESOLVED || echo RESOLVE-FAILED`).mustRun(t)

	if strings.Contains(r.out, "169.254.1.1") {
		t.Errorf("a sandbox sharing the HOST's network namespace is told to use pasta's "+
			"interception address, and no pasta runs in this mode, so every lookup waits "+
			"out a timeout:\n%s", r.out)
	}
	if !strings.Contains(r.out, "RESOLVED") {
		t.Errorf("@net-host cannot resolve, so the profile whose whole purpose is reaching "+
			"host services cannot name one:\n%s", r.out)
	}

	// The screen must say it too — the half of #164 that kept it invisible.
	screen, code := cli(t, nil, "--dry-run", "-p", "@net-host", "--i-know", proj, "--", "true")
	if code != 0 {
		t.Fatalf("--dry-run -p @net-host exited %d:\n%s", code, screen)
	}
	var dns string
	for _, line := range strings.Split(screen, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "dns" {
			dns = strings.Join(f[1:], " ")
			break
		}
	}
	if dns == "" {
		t.Fatalf("the NETWORK block prints no dns line for @net-host, which is how #164 "+
			"stayed invisible: the sandbox had a resolver and the screen never mentioned "+
			"one:\n%s", screen)
	}
	for _, line := range strings.Split(r.out, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "nameserver" && !strings.Contains(dns, f[1]) {
			t.Errorf("--dry-run's dns line says %q but the sandbox is told to use %s:\n%s",
				dns, f[1], r.out)
		}
	}
}
