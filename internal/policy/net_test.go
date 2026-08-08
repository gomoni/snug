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
			args := (&Policy{Net: tc.net}).PastaArgs(1234)

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
			args := (&Policy{Net: tc.net}).PastaArgs(1)
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
	a := (&Policy{Net: NetPolicy{Mode: NetEgress, Publish: []int{8080, 3000, 8080}}}).PastaArgs(1)
	b := (&Policy{Net: NetPolicy{Mode: NetEgress, Publish: []int{3000, 8080}}}).PastaArgs(1)
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
	if !slices.Contains((&Policy{Net: n}).PastaArgs(1), "--dns-forward") {
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
