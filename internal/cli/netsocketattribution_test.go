package cli

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// Issue #288: `--dry-run`, `doctor` and `config` printed, unconditionally and
// with no relation to the mount policy, that X11/D-Bus/Wayland are closed
// BECAUSE they are netns-scoped. Measured on the host that found this: the
// session D-Bus (/run/user/1000/bus), Wayland (/run/user/1000/wayland-0) and
// one of X11's two listeners (/tmp/.X11-unix/X0) are PATHNAME sockets, which a
// netns does not scope at all — they are closed by the MOUNT POLICY, by
// ABSENCE (no default profile grants a host /tmp or /run path). The netns
// closes the ABSTRACT instance only. `ro = ["/tmp:/mnt/hosttmp"]` re-opened
// X11; a `/run/user/<uid>` grant re-opened D-Bus, Wayland and more — while the
// "netns-scoped, so they are out too" line printed for that same run.
//
// networkClaimMisattributesPathnameSocketToNetns is the shared predicate this
// file's tests all reduce to. It is written once and applied to every
// corrected site's OWN rendered text, on purpose: CLAUDE.md's postmortem on
// this exact issue says "assert the SET, not the site" and points at
// TestNoSnugScreenEmitsARawControlCharacter (visible_test.go) as the model —
// drive the real sinks, apply ONE predicate to all of them, rather than
// hardcode four call sites and freeze the count at four. A fifth copy of the
// same sentence, added anywhere and fed into one of the units below (or into
// a future one that reuses this predicate), fails the same way.
//
// The property this asks of a self-contained rendered "claim" (one mode's
// NETWORK block, one doctor branch's message, one networkConsequence call):
// does it name a pathname-addressed service (X11, D-Bus, Wayland) AND invoke
// netns-scoping AND assert a closure (no/unreachable/closed), without ever
// saying "pathname" anywhere in the unit to redirect the reader to the real
// mechanism? That is exactly the shape of the pre-fix text — see the two
// verbatim fixtures in TestTheNetworkBlockDoesNotClaimPathnameSocketsAreNetnsScoped's
// control — and exactly what the fix removed: every corrected site now keeps
// the netns-closure claim (of ABSTRACT sockets) and the pathname-service
// mention in the same unit, but never lets the second imply the first.
func networkClaimMisattributesPathnameSocketToNetns(unit string) bool {
	lower := strings.ToLower(unit)
	mentionsNetns := strings.Contains(lower, "netns") || strings.Contains(lower, "network namespace")
	namesPathnameService := strings.Contains(lower, "x11") || strings.Contains(lower, "d-bus") ||
		strings.Contains(lower, "dbus") || strings.Contains(lower, "wayland")
	claimsClosure := strings.Contains(lower, "unreachable") || strings.Contains(lower, "no ") ||
		strings.Contains(lower, "closed") || strings.Contains(lower, "not reachable")
	saysPathname := strings.Contains(lower, "pathname")
	return mentionsNetns && namesPathnameService && claimsClosure && !saysPathname
}

// TestTheNetworkBlockDoesNotClaimPathnameSocketsAreNetnsScoped is the named
// regression test from issue #288, driving all four corrected emitters and
// applying networkClaimMisattributesPathnameSocketToNetns to each one's own
// rendered text.
func TestTheNetworkBlockDoesNotClaimPathnameSocketsAreNetnsScoped(t *testing.T) {
	// A TEST THAT CANNOT FAIL IS WORSE THAN NO TEST. Before sweeping the fixed
	// text, prove the detector can actually fail — against the real pre-fix
	// wording, copied verbatim from `git show` of the commit before this one
	// (dryrun.go's two describeNetwork arms, and doctor.go's single line,
	// before #288 split it in two). Without this, a detector with an inverted
	// condition, or one that vacuously returns false, would pass every check
	// below for measuring nothing.
	preFix := map[string]string{
		"dryrun.go, NetIsolated, pre-#288": "NETWORK  isolated — private netns, loopback only, no helper process.\n" +
			"         No egress. No host loopback. No abstract sockets (X11/D-Bus are\n" +
			"         netns-scoped, so they are out too). Add the '@net' profile for egress.\n",
		"dryrun.go, NetEgress, pre-#288": "NETWORK  egress — private netns (one per sandbox) with a pasta helper.\n" +
			"         host loopback   UNREACHABLE (--map-host-loopback none, -T none, -U none)\n" +
			"         abstract unix   UNREACHABLE (netns-scoped: X11, D-Bus)\n" +
			"         egress          full, IPv4 + IPv6\n",
		"doctor.go, pre-#288": "  ✅ private network namespace — loopback only\n" +
			"     🔒 no egress, no host loopback, no abstract sockets (X11/D-Bus)\n",
	}
	for name, text := range preFix {
		if !networkClaimMisattributesPathnameSocketToNetns(text) {
			t.Fatalf("control: the detector does not flag %s's own pre-fix wording, so it "+
				"cannot fail on the shape it exists to catch:\n%s", name, text)
		}
	}

	// Now the real sweep: the FOUR corrected emitters, driven for real rather
	// than quoted, so a future edit to any of them is checked automatically.
	isolated := networkBlock(t, resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw"}))
	egress := networkBlock(t, resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@net"}))

	units := map[string]string{
		"dryrun.go describeNetwork, NetIsolated arm": isolated,
		"dryrun.go describeNetwork, NetEgress arm":   egress,
		"doctor.go doctorNetnsOKMessage":             doctorNetnsOKMessage,
		"config.go networkConsequence(\"egress\")":   networkConsequence("egress"),
		"config.go networkConsequence(\"host\")":     networkConsequence("host"),
	}
	for name, unit := range units {
		if unit == "" {
			t.Fatalf("%s produced no text at all, so this check measures nothing", name)
		}
		if networkClaimMisattributesPathnameSocketToNetns(unit) {
			t.Errorf("%s attributes a pathname socket's absence to the netns:\n%s", name, unit)
		}
	}
}

// TestTheNetworkBlockStillMakesItsTrueClaims is the mandatory positive
// control for the sweep above: a fix that deleted every mention of X11,
// D-Bus, Wayland or "abstract" would also pass
// TestTheNetworkBlockDoesNotClaimPathnameSocketsAreNetnsScoped, for having
// nothing left to misattribute. These assert the corrected text still says
// the TRUE things — abstract sockets ARE netns-scoped, host loopback IS
// closed by the netns, and @net-host's warning still says abstract sockets
// ARE reachable there.
func TestTheNetworkBlockStillMakesItsTrueClaims(t *testing.T) {
	isolated := networkBlock(t, resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw"}))
	if !strings.Contains(isolated, "abstract unix sockets (netns-scoped)") {
		t.Errorf("the isolated arm no longer says abstract unix sockets are closed by the "+
			"netns, which remains TRUE:\n%s", isolated)
	}
	if !strings.Contains(isolated, "No host loopback") {
		t.Errorf("the isolated arm no longer says host loopback is closed, which remains "+
			"TRUE (closed by the netns):\n%s", isolated)
	}

	egress := networkBlock(t, resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@net"}))
	if !strings.Contains(egress, "abstract unix   UNREACHABLE (netns-scoped)") {
		t.Errorf("the egress arm no longer says abstract unix sockets are unreachable "+
			"because they are netns-scoped, which remains TRUE:\n%s", egress)
	}
	if !strings.Contains(egress, "host loopback   UNREACHABLE") {
		t.Errorf("the egress arm no longer says host loopback is unreachable, which "+
			"remains TRUE (closed by the netns):\n%s", egress)
	}

	hostConsequence := networkConsequence("host")
	if !strings.Contains(hostConsequence, "ARE reachable") {
		t.Errorf("networkConsequence(\"host\") no longer says abstract sockets ARE "+
			"reachable under @net-host, which remains TRUE — this mode genuinely shares "+
			"the host's own netns:\n%s", hostConsequence)
	}
	if !strings.Contains(hostConsequence, "abstract") {
		t.Errorf("networkConsequence(\"host\") no longer mentions abstract sockets at "+
			"all:\n%s", hostConsequence)
	}
}

// TestDryRunDoesNotContradictAGrantThatExposesAPathnameSocket is the
// behavioural check: a policy that GRANTS a directory holding a real pathname
// socket must not print, anywhere on the screen, a claim that the netns
// closes it. The two subtests are issue #288's own two spellings —
// `ro = ["/tmp:/mnt/hosttmp"]` (X11) and a `/run/user/<uid>`-shaped grant
// (D-Bus/Wayland) — rebuilt on throwaway directories so the test is hermetic
// rather than depending on this host's own X server or session bus.
func TestDryRunDoesNotContradictAGrantThatExposesAPathnameSocket(t *testing.T) {
	cases := []struct {
		name       string
		buildGrant func(t *testing.T) (hostDir, guest, sockRelPath string)
	}{
		// The issue's own first spelling: a directory shaped like /tmp,
		// carrying .X11-unix/X0.
		{"ro = [host-tmp:/mnt/hosttmp], X11", func(t *testing.T) (string, string, string) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, ".X11-unix"), 0o755); err != nil {
				t.Fatal(err)
			}
			return root, "/mnt/hosttmp", ".X11-unix/X0"
		}},
		// The issue's own second spelling: a directory shaped like
		// /run/user/<uid>, carrying the session bus socket directly.
		{"ro = [host-run-user:/mnt/run], D-Bus", func(t *testing.T) (string, string, string) {
			root := t.TempDir()
			return root, "/mnt/run", "bus"
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hostDir, guest, sockRel := tc.buildGrant(t)
			sockPath := filepath.Join(hostDir, sockRel)

			// POSITIVE CONTROL for the fixture itself: a REAL listening unix
			// socket, not a plain file, so "the directory holds a pathname
			// socket" is a fact and not a name.
			ln, err := net.Listen("unix", sockPath)
			if err != nil {
				t.Fatalf("could not create the fixture socket at %s: %v", sockPath, err)
			}
			t.Cleanup(func() { ln.Close() })

			reg := loadTestRegistry(t)
			home, target := testTree(t)
			reg["hostsock"] = &policy.Profile{
				Name: "hostsock",
				RO:   []string{hostDir + ":" + guest},
			}
			ctx := policy.Context{
				Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"},
			}
			p, err := policy.Resolve(reg, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "hostsock"}, ctx, policy.OSEnviron{})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}

			// POSITIVE CONTROL: the grant really landed in the resolved
			// policy and really covers the socket's directory. Without this,
			// a Resolve that silently dropped the grant would make every
			// assertion below pass for measuring nothing.
			m, ok := p.Mounts[guest]
			if !ok {
				t.Fatalf("fixture: %s never resolved to a mount in the policy at all", guest)
			}
			if m.Host != hostDir {
				t.Fatalf("fixture: %s resolved to host %q, want %q", guest, m.Host, hostDir)
			}

			got := captureStdout(t, func() { dryRun(p, p.BwrapArgs(0, 0), config{}, nil) })
			if !strings.Contains(got, guest) {
				t.Fatalf("the grant never reached the --dry-run screen, so this test "+
					"measures nothing:\n%s", got)
			}
			if networkClaimMisattributesPathnameSocketToNetns(got) {
				t.Errorf("--dry-run grants %s (which holds a real pathname socket at "+
					"%s/%s) and ALSO claims, somewhere on the same screen, that a "+
					"pathname socket is closed by the netns — contradicting the grant "+
					"immediately above it:\n%s", guest, hostDir, sockRel, got)
			}
		})
	}
}
