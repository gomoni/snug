//go:build integration

package integration

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPastaOffersNoHostValueUnderNetAnon is issue #196's regression test, and
// it exists because the issue turned out to be wrong in the safe direction: it
// asserted that pasta's built-in DHCP/DHCPv6 servers hand `@net-anon` the
// host's router, resolver and search domains, and a client had never been run
// to check. One was; they do not. What is true is that nothing ASSERTS it —
// the values are withheld by pasta's own `-D`/`-S` defaults ("don't use any
// addresses", "don't use any search list"), which is precisely the shape
// CLAUDE.md's "never trust a helper's default, in either direction" is about.
//
// So this test is the assertion the argv does not make. It changes no flags.
//
// WHY IT DOES NOT RUN INSIDE A SNUG SANDBOX. passt answers only source ports
// 67/68/546/547, and a payload runs with `CapEff=0`, so it cannot bind one —
// that is the reason the leak was never exploitable. Asking therefore needs
// privilege the payload does not have, and the honest way to get it is to run
// pasta with SNUG'S OWN ARGV, read out of `snug --dry-run`, and let it spawn
// the namespace the probe runs in as root. The property under test is a
// property of that argv, and the argv comes from the tool rather than from a
// literal in this file.
//
// THE CONTROL IS THE OTHER PROFILE. Plain `@net` is SUPPOSED to hand over the
// host's address and route — that is what the profile is for — so it proves
// the client asks correctly and the server answers. Without it, a probe that
// silently failed to send anything is indistinguishable from a server that
// correctly withheld everything, which is the failure this suite has a
// standing rule about.
//
// WHAT THIS DOES NOT COVER, stated because the next reader will assume it
// does: the RA/NDP half. A Router Solicitation drew no advertisement in either
// configuration when this was measured by hand, so there is no observation to
// assert on. Do not read a green run here as "IPv6 RA carries nothing" — it is
// unmeasured. And note that `--no-ndp` would not be a free way to close it:
// it also disables the neighbour-solicitation replies the sandbox uses to
// resolve its gateway.
func TestPastaOffersNoHostValueUnderNetAnon(t *testing.T) {
	budget(t, 90*time.Second)
	requirePasta(t)
	probe := dhcpProbeBin(t)
	proj, _ := target(t)

	host := hostNetFacts(t)
	t.Logf("host: router=%q nameservers=%v search=%v", host.router, host.nameservers, host.search)

	// ── the control, first: plain @net hands over host values ──────────────
	ctrl := askPasta(t, probe, proj, "@net")
	if !strings.Contains(ctrl, "V4-REPLY-FROM=") {
		t.Fatalf("no DHCP reply at all under plain @net, so this run cannot tell a withholding "+
			"server from a probe that never asked:\n%s", ctrl)
	}
	if host.router == "" {
		t.Skip("this host has no default route, so the control cannot demonstrate a host value " +
			"being handed over and the negative below would prove nothing")
	}
	if !strings.Contains(ctrl, host.router) {
		t.Fatalf("plain @net did not offer this host's router %q — the control that makes the "+
			"assertion below meaningful is not holding:\n%s", host.router, ctrl)
	}

	// ── the case: @net-anon offers nothing of the host's ──────────────────
	got := askPasta(t, probe, proj, "@net-anon")
	if !strings.Contains(got, "V4-REPLY-FROM=") {
		t.Fatalf("no DHCP reply under @net-anon. That is not a pass: this test asserts what the "+
			"server OFFERS, and a silent server means the probe did not ask:\n%s", got)
	}

	// Compared against what this host actually has, never against a literal:
	// a machine whose LAN happens to differ from the one this was written on
	// would otherwise pass by coincidence.
	for _, v := range host.values() {
		if v == "" {
			continue
		}
		if strings.Contains(got, v) {
			t.Errorf("@net-anon's DHCP server offered %q, which is this host's own — the profile "+
				"exists to withhold exactly that (issue #196):\n%s", v, got)
		}
	}

	// The three options the issue names, asked for explicitly by the probe's
	// option 55 and expected to be absent from the answer.
	for _, opt := range []struct{ code, what string }{
		{"V4-OPT-6=", "DNS servers"},
		{"V4-OPT-15=", "domain name"},
		{"V4-OPT-119=", "search list"},
	} {
		if strings.Contains(got, opt.code) {
			t.Errorf("@net-anon's DHCP server answered with %s (%s). The probe requests it in "+
				"option 55 and pasta's -D/-S defaults are what withhold it — if this fires, that "+
				"default has changed:\n%s", opt.code, opt.what, got)
		}
	}
}

// hostNet is what this host would leak if pasta passed it on.
type hostNet struct {
	router      string
	nameservers []string
	search      []string
}

func (h hostNet) values() []string {
	out := []string{h.router}
	out = append(out, h.nameservers...)
	out = append(out, h.search...)
	return out
}

// hostNetFacts reads the host's own default gateway and resolver configuration
// — the three things @net-anon exists to withhold.
func hostNetFacts(t *testing.T) hostNet {
	t.Helper()
	h := hostNet{router: defaultGateway4(t)}

	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return h
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch fields[0] {
		case "nameserver":
			// A loopback resolver is not a host value the sandbox could tell
			// apart from its own, so it cannot be part of this assertion.
			if ip := net.ParseIP(fields[1]); ip != nil && !ip.IsLoopback() {
				h.nameservers = append(h.nameservers, fields[1])
			}
		case "search", "domain":
			h.search = append(h.search, fields[1:]...)
		}
	}
	return h
}

// defaultGateway4 reads /proc/net/route rather than shelling out to `ip`, the
// same way testdata/netprobe does and for the same reason: one fewer binary
// this suite depends on.
func defaultGateway4(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(line)
		if len(f) <= 2 || f[1] != "00000000" {
			continue
		}
		var raw uint32
		if _, err := fmt.Sscanf(f[2], "%x", &raw); err != nil {
			continue
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, raw)
		return ip.String()
	}
	return ""
}

// askPasta runs pasta with the argv snug would use for this profile, with the
// probe as the spawned command, and returns what the probe printed.
//
// The argv is READ FROM `snug --dry-run` rather than assembled here. That is
// the whole point: a test that built its own flag list would assert a property
// of the test's list, and the flags are exactly what issue #196 is about.
func askPasta(t *testing.T, probe, proj, profile string) string {
	t.Helper()
	out, code := cli(t, nil, "--dry-run", "-p", profile, proj)
	if code != 0 {
		t.Fatalf("snug --dry-run -p %s exited %d:\n%s", profile, code, out)
	}
	args := pastaArgvFrom(t, out, profile)

	// pasta spawns the command in a namespace it creates itself, so the two
	// placeholder flags that aim it at a stage this test does not have are
	// dropped — see the dry-run screen's own note about /proc/0/fd/63.
	cmd := exec.Command("pasta", append(args, "--", probe)...)
	var buf strings.Builder
	var mu sync.Mutex
	w := &lockedWriter{w: &buf, mu: &mu}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting pasta: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("pasta -p %s did not finish within 30s:\n%s", profile, buf.String())
	}
	mu.Lock()
	defer mu.Unlock()
	got := buf.String()
	if !strings.Contains(got, "PROBE-DONE") {
		t.Fatalf("the DHCP probe did not run to the end under %s — every assertion about what "+
			"was offered would be about a probe that stopped early:\n%s", profile, got)
	}
	return got
}

// pastaArgvFrom pulls the pasta command line out of a --dry-run screen and
// strips the two placeholder flags that name a stage.
func pastaArgvFrom(t *testing.T, screen, profile string) []string {
	t.Helper()
	for _, line := range strings.Split(screen, "\n") {
		if !strings.HasPrefix(line, "pasta ") {
			continue
		}
		var args []string
		skip := 0
		for _, f := range strings.Fields(strings.TrimPrefix(line, "pasta ")) {
			if skip > 0 {
				skip--
				continue
			}
			if f == "--netns" || f == "--userns" {
				skip = 1 // drop the flag and its value
				continue
			}
			args = append(args, f)
		}
		return args
	}
	t.Fatalf("no pasta command line on the --dry-run screen for %s — either that profile does "+
		"not use pasta, or the screen's format changed:\n%s", profile, screen)
	return nil
}

type lockedWriter struct {
	w  *strings.Builder
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// dhcpProbeBin builds testdata/dhcpprobe the same lazy way netprobeBin builds
// netprobe: a static host-architecture binary, built only when a test in this
// file actually needs it.
var (
	dhcpProbeOnce sync.Once
	dhcpProbePath string
	dhcpProbeErr  error
)

func dhcpProbeBin(t *testing.T) string {
	t.Helper()
	dhcpProbeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "dhcpprobe")
		if err != nil {
			dhcpProbeErr = err
			return
		}
		bin := filepath.Join(dir, "dhcpprobe")
		cmd := exec.Command("go", "build", "-o", bin, "./testdata/dhcpprobe")
		cmd.Dir = "."
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			dhcpProbeErr = fmt.Errorf("building test/integration/testdata/dhcpprobe: %w: %s", err, out.String())
			return
		}
		dhcpProbePath = bin
	})
	if dhcpProbeErr != nil {
		t.Fatal(dhcpProbeErr)
	}
	return dhcpProbePath
}
