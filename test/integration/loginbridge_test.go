//go:build integration

package integration

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The login bridge (login = ["claude"]) lets a process in the sandbox ask
// snug to open ONE pinned Claude login URL in the host's browser and to carry
// the browser's callback back in. These tests run the real binary against two
// stand-ins: testdata/loginprobe is the sandbox half of /login, and
// testdata/fakeopener is a host xdg-open that plays the human's browser.
//
// The host side of every flow is exercised for real: the FIFO, the predicate,
// the listener on host localhost:P, the relay socket created inside the
// sandbox's network namespace. What is NOT real is the browser, the Claude
// binary and claude.com, so nothing here says the login completes; that is
// scripts/'s job and needs a human.

const (
	// loginState and loginChallenge are the 43-character values the probe puts
	// in its URL. Valid against the pinned shape and otherwise arbitrary.
	loginState     = "qUcPYbXlvfwBNYqnh52qhKs7Ac_7GNRvan-h3ihmgk8"
	loginChallenge = "fD5xTDCwgf63U088pqhV0TFHbLf0emkJPI844Pfplvs"

	// loginRebuiltFmt is the authorize URL as the bridge writes it, with the
	// pinned values spelled out HERE rather than read from the code under test:
	// a change to a pinned constant must turn this test red and be decided by a
	// person. The probe sends the same parameters in a different order, so
	// seeing this order at the opener means snug rebuilt the URL.
	loginRebuiltFmt = "https://claude.com/cai/oauth/authorize?code=true" +
		"&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e&response_type=code" +
		"&redirect_uri=http%%3A%%2F%%2Flocalhost%%3A%d%%2Fcallback" +
		"&scope=org%%3Acreate_api_key+user%%3Aprofile+user%%3Ainference" +
		"+user%%3Asessions%%3Aclaude_code+user%%3Amcp_servers+user%%3Afile_upload+user%%3Aplugins" +
		"&code_challenge=%s&code_challenge_method=S256&state=%s"
)

var loginBridgeArgs = []string{"-p", "@claude", "-p", "@net", "-p", "login"}

var (
	loginBuildOnce  sync.Once
	loginProbeBin   string
	loginOpenerDir  string
	loginBuildError error
)

// buildLoginFixtures builds both fixtures once per process, statically.
func buildLoginFixtures(t *testing.T) {
	t.Helper()
	loginBuildOnce.Do(func() {
		loginOpenerDir = filepath.Join(integrationTmp, "loginbin")
		if err := os.MkdirAll(loginOpenerDir, 0o755); err != nil {
			loginBuildError = err
			return
		}
		loginProbeBin = filepath.Join(integrationTmp, "loginprobe")
		for _, b := range []struct{ out, pkg string }{
			{loginProbeBin, "./test/integration/testdata/loginprobe"},
			{filepath.Join(loginOpenerDir, "xdg-open"), "./test/integration/testdata/fakeopener"},
		} {
			cmd := exec.Command("go", "build", "-o", b.out, b.pkg)
			cmd.Dir = "../.."
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				loginBuildError = fmt.Errorf("building %s: %v\n%s", b.pkg, err, out)
				return
			}
		}
	})
	if loginBuildError != nil {
		t.Fatal(loginBuildError)
	}
}

// loginFixture is one test's world: a target with the probe staged in it, a
// directory the fake opener records into, and an environment that puts the fake
// opener first on PATH and sets the one user profile that turns the bridge on.
type loginFixture struct {
	proj string
	rec  string
	env  []string
}

// newLoginFixture returns the fixture. mode is the fake opener's behaviour;
// extraEnv is appended last, so it wins.
//
// DISPLAY is set because the preflight refuses a run with neither it nor
// WAYLAND_DISPLAY, and that refusal is not what the callers want to measure
// (TestTheLoginBridgeRefusesWithoutADisplay is).
func newLoginFixture(t *testing.T, mode string, extraEnv ...string) *loginFixture {
	t.Helper()
	buildLoginFixtures(t)
	proj, _ := target(t)
	data, err := os.ReadFile(loginProbeBin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "loginprobe"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := t.TempDir()
	cfg := t.TempDir()
	pd := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pd, "login.toml"), []byte(
		"[profile.login]\n"+
			"description = \"the login bridge, for the integration suite\"\n"+
			"login = [\"claude\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := baseEnv(append([]string{
		"XDG_CONFIG_HOME=" + cfg,
		"PATH=" + loginOpenerDir + ":" + os.Getenv("PATH"),
		"DISPLAY=:99",
		"FAKEOPENER_DIR=" + rec,
		"FAKEOPENER_MODE=" + mode,
	}, extraEnv...)...)
	return &loginFixture{proj: proj, rec: rec, env: env}
}

// start launches snug with the bridge on and ./loginprobe as the payload.
func (f *loginFixture) start(t *testing.T, probeArgs ...string) *bgSandbox {
	t.Helper()
	return startBgSandbox(t, f.env, loginBridgeArgs, f.proj, "./loginprobe "+strings.Join(probeArgs, " "))
}

// loginWaitExit waits for the sandbox's snug to exit on its own and returns its
// exit code, failing the test with the log if it does not within d.
func loginWaitExit(t *testing.T, s *bgSandbox, d time.Duration) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.proc.wait() }()
	select {
	case err := <-done:
		if err == nil {
			return 0
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		t.Fatalf("waiting for snug: %v\n%s", err, s.log())
	case <-time.After(d):
		t.Fatalf("snug did not exit within %s:\n%s", d, s.log())
	}
	return -1
}

// loginField returns the rest of the first line of the probe's output that
// starts with key, or "" and false.
func loginField(out, key string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, key+" "); ok {
			return strings.TrimSpace(rest), true
		}
	}
	return "", false
}

// loginPort reads the port the probe says it listens on.
func loginPort(t *testing.T, out string) int {
	t.Helper()
	v, ok := loginField(out, "PORT")
	if !ok {
		t.Fatalf("the probe never printed its PORT line, so nothing below knows which host "+
			"port to measure:\n%s", out)
	}
	p, err := strconv.Atoi(v)
	if err != nil || p < 32768 || p > 60999 {
		t.Fatalf("the probe's PORT line %q is not a port in 32768-60999:\n%s", v, out)
	}
	return p
}

// requireLoginRefused fails unless nothing accepts a TCP connection at addr. A
// connection that completes is a failure; an address that does not exist on
// this host (no IPv6 loopback) is reported as skipped, not as a pass.
func requireLoginRefused(t *testing.T, network, addr, why string) {
	t.Helper()
	c, err := net.DialTimeout(network, addr, 2*time.Second)
	if err == nil {
		c.Close()
		t.Errorf("%s: something accepted a connection on %s %s", why, network, addr)
		return
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Errorf("%s: dialling %s %s failed, but not with a refusal, so it is not evidence "+
			"that nothing listens there: %v", why, network, addr, err)
	}
}

// loginHostHasV6 reports whether this host can bind [::1], which decides
// whether the v6 half of a host-listener assertion can mean anything.
func loginHostHasV6(t *testing.T) bool {
	t.Helper()
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Logf("no IPv6 loopback on this host, skipping the ::1 half: %v", err)
		return false
	}
	ln.Close()
	return true
}

func loginRec(t *testing.T, rec, name string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(rec, name))
	if err != nil {
		if os.IsNotExist(err) {
			return "", false
		}
		t.Fatal(err)
	}
	return string(b), true
}

// requireLoginBridgeEnv gathers the gates every bridge test shares.
func requireLoginBridgeEnv(t *testing.T) {
	t.Helper()
	requireSandbox(t)
	requirePasta(t)
}

// TestTheLoginBridgeRelaysOneRebuiltCallback fails if the bridge ever lets a
// byte of the browser's request or the sandbox's answer cross that is not
// code and state going in and one status integer coming out. The fake browser
// sends a Cookie, a User-Agent and a Referer; the probe answers with a
// Set-Cookie, a Location and a script.
//
// It does not reach a real browser's behaviour (cookie jars, HSTS), only the
// bytes on the two sockets.
func TestTheLoginBridgeRelaysOneRebuiltCallback(t *testing.T) {
	budget(t, 40*time.Second)
	requireLoginBridgeEnv(t)
	f := newLoginFixture(t, "callback")

	s := f.start(t, "state="+loginState, "challenge="+loginChallenge)
	if code := loginWaitExit(t, s, 30*time.Second); code != 0 {
		t.Fatalf("snug exited %d:\n%s", code, s.log())
	}
	out := s.log()
	if !strings.Contains(out, "PROBE-DONE") {
		t.Fatalf("the probe never finished:\n%s", out)
	}
	port := loginPort(t, out)

	if v, _ := loginField(out, "BROWSER"); v != "/snug/bin/snug-browser" {
		t.Errorf("BROWSER inside is %q, want /snug/bin/snug-browser:\n%s", v, out)
	}
	if v, _ := loginField(out, "SHIM-RC"); v != "0" {
		t.Errorf("the shim exited %q, want 0:\n%s", v, out)
	}

	// What the sandbox received: exactly snug's own request.
	raw, ok := loginField(out, "RECEIVED")
	if !ok {
		t.Fatalf("the probe received nothing, so the callback was never relayed:\n%s", out)
	}
	got, err := strconv.Unquote(raw)
	if err != nil {
		t.Fatalf("RECEIVED line %q is not a Go-quoted string: %v", raw, err)
	}
	want := fmt.Sprintf("GET /callback?code=CODE-1_x&state=%s HTTP/1.1\r\nHost: localhost:%d\r\n"+
		"Connection: close\r\n\r\n", loginState, port)
	if got != want {
		t.Errorf("the sandbox received\n%q\nwant\n%q", got, want)
	}
	for _, leak := range []string{"Cookie", "hostsession", "SECRET", "User-Agent", "fakebrowser", "Referer"} {
		if strings.Contains(got, leak) {
			t.Errorf("a browser header crossed into the sandbox (%q): %q", leak, got)
		}
	}
	if n := strings.Count(out, "RECEIVED "); n != 1 {
		t.Errorf("the probe received %d requests, want exactly 1:\n%s", n, out)
	}

	// What the opener was handed: the rebuilt URL, in snug's order, not the
	// probe's.
	argv, ok := loginRec(t, f.rec, "argv")
	if !ok {
		t.Fatalf("the fake opener never ran:\n%s", out)
	}
	wantURL := fmt.Sprintf(loginRebuiltFmt, port, loginChallenge, loginState)
	if wantArgv := "argc=1\nargv=" + wantURL + "\n"; argv != wantArgv {
		t.Errorf("the opener's argv was\n%q\nwant\n%q", argv, wantArgv)
	}
	sent, _ := loginField(out, "TARGET-URL")
	if sent == wantURL || sent == "" {
		t.Errorf("the probe's own URL %q equals the rebuilt one, so this test cannot tell a "+
			"rebuild from a copy", sent)
	}

	// What the browser was told: snug's page, with the sandbox's reply reduced
	// to its status.
	resp, ok := loginRec(t, f.rec, "response")
	if !ok {
		t.Fatal("the fake browser recorded no response")
	}
	if !strings.HasPrefix(resp, "HTTP/1.1 200 ") {
		t.Errorf("the browser was answered %q, want a 200", firstLine(resp))
	}
	if !strings.Contains(resp, "answered HTTP 302") {
		t.Errorf("the browser's page does not carry the sandbox's status (302), so the probe's "+
			"answer was not the one reported:\n%s", resp)
	}
	if !strings.Contains(resp, "Content-Security-Policy: default-src 'none'") {
		t.Errorf("the browser's answer has no Content-Security-Policy:\n%s", resp)
	}
	for _, bad := range []string{"Set-Cookie", "Location", "<script", "evil.example", "pwn"} {
		if strings.Contains(resp, bad) {
			t.Errorf("the sandbox's answer reached the browser (%q):\n%s", bad, resp)
		}
	}

	// And the host port is released. The browser reached it on 127.0.0.1 a few
	// lines up, which is the control that something was bound there.
	requireLoginRefused(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), "after the flow")
	if loginHostHasV6(t) {
		requireLoginRefused(t, "tcp6", fmt.Sprintf("[::1]:%d", port), "after the flow")
	}
}

// TestTheLoginBridgeRefusesANonClaudeURL fails if a URL outside the one pinned
// shape ever reaches the host's opener. The probe's shim hand-over works (the
// probe reports a zero exit and snug prints the refusal), so an absent opener
// marker means the predicate stopped it and not that the request was lost.
func TestTheLoginBridgeRefusesANonClaudeURL(t *testing.T) {
	budget(t, 40*time.Second)
	requireLoginBridgeEnv(t)
	f := newLoginFixture(t, "callback")

	s := f.start(t, "url=https://example.com/", "serve=0", "release=release")
	out := waitForLogLine(t, s, "not the Claude login URL snug pins", 15*time.Second)
	if !strings.Contains(out, "Nothing was opened") {
		t.Errorf("the refusal does not say nothing was opened:\n%s", out)
	}
	if !strings.Contains(out, "https://example.com/") {
		t.Errorf("the refusal does not name the refused URL:\n%s", out)
	}
	if _, ran := loginRec(t, f.rec, "ran"); ran {
		t.Errorf("the host opener ran for a URL that is not Claude's:\n%s", out)
	}
	time.Sleep(500 * time.Millisecond)
	handToPayload(t, f.proj, "release", "x")
	loginWaitExit(t, s, 20*time.Second)
	out = s.log()

	if v, _ := loginField(out, "SHIM-RC"); v != "0" {
		t.Errorf("the shim did not hand the URL over (exit %q), so the refusal above is not the "+
			"predicate's answer to it:\n%s", v, out)
	}
	if _, ran := loginRec(t, f.rec, "ran"); ran {
		t.Errorf("the host opener ran for a URL that is not Claude's:\n%s", out)
	}
	port := loginPort(t, out)
	requireLoginRefused(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), "no flow was started")
}

// TestTheLoginBridgeRefusesAPortNothingListensOn fails if snug opens a browser
// for a callback port nothing in the sandbox listens on. The URL is valid in
// every other respect, which the probe's own listening port (released just
// before the open) shows: the refusal names that port.
func TestTheLoginBridgeRefusesAPortNothingListensOn(t *testing.T) {
	budget(t, 40*time.Second)
	requireLoginBridgeEnv(t)
	f := newLoginFixture(t, "callback")

	s := f.start(t, "nolisten=1", "release=release")
	out := waitForLogLine(t, s, "refused an open request", 15*time.Second)
	port := loginPort(t, out)
	if want := fmt.Sprintf("nothing inside listens on 127.0.0.1:%d", port); !strings.Contains(out, want) {
		t.Errorf("the refusal does not say %q:\n%s", want, out)
	}
	if _, ran := loginRec(t, f.rec, "ran"); ran {
		t.Errorf("the host opener ran for a port nothing listens on:\n%s", out)
	}
	time.Sleep(500 * time.Millisecond)
	handToPayload(t, f.proj, "release", "x")
	loginWaitExit(t, s, 20*time.Second)
	out = s.log()
	if _, ran := loginRec(t, f.rec, "ran"); ran {
		t.Errorf("the host opener ran for a port nothing listens on:\n%s", out)
	}
	if v, _ := loginField(out, "SHIM-RC"); v != "0" {
		t.Errorf("the shim did not hand the URL over (exit %q):\n%s", v, out)
	}
	requireLoginRefused(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), "no flow was started")
}

// TestAWrongStateGets404AndTheFlowSurvives fails if a callback with the wrong
// state ends the flow, reaches the sandbox, or is answered with anything but
// snug's 404; and if the right state afterwards is not relayed, which is what
// shows the flow was still open.
func TestAWrongStateGets404AndTheFlowSurvives(t *testing.T) {
	budget(t, 40*time.Second)
	requireLoginBridgeEnv(t)
	f := newLoginFixture(t, "wrongstate")

	s := f.start(t, "state="+loginState, "challenge="+loginChallenge)
	if code := loginWaitExit(t, s, 30*time.Second); code != 0 {
		t.Fatalf("snug exited %d:\n%s", code, s.log())
	}
	out := s.log()

	wrong, ok := loginRec(t, f.rec, "response-wrong")
	if !ok {
		t.Fatalf("the fake browser never sent the wrong-state callback:\n%s", out)
	}
	if !strings.HasPrefix(wrong, "HTTP/1.1 404 ") {
		t.Errorf("a wrong state was answered %q, want a 404", firstLine(wrong))
	}
	if strings.Contains(wrong, "answered HTTP") {
		t.Errorf("the wrong-state request was relayed (the page reports the sandbox's status):\n%s", wrong)
	}
	if n := strings.Count(out, "RECEIVED "); n != 1 {
		t.Fatalf("the probe received %d requests, want exactly 1 (the right state's):\n%s", n, out)
	}
	raw, _ := loginField(out, "RECEIVED")
	got, _ := strconv.Unquote(raw)
	if !strings.Contains(got, "state="+loginState+" ") || strings.Contains(got, "WRONG") {
		t.Errorf("the one request the sandbox received is not the right-state one: %q", got)
	}
	resp, ok := loginRec(t, f.rec, "response")
	if !ok || !strings.HasPrefix(resp, "HTTP/1.1 200 ") || !strings.Contains(resp, "answered HTTP 302") {
		t.Errorf("the right state afterwards was not relayed (answer %q):\n%s", firstLine(resp), out)
	}
}

// TestTheLoginBridgeLeavesHostLoopbackClosed fails if holding localhost:P on
// the host for a pending login ever makes the host's loopback reachable from
// inside: the callback port itself, and a separate host service, over every
// address TestHostLoopbackIsUnreachable probes (loopback v4 and v6, the
// gateways, the host's own LAN address, UDP).
//
// Controls: the host connects to P while the probe dials (so the bridge's
// listener was up), the host reaches its own service, and the sandbox reaches
// the same internet address the host just did. The gateway is allowed to
// time out, as it is there, because a router owes nobody an answer; REACHED is
// the only outcome that fails everywhere.
func TestTheLoginBridgeLeavesHostLoopbackClosed(t *testing.T) {
	budget(t, 60*time.Second)
	requireLoginBridgeEnv(t)
	requireInternet(t)
	netTarget := internetTarget(t)
	f := newLoginFixture(t, "hold")

	ln4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveBanner(t, ln4)
	svc := ln4.Addr().(*net.TCPAddr).Port
	udp := serveUDPBanner(t, "127.0.0.1")

	haveV6 := loginHostHasV6(t)
	svc6 := 0
	if haveV6 {
		ln6, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Fatal(err)
		}
		serveBanner(t, ln6)
		svc6 = ln6.Addr().(*net.TCPAddr).Port
	}
	lan, lanErr := hostOutboundAddr()
	haveLAN := lanErr == nil
	lanTCP, lanUDP := 0, 0
	if haveLAN {
		lnL, err := net.Listen("tcp4", lan+":0")
		if err != nil {
			t.Logf("cannot bind this host's own address %s, skipping the LAN half: %v", lan, err)
			haveLAN = false
		} else {
			serveBanner(t, lnL)
			lanTCP = lnL.Addr().(*net.TCPAddr).Port
			lanUDP = serveUDPBanner(t, lan)
		}
	}
	if got := dialUDPBanner(t, "127.0.0.1", udp); got != hostBanner {
		t.Fatalf("precondition: the host cannot reach its own UDP service (got %q)", got)
	}

	// Each probe is label@network:host:port.
	var dials []string
	add := func(label, network, host string, port any) {
		dials = append(dials, fmt.Sprintf("dial=%s@%s:%s:%v", label, network, host, port))
	}
	add("egress", "tcp", strings.Split(netTarget, ":")[0], internetPort)
	for _, a := range []struct{ label, host string }{
		{"v4", "127.0.0.1"}, {"v6", "::1"}, {"gw", "gw"}, {"gw6", "gw6"},
	} {
		add("p-"+a.label, "tcp", a.host, "PORT")
		add("svc-"+a.label, "tcp", a.host, svc)
	}
	if haveV6 {
		add("svc6-v6", "tcp", "::1", svc6)
	}
	add("svc-udp-v4", "udp", "127.0.0.1", udp)
	add("svc-udp-gw", "udp", "gw", udp)
	if haveLAN {
		add("p-lan", "tcp", lan, "PORT")
		add("svc-lan", "tcp", lan, lanTCP)
		add("svc-udp-lan", "udp", lan, lanUDP)
	}

	args := append([]string{"go=go", "release=release"}, dials...)
	s := f.start(t, args...)
	out := waitForLogLine(t, s, "SHIM-RC", 15*time.Second)
	port := loginPort(t, out)

	// CONTROL: the bridge's listener is up on the host, on both families, and
	// the fake opener ran (it only records and exits in "hold" mode).
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("precondition: the host cannot connect to localhost:%d, so no flow holds "+
				"it and the refusals below would prove nothing: %v\n%s", port, err, s.log())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if haveV6 {
		c, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", port), time.Second)
		if err != nil {
			t.Fatalf("precondition: the bridge holds 127.0.0.1:%d but not [::1]:%d: %v", port, port, err)
		}
		c.Close()
	}
	// Polled, not read once: the bridge binds the port BEFORE it starts the
	// opener, so the connects above can succeed while the opener's record is
	// still unwritten.
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, ran := loginRec(t, f.rec, "ran"); ran {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("precondition: the fake opener never ran, so no flow was opened:\n%s", s.log())
		}
	}

	handToPayload(t, f.proj, "go", "x")
	out = waitForLogLine(t, s, "DIALS-COMPLETE", 40*time.Second)

	// The flow is STILL holding the port after the dials, so they ran against it.
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Errorf("the bridge's listener went away before the dials finished: %v", err)
	} else {
		c.Close()
	}
	handToPayload(t, f.proj, "release", "x")
	loginWaitExit(t, s, 20*time.Second)

	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "DIAL") {
			t.Log(line)
		}
	}
	verdicts := map[string]string{}
	targets := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 3 && f[0] == "DIAL":
			verdicts[f[1]] = f[2]
		case len(f) >= 4 && f[0] == "DIAL-TARGET":
			targets[f[1]] = f[3]
		}
	}
	if verdicts["egress"] != "REACHED" {
		t.Fatalf("precondition: the sandbox cannot reach %s, which the host just did, so a REFUSED "+
			"below could be a network that does not work (%q):\n%s", netTarget, verdicts["egress"], out)
	}
	// The probe printed the target it dialled for each label; assert the port
	// back out of it, so a label pointing at the wrong port cannot pass.
	for label, addr := range targets {
		if strings.HasPrefix(label, "p-") && !strings.HasSuffix(addr, ":"+strconv.Itoa(port)) {
			t.Errorf("probe %s dialled %s, not the bridge's port %d", label, addr, port)
		}
	}
	for _, label := range []string{"p-v4", "svc-v4", "p-gw", "svc-udp-v4"} {
		if _, ok := verdicts[label]; !ok {
			t.Errorf("probe %s produced no verdict:\n%s", label, out)
		}
	}
	if strings.Contains(out, hostBanner) {
		t.Errorf("the sandbox read the host service's banner:\n%s", out)
	}
	for label, v := range verdicts {
		if label == "egress" {
			continue
		}
		switch v {
		case "REFUSED":
		case "TIMEDOUT":
			// Only a router's address may drop instead of answer.
			if !strings.HasSuffix(label, "-gw") && !strings.HasSuffix(label, "-gw6") &&
				label != "svc-udp-gw" && label != "svc-udp-v4" && label != "svc-udp-lan" {
				t.Errorf("probe %s timed out; a loopback or LAN address should refuse:\n%s", label, out)
			}
		case "NOADDR":
			if !strings.HasSuffix(label, "gw6") {
				t.Errorf("probe %s found no address to dial:\n%s", label, out)
			} else {
				t.Logf("no IPv6 default route in the sandbox, skipping %s", label)
			}
		default:
			t.Errorf("probe %s ended %q, not a refusal:\n%s", label, v, out)
		}
	}
}

// TestWithoutTheLoginKeyThereIsNoBridge fails if BROWSER, the FIFO or the
// shim exist in a run whose profiles do not set login = ["claude"]. The
// same script runs again with the key on and must see all three, which is what
// shows the script looks at the right paths.
func TestWithoutTheLoginKeyThereIsNoBridge(t *testing.T) {
	budget(t, 40*time.Second)
	requireLoginBridgeEnv(t)
	proj, _ := target(t)
	f := newLoginFixture(t, "callback")

	const script = `if [ -n "${BROWSER+set}" ]; then echo "BROWSER=set:$BROWSER"; else echo "BROWSER=unset"; fi
if [ -e /snug/browser.fifo ]; then echo FIFO=present; else echo FIFO=absent; fi
if [ -e /snug/bin/snug-browser ]; then echo SHIM=present; else echo SHIM=absent; fi
`
	off := runEnv(t, f.env, []string{"-p", "@claude", "-p", "@net"}, proj, script).mustRun(t)
	for _, want := range []string{"BROWSER=unset", "FIFO=absent", "SHIM=absent"} {
		if !strings.Contains(off.out, want) {
			t.Errorf("without the key, want %q:\n%s", want, off.out)
		}
	}
	on := runEnv(t, f.env, loginBridgeArgs, proj, script).mustRun(t)
	for _, want := range []string{"BROWSER=set:/snug/bin/snug-browser", "FIFO=present", "SHIM=present"} {
		if !strings.Contains(on.out, want) {
			t.Errorf("control: with the key, want %q:\n%s", want, on.out)
		}
	}
}

// TestTheLoginBridgeDiesWithSnug fails if SIGKILL of snug with a login pending
// leaves the host port held, a process of the run alive, or anything in the run
// directory beyond the FIFO the bridge itself made.
//
// It does not show the stage or pasta are gone by name; it shows nothing on
// the host carries the run's token in its argv, and that the port is closed.
func TestTheLoginBridgeDiesWithSnug(t *testing.T) {
	budget(t, 60*time.Second)
	requireLoginBridgeEnv(t)

	rtOn, err := os.MkdirTemp("", "snug-lbrt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(rtOn) })
	rtOff, err := os.MkdirTemp("", "snug-lbrt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(rtOff) })

	tok := orphanToken()
	f := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rtOn)

	// The keyless baseline: same SIGKILL, same topology, what a run directory
	// holds afterwards without the bridge. It is the run directory's own
	// definition of "leftovers" the bridge must not add to.
	fOff := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rtOff)
	off := startBgSandbox(t, fOff.env, []string{"-p", "@claude", "-p", "@net"}, fOff.proj,
		"sleep 60 # "+tok)
	off.ready(t)
	offDir := off.runDir(rtOff)
	waitForLockFile(t, offDir)
	_ = off.proc.cmd.Process.Kill()
	off.proc.wait()
	baseline := loginDirNames(t, offDir)
	if !loginContains(baseline, "lock") {
		t.Fatalf("precondition: the baseline run directory %s holds no lock file: %v", offDir, baseline)
	}

	s := f.start(t, "token="+tok, "go=go", "release=release", "dial=ctl@tcp:127.0.0.1:PORT")
	out := waitForLogLine(t, s, "SHIM-RC", 15*time.Second)
	port := loginPort(t, out)
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("precondition: no flow holds localhost:%d on the host: %v\n%s", port, err, s.log())
		}
		time.Sleep(50 * time.Millisecond)
	}
	haveV6 := loginHostHasV6(t)
	if haveV6 {
		c, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", port), time.Second)
		if err != nil {
			t.Fatalf("precondition: [::1]:%d is not held: %v", port, err)
		}
		c.Close()
	}
	snugPID := s.pid()
	if live := pidsWithToken(tok, snugPID); len(live) == 0 {
		t.Fatalf("precondition: the token sweep finds no process of this run besides snug, so a "+
			"clean sweep after the kill would prove nothing:\n%s", s.log())
	}
	runDir := s.runDir(rtOn)
	if _, err := os.Stat(filepath.Join(runDir, "browser.fifo")); err != nil {
		t.Fatalf("precondition: the run's FIFO is not in %s: %v", runDir, err)
	}

	if err := s.proc.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	killed := time.Now()
	s.proc.wait()

	// Within a second, on both families.
	for {
		_, e4 := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		e6 := error(syscall.ECONNREFUSED)
		if haveV6 {
			_, e6 = net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", port), 200*time.Millisecond)
		}
		if e4 != nil && e6 != nil {
			break
		}
		if time.Since(killed) > time.Second {
			t.Errorf("localhost:%d still accepts connections %s after SIGKILL of snug (v4 err=%v, v6 err=%v)",
				port, time.Since(killed).Round(time.Millisecond), e4, e6)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	requireLoginRefused(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), "after SIGKILL of snug")

	// No process of the run survives: bwrap's pdeathsig takes the sandbox, so
	// poll for it rather than sampling once.
	var left []int
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if left = pidsWithToken(tok); len(left) == 0 {
			break
		}
	}
	if len(left) != 0 {
		defer killAll(left)
		t.Errorf("%d process(es) with the run's token survived SIGKILL of snug: %s",
			len(left), describePIDs(left))
	}

	// Run directory: the baseline plus the FIFO, and nothing else.
	got := loginDirNames(t, runDir)
	var extra, missing []string
	for _, n := range got {
		if !loginContains(baseline, n) {
			extra = append(extra, n)
		}
	}
	for _, n := range baseline {
		if !loginContains(got, n) {
			missing = append(missing, n)
		}
	}
	if len(extra) != 1 || extra[0] != "browser.fifo" || len(missing) != 0 {
		t.Errorf("the SIGKILLed run directory holds %v; the keyless baseline is %v. Extra: %v, "+
			"missing: %v, want exactly the bridge's browser.fifo extra", got, baseline, extra, missing)
	}

	// The next run in the same runtime directory sweeps the corpse, FIFO and all.
	next := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rtOn)
	r := runEnv(t, next.env, loginBridgeArgs, next.proj, "true").mustRun(t)
	if r.code != 0 {
		t.Fatalf("the follow-up run failed (%d):\n%s", r.code, r.out)
	}
	if _, err := os.Stat(runDir); !os.IsNotExist(err) {
		t.Errorf("the SIGKILLed run's directory %s survived the next run's sweep (stat err: %v)", runDir, err)
	}
}

func loginDirNames(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func loginContains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// TestTheLoginBridgeRefusesWithoutADisplay fails if a run asking for the bridge
// starts when snug has neither DISPLAY nor WAYLAND_DISPLAY: the open would go
// nowhere and the user would believe a login path existed. It must exit 77
// before any payload runs and name both variables and the paste fallback. The
// same environment with DISPLAY set runs the payload, which is what shows the
// refusal is about the display.
func TestTheLoginBridgeRefusesWithoutADisplay(t *testing.T) {
	budget(t, 30*time.Second)
	requireLoginBridgeEnv(t)
	f := newLoginFixture(t, "callback")

	var noDisplay []string
	for _, e := range f.env {
		if strings.HasPrefix(e, "DISPLAY=") || strings.HasPrefix(e, "WAYLAND_DISPLAY=") {
			continue
		}
		noDisplay = append(noDisplay, e)
	}
	argv := append(append([]string{}, loginBridgeArgs...), f.proj, "--", "/bin/sh", "-c", "echo PAYLOAD-RAN")
	out, code := cli(t, noDisplay, argv...)
	if code != exitPolicyCode {
		t.Errorf("exit code %d, want %d:\n%s", code, exitPolicyCode, out)
	}
	for _, want := range []string{"DISPLAY", "WAYLAND_DISPLAY", "pasting the code"} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "PAYLOAD-RAN") {
		t.Errorf("the payload ran despite the refusal:\n%s", out)
	}

	out, code = cli(t, f.env, argv...)
	if code != 0 || !strings.Contains(out, "PAYLOAD-RAN") {
		t.Errorf("control: with DISPLAY set the run should work (exit %d):\n%s", code, out)
	}
}

// TestTheShimAndFIFOAreReadOnlyOrScoped fails if the sandbox can rewrite or
// replace the shim that BROWSER names, or if the FIFO is anything but a 0600
// FIFO owned by the run's uid. It does not show who else on the host can open
// the FIFO: that is the run directory's own mode, not asserted here.
func TestTheShimAndFIFOAreReadOnlyOrScoped(t *testing.T) {
	budget(t, 30*time.Second)
	requireLoginBridgeEnv(t)
	proj, _ := target(t)
	f := newLoginFixture(t, "callback")

	const script = `echo "UID $(id -u)"
stat -c 'SHIM %a %u' /snug/bin/snug-browser
stat -c 'FIFO %F %a %u' /snug/browser.fifo
(printf x >> /snug/bin/snug-browser) 2>&1
echo "APPEND-RC $?"
(rm -f /snug/bin/snug-browser) 2>&1
echo "RM-RC $?"
(touch /snug/bin/another) 2>&1
echo "TOUCH-RC $?"
(chmod 0777 /snug/bin/snug-browser) 2>&1
echo "CHMOD-RC $?"
head -c 20 /snug/bin/snug-browser
echo
`
	r := runEnv(t, f.env, loginBridgeArgs, proj, script).mustRun(t)
	t.Logf("%s", r.out)

	uid, _ := loginField(r.out, "UID")
	if uid != strconv.Itoa(os.Getuid()) {
		t.Errorf("inside, id -u is %q, want the run's uid %d", uid, os.Getuid())
	}
	if shim, _ := loginField(r.out, "SHIM"); shim == "" {
		t.Errorf("control: stat of the shim printed nothing, so the write checks below ran against nothing:\n%s", r.out)
	}
	if fifo, _ := loginField(r.out, "FIFO"); fifo != fmt.Sprintf("fifo 600 %d", os.Getuid()) {
		t.Errorf("the FIFO is %q, want %q", fifo, fmt.Sprintf("fifo 600 %d", os.Getuid()))
	}
	for _, name := range []string{"APPEND", "RM", "TOUCH", "CHMOD"} {
		rc, _ := loginField(r.out, name+"-RC")
		if rc == "" || rc == "0" {
			t.Errorf("%s inside succeeded or never ran (rc %q):\n%s", name, rc, r.out)
		}
	}
	if !strings.Contains(r.out, "Read-only file system") {
		t.Errorf("the write was not refused as read-only:\n%s", r.out)
	}
	if !strings.Contains(r.out, "#!/bin/sh") {
		t.Errorf("the shim is not intact after the attempts (first bytes not a shell shebang):\n%s", r.out)
	}
}

// bridgeContainerScript builds one FROM scratch image whose RUN step and
// entrypoint are the dialer, runs the RUN step with the targets as arguments
// (the build vantage), then creates and runs a container with the same targets
// as Cmd, which podman appends to the ENTRYPOINT (the container vantage). Both
// print what the dialer said, under markers.
const bridgeContainerScript = `import sys, tarfile, io, urllib.parse
targets = sys.argv[1:]
tag = "snugtest-bridgedial:1"
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as tf:
    df = ("FROM scratch\nCOPY bridgedialprobe /bridgedialprobe\nRUN " + json.dumps(["/bridgedialprobe"] + targets) + "\nENTRYPOINT [\"/bridgedialprobe\"]\n").encode()
    ti = tarfile.TarInfo("Dockerfile"); ti.size = len(df); tf.addfile(ti, io.BytesIO(df))
    data = open("bridgedialprobe", "rb").read()
    t2 = tarfile.TarInfo("bridgedialprobe"); t2.size = len(data); t2.mode = 0o755; tf.addfile(t2, io.BytesIO(data))
q = {"dockerfile": '["Dockerfile"]', "t": tag, "output": tag,
     "networkmode": "0", "nsoptions": '[{"Name":"user","Host":true,"Path":""}]',
     "isolation": "0", "rm": "1", "layers": "1", "pullpolicy": "missing",
     "seccomp": "/usr/share/containers/seccomp.json", "shmsize": "67108864", "nocache": "1"}
st, body = req("POST", "/v5.0.0/libpod/build?" + urllib.parse.urlencode(q), buf.getvalue(), {"Content-Type": "application/x-tar"})
print("BUILD %s: %d" % (tag, st), flush=True)
print("BUILD-OUTPUT-BEGIN")
for line in body.decode(errors="replace").splitlines():
    try:
        s = json.loads(line).get("stream", "")
    except Exception:
        s = line
    for l in s.splitlines():
        if l.startswith("DIAL") or l.startswith("ARGS"):
            print("BUILD-STEP " + l.strip())
print("BUILD-OUTPUT-END", flush=True)
if st == 200:
    spec = {"Image": "localhost/" + tag, "Cmd": targets, "Tty": True}
    st, r = req("POST", "/v1.41/containers/create", json.dumps(spec).encode(), {"Content-Type": "application/json"})
    print("CREATE %d" % st, flush=True)
    if st == 201:
        cid = json.loads(r)["Id"]
        print("START %d" % req("POST", "/v1.41/containers/%s/start" % cid)[0], flush=True)
        print("WAIT %s" % (req("POST", "/v1.41/containers/%s/wait" % cid),), flush=True)
        st, logs = req("GET", "/v1.41/containers/%s/logs?stdout=1&stderr=1" % cid)
        print("CTR-LOGS-BEGIN")
        for l in logs.decode(errors="replace").replace("\r", "").splitlines():
            print("CTR " + l)
        print("CTR-LOGS-END", flush=True)
`

// bridgeVerdicts reads the dialer's lines that start with prefix into
// label -> {verdict, address}.
func bridgeVerdicts(out, prefix string) map[string][2]string {
	m := map[string][2]string{}
	for _, l := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(l, prefix+"DIAL ")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) >= 3 {
			m[f[0]] = [2]string{f[1], f[2]}
		}
	}
	return m
}

// TestAContainerCannotReachTheLoginBridgeListener fails if, with a login flow
// pending, a container started through snug's engine or a build RUN step can
// connect to the bridge's host listener on 127.0.0.1:P or [::1]:P, or to any
// other host loopback, LAN or gateway service; if either of them is answered
// by snug's page; if snug logs a listener notice for a connection from
// either; or if a container's request, which carries the flow's right state,
// ends the human's pending login.
//
// Measured claim being kept: containers share the sandbox's network namespace
// N, whose view of host loopback pasta seals, so 127.0.0.1:P from a container
// is N's own listener (the login probe's, which never answers) and never
// snug's. That the uid gate would NOT stop a pasta-forwarded connection is
// why the seal, not the gate, is what this asserts.
//
// Controls: the host connects to 127.0.0.1:P and (where it has IPv6 loopback)
// [::1]:P before the container starts, and the opener ran; the container's own
// 127.0.0.1:P connects and gets no answer; every dialled address is read back
// from the dialer's output; egress is reached when the host has it. It does
// not cover a forward of a port into N (pasta -T), which no profile builds.
func TestAContainerCannotReachTheLoginBridgeListener(t *testing.T) {
	budget(t, 240*time.Second)
	requireLoginBridgeEnv(t)
	engEnv, _ := containerEngineEnv(t)
	requireRealEngine(t, engEnv)
	buildLoginFixtures(t)

	f := newLoginFixture(t, "hold")
	for _, e := range engEnv {
		for _, k := range []string{"XDG_RUNTIME_DIR=", "SNUG_PODMAN=", "SNUG_PODMAN_ROOT="} {
			if strings.HasPrefix(e, k) {
				f.env = append(f.env, e)
			}
		}
	}

	dialer := filepath.Join(t.TempDir(), "bridgedialprobe")
	build := exec.Command("go", "build", "-o", dialer, "./test/integration/testdata/bridgedialprobe")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building bridgedialprobe: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(f.proj, "bridgedialprobe"), mustRead(t, dialer), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.proj, "container.py"), []byte(pyPreamble+bridgeContainerScript), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.proj, "attack.sh"), []byte(`"$BROWSER" "$URL"; echo "OPEN-RC $?"
while [ ! -f go ]; do sleep 0.2; done
python3 container.py $(cat go); echo "CTR-DONE $?"
while [ ! -f done ]; do sleep 0.2; done
`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Host services the dials must not reach.
	type svc struct{ label, network, host string }
	var svcs []svc
	addSvc := func(label, network, addr string) {
		ln, err := net.Listen(network, net.JoinHostPort(addr, "0"))
		if err != nil {
			t.Logf("no %s listener on %s here, skipping %s: %v", network, addr, label, err)
			return
		}
		serveBanner(t, ln)
		svcs = append(svcs, svc{label, network, net.JoinHostPort(addr, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))})
	}
	addSvc("svc-v4", "tcp4", "127.0.0.1")
	haveV6 := loginHostHasV6(t)
	if haveV6 {
		addSvc("svc-v6", "tcp6", "::1")
	}
	lan, lanErr := hostOutboundAddr()
	if lanErr == nil {
		addSvc("svc-lan", "tcp4", lan)
	} else {
		t.Logf("no LAN address, skipping the LAN rows: %v", lanErr)
	}

	args := []string{"-p", "@podman-build", "-p", "@net", "-p", "login"}
	s := startBgSandbox(t, f.env, args, f.proj, "./loginprobe script=attack.sh")
	out := waitForLogLine(t, s, "OPEN-RC 0", 60*time.Second)
	port := loginPort(t, out)

	// Preconditions: the host reaches the bridge's listener on both families,
	// and the opener ran for this flow.
	if !loginWaitPort(t, port, true, 10*time.Second) {
		t.Fatalf("precondition: nothing holds 127.0.0.1:%d on the host:\n%s", port, s.log())
	}
	if haveV6 {
		c, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", port), 2*time.Second)
		if err != nil {
			t.Fatalf("precondition: the host cannot connect to [::1]:%d: %v", port, err)
		}
		c.Close()
	}
	if _, ran := loginRec(t, f.rec, "ran"); !ran {
		t.Fatalf("precondition: the fake opener never ran:\n%s", s.log())
	}

	type target struct{ label, network, hostport string }
	// The host's own probes above close a connection before sending a head, and
	// snug refuses those (a closed client's row shows uid 0). Count them now, so
	// the check after the container's dials is about the container's.
	time.Sleep(500 * time.Millisecond)
	noticesBefore := strings.Count(s.log(), "snug: login bridge:")

	targets := []target{{"p-v4", "tcp4", fmt.Sprintf("127.0.0.1:%d", port)}}
	if haveV6 {
		targets = append(targets, target{"p-v6", "tcp6", fmt.Sprintf("::1:%d", port)})
	}
	if lanErr == nil {
		targets = append(targets, target{"p-lan", "tcp4", fmt.Sprintf("%s:%d", lan, port)})
	}
	targets = append(targets, target{"p-gw", "tcp4", fmt.Sprintf("gw:%d", port)})
	for _, v := range svcs {
		targets = append(targets, target{v.label, v.network, strings.NewReplacer("[", "", "]", "").Replace(v.host)})
	}
	egress := false
	if os.Getenv("SNUG_TEST_NET") != "" {
		if _, err := probeInternet(); err == nil {
			targets = append(targets, target{"egress", "tcp4", internetTarget(t)})
			egress = true
		}
	}
	var words []string
	for _, tg := range targets {
		words = append(words, fmt.Sprintf("%s@%s:%s", tg.label, tg.network, tg.hostport))
	}
	handToPayload(t, f.proj, "go", strings.Join(words, " "))
	out = waitForLogLine(t, s, "CTR-DONE", 200*time.Second)

	if !strings.Contains(out, "BUILD snugtest-bridgedial:1: 200") || !strings.Contains(out, "CTR-LOGS-END") {
		t.Fatalf("control: the image did not build or the container did not run, so no dial below was made:\n%s", out)
	}
	if strings.Contains(out, hostBanner) {
		t.Errorf("a host service's banner reached the output: something connected to a host service:\n%s", out)
	}
	if n := strings.Count(out, "snug: login bridge:"); n != noticesBefore {
		t.Errorf("snug logged %d listener notice(s) during the container's dials, so a connection "+
			"reached its listener from inside:\n%s", n-noticesBefore, out)
	}

	for _, v := range []struct{ name, prefix string }{{"build RUN step", "BUILD-STEP "}, {"container", "CTR "}} {
		if !strings.Contains(out, v.prefix+"ARGS "+strconv.Itoa(len(targets))) {
			t.Errorf("%s: the dialer was not given %d targets:\n%s", v.name, len(targets), out)
			continue
		}
		got := bridgeVerdicts(out, v.prefix)
		for _, tg := range targets {
			r, ok := got[tg.label]
			if !ok {
				t.Errorf("%s: no verdict for %s:\n%s", v.name, tg.label, out)
				continue
			}
			verdict, addr := r[0], r[1]
			if tg.hostport != "" && !strings.HasPrefix(tg.hostport, "gw:") {
				want := tg.hostport
				if tg.network == "tcp6" {
					i := strings.LastIndex(want, ":")
					want = net.JoinHostPort(want[:i], want[i+1:])
				}
				if addr != want {
					t.Errorf("%s: %s dialled %s, want %s, so the verdict is about another target", v.name, tg.label, addr, want)
				}
			} else if !strings.HasSuffix(addr, fmt.Sprintf(":%d", port)) || strings.HasPrefix(addr, "127.") {
				t.Errorf("%s: %s dialled %s, want the gateway on port %d", v.name, tg.label, addr, port)
			}
			switch tg.label {
			case "p-v4":
				if verdict != "CONNECTED-SILENT" {
					t.Errorf("%s: control: the container's own 127.0.0.1:%d gave %s, want a completed "+
						"handshake and no answer (the sandbox's listener, not snug's)", v.name, port, verdict)
				}
			case "egress":
				if !strings.HasPrefix(verdict, "CONNECTED") {
					t.Errorf("%s: control: egress gave %s, so a REFUSED elsewhere may be a dead network", v.name, verdict)
				}
			case "p-gw":
				if strings.HasPrefix(verdict, "CONNECTED") {
					t.Errorf("%s: the gateway on the bridge's port answered: %s", v.name, verdict)
				}
			default:
				if verdict != "REFUSED" {
					t.Errorf("%s: %s gave %s, want REFUSED", v.name, tg.label, verdict)
				}
			}
		}
	}
	if !egress {
		t.Log("egress control skipped: SNUG_TEST_NET is unset or the host has no route")
	}

	// The flow is still pending: none of the requests, each carrying the right
	// state, was relayed or ended it.
	resp, err := loginHostRequest(t, port, loginCallbackTarget("CODE-HOST", strings.Repeat("W", 43)))
	if err != nil {
		t.Fatalf("the host's own request after the container's dials: %v\n%s", err, s.log())
	}
	if !strings.HasPrefix(resp, "HTTP/1.1 404 ") || !strings.Contains(resp, "snug is waiting for a Claude login callback") {
		t.Errorf("the host's wrong-state request got %q, want snug's 404 for a flow still waiting:\n%s",
			firstLine(resp), resp)
	}
	waitForLogLine(t, s, "The login is still pending.", 10*time.Second)
	handToPayload(t, f.proj, "done", "x")
	if code := loginWaitExit(t, s, 30*time.Second); code != 0 {
		t.Errorf("snug exited %d:\n%s", code, s.log())
	}
}
