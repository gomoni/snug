//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Shared by loginbridge_test.go, loginbridgecombos_test.go and
// loginbridgehardening_test.go: the two stand-ins, the per-test fixture, and
// the waits and readers every bridge test repeats. A helper whose answer can
// pass a test on its own (a "nothing is there" reading) says what its control
// is in its comment, or the caller does.

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

	// loginDoorProfile is one http door, for the selections that pair it with
	// the bridge.
	loginDoorProfile = "[profile.door]\ndescription = \"one http door\"\nlisten_names = [\"web\"]\n"
)

var (
	// loginKeylessArgs is the bridge's selection without the key: the baseline
	// every "the bridge added nothing else" comparison is made against.
	loginKeylessArgs = []string{"-p", "@claude", "-p", "@net"}
	loginBridgeArgs  = []string{"-p", "@claude", "-p", "@net", "-p", "login"}
)

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
	// profiles is the user profile directory XDG_CONFIG_HOME names, where
	// login.toml is and addProfile writes.
	profiles string
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
	f := &loginFixture{proj: proj, rec: rec, profiles: filepath.Join(cfg, "snug", "profiles.d")}
	if err := os.MkdirAll(f.profiles, 0o755); err != nil {
		t.Fatal(err)
	}
	f.addProfile(t, "login", "[profile.login]\n"+
		"description = \"the login bridge, for the integration suite\"\n"+
		"login = [\"claude\"]\n")
	f.env = baseEnv(append([]string{
		"XDG_CONFIG_HOME=" + cfg,
		"PATH=" + loginOpenerDir + ":" + os.Getenv("PATH"),
		"DISPLAY=:99",
		"FAKEOPENER_DIR=" + rec,
		"FAKEOPENER_MODE=" + mode,
	}, extraEnv...)...)
	return f
}

// newLoginFixtureRT is newLoginFixture with a runtime directory of the test's
// own, returned, so the run directory the test reads is this test's alone.
func newLoginFixtureRT(t *testing.T, mode string, extraEnv ...string) (*loginFixture, string) {
	t.Helper()
	rt := loginRuntimeDir(t)
	return newLoginFixture(t, mode, append([]string{"XDG_RUNTIME_DIR=" + rt}, extraEnv...)...), rt
}

func (f *loginFixture) addProfile(t *testing.T, name, toml string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.profiles, name+".toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
}

// start launches snug with the bridge on and ./loginprobe as the payload.
func (f *loginFixture) start(t *testing.T, probeArgs ...string) *bgSandbox {
	t.Helper()
	return startBgSandbox(t, f.env, loginBridgeArgs, f.proj, "./loginprobe "+strings.Join(probeArgs, " "))
}

// startWith is start with more profiles selected and a payload prelude, run by
// the same bash before ./loginprobe.
func (f *loginFixture) startWith(t *testing.T, extraProfiles []string, prelude string, probeArgs ...string) *bgSandbox {
	t.Helper()
	args := append([]string{}, loginBridgeArgs...)
	for _, p := range extraProfiles {
		args = append(args, "-p", p)
	}
	return startBgSandbox(t, f.env, args, f.proj, prelude+"\n./loginprobe "+strings.Join(probeArgs, " "))
}

// loginScript stages a shell script in the fixture's target and returns the
// probe argument that runs it.
func (f *loginFixture) loginScript(t *testing.T, body string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.proj, "attack.sh"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return "script=attack.sh"
}

// release hands the probe its release file and returns snug's exit code.
func (f *loginFixture) release(t *testing.T, s *bgSandbox) int {
	t.Helper()
	handToPayload(t, f.proj, "release", "x")
	return loginWaitExit(t, s, 20*time.Second)
}

// releaseOK is release that fails the test unless snug exits 0.
func (f *loginFixture) releaseOK(t *testing.T, s *bgSandbox) {
	t.Helper()
	if code := f.release(t, s); code != 0 {
		t.Errorf("snug exited %d:\n%s", code, s.log())
	}
}

// loginRuntimeDir is a short XDG_RUNTIME_DIR the test owns, so the run
// directory it reads is this test's alone.
func loginRuntimeDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "snug-lbrt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// requireLoginBridgeEnv gathers the gates every bridge test shares.
func requireLoginBridgeEnv(t *testing.T) {
	t.Helper()
	requireSandbox(t)
	requirePasta(t)
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

// loginCount counts the lines of out that start with prefix. It is not
// strings.Count: "DOOR-RECEIVED " contains "RECEIVED ".
func loginCount(out, prefix string) int {
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

// loginReceived is the first request the probe's listener received, unquoted,
// or "" if it received none. A RECEIVED line that is not Go-quoted fails the
// test rather than reading as an empty request.
func loginReceived(t *testing.T, out string) string {
	t.Helper()
	raw, ok := loginField(out, "RECEIVED")
	if !ok {
		return ""
	}
	got, err := strconv.Unquote(raw)
	if err != nil {
		t.Fatalf("RECEIVED line %q is not a Go-quoted string: %v", raw, err)
	}
	return got
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

// loginRec reads the fake opener's record name, or "" and false if the opener
// never wrote it.
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

// loginRunCount is how many times the fake opener ran.
func loginRunCount(t *testing.T, rec string) int {
	t.Helper()
	s, _ := loginRec(t, rec, "runs")
	return len(s)
}

// loginWaitOpenerRan polls until the fake opener has run at least once, within
// d. It reads "runs", which the opener writes after "ran", so a true answer
// means both records exist. The bridge binds the port BEFORE it starts the
// opener, so a held port does not mean the record is written yet.
func loginWaitOpenerRan(t *testing.T, rec string, d time.Duration) bool {
	t.Helper()
	for end := time.Now().Add(d); ; time.Sleep(50 * time.Millisecond) {
		if loginRunCount(t, rec) > 0 {
			return true
		}
		if time.Now().After(end) {
			return false
		}
	}
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

// requireLoginPortClosed is requireLoginRefused on 127.0.0.1:port and, where
// this host has IPv6 loopback, on [::1]:port.
func requireLoginPortClosed(t *testing.T, port int, why string) {
	t.Helper()
	requireLoginRefused(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), why)
	if loginHostHasV6(t) {
		requireLoginRefused(t, "tcp6", fmt.Sprintf("[::1]:%d", port), why)
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

// loginWaitPort polls until localhost:port accepts (held) or refuses
// (!held) on 127.0.0.1, within d.
func loginWaitPort(t *testing.T, port int, held bool, d time.Duration) bool {
	t.Helper()
	for end := time.Now().Add(d); ; time.Sleep(25 * time.Millisecond) {
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			c.Close()
		}
		if (err == nil) == held {
			return true
		}
		if time.Now().After(end) {
			return false
		}
	}
}

// requireLoginHeld is the precondition of every "the flow's port is closed
// afterwards" negative: the host connects to 127.0.0.1:port within 10 s and,
// when v6 is set, to [::1]:port.
func requireLoginHeld(t *testing.T, s *bgSandbox, port int, v6 bool) {
	t.Helper()
	if !loginWaitPort(t, port, true, 10*time.Second) {
		t.Fatalf("precondition: no flow holds localhost:%d on the host, so the refusals the test "+
			"measures would prove nothing:\n%s", port, s.log())
	}
	if v6 {
		c, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", port), 2*time.Second)
		if err != nil {
			t.Fatalf("precondition: the bridge holds 127.0.0.1:%d but not [::1]:%d: %v", port, port, err)
		}
		c.Close()
	}
}

// loginHostRequest plays the human's browser from the host: one request on
// 127.0.0.1:port with Host localhost:port, as the test's own uid, and the whole
// answer back. A refused connection is the error.
func loginHostRequest(t *testing.T, port int, target string) (string, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(25 * time.Second))
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: localhost:%d\r\nConnection: close\r\n\r\n", target, port)
	b, err := io.ReadAll(c)
	if err != nil && len(b) == 0 {
		return "", err
	}
	return string(b), nil
}

func loginCallbackTarget(code, state string) string {
	return "/callback?code=" + code + "&state=" + state
}

// loginPollUntilNone calls list every 50 ms until it returns nothing or d
// passes, and returns its last answer.
func loginPollUntilNone(d time.Duration, list func() []int) []int {
	var left []int
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if left = list(); len(left) == 0 {
			break
		}
	}
	return left
}

// loginHoldFlow starts payload, which must carry tok in its argv and run the
// probe, waits for the probe's SHIM-RC within shimWait, and returns the sandbox
// and the flow's port once host localhost:P accepts. The control it checks is
// that the token sweep finds the run while it lives.
func loginHoldFlow(t *testing.T, f *loginFixture, tok, payload string, shimWait time.Duration) (*bgSandbox, int) {
	t.Helper()
	s := startBgSandbox(t, f.env, loginBridgeArgs, f.proj, payload)
	port := loginPort(t, waitForLogLine(t, s, "SHIM-RC", shimWait))
	requireLoginHeld(t, s, port, false)
	if live := pidsWithToken(tok, s.pid()); len(live) == 0 {
		t.Fatalf("precondition: the token sweep finds no process of this run besides snug, so a "+
			"clean sweep afterwards would prove nothing:\n%s", s.log())
	}
	return s, port
}

// loginHeldFlow holds a flow open with the probe's control dial armed (the
// fake opener only records). tok is the run's token.
func loginHeldFlow(t *testing.T, f *loginFixture, tok string) (*bgSandbox, int) {
	t.Helper()
	return loginHoldFlow(t, f, tok, "./loginprobe token="+tok+" go=go release=release dial=ctl@tcp:127.0.0.1:PORT",
		15*time.Second)
}

// loginHeldFlowIn holds a flow open with the probe waiting 30 s for its
// callback, then runs payloadAfter in the same bash. It returns the run's
// token as well.
func loginHeldFlowIn(t *testing.T, f *loginFixture, payloadAfter string, probeArgs ...string) (*bgSandbox, int, string) {
	t.Helper()
	tok := orphanToken()
	args := append([]string{"token=" + tok, "release=release", "wait=30s"}, probeArgs...)
	s, port := loginHoldFlow(t, f, tok, "./loginprobe "+strings.Join(args, " ")+"\n"+payloadAfter, 20*time.Second)
	return s, port, tok
}

// loginAssertRunGone fails if, after why, localhost:port still accepts on
// either family within 5 s or a process carrying tok is alive 8 s later.
func loginAssertRunGone(t *testing.T, port int, tok string, why string) {
	t.Helper()
	if !loginWaitPort(t, port, false, 5*time.Second) {
		t.Errorf("localhost:%d still accepts connections 5s after %s", port, why)
	}
	requireLoginPortClosed(t, port, "after "+why)
	if left := loginPollUntilNone(8*time.Second, func() []int { return pidsWithToken(tok) }); len(left) != 0 {
		defer killAll(left)
		t.Errorf("%d process(es) with the run's token survived %s: %s", len(left), why, describePIDs(left))
	}
}

// loginAssertNextRunSweeps runs the bridge once more in rt and fails unless it
// exits 0 and the SIGKILLed run's directory runDir is gone afterwards.
func loginAssertNextRunSweeps(t *testing.T, rt, runDir string) {
	t.Helper()
	next := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rt)
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

// loginDry is the part of `snug --dry-run --json` these tests read.
type loginDry struct {
	Mounts []struct {
		Guest     string `json:"guest"`
		Kind      string `json:"kind"`
		Access    string `json:"access"`
		RunScoped bool   `json:"run_scoped"`
	} `json:"mounts"`
	Bwrap struct {
		Argv []string `json:"argv"`
	} `json:"bwrap"`
	Pasta struct {
		Argv []string `json:"argv"`
	} `json:"pasta"`
	BrowserBridge *struct {
		Login []string `json:"login"`
	} `json:"browser_bridge"`
}

func loginDryRun(t *testing.T, env []string, proj string, args ...string) loginDry {
	t.Helper()
	cmd := exec.Command(snugBin, append(append([]string{"--dry-run", "--json"}, args...), proj)...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("snug --dry-run --json %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	var d loginDry
	if err := json.Unmarshal(stdout.Bytes(), &d); err != nil {
		t.Fatalf("the dry-run document is not JSON (%v):\n%s", err, stdout.String())
	}
	if len(d.Bwrap.Argv) == 0 {
		t.Fatalf("the dry-run document carries no bwrap argv, so every comparison below would be "+
			"against nothing:\n%s", stdout.String())
	}
	return d
}

var (
	loginRunDirRE  = regexp.MustCompile(`run-[0-9]+`)
	loginDataFDRE  = regexp.MustCompile(`(--(?:ro-)?bind-data|--file) [0-9]+ `)
	loginProfileRE = regexp.MustCompile(`^--setenv SNUG_PROFILES (\S+)$`)
)

// loginArgvOps splits a bwrap argv into one string per operation (a flag and
// its operands, with a --perms or --size modifier kept with the operation it
// modifies) and normalises the three things that differ between two dry runs
// of the same policy: the pid in the run directory, the number of a data
// descriptor, and the profile list. The profile list is returned apart so the
// caller can say what it is.
func loginArgvOps(argv []string) (ops []string, profiles string) {
	var cur []string
	var raw []string
	flush := func() {
		if len(cur) > 0 {
			raw = append(raw, strings.Join(cur, " "))
			cur = nil
		}
	}
	for _, tok := range argv {
		if strings.HasPrefix(tok, "--") {
			flush()
		}
		cur = append(cur, tok)
	}
	flush()
	var mod string
	for _, op := range raw {
		if strings.HasPrefix(op, "--perms ") || strings.HasPrefix(op, "--size ") {
			mod += op + " "
			continue
		}
		op = mod + op
		mod = ""
		op = loginRunDirRE.ReplaceAllString(op, "run-N")
		op = loginDataFDRE.ReplaceAllString(op, "$1 <fd> ")
		if m := loginProfileRE.FindStringSubmatch(op); m != nil {
			profiles = m[1]
			op = "--setenv SNUG_PROFILES <list>"
		}
		ops = append(ops, op)
	}
	return ops, profiles
}

// loginHostLeftovers is what a finished run leaves in the places the bridge
// could add to: the entries of $XDG_RUNTIME_DIR/snug, and the per-target
// records in the uid-derived directory, with pids and hashes folded away so a
// keyed and a keyless run compare.
func loginHostLeftovers(t *testing.T, rt, proj string) string {
	t.Helper()
	var names []string
	if _, err := os.Stat(filepath.Join(rt, "snug")); err == nil {
		for _, n := range loginDirNames(t, filepath.Join(rt, "snug")) {
			names = append(names, loginRunDirRE.ReplaceAllString(n, "run-N"))
		}
	}
	for _, ext := range []string{".json", ".lock"} {
		if m, _ := filepath.Glob(targetRecordGlob(t, uidRuntimeSnugDir(t), proj, ext)); len(m) > 0 {
			names = append(names, fmt.Sprintf("%d target %s records", len(m), ext))
		}
	}
	return strings.Join(names, ",")
}

// loginKeylessBaseline runs the same shape of run without the key, to the same
// exit, and returns what it leaves. It is the definition of "nothing the bridge
// added" the keyed run is measured against.
func loginKeylessBaseline(t *testing.T, script string, wantCode int) string {
	t.Helper()
	f, rt := newLoginFixtureRT(t, "hold")
	r := runEnv(t, f.env, loginKeylessArgs, f.proj, script).mustRun(t)
	if r.code != wantCode {
		t.Fatalf("control: the keyless baseline exited %d, want %d:\n%s", r.code, wantCode, r.out)
	}
	return loginHostLeftovers(t, rt, f.proj)
}
