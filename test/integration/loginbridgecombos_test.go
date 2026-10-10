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
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Second hardening round for the login bridge: the bridge together with the
// other holes a selection can carry (an http door, an ssh-agent proxy, a second
// run), the dry run measured against a real run, and what a run leaves on the
// host. Fixtures are the ones loginbridge_test.go builds.

// profilesDir is the user profile directory this fixture's XDG_CONFIG_HOME
// names, the one newLoginFixture wrote login.toml into.
func (f *loginFixture) profilesDir(t *testing.T) string {
	t.Helper()
	cfg := ""
	for _, e := range f.env {
		if v, ok := strings.CutPrefix(e, "XDG_CONFIG_HOME="); ok {
			cfg = v
		}
	}
	if cfg == "" {
		t.Fatal("the fixture environment names no XDG_CONFIG_HOME")
	}
	return filepath.Join(cfg, "snug", "profiles.d")
}

func (f *loginFixture) addProfile(t *testing.T, name, toml string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.profilesDir(t), name+".toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
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

// loginRemoveOnce removes the first occurrence of want from ops, or fails.
func loginRemoveOnce(t *testing.T, ops []string, want string) []string {
	t.Helper()
	for i, op := range ops {
		if op == want {
			return append(append([]string{}, ops[:i]...), ops[i+1:]...)
		}
	}
	t.Errorf("the bridge's argv does not carry %q", want)
	return ops
}

// TestAnHTTPDoorAndTheLoginBridgeInOneSelection fails if selecting a door
// (listen_names) and login = ["claude"] together stops resolving, stops
// either from working, changes what the door grants, lets the door's socket
// carry a callback or the bridge's listener carry door traffic, or lets a host
// request that holds the sandbox's code and state do more than one relayed
// callback and an answer in snug's own words.
//
// Controls: the door answers a host request with its body while the flow is
// pending; the callback is relayed once (the probe prints it); the second one
// finds no listener.
//
// What the host request here is NOT: a browser. It is the test's own uid
// connecting to localhost:P, which is exactly what the uid gate admits; another
// uid is scripts/0036's. It reaches nothing a process inside could not do to
// its own listener, because the bytes that arrive are snug's rebuilt request,
// which the test compares whole.
func TestAnHTTPDoorAndTheLoginBridgeInOneSelection(t *testing.T) {
	budget(t, 60*time.Second)
	requireLoginBridgeEnv(t)
	rt := loginRuntimeDir(t)
	f := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rt)
	f.addProfile(t, "door", "[profile.door]\ndescription = \"one http door\"\nlisten_names = [\"web\"]\n")

	// The dry run first: the door's argv is the door's argv with or without the
	// bridge, and the bridge adds its three operations and nothing else.
	base := []string{"-p", "@claude", "-p", "@net", "-p", "door"}
	without := loginDryRun(t, f.env, f.proj, base...)
	with := loginDryRun(t, f.env, f.proj, append(append([]string{}, base...), "-p", "login")...)
	wOps, wProf := loginArgvOps(without.Bwrap.Argv)
	bOps, bProf := loginArgvOps(with.Bwrap.Argv)
	if !loginHasOp(wOps, "--perms 0755 --ro-bind-data <fd> /snug/bin/http-door-handover") {
		t.Fatalf("control: the door's handover script is not in the argv without the bridge, so "+
			"'the door is unchanged' would be about an argv with no door:\n%s", strings.Join(wOps, "\n"))
	}
	if !loginHasOp(wOps, "--setenv LISTEN_FDS 1") && !strings.Contains(strings.Join(wOps, "\n"), "LISTEN_FDS") {
		t.Fatalf("control: no LISTEN_FDS in the door's argv:\n%s", strings.Join(wOps, "\n"))
	}
	rest := bOps
	for _, add := range []string{
		"--bind " + rt + "/snug/run-N/browser.fifo /snug/browser.fifo",
		"--perms 0755 --ro-bind-data <fd> /snug/bin/snug-browser",
		"--setenv BROWSER /snug/bin/snug-browser",
	} {
		rest = loginRemoveOnce(t, rest, add)
	}
	if strings.Join(rest, "\n") != strings.Join(wOps, "\n") {
		t.Errorf("adding the bridge to a door selection changed more than the FIFO bind, the shim "+
			"and BROWSER.\nwithout the bridge:\n%s\nwith it, those three removed:\n%s",
			strings.Join(wOps, "\n"), strings.Join(rest, "\n"))
	}
	if bProf != wProf+",login" {
		t.Errorf("SNUG_PROFILES is %q with the bridge and %q without; want the same plus ,login", bProf, wProf)
	}
	if strings.Join(with.Pasta.Argv, "\n") != strings.Join(without.Pasta.Argv, "\n") {
		t.Errorf("the bridge changed pasta's argv:\nwithout: %v\nwith:    %v", without.Pasta.Argv, with.Pasta.Argv)
	}
	wm := map[string]string{}
	for _, m := range without.Mounts {
		wm[m.Guest] = m.Kind + "/" + m.Access
	}
	for _, m := range with.Mounts {
		have, ok := wm[m.Guest]
		switch {
		case !ok && (m.Guest == "/snug/bin/snug-browser" || m.Guest == "/snug/browser.fifo"):
		case !ok:
			t.Errorf("the bridge added a mount at %s (%s/%s) besides the shim and the FIFO", m.Guest, m.Kind, m.Access)
		case have != m.Kind+"/"+m.Access:
			t.Errorf("the bridge changed %s from %s to %s/%s", m.Guest, have, m.Kind, m.Access)
		}
	}

	s := f.startWith(t, []string{"door"}, "", "door=1", "release=release", "wait=30s")
	waitForLogLine(t, s, "SHIM-RC", 20*time.Second)
	out := waitForLogLine(t, s, "DOOR-READY web", 10*time.Second)
	port := loginPort(t, out)
	if !loginWaitPort(t, port, true, 10*time.Second) {
		t.Fatalf("precondition: no flow holds localhost:%d:\n%s", port, s.log())
	}

	// The door carries traffic while the flow is pending.
	sock := filepath.Join(s.runDir(rt), "door-web.sock")
	dc, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		t.Fatalf("the host cannot connect to the door %s: %v\n%s", sock, err, s.log())
	}
	doorReq := "GET /via-the-door HTTP/1.1\r\nHost: doortest\r\nConnection: close\r\n\r\n"
	io.WriteString(dc, doorReq)
	dc.SetReadDeadline(time.Now().Add(10 * time.Second))
	doorResp, _ := io.ReadAll(dc)
	dc.Close()
	if !strings.Contains(string(doorResp), "DOOR-BODY") {
		t.Fatalf("the door answered %q, not the payload's body, so the door does not work beside the bridge:\n%s",
			doorResp, s.log())
	}

	// A wrong state first: 404 from snug, nothing relayed.
	wrongState := strings.Repeat("W", 43)
	resp, err := loginHostRequest(t, port, loginCallbackTarget("CODE-A_1", wrongState))
	if err != nil || !strings.HasPrefix(resp, "HTTP/1.1 404 ") {
		t.Errorf("a callback with a state the sandbox did not choose got %q (err %v), want snug's 404", firstLine(resp), err)
	}
	if n := loginCount(s.log(), "RECEIVED "); n != 0 {
		t.Errorf("a wrong-state callback reached the sandbox's listener (%d requests)", n)
	}

	resp, err = loginHostRequest(t, port, loginCallbackTarget("CODE-A_1", loginState))
	if err != nil {
		t.Fatalf("the right callback was not served: %v\n%s", err, s.log())
	}
	if !strings.HasPrefix(resp, "HTTP/1.1 200 ") || !strings.Contains(resp, "answered HTTP 302") {
		t.Errorf("the browser's answer is not snug's page carrying the sandbox's status:\n%s", resp)
	}
	for _, bad := range []string{"Set-Cookie", "Location", "<script", "evil.example", "pwn", "DOOR-BODY"} {
		if strings.Contains(resp, bad) {
			t.Errorf("a byte of the sandbox's side reached the browser (%q):\n%s", bad, resp)
		}
	}
	// A second one: the flow ended with the first, so there is no listener, or
	// there is one and it says 404. Either way nothing more is relayed.
	if resp2, err := loginHostRequest(t, port, loginCallbackTarget("CODE-A_2", loginState)); err == nil &&
		strings.Contains(resp2, "answered HTTP") {
		t.Errorf("a second callback was relayed:\n%s", resp2)
	}
	time.Sleep(300 * time.Millisecond)

	log := s.log()
	if n := loginCount(log, "RECEIVED "); n != 1 {
		t.Errorf("the sandbox's own listener received %d requests, want exactly the one relayed:\n%s", n, log)
	}
	raw, _ := loginField(log, "RECEIVED")
	got, _ := strconv.Unquote(raw)
	want := fmt.Sprintf("GET /callback?code=CODE-A_1&state=%s HTTP/1.1\r\nHost: localhost:%d\r\nConnection: close\r\n\r\n",
		loginState, port)
	if got != want {
		t.Errorf("the listener received\n%q\nwant snug's rebuilt request\n%q", got, want)
	}
	if n := loginCount(log, "DOOR-RECEIVED "); n != 1 {
		t.Errorf("the door received %d requests, want only the one the host sent through it:\n%s", n, log)
	}
	if d, _ := loginField(log, "DOOR-RECEIVED"); strings.Contains(d, "callback") {
		t.Errorf("a callback reached the door's socket: %s", d)
	}

	handToPayload(t, f.proj, "release", "x")
	if code := loginWaitExit(t, s, 20*time.Second); code != 0 {
		t.Fatalf("snug exited %d:\n%s", code, s.log())
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("the door socket %s survived the run (stat: %v)", sock, err)
	}
	requireLoginRefused(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), "after the run")
}

func loginHasOp(ops []string, want string) bool {
	for _, op := range ops {
		if op == want {
			return true
		}
	}
	return false
}

// TestTwoRunsWithTheBridgeNeverShareAFlow fails if two concurrent snug runs
// that both carry the bridge share a FIFO or a run directory, if the second
// run's open of a host port the first holds does anything but refuse with
// the in-use reason and open nothing, if that refusal spends the second run's
// budget or blocks its later open on another port, or if a callback delivered
// to one run's port with the other run's state is relayed anywhere.
//
// Controls: each run's FIFO exists in its own run directory and is named so
// from inside; both ports are held on the host before any request is sent; the
// right state on the right port is relayed in each run afterwards.
//
// It does not cover a second run from another uid, which is the host's port
// space as one tenant sees it, and not two runs on one target (the target lock
// refuses that).
func TestTwoRunsWithTheBridgeNeverShareAFlow(t *testing.T) {
	budget(t, 90*time.Second)
	requireLoginBridgeEnv(t)
	rt := loginRuntimeDir(t)
	fA := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rt)
	fB := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rt)
	if fA.proj == fB.proj {
		t.Fatal("precondition: both runs have the same target")
	}
	stateA, stateB := loginState, strings.Repeat("Bb", 21)+"B"
	prelude := `echo "FIFO-SRC $(awk '$5 == "/snug/browser.fifo" {print $4}' /proc/self/mountinfo)"`

	a := fA.startWith(t, nil, prelude, "release=release", "wait=40s")
	outA := waitForLogLine(t, a, "SHIM-RC", 20*time.Second)
	portP := loginPort(t, outA)
	if !loginWaitPort(t, portP, true, 10*time.Second) {
		t.Fatalf("precondition: run A holds no localhost:%d:\n%s", portP, a.log())
	}

	// Run B names A's port. Its own kernel accepts that: the port is only its
	// own loopback's.
	b := fB.startWith(t, nil, prelude, "port="+strconv.Itoa(portP), "state="+stateB,
		"second=second", "release=release")
	outB := waitForLogLine(t, b, "refused an open request", 20*time.Second)
	if want := fmt.Sprintf("localhost:%d is in use on this host", portP); !strings.Contains(outB, want) {
		t.Errorf("run B's refusal does not say %q:\n%s", want, outB)
	}
	if got := loginCount(outB, "PORT "); got != 1 || loginPort(t, outB) != portP {
		t.Fatalf("control: run B's probe is not listening on A's port %d:\n%s", portP, outB)
	}
	time.Sleep(500 * time.Millisecond)
	if _, ran := loginRec(t, fB.rec, "ran"); ran {
		t.Errorf("run B's opener ran for a port the host already holds:\n%s", outB)
	}
	if n := loginRunCount(t, fA.rec); n != 1 {
		t.Errorf("run A's opener ran %d times, want 1", n)
	}
	if !loginWaitPort(t, portP, true, 2*time.Second) {
		t.Errorf("run B's refused open released run A's port %d", portP)
	}

	// B's later open, on another port, is not blocked by the refusal.
	handToPayload(t, fB.proj, "second", "x")
	outB = waitForLogLine(t, b, "SHIM2-RC 0", 20*time.Second)
	portQ, err := strconv.Atoi(func() string { v, _ := loginField(outB, "PORT2"); return v }())
	if err != nil {
		t.Fatalf("run B printed no PORT2:\n%s", outB)
	}
	if portQ == portP {
		t.Skipf("run B's kernel handed out run A's port %d twice; the cross-delivery below needs two ports", portQ)
	}
	if !loginWaitPort(t, portQ, true, 10*time.Second) {
		t.Fatalf("run B's second open did not hold localhost:%d after the first was refused:\n%s", portQ, b.log())
	}
	// Polled, not read once: the bridge binds the port BEFORE it starts the
	// opener, so the wait above can succeed while the opener's record is
	// still unwritten.
	for deadline := time.Now().Add(5 * time.Second); loginRunCount(t, fB.rec) == 0; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			break
		}
	}
	argvB, _ := loginRec(t, fB.rec, "argv")
	if !strings.Contains(argvB, fmt.Sprintf("localhost%%3A%d%%2Fcallback", portQ)) || loginRunCount(t, fB.rec) != 1 {
		t.Errorf("run B's one open did not carry its second port %d (runs=%d):\n%s", portQ, loginRunCount(t, fB.rec), argvB)
	}

	// Distinct FIFOs, distinct run directories, each named from inside.
	dirA, dirB := a.runDir(rt), b.runDir(rt)
	if dirA == dirB {
		t.Fatalf("both runs have the run directory %s", dirA)
	}
	var inodes []uint64
	for _, d := range []string{dirA, dirB} {
		fi, err := os.Stat(filepath.Join(d, "browser.fifo"))
		if err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("no FIFO at %s/browser.fifo (%v)", d, err)
		}
		inodes = append(inodes, fi.Sys().(*syscall.Stat_t).Ino)
	}
	if inodes[0] == inodes[1] {
		t.Errorf("the two runs' FIFOs are the same inode %d", inodes[0])
	}
	for _, c := range []struct {
		name string
		s    *bgSandbox
	}{{"A", a}, {"B", b}} {
		src, _ := loginField(c.s.log(), "FIFO-SRC")
		if !strings.HasSuffix(src, fmt.Sprintf("/snug/run-%d/browser.fifo", c.s.pid())) {
			t.Errorf("inside run %s, /snug/browser.fifo is bound from %q, not from its own run directory run-%d",
				c.name, src, c.s.pid())
		}
	}

	// Cross-delivery, both ways: wrong state on the right port is snug's 404.
	for _, c := range []struct {
		name  string
		port  int
		state string
	}{{"A's state to B's port", portQ, stateA}, {"B's state to A's port", portP, stateB}} {
		resp, err := loginHostRequest(t, c.port, loginCallbackTarget("CODE-X", c.state))
		if err != nil || !strings.HasPrefix(resp, "HTTP/1.1 404 ") || strings.Contains(resp, "answered HTTP") {
			t.Errorf("%s: got %q (err %v), want snug's 404 and no relay", c.name, firstLine(resp), err)
		}
	}
	for _, c := range []struct {
		name string
		s    *bgSandbox
	}{{"A", a}, {"B", b}} {
		if n := loginCount(c.s.log(), "RECEIVED "); n != 0 {
			t.Errorf("run %s's listener received %d requests from the other run's state:\n%s", c.name, n, c.s.log())
		}
	}

	// Controls: the right state on the right port is relayed, in each run.
	for _, c := range []struct {
		name  string
		s     *bgSandbox
		port  int
		state string
	}{{"A", a, portP, stateA}, {"B", b, portQ, stateB}} {
		resp, err := loginHostRequest(t, c.port, loginCallbackTarget("CODE-"+c.name, c.state))
		if err != nil || !strings.Contains(resp, "answered HTTP 302") {
			t.Errorf("control: run %s's own state on its own port was not relayed: %q (err %v)", c.name, firstLine(resp), err)
		}
		time.Sleep(300 * time.Millisecond)
		got, _ := loginField(c.s.log(), "RECEIVED")
		if !strings.Contains(got, "code=CODE-"+c.name+"&state="+c.state) {
			t.Errorf("run %s's listener received %s, want its own code and state", c.name, got)
		}
	}
	for _, c := range []struct {
		s *bgSandbox
		f *loginFixture
	}{{a, fA}, {b, fB}} {
		handToPayload(t, c.f.proj, "release", "x")
		if code := loginWaitExit(t, c.s, 20*time.Second); code != 0 {
			t.Errorf("snug exited %d:\n%s", code, c.s.log())
		}
	}
}

// TestTheLoginBridgeBesideTheSSHAgentProxy fails if selecting
// identity.ssh.agent = "proxy" next to the bridge puts the FIFO and the agent
// socket on one guest path or one run-directory entry, leaves either missing
// or of the wrong type, or stops the bridge relaying a callback.
//
// The agent is a throwaway ssh-agent with one generated key, never the
// developer's. It does not show the proxy forwards a signature (identity_test.go
// does) nor that the sandbox cannot reach the real agent socket.
func TestTheLoginBridgeBesideTheSSHAgentProxy(t *testing.T) {
	budget(t, 60*time.Second)
	requireLoginBridgeEnv(t)
	pub, agent := sshAgentAndKey(t)
	rt := loginRuntimeDir(t)
	f := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rt, "SSH_AUTH_SOCK="+agent)
	f.addProfile(t, "pinned", "[profile.pinned]\n"+
		"description = \"one throwaway key\"\n"+
		"[profile.pinned.identity.ssh]\n"+
		"agent = \"proxy\"\n"+
		"key = \""+pub+"\"\n")

	prelude := `echo "AGENT-PATH $SSH_AUTH_SOCK"
[ -S "$SSH_AUTH_SOCK" ] && echo AGENT-IS-SOCKET
[ -p /snug/browser.fifo ] && echo FIFO-IS-FIFO
echo "FIFO-SRC $(awk '$5 == "/snug/browser.fifo" {print $4}' /proc/self/mountinfo)"
echo "AGENT-SRC $(awk -v p="$SSH_AUTH_SOCK" '$5 == p {print $4}' /proc/self/mountinfo)"`
	s := f.startWith(t, []string{"pinned"}, prelude, "release=release", "wait=30s")
	out := waitForLogLine(t, s, "SHIM-RC", 20*time.Second)
	port := loginPort(t, out)
	if !loginWaitPort(t, port, true, 10*time.Second) {
		t.Fatalf("precondition: no flow holds localhost:%d:\n%s", port, s.log())
	}

	agentPath, ok := loginField(out, "AGENT-PATH")
	if !ok || agentPath == "" {
		t.Fatalf("control: no agent socket is named inside, so the proxy is not in this run:\n%s", out)
	}
	if agentPath == "/snug/browser.fifo" || agentPath == "/snug/bin/snug-browser" {
		t.Errorf("the agent socket is at the bridge's path %s", agentPath)
	}
	for _, want := range []string{"AGENT-IS-SOCKET", "FIFO-IS-FIFO"} {
		if !strings.Contains(out, want) {
			t.Errorf("inside, %s is missing:\n%s", want, out)
		}
	}
	fifoSrc, _ := loginField(out, "FIFO-SRC")
	agentSrc, _ := loginField(out, "AGENT-SRC")
	if fifoSrc == "" || agentSrc == "" || fifoSrc == agentSrc {
		t.Errorf("the FIFO and the agent socket are bound from %q and %q; want two distinct host files", fifoSrc, agentSrc)
	}

	dir := s.runDir(rt)
	names := loginDirNames(t, dir)
	var fifoIno, sockIno uint64
	var sockName string
	for _, n := range names {
		fi, err := os.Lstat(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case n == "browser.fifo" && fi.Mode()&os.ModeNamedPipe != 0:
			fifoIno = fi.Sys().(*syscall.Stat_t).Ino
		case fi.Mode()&os.ModeSocket != 0 && strings.Contains(n, "agent"):
			sockName, sockIno = n, fi.Sys().(*syscall.Stat_t).Ino
		}
	}
	if fifoIno == 0 || sockIno == 0 || fifoIno == sockIno {
		t.Errorf("the run directory %s holds %v: want a FIFO browser.fifo and an agent socket as different files", dir, names)
	}
	if sockName != "" && !strings.HasSuffix(agentSrc, "/"+sockName) {
		t.Errorf("inside, the agent socket is bound from %q, not from the run directory's %s", agentSrc, sockName)
	}

	resp, err := loginHostRequest(t, port, loginCallbackTarget("CODE-S_1", loginState))
	if err != nil || !strings.Contains(resp, "answered HTTP 302") {
		t.Errorf("with the agent proxy selected the callback was not relayed: %q (err %v)", firstLine(resp), err)
	}
	handToPayload(t, f.proj, "release", "x")
	if code := loginWaitExit(t, s, 20*time.Second); code != 0 {
		t.Fatalf("snug exited %d:\n%s", code, s.log())
	}
}

// loginMountpoints parses the mount points out of "MP <path>" lines.
func loginMountpoints(out string) []string {
	var mps []string
	for _, l := range strings.Split(out, "\n") {
		if p, ok := strings.CutPrefix(l, "MP "); ok {
			mps = append(mps, strings.TrimSpace(p))
		}
	}
	return mps
}

// loginDryDests reads the destinations of the mounts a dry-run bwrap argv
// requests. required are those bwrap fails on when missing; allowed adds the
// -try spellings, which may legitimately be absent.
func loginDryDests(ops []string) (required, allowed []string) {
	for _, op := range ops {
		f := strings.Fields(op)
		for len(f) > 0 && (f[0] == "--perms" || f[0] == "--size") {
			f = f[2:]
		}
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "--bind", "--ro-bind", "--dev-bind", "--ro-bind-data", "--bind-data":
			required = append(required, f[len(f)-1])
		case "--bind-try", "--ro-bind-try", "--dev-bind-try":
			allowed = append(allowed, f[len(f)-1])
		case "--tmpfs", "--proc", "--dev", "--mqueue":
			required = append(required, f[1])
		}
	}
	return required, append(allowed, required...)
}

// TestDryRunNamesTheMountsAndEnvironmentARealRunHas fails if, for a selection
// with the bridge (and for one with a door too), the mounts a real run has
// differ from the mounts --dry-run --json lists in its bwrap argv: a mount the
// run has and the screen does not (a hidden hole), or one the screen lists and
// the run lacks (a promise not kept). It also compares the bridge's three
// entries one by one: the FIFO's source in the run directory, the shim, and
// BROWSER inside.
//
// Not covered: bwrap's own argv of a real run. snug hands it over through a
// memfd that is closed before the payload starts, on purpose (exec.go), so
// there is nothing to read back, and this compares what the argv produced.
// A mount under a recursively bound parent (a submount of /usr) is allowed by
// the parent's entry and so is not compared one by one, and a --dir, --symlink
// or --file is not a mount and is not compared.
func TestDryRunNamesTheMountsAndEnvironmentARealRunHas(t *testing.T) {
	budget(t, 60*time.Second)
	requireLoginBridgeEnv(t)
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"claude net login", []string{"-p", "@claude", "-p", "@net", "-p", "login"}},
		{"claude net login door", []string{"-p", "@claude", "-p", "@net", "-p", "login", "-p", "door"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := loginRuntimeDir(t)
			f := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rt)
			f.addProfile(t, "door", "[profile.door]\ndescription = \"one http door\"\nlisten_names = [\"web\"]\n")

			dry := loginDryRun(t, f.env, f.proj, tc.args...)
			ops, _ := loginArgvOps(dry.Bwrap.Argv)
			required, allowed := loginDryDests(ops)
			if len(required) < 10 {
				t.Fatalf("control: the dry run lists %d mounts, so the comparison below is about almost nothing: %v", len(required), required)
			}

			r := runEnv(t, f.env, tc.args, f.proj, `awk '{print "MP " $5}' /proc/self/mountinfo
awk '$5 == "/snug/browser.fifo" {print "FIFO-SRC " $4}' /proc/self/mountinfo
awk '$5 == "/snug/bin/snug-browser" {print "SHIM-MOUNT " $6}' /proc/self/mountinfo
echo "BROWSER-IS $BROWSER"
`).mustRun(t)
			real := loginMountpoints(r.out)
			if len(real) < 10 {
				t.Fatalf("control: the real run lists %d mount points:\n%s", len(real), r.out)
			}
			have := map[string]bool{}
			for _, m := range real {
				have[m] = true
			}
			for _, d := range required {
				if !have[d] {
					t.Errorf("--dry-run lists a mount at %s that the real run does not have", d)
				}
			}
			for _, m := range real {
				if m == "/" || strings.HasPrefix(m, "/dev/") {
					continue
				}
				covered := false
				for _, d := range allowed {
					if m == d || strings.HasPrefix(m, strings.TrimSuffix(d, "/")+"/") {
						covered = true
						break
					}
				}
				if !covered {
					t.Errorf("the real run has a mount at %s that no entry of --dry-run's argv accounts for", m)
				}
			}

			fifoWant := "--bind " + rt + "/snug/run-N/browser.fifo /snug/browser.fifo"
			if !loginHasOp(ops, fifoWant) {
				t.Errorf("--dry-run's argv lacks %q", fifoWant)
			}
			src, _ := loginField(r.out, "FIFO-SRC")
			if !strings.HasSuffix(loginRunDirRE.ReplaceAllString(src, "run-N"), "/snug/run-N/browser.fifo") {
				t.Errorf("inside, the FIFO is bound from %q, not from a run directory's browser.fifo", src)
			}
			if opts, _ := loginField(r.out, "SHIM-MOUNT"); !strings.HasPrefix(opts, "ro,") {
				t.Errorf("inside, the shim mount options are %q, want read-only as --dry-run says", opts)
			}
			if !loginHasOp(ops, "--perms 0755 --ro-bind-data <fd> /snug/bin/snug-browser") {
				t.Errorf("--dry-run's argv lacks the shim's read-only data mount")
			}
			if v, _ := loginField(r.out, "BROWSER-IS"); v != "/snug/bin/snug-browser" {
				t.Errorf("BROWSER inside is %q", v)
			}
			if !loginHasOp(ops, "--setenv BROWSER /snug/bin/snug-browser") {
				t.Errorf("--dry-run's argv lacks BROWSER")
			}
			if dry.BrowserBridge == nil || !reflect.DeepEqual(dry.BrowserBridge.Login, []string{"claude"}) {
				t.Errorf("--dry-run --json has no browser_bridge row for a selection that has the bridge: %+v", dry.BrowserBridge)
			}
		})
	}
}

// TestTheBridgeRowsAppearExactlyWhenTheKeyIsOn fails if the built binary's
// --dry-run (human and JSON) or --explain mentions the bridge for a selection
// without the key, or omits it for one with. internal/cli's
// TestBrowserBridgeRowsAreAbsentWhenTheKeyIsOff and the golden screens pin the
// same through the renderers; this goes through the binary and its flag
// parsing.
func TestTheBridgeRowsAppearExactlyWhenTheKeyIsOn(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	f := newLoginFixture(t, "hold")
	off := []string{"-p", "@claude", "-p", "@net"}
	on := append(append([]string{}, off...), "-p", "login")
	for _, c := range []struct {
		flag string
		key  string
	}{
		{"--dry-run", `browser bridge  login = ["claude"]`},
		{"--dry-run", "login opener"},
		{"--dry-run", "/snug/browser.fifo"},
		{"--explain", "Login bridge"},
		{"--explain", "except the xdg-open snug starts"},
	} {
		for _, sel := range []struct {
			args []string
			want bool
		}{{on, true}, {off, false}} {
			out, code := cli(t, f.env, append(append([]string{c.flag}, sel.args...), f.proj)...)
			if code != 0 {
				t.Fatalf("snug %s %v exited %d:\n%s", c.flag, sel.args, code, out)
			}
			if got := strings.Contains(out, c.key); got != sel.want {
				t.Errorf("snug %s %s: mentions %q = %v, want %v", c.flag, strings.Join(sel.args, " "), c.key, got, sel.want)
			}
		}
	}
	if d := loginDryRun(t, f.env, f.proj, on...); d.BrowserBridge == nil {
		t.Error("--dry-run --json with the key on has no browser_bridge")
	}
	if d := loginDryRun(t, f.env, f.proj, off...); d.BrowserBridge != nil {
		t.Errorf("--dry-run --json with the key off has browser_bridge %+v", d.BrowserBridge)
	}
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
	rt := loginRuntimeDir(t)
	f := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rt)
	r := runEnv(t, f.env, []string{"-p", "@claude", "-p", "@net"}, f.proj, script).mustRun(t)
	if r.code != wantCode {
		t.Fatalf("control: the keyless baseline exited %d, want %d:\n%s", r.code, wantCode, r.out)
	}
	return loginHostLeftovers(t, rt, f.proj)
}

func loginPIDAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// loginHeldFlowIn starts the probe in f's run, waits for the flow to hold the
// host port and returns what the exit checks need. The probe's argv carries a
// token the host can search for; the control is that the search finds the run
// while it lives.
func loginHeldFlowIn(t *testing.T, f *loginFixture, payloadAfter string, probeArgs ...string) (*bgSandbox, int, string) {
	t.Helper()
	tok := orphanToken()
	args := append([]string{"token=" + tok, "release=release", "wait=30s"}, probeArgs...)
	s := startBgSandbox(t, f.env, loginBridgeArgs, f.proj, "./loginprobe "+strings.Join(args, " ")+"\n"+payloadAfter)
	out := waitForLogLine(t, s, "SHIM-RC", 20*time.Second)
	port := loginPort(t, out)
	if !loginWaitPort(t, port, true, 10*time.Second) {
		t.Fatalf("precondition: no flow holds localhost:%d:\n%s", port, s.log())
	}
	if live := pidsWithToken(tok, s.pid()); len(live) == 0 {
		t.Fatalf("precondition: the token sweep finds no process of this run besides snug, so a clean "+
			"sweep afterwards would prove nothing:\n%s", s.log())
	}
	return s, port, tok
}

// TestAfterANormalExitTheHostHoldsNothingOfTheRun fails if a run that exits
// normally with the bridge leaves a listener on the flow's port (either
// family), a process carrying the run's token, anything in the runtime
// directory a keyless run does not leave, or a pending-login opener that snug
// killed or pinned.
//
// Two shapes, both exit 0: a flow completed by a callback, and a flow still
// pending when the payload exits with the opener still running (a browser
// started by xdg-open and left open). The second is the case teardown has to
// close by itself.
//
// The lingering opener is the control that the fake was really detached: it
// is still alive when snug has exited, and it ends by itself. That snug leaves
// a real browser running is the design (opener.go: Setsid, no Pdeathsig). Not
// covered: an opener still running after OpenerPatience (30 s), which this
// would take longer than the test budget to wait for.
func TestAfterANormalExitTheHostHoldsNothingOfTheRun(t *testing.T) {
	budget(t, 60*time.Second)
	requireLoginBridgeEnv(t)
	baseline := loginKeylessBaseline(t, "true", 0)

	t.Run("completed flow", func(t *testing.T) {
		rt := loginRuntimeDir(t)
		f := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rt)
		s, port, tok := loginHeldFlowIn(t, f, "")
		resp, err := loginHostRequest(t, port, loginCallbackTarget("CODE-E_1", loginState))
		if err != nil || !strings.Contains(resp, "answered HTTP 302") {
			t.Fatalf("control: the callback was not relayed: %q (%v)\n%s", firstLine(resp), err, s.log())
		}
		handToPayload(t, f.proj, "release", "x")
		if code := loginWaitExit(t, s, 20*time.Second); code != 0 {
			t.Fatalf("snug exited %d:\n%s", code, s.log())
		}
		loginAssertRunGone(t, port, tok, "a normal exit")
		if got := loginHostLeftovers(t, rt, f.proj); got != baseline {
			t.Errorf("a normal exit with the bridge leaves %q, the keyless run leaves %q", got, baseline)
		}
	})

	t.Run("pending flow and a lingering opener", func(t *testing.T) {
		rt := loginRuntimeDir(t)
		f := newLoginFixture(t, "linger", "XDG_RUNTIME_DIR="+rt, "FAKEOPENER_LINGER=8s")
		s, port, tok := loginHeldFlowIn(t, f, "", "serve=0")
		if _, ok := loginRec(t, f.rec, "pid"); !ok {
			for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
				if _, ok = loginRec(t, f.rec, "pid"); ok {
					break
				}
			}
		}
		raw, ok := loginRec(t, f.rec, "pid")
		if !ok {
			t.Fatalf("control: the fake opener never recorded its pid:\n%s", s.log())
		}
		opener, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || !loginPIDAlive(opener) {
			t.Fatalf("control: the fake opener %q is not alive while the flow is pending (%v)", raw, err)
		}
		handToPayload(t, f.proj, "release", "x")
		if code := loginWaitExit(t, s, 20*time.Second); code != 0 {
			t.Fatalf("snug exited %d:\n%s", code, s.log())
		}
		stillThere := loginPIDAlive(opener)
		t.Logf("after snug exited, the lingering opener (pid %d) is %s", opener,
			map[bool]string{true: "still running (detached, as designed)", false: "gone"}[stillThere])
		loginAssertRunGone(t, port, tok, "a normal exit with a pending flow")
		if got := loginHostLeftovers(t, rt, f.proj); got != baseline {
			t.Errorf("a normal exit with a pending flow leaves %q, the keyless run leaves %q", got, baseline)
		}
		if !stillThere {
			t.Errorf("the fake opener ended before snug did, so the detachment this test controls for " +
				"was not exercised; raise FAKEOPENER_LINGER")
		}
		for end := time.Now().Add(15 * time.Second); loginPIDAlive(opener); time.Sleep(100 * time.Millisecond) {
			if time.Now().After(end) {
				syscall.Kill(opener, syscall.SIGKILL)
				t.Fatalf("the fake opener %d is still running 15 s after snug exited though it was to end itself in 8 s", opener)
			}
		}
	})
}

// TestAfterAPayloadCrashTheHostHoldsNothingOfTheRun fails if a payload that
// exits non-zero, or dies of SIGSEGV, while a login is pending leaves the
// flow's port held on either family, a process carrying the run's token, or
// anything in the runtime directory a keyless run with the same exit does not
// leave. snug must also pass the payload's status on.
//
// SIGKILL of the payload is TestSIGKILLOfThePayloadMidFlowReleasesTheHostPort;
// this is the exits it does not reach.
func TestAfterAPayloadCrashTheHostHoldsNothingOfTheRun(t *testing.T) {
	budget(t, 90*time.Second)
	requireLoginBridgeEnv(t)
	for _, tc := range []struct {
		name   string
		tail   string
		want   int
		anyBad bool
	}{
		{"exit 7", "exit 7", 7, false},
		{"SIGSEGV", "kill -SEGV $$", 139, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseline := loginKeylessBaseline(t, tc.tail, tc.want)
			rt := loginRuntimeDir(t)
			f := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rt)
			s, port, tok := loginHeldFlowIn(t, f, tc.tail, "serve=0")
			handToPayload(t, f.proj, "release", "x")
			code := loginWaitExit(t, s, 20*time.Second)
			if code != tc.want {
				t.Errorf("snug exited %d for a payload that did %q, want %d:\n%s", code, tc.tail, tc.want, s.log())
			}
			loginAssertRunGone(t, port, tok, "a payload crash ("+tc.name+")")
			if got := loginHostLeftovers(t, rt, f.proj); got != baseline {
				t.Errorf("a crash (%s) with the bridge leaves %q, the keyless run leaves %q", tc.name, got, baseline)
			}
		})
	}
}

// loginProcsInNetns returns the pids of this user's processes whose network
// namespace is the one ino names, read from /proc/<pid>/ns/net.
func loginProcsInNetns(ino string) []int {
	var out []int
	es, _ := os.ReadDir("/proc")
	for _, e := range es {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if l, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid)); err == nil && l == ino {
			out = append(out, pid)
		}
	}
	return out
}

// TestAfterSIGKILLOfSnugNoHelperOrNamespaceOfTheRunSurvives fails if SIGKILL of
// snug while a login is pending leaves a pasta of this run, a process in the
// run's network namespace, a process carrying the run's token, the flow's port
// held, or a run directory the next run does not sweep.
//
// Controls: before the kill, a new pasta exists, and at least one process other
// than snug is in the namespace the payload reported. The namespace is named by
// the payload's /proc/<pid>/ns/net; "survives" means a process still
// holds it, since a network namespace nothing holds is gone. It does not
// enumerate namespaces nothing is in, which a process-level view cannot see.
// TestTheLoginBridgeDiesWithSnug covers the run directory against the keyless
// baseline and the token sweep; this adds pasta and the namespace.
func TestAfterSIGKILLOfSnugNoHelperOrNamespaceOfTheRunSurvives(t *testing.T) {
	budget(t, 60*time.Second)
	requireLoginBridgeEnv(t)
	rt := loginRuntimeDir(t)
	f := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rt)
	pastaBefore := pastaPIDs()

	s, port, tok := loginHeldFlowIn(t, f, "", "serve=0")
	pastaDuring := newPIDs(pastaBefore, pastaPIDs())
	if len(pastaDuring) == 0 {
		t.Fatalf("precondition: no new pasta while the run is up, so 'no pasta afterwards' proves nothing:\n%s", s.log())
	}
	var ino string
	for _, pid := range pidsWithToken(tok, s.pid()) {
		if commOf(pid) != "loginprobe" {
			continue
		}
		ino, _ = os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	}
	own, _ := os.Readlink("/proc/self/ns/net")
	if ino == "" || ino == own {
		t.Fatalf("precondition: could not name the payload's own network namespace (got %q, ours %q)", ino, own)
	}
	if n := len(loginProcsInNetns(ino)); n == 0 {
		t.Fatalf("precondition: nothing is in namespace %s while the run is up", ino)
	}

	if err := s.proc.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	s.proc.wait()

	loginAssertRunGone(t, port, tok, "SIGKILL of snug")
	var left []int
	for end := time.Now().Add(8 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		left = nil
		for _, p := range pastaDuring {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", p)); err == nil {
				left = append(left, p)
			}
		}
		if len(left) == 0 {
			break
		}
	}
	if len(left) != 0 {
		defer killAll(left)
		t.Errorf("pasta of the run survived SIGKILL of snug: %s", describePIDs(left))
	}
	var inNS []int
	for end := time.Now().Add(8 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if inNS = loginProcsInNetns(ino); len(inNS) == 0 {
			break
		}
	}
	if len(inNS) != 0 {
		defer killAll(inNS)
		t.Errorf("%d process(es) still hold the run's network namespace %s: %s", len(inNS), ino, describePIDs(inNS))
	}

	// Control for loginHostLeftovers, whose clean answers elsewhere in this file
	// are empty strings: after a SIGKILL it sees the corpse's run directory.
	if got := loginHostLeftovers(t, rt, f.proj); !strings.Contains(got, "run-N") {
		t.Errorf("control: loginHostLeftovers sees %q after a SIGKILL, so its empty answers after a "+
			"normal exit prove nothing", got)
	}

	next := newLoginFixture(t, "hold", "XDG_RUNTIME_DIR="+rt)
	r := runEnv(t, next.env, loginBridgeArgs, next.proj, "true").mustRun(t)
	if r.code != 0 {
		t.Fatalf("the follow-up run failed (%d):\n%s", r.code, r.out)
	}
	if _, err := os.Stat(s.runDir(rt)); !os.IsNotExist(err) {
		t.Errorf("the SIGKILLed run's directory %s survived the next run (stat: %v)", s.runDir(rt), err)
	}
}
