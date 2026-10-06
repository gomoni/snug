//go:build integration

package integration

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Hardening round for the login bridge: each test below turns one line of the
// bridge's review checklist into a negative that runs against the real
// binary. They share loginFixture and the loginprobe/fakeopener stand-ins
// with loginbridge_test.go; the probe's script= option runs a /bin/sh script
// as the sandbox's side of /login, so a test can do things Claude Code never
// would (compete for the FIFO, replace its path, flood it).

// loginScript stages a shell script in the fixture's target and returns the
// probe argument that runs it.
func (f *loginFixture) loginScript(t *testing.T, body string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.proj, "attack.sh"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return "script=attack.sh"
}

func loginRunCount(t *testing.T, rec string) int {
	t.Helper()
	s, _ := loginRec(t, rec, "runs")
	return len(s)
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

func loginVmRSS(t *testing.T, pid int) int64 {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(l, "VmRSS:"); ok {
			f := strings.Fields(rest)
			kb, _ := strconv.ParseInt(f[0], 10, 64)
			return kb << 10
		}
	}
	t.Fatalf("no VmRSS in /proc/%d/status", pid)
	return 0
}

// TestASecondFIFOReaderInsideCostsOnlyTheBridge fails if a sandbox process
// that opens /snug/browser.fifo for reading can hang or crash snug, leave
// the bridge unable to see a later request, or make snug open anything but
// the rebuilt URL.
//
// MEASURED, and logged by the test rather than asserted, because it is a race:
// which of two blocked readers gets a written line is the kernel's. What is
// asserted is the cost bound: after the competing reader is killed, a request
// the shim writes is seen and opened, snug exits 0, and every URL the opener
// received is the rebuilt one. It does not show the stealer gets nothing; it
// shows what it takes is the sandbox's own login attempt.
func TestASecondFIFOReaderInsideCostsOnlyTheBridge(t *testing.T) {
	budget(t, 60*time.Second)
	requireLoginBridgeEnv(t)
	f := newLoginFixture(t, "hold")
	script := f.loginScript(t, `cat /snug/browser.fifo >/dev/null 2>&1 &
R=$!
echo "STEALER-PID $R"
"$BROWSER" "$URL"; echo "W1-RC $?"
while [ ! -f go1 ]; do sleep 0.1; done
kill $R 2>/dev/null; wait $R 2>/dev/null
echo "STEALER-GONE"
"$BROWSER" "$URL"; echo "W2-RC $?"
`)
	s := f.start(t, script, "release=release")
	out := waitForLogLine(t, s, "W1-RC 0", 20*time.Second)
	if _, ok := loginField(out, "STEALER-PID"); !ok {
		t.Fatalf("control: the competing reader never started:\n%s", out)
	}
	port := loginPort(t, out)
	time.Sleep(1500 * time.Millisecond)
	_, seen := loginRec(t, f.rec, "ran")
	t.Logf("with a competing O_RDONLY reader inside, the first request was %s",
		map[bool]string{true: "SEEN by snug (opener ran)", false: "STOLEN (opener never ran)"}[seen])
	handToPayload(t, f.proj, "go1", "x")
	waitForLogLine(t, s, "W2-RC 0", 20*time.Second)

	for end := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, ran := loginRec(t, f.rec, "ran"); ran {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("after the competing reader died, snug never saw a request: the bridge is wedged:\n%s", s.log())
		}
	}
	argv, _ := loginRec(t, f.rec, "argv")
	wantURL := fmt.Sprintf(loginRebuiltFmt, port, loginChallenge, loginState)
	if want := "argc=1\nargv=" + wantURL + "\n"; argv != want {
		t.Errorf("the opener's argv was\n%q\nwant\n%q", argv, want)
	}
	if n := loginRunCount(t, f.rec); n != 1 {
		t.Errorf("the opener ran %d times for two writes inside the supersede window, want 1", n)
	}
	handToPayload(t, f.proj, "release", "x")
	if code := loginWaitExit(t, s, 20*time.Second); code != 0 {
		t.Fatalf("snug exited %d:\n%s", code, s.log())
	}
	if strings.Contains(s.log(), "panic") {
		t.Errorf("snug panicked:\n%s", s.log())
	}
}

// TestAFIFOFloodFromInsideNeitherGrowsSnugNorBlocksItsExit fails if lines
// written to /snug/browser.fifo faster than snug wants them grow snug's RSS
// by more than a small bound, stall the writer (snug stops reading), flood
// the terminal past the refusal cap, open more than one browser for a flood
// of VALID urls, or keep snug from exiting when the payload does.
//
// The garbage flood is 20 MB, far more than the 64 KiB the pipe holds, so the
// writer finishing is the control that snug read it. RSS is VmRSS of snug
// itself, before and after; it does not cover the stage, pasta or bwrap.
func TestAFIFOFloodFromInsideNeitherGrowsSnugNorBlocksItsExit(t *testing.T) {
	budget(t, 90*time.Second)
	requireLoginBridgeEnv(t)
	f := newLoginFixture(t, "hold")
	line := strings.Repeat("g", 99)
	script := f.loginScript(t, fmt.Sprintf(`command -v yes head >/dev/null || echo NO-YES-OR-HEAD
echo FLOOD-START
yes %s | head -c 20000000 > /snug/browser.fifo
echo "FLOOD-RC $?"
i=0
while [ $i -lt 300 ]; do echo "$URL"; i=$((i+1)); done > /snug/browser.fifo
echo VALID-FLOOD-DONE
`, line))
	s := f.start(t, script, "release=release")
	waitForLogLine(t, s, "FLOOD-START", 20*time.Second)
	before := loginVmRSS(t, s.pid())
	out := waitForLogLine(t, s, "VALID-FLOOD-DONE", 60*time.Second)
	if strings.Contains(out, "NO-YES-OR-HEAD") {
		t.Fatalf("control: yes or head is missing inside, so the flood was never sent:\n%s", out)
	}
	if rc, _ := loginField(out, "FLOOD-RC"); rc != "0" {
		t.Errorf("the flood's writer ended %q, want 0:\n%s", rc, out)
	}
	after := loginVmRSS(t, s.pid())
	t.Logf("snug VmRSS %d KiB before the flood, %d KiB after", before>>10, after>>10)
	if grew := after - before; grew > 24<<20 {
		t.Errorf("snug's RSS grew by %d bytes over a 20 MB flood", grew)
	}
	for end := time.Now().Add(10 * time.Second); loginRunCount(t, f.rec) == 0 && time.Now().Before(end); {
		time.Sleep(50 * time.Millisecond)
	}
	if n := loginRunCount(t, f.rec); n != 1 {
		t.Errorf("the opener ran %d times for a flood of valid URLs in one supersede window, want 1", n)
	}
	log := s.log()
	if n := strings.Count(log, "refused an open request from the sandbox"); n > 5 {
		t.Errorf("%d refusal lines on the terminal, the cap is 5:\n%.600s", n, log)
	}
	if !strings.Contains(log, "further refusals suppressed") {
		t.Errorf("no suppression line after 20 MB of refusals:\n%.600s", log)
	}
	handToPayload(t, f.proj, "release", "x")
	if code := loginWaitExit(t, s, 20*time.Second); code != 0 {
		t.Fatalf("snug exited %d after the flood:\n%s", code, s.log())
	}
}

// TestTheFIFOPathCannotBeReplacedFromInside fails if anything inside can
// remove, rename over, symlink over, re-create or shadow /snug/browser.fifo,
// so that the shim (or anything) writing that path reaches a file the
// sandbox chose instead of snug's. Every attack must fail, the FIFO's inode
// must be unchanged, and a request written afterwards must still reach snug.
//
// Controls: the same rm, mv, ln and mkfifo succeed on a scratch path in /tmp
// in the same script, so the failures below are about the FIFO's mount and
// not about a missing tool. It does not cover a write to the FIFO itself,
// which is allowed by design (anything inside may write it).
func TestTheFIFOPathCannotBeReplacedFromInside(t *testing.T) {
	budget(t, 60*time.Second)
	requireLoginBridgeEnv(t)
	f := newLoginFixture(t, "hold")
	script := f.loginScript(t, `ino() { stat -c %i /snug/browser.fifo; }
echo "INO-BEFORE $(ino)"
mkfifo /tmp/r1 && echo "CTL-MKFIFO 0" || echo "CTL-MKFIFO 1"
mv /tmp/r1 /tmp/r2 && echo "CTL-MV 0" || echo "CTL-MV 1"
ln -sf /tmp/r2 /tmp/r3 && echo "CTL-LN 0" || echo "CTL-LN 1"
rm -f /tmp/r2 /tmp/r3 && echo "CTL-RM 0" || echo "CTL-RM 1"
mkfifo /tmp/r4
n=0
for c in "rm -f /snug/browser.fifo" "rm -rf /snug/browser.fifo" "mv /snug/browser.fifo /tmp/gone" \
  "mv /tmp/r4 /snug/browser.fifo" "ln -sf /tmp/r4 /snug/browser.fifo" "ln -f /tmp/r4 /snug/browser.fifo" \
  "mkfifo /snug/browser.fifo" "mkfifo /snug/other.fifo" "touch /snug/shadow" "mkdir /snug/d" \
  "ln -s /tmp/r4 /snug/browser.fifo2" "rm -f /snug/bin/snug-browser" "mv /snug/bin /snug/bin2"; do
  n=$((n+1))
  sh -c "$c" >/dev/null 2>&1
  echo "ATTACK-$n RC $? $c"
done
echo "INO-AFTER $(ino)"
"$BROWSER" "$URL"; echo "W-RC $?"
`)
	s := f.start(t, script, "release=release")
	out := waitForLogLine(t, s, "W-RC", 20*time.Second)
	for _, c := range []string{"CTL-MKFIFO", "CTL-MV", "CTL-LN", "CTL-RM"} {
		if v, _ := loginField(out, c); v != "0" {
			t.Errorf("control: %s ended %q, so the scratch path is not a fair comparison:\n%s", c, v, out)
		}
	}
	attacks := 0
	for _, l := range strings.Split(out, "\n") {
		if !strings.HasPrefix(l, "ATTACK-") {
			continue
		}
		attacks++
		fs := strings.Fields(l)
		if len(fs) < 3 || fs[2] == "0" {
			t.Errorf("an attack on the FIFO's path succeeded: %s", l)
		}
	}
	if attacks != 13 {
		t.Errorf("saw %d attack results, want 13:\n%s", attacks, out)
	}
	before, _ := loginField(out, "INO-BEFORE")
	after, _ := loginField(out, "INO-AFTER")
	if before == "" || before != after {
		t.Errorf("the FIFO's inode is %q before and %q after the attacks", before, after)
	}
	if v, _ := loginField(out, "W-RC"); v != "0" {
		t.Errorf("the shim failed after the attacks (%q):\n%s", v, out)
	}
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, ran := loginRec(t, f.rec, "ran"); ran {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("a request written after the attacks never reached snug:\n%s", s.log())
		}
	}
	handToPayload(t, f.proj, "release", "x")
	loginWaitExit(t, s, 20*time.Second)
}

// TestSandboxChosenBytesNeverReachSnugsScreenRaw fails if a line the sandbox
// writes to the FIFO puts a raw escape, C1 control, BEL or bidi override on
// snug's own output. The lines are real printf output, so the bytes on the
// wire are the hostile ones. Control: the refusals ARE printed, so snug's
// stderr was in the log being checked. The unit tests cover the listener's
// notices; this one covers the end-to-end FIFO path only.
func TestSandboxChosenBytesNeverReachSnugsScreenRaw(t *testing.T) {
	budget(t, 60*time.Second)
	requireLoginBridgeEnv(t)
	f := newLoginFixture(t, "hold")
	script := f.loginScript(t, `P=https://claude.com/cai/oauth/authorize
{
printf '%s?\033[2J\033[31mred\n' "$P"
printf 'https://evil.example/\033]0;pwned\007\n'
printf '\342\200\256evil\n'
printf '\302\233\062J\n'
printf '\233\062J\n'
printf '%s?\033[31m=1\n' "$P"
printf '%s?code=true&%%1b=1\n' "$P"
printf 'hostile\177line\n'
} > /snug/browser.fifo
echo HOSTILE-WRITTEN
`)
	s := f.start(t, script, "release=release")
	waitForLogLine(t, s, "HOSTILE-WRITTEN", 20*time.Second)
	waitForLogLine(t, s, "refused an open request from the sandbox", 10*time.Second)
	time.Sleep(500 * time.Millisecond)
	handToPayload(t, f.proj, "release", "x")
	loginWaitExit(t, s, 20*time.Second)
	out := s.log()
	for _, bad := range []string{"\x1b", "\x9b", "\u009b", "\u202e", "\a", "\x7f", "\x00"} {
		if strings.Contains(out, bad) {
			t.Errorf("snug's output carries the raw byte(s) %q:\n%q", bad, out)
		}
	}
	if _, ran := loginRec(t, f.rec, "ran"); ran {
		t.Errorf("the opener ran for a hostile line")
	}
	if !strings.Contains(out, "byte 0x1b at offset") {
		t.Errorf("control: no refusal names the ESC byte, so the ESC line may never have been read:\n%s", out)
	}
}

// loginHeldFlow starts the probe holding a flow open (the fake opener only
// records) and waits until host localhost:P accepts. It returns the sandbox,
// the port and the run's token.
func loginHeldFlow(t *testing.T, f *loginFixture) (*bgSandbox, int, string) {
	t.Helper()
	tok := orphanToken()
	s := f.start(t, "token="+tok, "go=go", "release=release", "dial=ctl@tcp:127.0.0.1:PORT")
	out := waitForLogLine(t, s, "SHIM-RC", 15*time.Second)
	port := loginPort(t, out)
	if !loginWaitPort(t, port, true, 10*time.Second) {
		t.Fatalf("precondition: no flow holds localhost:%d on the host:\n%s", port, s.log())
	}
	if live := pidsWithToken(tok, s.pid()); len(live) == 0 {
		t.Fatalf("precondition: the token sweep finds no process of this run besides snug, so a "+
			"clean sweep afterwards would prove nothing:\n%s", s.log())
	}
	return s, port, tok
}

func loginAssertRunGone(t *testing.T, port int, tok string, why string) {
	t.Helper()
	if !loginWaitPort(t, port, false, 5*time.Second) {
		t.Errorf("localhost:%d still accepts connections 5s after %s", port, why)
	}
	requireLoginRefused(t, "tcp4", fmt.Sprintf("127.0.0.1:%d", port), "after "+why)
	if loginHostHasV6(t) {
		requireLoginRefused(t, "tcp6", fmt.Sprintf("[::1]:%d", port), "after "+why)
	}
	var left []int
	for end := time.Now().Add(8 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if left = pidsWithToken(tok); len(left) == 0 {
			break
		}
	}
	if len(left) != 0 {
		defer killAll(left)
		t.Errorf("%d process(es) with the run's token survived %s: %s", len(left), why, describePIDs(left))
	}
}

// TestSIGKILLOfThePayloadMidFlowReleasesTheHostPort fails if killing the
// sandbox's payload while a login is pending leaves snug running, localhost:P
// held on either family, or any process of the run alive. The payload is the
// process snug's command line started, killed from the host; bash execs the
// probe, so it is the probe that is killed.
//
// Control: the port is held, on the host, before the kill.
func TestSIGKILLOfThePayloadMidFlowReleasesTheHostPort(t *testing.T) {
	budget(t, 60*time.Second)
	requireLoginBridgeEnv(t)
	f := newLoginFixture(t, "hold")
	s, port, tok := loginHeldFlow(t, f)

	var payload []int
	for _, pid := range pidsWithToken(tok, s.pid()) {
		if c := commOf(pid); c == "loginprobe" {
			payload = append(payload, pid)
		}
	}
	if len(payload) != 1 {
		t.Fatalf("precondition: want exactly one payload (bash execs the probe, so its comm is loginprobe) carrying the token, found %v among %s",
			payload, describePIDs(pidsWithToken(tok, s.pid())))
	}
	if err := syscall.Kill(payload[0], syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	code := loginWaitExit(t, s, 20*time.Second)
	t.Logf("snug exited %d after SIGKILL of the payload", code)
	if code == 0 {
		t.Errorf("snug exited 0 although its payload was SIGKILLed:\n%s", s.log())
	}
	loginAssertRunGone(t, port, tok, "SIGKILL of the payload")
}

// TestSIGKILLOfTheStageMidFlowCollapsesTheRun fails if killing P1 (the
// stage) while a login is pending leaves snug running, the sandbox alive, or
// localhost:P held. The stage is found by its argv under snug's own pid.
func TestSIGKILLOfTheStageMidFlowCollapsesTheRun(t *testing.T) {
	budget(t, 60*time.Second)
	requireLoginBridgeEnv(t)
	f := newLoginFixture(t, "hold")
	s, port, tok := loginHeldFlow(t, f)

	stage, ok := findDescendant(s.pid(), isServingStage, 5*time.Second)
	if !ok {
		t.Fatalf("precondition: no serving stage under snug %d", s.pid())
	}
	if err := syscall.Kill(stage, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	code := loginWaitExit(t, s, 20*time.Second)
	t.Logf("snug exited %d after SIGKILL of the stage", code)
	loginAssertRunGone(t, port, tok, "SIGKILL of the stage")
}
