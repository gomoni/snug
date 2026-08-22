//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestASocketCreatedAfterTheSandboxStartsStillReachesTheHost pins issue
// #292(b), the LIVE half of the directory-endpoint residual for sockets.
//
// TestABindOfADirectoryHoldingAnEndpointIsStillAccepted (endpointsource_test.go)
// pins the same gap on --dry-run alone — which is #292's own complaint about
// that earlier regression test: it never shows the socket is USABLE, and it
// never covers a socket that appears AFTER Validate. This test starts a real
// sandbox against an EMPTY granted directory, waits for Validate to have run
// against that empty tree, and only THEN has a host process create the
// socket — the exact ordering issue #292(b) measured ("profile binds an
// EMPTY directory; grant validates; three seconds into the run a host
// ssh-agent is started inside it"). Here the endpoint is a generic unix
// socket rather than ssh-agent specifically; see
// TestDirectoryBindOfALiveAgentSocketEnumeratesAndSignsWithTheDecoy
// (agentdirectory_test.go) for the ssh-agent-specific pairing (#292(a)),
// which needs its own fixture and its own two-halves assertion.
//
// Default profiles only (@parent-ro), no user profile at all — the same
// selection this residual's FIFO counterparts use, and for the same reason:
// "reachable with no user profile at all, under the shipped defaults" is what
// makes #219's ratchet damning. "Reachable through a one-line test profile" is
// one a reader can dismiss as a self-inflicted grant. Getting there needed
// shortTarget() (sandbox_test.go) instead of target(): the directory sits
// under the target's PARENT, planted empty before the sandbox starts, so
// Validate's stat sees nothing, and the socket filename on top of
// shortTarget()'s short root stays comfortably inside AF_UNIX's sun_path
// limit — see shortTarget's own doc comment for the measurement that made
// target() unusable here (nesting the socket under a target()-rooted parent
// failed with "bind: invalid argument" before this fixture moved).
//
// NOT started via run()/cli(): this test has to act on the sandbox WHILE it
// is alive (create the socket only once the payload has actually started),
// and calling t.Fatal from a background goroutine is unsupported — the same
// constraint documented on probeSandboxPort in sandbox_test.go, whose
// handshake-file idiom this test reuses (a file under the writable target,
// touched by the payload, polled for by the host).
//
// The residual is bounded, and the bound is asserted here too: the payload
// tries to CREATE a fresh socket in the very same read-only directory, which
// must be refused. Without that half, a regression that let the sandbox
// manufacture endpoints (not just speak into ones a host process already
// made) would leave this test believing the sandbox is safer than it is.
func TestASocketCreatedAfterTheSandboxStartsStillReachesTheHost(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	requirePython(t)
	proj, _ := shortTarget(t)

	parent := filepath.Dir(proj)
	liveDir := filepath.Join(parent, "live-socket")
	if err := os.Mkdir(liveDir, 0o700); err != nil {
		t.Fatalf("fixture: creating the (empty) granted directory: %v", err)
	}
	sockPath := filepath.Join(liveDir, "endpoint.sock")
	freshSock := filepath.Join(liveDir, "payload-made-this.sock")
	started := filepath.Join(proj, "SOCKET-AFTER-START-BEGAN")

	const marker = "SNUG-292B-SOCKET-AFTER-START-MARKER"

	// The payload:
	//  1. signals it has started — proving Validate already ran, against a
	//     directory that has held nothing but itself since the Mkdir above,
	//     which happened before this process existed.
	//  2. tries to CREATE a fresh socket in the same read-only-granted
	//     directory: must be refused (the bound half of this residual).
	//  3. polls — bounded, no fixed sleep, a real deadline with a named
	//     failure — for the HOST to create the real socket, which only
	//     happens after step 1's signal is observed on the host side.
	//  4. connects and sends the marker.
	script := fmt.Sprintf(`
touch %[1]s
python3 - <<'PY' 2>&1
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.bind(%[2]q)
    print("UNEXPECTED-BIND-SUCCEEDED")
except OSError as e:
    print("BIND-REFUSED:", e)
PY
deadline=$(( $(date +%%s) + 15 ))
while [ ! -S %[3]q ]; do
  if [ "$(date +%%s)" -ge "$deadline" ]; then
    echo "SOCKET-NEVER-APPEARED"
    exit 1
  fi
  sleep 0.05
done
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(%[3]q)
s.sendall(%[4]q.encode())
s.close()
print("SENT-OK")
PY
`, started, freshSock, sockPath, marker)

	full := []string{proj, "--", "/bin/bash", "-c", script}
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, snugBin, full...)
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting snug: %v", err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	if err := waitForFile(started, 10*time.Second); err != nil {
		t.Fatalf("the sandbox never signalled it had started: %v — Validate must already have "+
			"resolved the directory grant against an EMPTY tree by the time the socket below "+
			"appears, or the ordering this test exists to prove is not established:\n%s",
			err, buf.String())
	}

	// STRICTLY after the signal above: the socket exists only from this
	// point on, once the sandbox is known to be running with Validate
	// already behind it.
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("host: creating the fixture socket after the sandbox already started: %v", err)
	}
	defer ln.Close()

	type acceptResult struct {
		data []byte
		err  error
	}
	resultCh := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			resultCh <- acceptResult{err: err}
			return
		}
		defer c.Close()
		data, err := io.ReadAll(c)
		resultCh <- acceptResult{data: data, err: err}
	}()

	werr := cmd.Wait()
	waited = true
	out := buf.String()
	if errors.Is(werr, exec.ErrWaitDelay) {
		t.Fatalf("snug exited but something still holds its output pipe after %s:\n%s", waitDelay, out)
	}
	if ctx.Err() != nil {
		t.Fatalf("snug did not finish within %s:\n%s", cmdTimeout, out)
	}
	if !strings.Contains(out, "BIND-REFUSED") {
		t.Errorf("creating a FRESH socket inside the read-only-granted directory did not report "+
			"a refusal — the residual this test pins is bounded to SPEAKING into a socket a host "+
			"process already created, never manufacturing a fresh one:\n%s", out)
	}
	if strings.Contains(out, "UNEXPECTED-BIND-SUCCEEDED") {
		t.Fatalf("the sandbox created a NEW socket inside a read-only bind — that widens the "+
			"residual beyond what issue #292(b) measured:\n%s", out)
	}
	if !strings.Contains(out, "SENT-OK") {
		t.Fatalf("the payload never reported sending through the socket (did the poll loop time "+
			"out waiting for it to appear?):\n%s", out)
	}

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("the host's accept/read on the socket failed: %v\nsandbox output:\n%s",
				res.err, out)
		}
		if string(res.data) != marker {
			t.Fatalf("the host received %q through the socket, want %q — issue #292(b)'s "+
				"residual is that a socket created in a merely read-only-GRANTED directory "+
				"AFTER the sandbox is already running (@parent-ro alone, no user profile) still "+
				"reaches a payload inside:\nsandbox output:\n%s", string(res.data), marker, out)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the host never received anything through the socket within 10s. If issue "+
			"#292(b)'s residual has genuinely been closed since this test was written, that is "+
			"real news — update this test with the measurement that closed it. Do not leave this "+
			"assertion unable to fail.\nsandbox output:\n%s", out)
	}
}
