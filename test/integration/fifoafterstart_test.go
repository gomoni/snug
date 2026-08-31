//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestAFifoCreatedAfterTheSandboxStartsStillReachesTheHost pins issue #296's
// LIVE half for the FIFO case, the parallel of
// TestASocketCreatedAfterTheSandboxStartsStillReachesTheHost
// (socketafterstart_test.go) for #292(b).
//
// TestAFifoInAGrantedDirectoryStillReachesTheHost (fiforesidual_test.go) only
// covers a FIFO that already existed before the sandbox started — the
// coordinator's brief for this test named that gap explicitly. This test
// creates the FIFO strictly AFTER a host-observed signal that the payload is
// already running (and therefore that Validate already resolved the
// directory grant against a tree that did not yet contain this node).
//
// Default profiles only (@parent-ro), no user profile: the pipe sits under
// the target's PARENT, at the identical absolute path inside and out.
//
// Hand-rolled, like its socket counterpart: the test has to create the FIFO
// while the sandbox is alive, which needs a live handshake rather than the
// blocking run()/mustRun() helper.
func TestAFifoCreatedAfterTheSandboxStartsStillReachesTheHost(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	proj, _ := target(t)

	parent := filepath.Dir(proj)
	pipe := filepath.Join(parent, "escape-after-start.fifo")
	freshFifo := filepath.Join(parent, "payload-made-this.fifo")
	started := filepath.Join(proj, "FIFO-AFTER-START-BEGAN")

	const marker = "SNUG-296-FIFO-AFTER-START-MARKER"

	// 1. signal started (Validate already ran against a tree with no FIFO in
	//    it — the pipe below is created only once the host observes this).
	// 2. control: mkfifo of a FRESH node in the same ro directory must fail.
	// 3. poll — bounded, no fixed sleep — for the host-created FIFO.
	// 4. write the marker into it.
	script := fmt.Sprintf(`
touch %[1]s
mkfifo %[2]s 2>&1
deadline=$(( $(date +%%s) + 15 ))
while [ ! -p %[3]s ]; do
  if [ "$(date +%%s)" -ge "$deadline" ]; then
    echo "FIFO-NEVER-APPEARED"
    exit 1
  fi
  sleep 0.05
done
printf '%%s' %[4]s > %[3]s
echo WRITE-OK
`, started, freshFifo, pipe, marker)

	full := []string{"-p", "@parent-ro", proj, "--", "/bin/bash", "-c", script}
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
		t.Fatalf("the sandbox never signalled it had started: %v\n%s", err, buf.String())
	}

	// STRICTLY after the signal above.
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatalf("host: creating the fixture FIFO after the sandbox already started: %v", err)
	}

	type readResult struct {
		data []byte
		err  error
	}
	resultCh := make(chan readResult, 1)
	// open(2) on a FIFO for reading blocks until a writer opens it, so this
	// goroutine models "a host process holding the read end open", the same
	// role TestAFifoInAGrantedDirectoryStillReachesTheHost's reader plays.
	go func() {
		f, err := os.Open(pipe)
		if err != nil {
			resultCh <- readResult{err: err}
			return
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		resultCh <- readResult{data: data, err: err}
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

	if !strings.Contains(out, "Read-only file system") {
		t.Errorf("mkfifo of a FRESH node inside the read-only @parent-ro bind did not report a "+
			"read-only filesystem — the residual this test pins is bounded to SPEAKING into a "+
			"FIFO a host process already created, never manufacturing a fresh one:\n%s", out)
	}
	if !strings.Contains(out, "WRITE-OK") {
		t.Fatalf("the payload never reported writing into the FIFO (did the poll loop time out "+
			"waiting for it to appear?):\n%s", out)
	}

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("the host's read from the FIFO failed: %v\nsandbox output:\n%s", res.err, out)
		}
		if string(res.data) != marker {
			t.Fatalf("the host received %q through the FIFO, want %q — issue #296's residual is "+
				"that a FIFO created in a merely read-only-GRANTED directory AFTER the sandbox is "+
				"already running (@parent-ro alone, no user profile) still reaches a host reader:"+
				"\nsandbox output:\n%s", string(res.data), marker, out)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the host never received anything through the FIFO within 10s. If issue #296's "+
			"residual has genuinely been closed since this test was written, that is real news — "+
			"update this test (and VERIFY.md §4b, which carries the same residual for a human) "+
			"with the measurement that closed it. Do not leave this assertion unable to fail."+
			"\nsandbox output:\n%s", out)
	}
}

// TestTheFifoResidualAlsoReachesFromHostIntoTheSandbox is issue #296's other
// direction: the issue text claims the residual works "in both directions",
// and until this test only sandbox-to-host had ever been measured
// (TestAFifoInAGrantedDirectoryStillReachesTheHost). This is the same fixture
// with the roles reversed — the host writes, the sandbox reads — using the
// default profile selection alone (@parent-ro), the way its sibling does.
//
// TWO MARKERS ON THE PAYLOAD SIDE, matching the brief's requirement that a
// host-to-sandbox test must not pass on a sandbox that read nothing:
//   - mustRun's payloadMarker proves the shell itself started.
//   - "PAYLOAD-ABOUT-TO-READ", printed immediately before the blocking read,
//     proves execution reached the read attempt — so a genuine "the host's
//     write never arrived" result is distinguishable from "the payload never
//     got that far".
//   - "PAYLOAD-READ-MARKER:<bytes>" then proves it received the EXACT bytes
//     the host wrote, not merely that a read returned something.
func TestTheFifoResidualAlsoReachesFromHostIntoTheSandbox(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	proj, _ := target(t)

	parent := filepath.Dir(proj)
	pipe := filepath.Join(parent, "escape-into-sandbox.fifo")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatalf("fixture: creating the host FIFO: %v", err)
	}
	freshFifo := filepath.Join(parent, "sandbox-made-this-c.fifo")

	const marker = "SNUG-296-HOST-TO-SANDBOX-MARKER"

	writeErrCh := make(chan error, 1)
	// The host WRITER is started before the sandbox: open(2) on a FIFO for
	// writing blocks until a reader opens the read end, so this goroutine
	// models "a host process already holding it open, ready to send" — the
	// mirror of the sibling test's host READER.
	go func() {
		f, err := os.OpenFile(pipe, os.O_WRONLY, 0)
		if err != nil {
			writeErrCh <- err
			return
		}
		defer f.Close()
		_, err = f.Write([]byte(marker))
		writeErrCh <- err
	}()

	// The negative control (mkfifo of a fresh node must fail) runs FIRST, so
	// a failure there is never masked by the blocking read that follows.
	script := fmt.Sprintf(`
mkfifo %[1]s 2>&1
echo "PAYLOAD-ABOUT-TO-READ"
data=$(cat %[2]s)
echo "PAYLOAD-READ-MARKER:${data}"
`, freshFifo, pipe)

	// -p @parent-ro: the FIFO sits in the target's PARENT, which stopped being a
	// default grant in issue #550. The residual this test measures belongs to
	// the profile, not to the default selection.
	r := run(t, []string{"-p", "@parent-ro"}, proj, script).mustRun(t)

	if !strings.Contains(r.out, "Read-only file system") {
		t.Errorf("mkfifo of a FRESH node inside the read-only @parent-ro bind did not report a "+
			"read-only filesystem:\n%s", r.out)
	}
	if !strings.Contains(r.out, "PAYLOAD-ABOUT-TO-READ") {
		t.Fatalf("the payload never reported reaching the read — without this marker, \"the host "+
			"received no confirmation\" would be indistinguishable from a sandbox that never ran "+
			"far enough to try:\n%s", r.out)
	}

	select {
	case err := <-writeErrCh:
		if err != nil {
			t.Fatalf("host: writing into the FIFO: %v\nsandbox output:\n%s", err, r.out)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the host's write into the FIFO never completed within 10s — it never "+
			"rendezvoused with a reader inside the sandbox. If issue #296's host-to-sandbox half "+
			"has genuinely been closed since this test was written, that is real news — update "+
			"this test with the measurement that closed it. Do not leave this assertion unable to "+
			"fail.\nsandbox output:\n%s", r.out)
	}

	want := "PAYLOAD-READ-MARKER:" + marker
	if !strings.Contains(r.out, want) {
		t.Fatalf("the payload ran and reached the read (PAYLOAD-ABOUT-TO-READ present) but did "+
			"not report the exact bytes the host wrote through the FIFO — want substring %q, got:"+
			"\n%s", want, r.out)
	}
}
