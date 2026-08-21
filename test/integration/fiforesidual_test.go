//go:build integration

package integration

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestAFifoInAGrantedDirectoryStillReachesTheHost is issue #287's residual,
// asserted POSITIVELY rather than left to prose.
//
// rejectEndpointSource (internal/policy/validate.go) refuses a grant that
// NAMES a socket or a FIFO directly, but its own doc comment says exactly what
// it does not cover: a stat at resolve time sees only endpoints that exist
// THEN, so a grant of a DIRECTORY is still a grant of every FIFO anyone puts
// in it afterwards — and that is precisely #287's own headline measurement,
// through @parent-ro alone, with NO user profile at all. This test is the
// honest counterpart to internal/policy's TestBindOfAnEndpointSourceIsRefused
// (T1): that one proves the NAMED case is refused; this one proves the
// UNNAMED case still leaks, using nothing but the DEFAULT profile selection.
//
// It must fail the day someone believes #287 is fully closed. If a future
// change makes the write below refused or unreachable, that is real news —
// come here, read why, and update this test (and VERIFY.md §4b, which carries
// the same residual for a human) rather than leaving an assertion that quietly
// stopped being able to fail.
//
// TWO MARKERS, ONE PER HALF OF THE CLAIM:
//   - payloadMarker (via run().mustRun) proves the SANDBOX actually started —
//     "the host received nothing" is trivially true of a sandbox that never ran.
//   - a distinct, single-use FIFO marker string proves the HOST actually
//     received the SANDBOX's bytes specifically, through the FIFO, rather than
//     the assertion passing because a channel timed out into a zero value that
//     happens to equal "" or because some other write coincidentally matched.
//
// AND THE POSITIVE CONTROL FOR THE COUNTERPART CLAIM: the same script also
// attempts `mkfifo` inside the SAME read-only bind, and that attempt MUST fail
// with a read-only-filesystem error — measured on this host:
//
//	mkfifo: cannot create fifo '<path>': Read-only file system
//
// which is what bounds the residual to "speak into a FIFO a host process
// already created and is holding open" rather than "manufacture a fresh
// endpoint anywhere read-only reaches". Without this half, a regression that
// silently widened `ro` to permit creating new endpoints would leave this
// test believing the sandbox is safer than it is.
func TestAFifoInAGrantedDirectoryStillReachesTheHost(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	proj, _ := target(t)

	// @parent-ro grants the target's PARENT read-only, identity-mapped (no
	// guest remap — internal/profile/profiles/base.toml, [profile.parent-ro]:
	// `ro = ["{target_parent}"]`), so a FIFO planted here is visible inside the
	// sandbox at this exact same absolute path. No profile of any kind is
	// selected beyond the default set — this is the plain, unmodified `snug
	// <dir>` a human runs every day.
	parent := filepath.Dir(proj)
	pipe := filepath.Join(parent, "escape.fifo")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatalf("fixture: creating the host FIFO: %v", err)
	}

	const marker = "SNUG-287-FIFO-RESIDUAL-MARKER"

	type readResult struct {
		data []byte
		err  error
	}
	resultCh := make(chan readResult, 1)
	// The host reader is started BEFORE the sandbox, and open(2) on a FIFO
	// blocks until BOTH ends are present — this goroutine is the "host process
	// already holding it open" half of the residual's own bound, not a race
	// against the payload.
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

	// The negative control (mkfifo inside the read-only bind must fail) runs
	// FIRST in the same script, before the write that would otherwise block
	// the payload until the host reader rendezvous — so a failure in the
	// control is never masked by the write simply not having happened yet.
	script := fmt.Sprintf(
		"mkfifo %s 2>&1\n"+
			"printf '%%s' %s > %s\n",
		filepath.Join(parent, "newfifo"), marker, pipe)

	r := run(t, nil, proj, script).mustRun(t)

	if !strings.Contains(r.out, "Read-only file system") {
		t.Errorf("mkfifo inside the read-only @parent-ro bind did not report a read-only "+
			"filesystem — the residual measured by issue #287 is bounded to SPEAKING into an "+
			"endpoint a host process already created, never manufacturing a fresh one, and this "+
			"is the assertion for that bound:\n%s", r.out)
	}

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("the host's read from the FIFO failed: %v\nsandbox output:\n%s", res.err, r.out)
		}
		if string(res.data) != marker {
			t.Fatalf("the host received %q through the FIFO, want %q — issue #287's residual is "+
				"that a payload can write into a FIFO planted inside a merely read-only-GRANTED "+
				"directory (@parent-ro alone, no user profile) and a host process on the other "+
				"end receives the bytes:\nsandbox output:\n%s", string(res.data), marker, r.out)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("the host never received anything through the FIFO within 20s. If issue #287's "+
			"residual has genuinely been closed since this test was written, that is real news — "+
			"update this test AND VERIFY.md §4b together, with the measurement that closed it. Do "+
			"not leave this assertion unable to fail.\nsandbox output:\n%s", r.out)
	}
}
