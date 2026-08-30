package stage

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// TestTheStageReadsNoRequestAfterStart pins the one-shot property review §1
// argues for and proto.go's own header states: the stage serves AT MOST TWO
// requests — one optional "netready", one "start" — and "start" is TERMINAL.
// The number of REQUESTS is what one-shot means; there is no third request
// and no way back, and the loop is not re-entered once a sandbox exists.
//
// A test that a SECOND "start" is specifically refused would pin one shape of
// the property. This pins the general one: after "enginestarted" arrives and
// while the real payload is still very much alive, this test queues a SECOND,
// entirely well-formed request on the same control socket and never expects
// an answer to it. The queued bytes are never read by the stage at all — they
// are still sitting, unconsumed, in the kernel's own socket buffer on the
// stage's end when that end closes at process exit, and the kernel discards
// them then. There is no way to read them back afterwards (a connected
// AF_UNIX socket does not hand queued-but-unread bytes back to the sender),
// so what this test asserts instead is the one thing an actually-consumed
// request could not fail to produce: the real payload's own "exited" event,
// received CLEANLY as the very next thing on the wire, with nothing else
// ahead of or instead of it.
//
// The injected request is chosen to make "consumed" loud rather than silent,
// on purpose (CLAUDE.md: "a test that cannot fail is worse than no test"): a
// second "start" naming a bwrap path that cannot possibly exist. If the loop
// were ever re-entered while this is queued, runOneSandbox would attempt it,
// fail at cmd.Start() (ENOENT) near-instantly, and emit a SECOND
// "enginestarted{Err: ...}" event — which st.Wait()'s single recvEvent call
// below would then see INSTEAD of, or interleaved with, the real "exited",
// and report as a mismatched-event error. A silent no-op could never produce
// that.
func TestTheStageReadsNoRequestAfterStart(t *testing.T) {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bubblewrap is not installed")
	}

	infoR, infoW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer infoR.Close()

	st, err := Start(Config{
		Topology: policy.Topology{Netns: policy.NetnsStage, Subuid: policy.SubuidNone},
		// The one sandbox descriptor this run needs: the WRITE end of the
		// --info-fd pipe, handed to bwrap itself. Its read end (infoR, above)
		// is Config.BwrapInfo — the stage's own copy, per issue #125's move of
		// that read out of P0 (fds.go's fdBwrapInfo).
		Sandbox:   []*os.File{infoW},
		BwrapInfo: infoR,
		Stdin:     devNullFile(t), Stdout: devNullFile(t), Stderr: devNullFile(t),
	})
	if err != nil {
		if isUnprivilegedUsernsRefusal(err) {
			t.Skipf("this host refuses unprivileged user namespaces: %v", err)
		}
		t.Fatalf("Start: %v", err)
	}
	defer st.Close()
	// Start's own fork dup3's every Sandbox descriptor into P1; this
	// process's copy is no longer needed, exactly as internal/sandbox.Run's
	// own `extra` slice is closed once Start has taken ownership of it.
	infoW.Close()

	// An ordinary, ungated, minimal real sandbox — the same probe recipe
	// requireSandbox (test/integration/sandbox_test.go) uses to prove a host
	// can create a user namespace at all, plus --info-fd 3 (the ONE Sandbox
	// descriptor above, renumbered to bwrap's own fd 3) and a payload with
	// enough runtime (sleep 1) to still be alive when the injection below
	// happens.
	argv := []string{
		"--unshare-all",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--proc", "/proc", "--dev", "/dev",
		"--die-with-parent",
		"--info-fd", "3",
		"--", "/bin/sleep", "1",
	}
	// "start" refuses until a successful "netready" has been asked
	// (serve.go's own enforcement, restated here rather than skipped: the
	// property this test is about is layered on TOP of that one, not a
	// replacement for it). "lo" is what an offline run with no pasta attached
	// waits for — already up inside N before the stage ever left it.
	if err := st.WaitNetReady(5*time.Second, "lo"); err != nil {
		t.Fatalf("PRECONDITION: netready failed: %v", err)
	}

	if _, err := st.StartSandbox(bwrapPath, argv, nil, false); err != nil {
		t.Fatalf("PRECONDITION: an ordinary \"start\" failed, so nothing below is testing what "+
			"it claims to: %v", err)
	}

	// THE INJECTION. Sent directly on st.control (this file is `package
	// stage`, so the unexported field is reachable) — StartSandbox's own
	// public API has no way to express "send a request and do not wait for an
	// answer", which is exactly the point: nothing a legitimate caller can do
	// reaches this. What it stands in for is a P0 that has been confused or
	// taken over — the one client this channel has — not a second client, of
	// which there is none and never will be (SUPERVISOR-DESIGN.md §3.3).
	if err := sendRequest(st.control, request{
		Op: "start", Bwrap: "/definitely/not/a/real/bwrap-binary", Passthrough: 0,
	}); err != nil {
		t.Fatalf("writing the injected request: %v", err)
	}

	// The real payload's own, and ONLY, "exited" event — read with a bound so
	// a regression that HANGS (rather than misbehaves) still fails this test
	// instead of the whole package.
	type waitResult struct {
		exited bool
		status int
		err    error
	}
	done := make(chan waitResult, 1)
	go func() {
		ws, err := st.Wait()
		if err != nil {
			done <- waitResult{err: err}
			return
		}
		done <- waitResult{exited: ws.Exited(), status: ws.ExitStatus()}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("the stage did not report the real payload's own exit cleanly: %v\n"+
				"That is the injected request being CONSUMED instead of ignored — the "+
				"control loop read a second request after \"start\", exactly the property "+
				"this test exists to refuse.", r.err)
		}
		if !r.exited || r.status != 0 {
			t.Fatalf("the real payload's own wait status was not a clean exit(0) (exited=%v "+
				"status=%d) — something other than /bin/sleep 1 running to completion produced "+
				"this event", r.exited, r.status)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("st.Wait() never returned — the stage is hung rather than having simply " +
			"ignored the injected request, which is itself a regression from this test's " +
			"own point of view")
	}
}
