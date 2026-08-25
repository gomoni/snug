package stage

import (
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeControlPair returns a connected SOCK_SEQPACKET pair in the exact shape
// Start() creates (stage.go's own unix.Socketpair call): p0 is what a real
// Stage would keep as its own control field, p1 is a stand-in for __stage-serve
// driven directly by the test rather than by a forked process. This lets
// StartSandbox's own client-side loop be exercised without bwrap, a user
// namespace or any privilege at all — the loop's correctness does not depend
// on what is on the other end of the socket, only on what arrives on it.
func fakeControlPair(t *testing.T) (p0, p1 *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("creating a fake control socketpair: %v", err)
	}
	p0 = os.NewFile(uintptr(fds[0]), "fake-stage-control-p0")
	p1 = os.NewFile(uintptr(fds[1]), "fake-stage-control-p1")
	t.Cleanup(func() { p0.Close(); p1.Close() })
	return p0, p1
}

// TestTheStageReportsTheInitPIDBeforeTheEngineStarts is issue #236's protocol
// half: StartSandbox's own loop (stage.go) must hand "forked"'s InitPID to
// Config.OnSandboxForked SYNCHRONOUSLY, before it goes back to reading and
// eventually returns on "enginestarted" — otherwise the whole reason the
// event exists (naming the init BEFORE the engine's cold start, not after) is
// lost regardless of what the wire carries.
//
// A fake P1 drives the other end of the socketpair directly, so this needs no
// bwrap, no user namespace and no privilege: the property under test is
// StartSandbox's own dispatch, not bwrap's behaviour.
func TestTheStageReportsTheInitPIDBeforeTheEngineStarts(t *testing.T) {
	p0, p1 := fakeControlPair(t)

	const wantPID = 4242
	wantNS := map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6}

	var hookPID int
	hookCalled := make(chan struct{}, 1)
	st := &Stage{
		control: p0,
		onSandboxForked: func(pid int) {
			hookPID = pid
			hookCalled <- struct{}{}
		},
	}

	fakeErr := make(chan error, 1)
	go func() {
		if _, err := recvRequest(p1); err != nil {
			fakeErr <- err
			return
		}
		if err := sendEvent(p1, event{Op: "forked", InitPID: wantPID}); err != nil {
			fakeErr <- err
			return
		}
		if err := sendEvent(p1, event{Op: "enginestarted", InitPID: wantPID, Namespaces: wantNS}); err != nil {
			fakeErr <- err
			return
		}
		fakeErr <- nil
	}()

	info, err := st.StartSandbox("bwrap", []string{"--version"}, nil, false)
	if err != nil {
		t.Fatalf("StartSandbox: %v", err)
	}
	if err := <-fakeErr; err != nil {
		t.Fatalf("the fake P1 side failed to drive the exchange: %v", err)
	}

	select {
	case <-hookCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("OnSandboxForked was never called — StartSandbox returned on \"enginestarted\" " +
			"without ever having seen a \"forked\" event, which defeats issue #236's whole point")
	}
	if hookPID != wantPID {
		t.Errorf("OnSandboxForked got pid %d, want %d — the hook must see the SAME InitPID "+
			"\"enginestarted\" reports, not some other number", hookPID, wantPID)
	}
	if info.InitPID != wantPID {
		t.Errorf("StartSandbox returned InitPID %d, want %d", info.InitPID, wantPID)
	}
	for k, v := range wantNS {
		if info.Namespaces[k] != v {
			t.Errorf("StartSandbox returned Namespaces[%q]=%d, want %d", k, info.Namespaces[k], v)
		}
	}

	// The regression this test is really pinned against: mutate OnInit
	// (internal/cli/main.go) into a no-op, or delete the "forked" case from
	// StartSandbox's switch (stage.go), and this select times out — the hook
	// is the only observable this test has, and its absence is exactly what
	// issue #236 measured as "no host record for that whole interval".
}

// TestASecondForkedEventIsRefused pins the bound stage.go's own comment
// states rather than merely documents: each event read renews
// startRoundTripTimeout, so a P1 that sent "forked" repeatedly would keep
// StartSandbox's loop alive indefinitely and re-run the caller's hook every
// time. One init is forked per stage, so StartSandbox must refuse a second
// "forked" as a protocol violation rather than loop forever or call the hook
// twice.
func TestASecondForkedEventIsRefused(t *testing.T) {
	p0, p1 := fakeControlPair(t)

	hookCalls := 0
	st := &Stage{
		control:         p0,
		onSandboxForked: func(int) { hookCalls++ },
	}

	go func() {
		if _, err := recvRequest(p1); err != nil {
			return
		}
		_ = sendEvent(p1, event{Op: "forked", InitPID: 111})
		_ = sendEvent(p1, event{Op: "forked", InitPID: 222})
	}()

	_, err := st.StartSandbox("bwrap", []string{"--version"}, nil, false)
	if err == nil {
		t.Fatal("StartSandbox accepted a second \"forked\" event instead of refusing it")
	}
	if !strings.Contains(err.Error(), "forked") {
		t.Errorf("the refusal does not name the event it rejected: %v", err)
	}
	if hookCalls != 1 {
		t.Errorf("OnSandboxForked was called %d times, want exactly 1 — a second \"forked\" "+
			"event must be refused BEFORE the hook runs a second time", hookCalls)
	}
}
