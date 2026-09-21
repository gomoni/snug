package stage

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// startEngineRefusalFixture drives one real "start" request carrying spec
// through a real Stage, exactly like onerequest_test.go's own harness: a
// real bwrap fork, gated so the payload is tracked by parked.arm, no engine
// grafts needed for these cases because every one of them is refused before
// startEngine ever reaches the graft check. It returns the error
// StartSandbox reported and the pid OnSandboxForked observed, so a caller can
// assert both that the refusal fired and that nothing survived it.
func startEngineRefusalFixture(t *testing.T, spec *EngineSpec, gated bool) (err error, forkedPID int) {
	t.Helper()
	bwrapPath, lookErr := exec.LookPath("bwrap")
	if lookErr != nil {
		t.Skip("bubblewrap is not installed")
	}

	infoR, infoW, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	defer infoR.Close()

	var pid int
	st, startErr := Start(Config{
		Topology:        policy.Topology{Netns: policy.NetnsStage, Subuid: policy.SubuidNone},
		Sandbox:         []*os.File{infoW},
		BwrapInfo:       infoR,
		Stdin:           devNullFile(t),
		Stdout:          devNullFile(t),
		Stderr:          devNullFile(t),
		OnSandboxForked: func(p int) { pid = p },
	})
	if startErr != nil {
		if isUnprivilegedUsernsRefusal(startErr) {
			t.Skipf("this host refuses unprivileged user namespaces: %v", startErr)
		}
		t.Fatalf("Start: %v", startErr)
	}
	defer st.Close()
	infoW.Close()

	// A real, minimal, LONG-RUNNING payload: long enough that if this
	// fixture's refusal did NOT kill it, it would still be alive when this
	// function's caller checks — a payload that exits on its own inside the
	// fixture's own window would make "no payload started" pass whether or
	// not the refusal did anything.
	argv := []string{
		"--unshare-all",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--proc", "/proc", "--dev", "/dev",
		"--remount-ro", "/",
		"--die-with-parent",
		"--info-fd", "3",
		"--", "/bin/sleep", "30",
	}

	if werr := st.WaitNetReady(5*time.Second, "lo", nil); werr != nil {
		t.Fatalf("PRECONDITION: netready failed: %v", werr)
	}

	_, err = st.StartSandbox(bwrapPath, argv, spec, gated)
	return err, pid
}

// assertNoSurvivor checks that pid — the sandbox init startEngineRefusalFixture
// observed via OnSandboxForked — is gone, so a refused engine start is
// checked to have taken its sandbox down with it and not merely to have
// reported an error while /bin/sleep 30 kept running underneath.
func assertNoSurvivor(t *testing.T, pid int) {
	t.Helper()
	if pid <= 1 {
		t.Fatalf("OnSandboxForked never reported a pid — this fixture cannot check survival")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); err != nil {
			return // gone
		}
		if time.Now().After(deadline) {
			t.Errorf("pid %d is still alive 5s after a refused engine start — the refusal "+
				"reported an error but left the payload it should have taken down running", pid)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestStartEngineRefusesAStartWithNoRunLabel is startEngine's first refusal
// (enginefork.go): an EngineRunLabel that fails runstop.Split at all —
// here, simply absent — is malformed and refused before anything is forked.
func TestStartEngineRefusesAStartWithNoRunLabel(t *testing.T) {
	spec := &EngineSpec{
		Podman:          "/does-not-matter",
		Sock:            "/tmp/does-not-matter.sock",
		RunSizeBytes:    16 << 20,
		VarTmpSizeBytes: 16 << 20,
		RunLabel:        "",
	}
	err, pid := startEngineRefusalFixture(t, spec, true)
	if err == nil {
		t.Fatal("StartSandbox succeeded for a spec with no run label at all")
	}
	if !strings.Contains(err.Error(), "not key=value") {
		t.Errorf("error does not name Split's own refusal reason: %v", err)
	}
	assertNoSurvivor(t, pid)
}

// TestStartEngineRefusesAMalformedRunLabel is the second shape of the same
// refusal: a label that IS key=value but carries a rune outside
// [A-Za-z0-9._-] in its value, per Split's own charset (runstop.go).
func TestStartEngineRefusesAMalformedRunLabel(t *testing.T) {
	spec := &EngineSpec{
		Podman:          "/does-not-matter",
		Sock:            "/tmp/does-not-matter.sock",
		RunSizeBytes:    16 << 20,
		VarTmpSizeBytes: 16 << 20,
		RunLabel:        "snug.run=in/valid",
	}
	err, pid := startEngineRefusalFixture(t, spec, true)
	if err == nil {
		t.Fatal("StartSandbox succeeded for a spec whose run label value carries an illegal rune")
	}
	if !strings.Contains(err.Error(), "carries") {
		t.Errorf("error does not name Split's own bad-rune refusal reason: %v", err)
	}
	assertNoSurvivor(t, pid)
}

// TestStartEngineRefusesAnotherRunsLabel is the fourth refusal (added after
// the run-label-ownership check landed): a WELL-FORMED snug.run label naming
// a DIFFERENT pid than the one that forked this stage is refused, never
// acted on — the same-uid-store rule startEngine's own comment states
// ("this stage stops the containers of the run that forked it").
//
// TestStartEngineAcceptsThisRunsLabel is the positive control: without it, a
// startEngine that refused EVERY label — this run's own included — would
// pass this test for the wrong reason.
func TestStartEngineRefusesAnotherRunsLabel(t *testing.T) {
	notThisRun := os.Getpid() + 1
	spec := &EngineSpec{
		Podman:          "/does-not-matter",
		Sock:            "/tmp/does-not-matter.sock",
		RunSizeBytes:    16 << 20,
		VarTmpSizeBytes: 16 << 20,
		RunLabel:        fmt.Sprintf("snug.run=%d", notThisRun),
	}
	err, pid := startEngineRefusalFixture(t, spec, true)
	if err == nil {
		t.Fatal("StartSandbox succeeded for a well-formed run label naming a different run")
	}
	if !strings.Contains(err.Error(), "refusing a \"start\" whose run label is") {
		t.Errorf("error does not name the run-label-ownership refusal: %v", err)
	}
	assertNoSurvivor(t, pid)
}

// TestStartEngineAcceptsThisRunsLabel is TestStartEngineRefusesAnotherRunsLabel's
// positive control. It still fails — no grafts are supplied, which is a
// DIFFERENT, later refusal — but it must fail with THAT refusal's own text,
// never with the run-label-ownership one: if it did, the negative test above
// would be passing because startEngine refuses every label, not because it
// checks ownership.
func TestStartEngineAcceptsThisRunsLabel(t *testing.T) {
	spec := &EngineSpec{
		Podman:          "/does-not-matter",
		Sock:            "/tmp/does-not-matter.sock",
		RunSizeBytes:    16 << 20,
		VarTmpSizeBytes: 16 << 20,
		RunLabel:        fmt.Sprintf("snug.run=%d", os.Getpid()),
	}
	err, pid := startEngineRefusalFixture(t, spec, true)
	if err == nil {
		t.Fatal("StartSandbox succeeded with no engine grafts at all — a later refusal should " +
			"still have fired")
	}
	if strings.Contains(err.Error(), "refusing a \"start\" whose run label is") {
		t.Errorf("this run's OWN label was refused as though it belonged to another run: %v", err)
	}
	if !strings.Contains(err.Error(), "an engine with no grafts") {
		t.Errorf("error is not the expected no-grafts refusal, so this control is not testing "+
			"what it claims to: %v", err)
	}
	assertNoSurvivor(t, pid)
}

// TestStartEngineRefusesAnUngatedEngine is startEngine's third refusal: an
// engine request on a "start" that did not carry Gated: true, which would
// leave the abort paths unable to account for containers a payload that was
// never parked might already have created.
func TestStartEngineRefusesAnUngatedEngine(t *testing.T) {
	spec := &EngineSpec{
		Podman:          "/does-not-matter",
		Sock:            "/tmp/does-not-matter.sock",
		RunSizeBytes:    16 << 20,
		VarTmpSizeBytes: 16 << 20,
		RunLabel:        fmt.Sprintf("snug.run=%d", os.Getpid()),
	}
	err, pid := startEngineRefusalFixture(t, spec, false)
	if err == nil {
		t.Fatal("StartSandbox succeeded for an engine request on an ungated start")
	}
	if !strings.Contains(err.Error(), "an engine on an ungated run") {
		t.Errorf("error does not name the ungated-engine refusal: %v", err)
	}
	assertNoSurvivor(t, pid)
}
