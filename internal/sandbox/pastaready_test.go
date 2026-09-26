package sandbox

// Issue #605: the stage sealed the host's addresses onto snug0 as soon as
// snug0 was UP and RUNNING, which pasta makes true BEFORE it copies the host's
// addresses there; a v6 seal that won the race made pasta's own add fail with
// EEXIST and pasta died. Readiness is now pasta's pid line on its stdout
// (policy.PastaReadyPath), and these pin that netHelper reports it only then.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/stage"
)

// fakePasta puts a shell script named pasta first on PATH. The script finds
// its --pid argument the way pasta's getopt would and runs body with it in
// $pidfile.
func fakePasta(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\npidfile=\n" +
		"while [ $# -gt 0 ]; do [ \"$1\" = --pid ] && pidfile=$2; shift; done\n" + body
	if err := os.WriteFile(filepath.Join(dir, "pasta"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

func egressPolicy() *policy.Policy {
	return &policy.Policy{Net: policy.NetPolicy{Mode: policy.NetEgress}}
}

func TestPastaIsNotConfiguredUntilItWritesItsPid(t *testing.T) {
	gate := filepath.Join(t.TempDir(), "gate")
	if err := syscall.Mkfifo(gate, 0o600); err != nil {
		t.Fatal(err)
	}
	// Opens the path it was handed exactly as pasta's output_file_open does —
	// a fresh open of /proc/self/fd/1, not a write to an inherited fd — so the
	// test fails if that path stops naming the pipe startPasta reads.
	fakePasta(t, "read x < "+gate+"\necho $$ > \"$pidfile\"\nexec sleep 30\n")

	h, err := startPasta(egressPolicy(), policy.PastaTargetChild(1))
	if err != nil {
		t.Fatal(err)
	}
	defer h.stop()

	select {
	case <-h.configured():
		t.Fatal("configured() fired before pasta wrote its pid: the stage would seal " +
			"snug0 while pasta is still configuring it (issue #605)")
	case <-h.died():
		t.Fatalf("the fake pasta died: %s", h.failure())
	case <-time.After(300 * time.Millisecond):
	}

	g, err := os.OpenFile(gate, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	g.WriteString("go\n")
	g.Close()

	select {
	case <-h.configured():
	case <-h.died():
		t.Fatalf("the fake pasta died instead of reporting ready: %s", h.failure())
	case <-time.After(5 * time.Second):
		t.Fatalf("pasta wrote its pid to %s and configured() never fired", policy.PastaReadyPath)
	}
}

func TestPastaThatDiesBeforeItsPidIsNeverConfigured(t *testing.T) {
	const msg = "Couldn't set IPv6 address(es) in namespace: File exists"
	fakePasta(t, "echo \""+msg+"\" >&2\nexit 1\n")

	h, err := startPasta(egressPolicy(), policy.PastaTargetChild(1))
	if err != nil {
		t.Fatal(err)
	}
	defer h.stop()

	select {
	case <-h.died():
	case <-time.After(5 * time.Second):
		t.Fatal("the fake pasta never exited")
	}
	select {
	case <-h.configured():
		t.Fatal("configured() fired for a pasta that exited without writing its pid")
	case <-time.After(200 * time.Millisecond):
	}

	// Invariant 5: this is the state runStaged refuses in, never warns in.
	err = helperDiedBeforePayload(h)
	if err == nil {
		t.Fatal("a pasta that is already dead did not refuse the run: the payload would " +
			"get loopback only after asking for @net")
	}
	if !strings.Contains(err.Error(), msg) {
		t.Errorf("the refusal does not carry pasta's own reason %q:\n%v", msg, err)
	}
}

func TestALivePastaDoesNotRefuseTheRun(t *testing.T) {
	fakePasta(t, "echo $$ > \"$pidfile\"\nexec sleep 30\n")
	h, err := startPasta(egressPolicy(), policy.PastaTargetChild(1))
	if err != nil {
		t.Fatal(err)
	}
	defer h.stop()
	select {
	case <-h.configured():
	case <-time.After(5 * time.Second):
		t.Fatal("PRECONDITION: the fake pasta never reported ready")
	}
	if err := helperDiedBeforePayload(h); err != nil {
		t.Errorf("a live pasta refused the run: %v", err)
	}
	if err := helperDiedBeforePayload(nil); err != nil {
		t.Errorf("a run with no pasta refused: %v", err)
	}
}

// Every run with a pasta is gated (issue #605, red-team F1/F2): the payload
// is parked until the release byte, so a pasta that dies before then is
// refused — and must not ALSO print watch()'s "the sandbox now has loopback
// only", which describes a sandbox that never runs. The red team saw both
// lines, warning first.
func TestAGatedRunWhosePastaDiesBeforeReleaseDoesNotWarnLoopbackOnly(t *testing.T) {
	for _, dies := range []bool{true, false} {
		name := "released-then-dies-control"
		if dies {
			name = "dies-before-release"
		}
		t.Run(name, func(t *testing.T) {
			fakePasta(t, "echo $$ > \"$pidfile\"\nexec sleep 30\n")
			h, err := startPasta(egressPolicy(), policy.PastaTargetChild(1))
			if err != nil {
				t.Fatal(err)
			}
			defer h.stop()
			<-h.configured()

			warned := make(chan string, 1)
			warn := func(s string) { warned <- s }
			if err := h.checkBeforeSandbox(true); err != nil {
				t.Fatalf("PRECONDITION: a live pasta refused: %v", err)
			}

			if !dies {
				// CONTROL: released first, so a death now IS the mid-run
				// warning — and it proves watch fires at all.
				if err := h.checkBeforeRelease(warn); err != nil {
					t.Fatalf("PRECONDITION: a live pasta refused the release: %v", err)
				}
				h.cmd.Process.Kill()
				select {
				case msg := <-warned:
					if !strings.Contains(msg, "now has loopback only") {
						t.Errorf("unexpected warning: %s", msg)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("CONTROL: a pasta death after the release was never reported")
				}
				return
			}

			// pasta dies while bwrap builds the sandbox / the engine starts.
			h.cmd.Process.Kill()
			<-h.died()
			err = h.checkBeforeRelease(warn)
			if err == nil || !strings.Contains(err.Error(), "exited before the payload started") {
				t.Fatalf("a run whose pasta died before the release was not refused: %v", err)
			}
			select {
			case msg := <-warned:
				t.Errorf("a refused run also printed the mid-run warning for a sandbox "+
					"that never runs:\n%s", msg)
			case <-time.After(300 * time.Millisecond):
			}
		})
	}
}

// A pasta on an ungated run would leave the bwrap build -> exec interval
// unchecked, so runStaged refuses the combination outright rather than
// trusting Run to have gated every @net run.
func TestAPastaOnAnUngatedRunIsRefused(t *testing.T) {
	fakePasta(t, "echo $$ > \"$pidfile\"\nexec sleep 30\n")
	h, err := startPasta(egressPolicy(), policy.PastaTargetChild(1))
	if err != nil {
		t.Fatal(err)
	}
	defer h.stop()
	<-h.configured()
	if err := h.checkBeforeSandbox(false); err == nil {
		t.Fatal("a live pasta on an ungated run was allowed to start a sandbox")
	}
	var none *netHelper
	if err := none.checkBeforeSandbox(false); err != nil {
		t.Errorf("an offline ungated run (no pasta) refused: %v", err)
	}
}

func TestEveryNetEgressRunIsGated(t *testing.T) {
	if !runIsGated(egressPolicy(), Options{}) {
		t.Error("an @net run with no container engine is not gated: a pasta that dies while " +
			"bwrap builds the sandbox would leave a payload with loopback only")
	}
	if runIsGated(&policy.Policy{}, Options{}) {
		t.Error("an offline run with no engine is gated, and its path has no stage to release it")
	}
	if !runIsGated(&policy.Policy{}, Options{EngineSpec: &stage.EngineSpec{}}) {
		t.Error("a container run is not gated")
	}
}

// A pasta whose own descendant keeps its stderr pipe open must still be
// reported dead once pasta exits; without cmd.WaitDelay, died() waits for the
// descendant.
func TestPastaDeathIsReportedWhileADescendantHoldsItsStderr(t *testing.T) {
	fakePasta(t, "sleep 5 &\nexit 1\n")
	h, err := startPasta(egressPolicy(), policy.PastaTargetChild(1))
	if err != nil {
		t.Fatal(err)
	}
	defer h.stop()
	select {
	case <-h.died():
	case <-time.After(3 * time.Second):
		t.Fatal("pasta exited but died() did not fire while its background child held stderr")
	}
}
