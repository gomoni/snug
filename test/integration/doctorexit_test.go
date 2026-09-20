//go:build integration

package integration

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestDoctorsExitCodeFollowsTheRowsItPrinted asserts the one property of
// `snug doctor`'s report that is host-INDEPENDENT.
//
// A transcript of any particular host's report tells a reader about that
// machine and nothing about theirs. What holds everywhere is the relationship
// between the rows and the status:
//
//	a ❌ row is fatal   — at least one ❌  =>  exit 69
//	a ⚠️ row is not    — no ❌, any number of ⚠️  =>  exit 0
//
// Each ⚠️ gates ONE capability (pasta, the podman client, podman's helper
// binaries, the delegated subuid/subgid range) and not snug, so it must leave
// the exit code alone. That is what lets `snug doctor` be run unattended.
//
// No requireSandbox: both arms are legitimate answers and the test asserts
// the relationship, not which one this host gives. A runner that cannot
// create a user namespace takes the ❌ arm and is graded just as hard.
// TestDoctorRunsCleanOnAHostThatCanRunSnug is the other half — that a host
// which CAN run snug is told so.
func TestDoctorsExitCodeFollowsTheRowsItPrinted(t *testing.T) {
	budget(t, 30*time.Second)

	report, code := cli(t, nil, "doctor")

	crosses := strings.Count(report, "❌")
	warns := strings.Count(report, "⚠️")

	if crosses > 0 {
		if code != 69 {
			t.Errorf("doctor printed %d ❌ row(s) and exited %d, want 69:\n%s", crosses, code, report)
		}
		return
	}
	if code != 0 {
		t.Errorf("doctor printed no ❌ row and exited %d, want 0 — a ⚠️ (there are %d here) "+
			"gates one capability, not snug:\n%s", code, warns, report)
	}
}

// TestFixSubuidIsSafeToCallFromAnErrexitInitHook covers `snug fix subuid`'s
// exit status, which is a contract rather than a detail: the command exists
// to be called from a distrobox `init_hook`, and `distrobox-init` runs hooks
// under `set -o errexit`. A nonzero exit on a host that needs nothing would
// not report a problem — it would stop the box from coming up.
//
// STDOUT SPECIFICALLY, which is why this runs the binary directly instead of
// through cli()'s CombinedOutput: the reason belongs on stderr, so a caller
// that captures stdout to decide whether anything happened gets an empty
// string on a host with nothing to do.
//
// THE THIRD ARM IS THE TRAP. Under sudo, os.Getuid() is 0, so the obvious
// implementation "fixes" root instead of saying it cannot find the named
// account. An unknown name must be a usage error (64) and must never be
// silently resolved to whoever is running.
func TestFixSubuidIsSafeToCallFromAnErrexitInitHook(t *testing.T) {
	budget(t, 30*time.Second)

	cmd := exec.Command(snugBin, "fix", "subuid")
	cmd.Env = baseEnv()
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running snug fix subuid: %v", err)
		}
		t.Fatalf("`snug fix subuid` exited %d; only 0 is safe for a distrobox init_hook "+
			"running under `set -o errexit`:\n%s", ee.ExitCode(), ee.Stderr)
	}
	if len(stdout) != 0 {
		t.Errorf("`snug fix subuid` exited 0 but wrote to stdout, where the reason does not "+
			"belong: %q", stdout)
	}

	_, code := cli(t, nil, "fix", "subuid", "nosuchuser42")
	if code != 64 {
		t.Errorf("`snug fix subuid nosuchuser42` exited %d, want 64 — a usage error, not a "+
			"guess at whoever is running", code)
	}
}
