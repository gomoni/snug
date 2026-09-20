//go:build integration

package integration

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestDoctorSaysNoOnAHostWhereUserNamespacesDoNotWork is issue #98 end to
// end, and it is the half internal/cli's own tests structurally cannot make.
//
// A green tick never proves a check CAN fail. This one could not: probeBase()
// passes `--unshare-all`, whose `-try` spellings skip silently and exit 0, and
// the check read the exit code alone — so `✅ unprivileged user namespaces
// work` printed on a host where they do not.
//
// internal/cli/doctoruserns_test.go covers the DECISION exhaustively
// (classifyUserns over five inputs) and the wiring (probeUserns against
// whatever host runs it). Neither can produce the failing host: that needs a
// writable /proc/sys/user/max_user_namespaces inside a fresh user namespace,
// which is a fabrication rather than a fixture. So it is built here, and the
// whole binary is graded on it — the row, and the exit code that follows the
// row.
//
// The fabrication is a user namespace of our own with
// /proc/sys/user/max_user_namespaces set to 0. That file is
// per-user-namespace, so nothing about the real machine changes and no root
// is needed.
//
// THE POSITIVE CONTROL IS THE HALF THAT MATTERS: a nested `unshare` must FAIL
// in there. Without it, a doctor printing ❌ for an unrelated reason would
// pass this test, which is the same defect in a new costume.
func TestDoctorSaysNoOnAHostWhereUserNamespacesDoNotWork(t *testing.T) {
	budget(t, 30*time.Second)

	if _, err := exec.LookPath("unshare"); err != nil {
		skipOrFail(t, "no unshare(1) on this host, so there is no weak host to fabricate")
	}
	if err := exec.Command("unshare", "--user", "--map-root-user", "--", "/bin/true").Run(); err != nil {
		skipOrFail(t, "this host cannot create an unprivileged user namespace at all, so "+
			"there is no weak host to fabricate and doctor is right to say no (see "+
			"kernel.apparmor_restrict_unprivileged_userns and "+
			"/proc/sys/kernel/unprivileged_userns_clone): %v", err)
	}

	script := `
		echo 0 > /proc/sys/user/max_user_namespaces
		if unshare --user --map-root-user -- /bin/true 2>&1; then
			echo CONTROL-PASSED
		else
			echo CONTROL-FAILED
		fi
		` + snugBin + ` doctor 2>&1
		echo "doctor-exit=$?"`

	cmd := exec.Command("unshare", "--user", "--map-root-user", "--", "/bin/sh", "-c", script)
	cmd.Env = baseEnv()
	raw, _ := cmd.CombinedOutput() // doctor's own nonzero exit is the point; it is read below
	out := string(raw)

	if !strings.Contains(out, "CONTROL-FAILED") {
		t.Fatalf("the positive control still created a namespace, so this host was never made "+
			"weak and every assertion below would be vacuous:\n%s", out)
	}

	if strings.Contains(out, "✅ unprivileged user namespaces work") {
		t.Errorf("doctor printed ✅ unprivileged user namespaces work on a host where they do "+
			"not (issue #98):\n%s", out)
	}
	if !strings.Contains(out, "❌ cannot create a user namespace here") {
		t.Errorf("doctor did not print ❌ cannot create a user namespace here:\n%s", out)
	}
	if !strings.Contains(out, "doctor-exit=69") {
		t.Errorf("doctor did not exit 69 on a host it cannot serve:\n%s", out)
	}
}
