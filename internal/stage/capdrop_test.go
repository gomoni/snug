package stage

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

func TestDropCapsToExactlyRefusesAnUnknownCapability(t *testing.T) {
	err := dropCapsToExactly([]string{"CAP_SETPCAP", "CAP_NOT_A_REAL_CAPABILITY"})
	if err == nil {
		t.Fatal("dropCapsToExactly accepted an unknown capability name")
	}
	if !strings.Contains(err.Error(), "CAP_NOT_A_REAL_CAPABILITY") {
		t.Errorf("error %q does not name the offending capability", err)
	}
}

func TestDropCapsToExactlyRefusesASetWithoutSetpcap(t *testing.T) {
	err := dropCapsToExactly([]string{"CAP_CHOWN"})
	if err == nil {
		t.Fatal("dropCapsToExactly accepted a set without CAP_SETPCAP, which it needs to run at all")
	}
	if !strings.Contains(err.Error(), "CAP_SETPCAP") {
		t.Errorf("error %q does not name the missing capability", err)
	}
}

// TestEngineCapBoundingCapsAllHaveAKnownBit is the drift guard between the
// two files: policy.EngineCapBounding names capabilities, this package's
// engineCapBit resolves them to kernel numbers, and a name added to one
// without the other would fail LOUDLY, mid-run, on the engine's own launch —
// far from the diff that introduced it. This test is what makes that gap a
// build-time fact instead.
func TestEngineCapBoundingCapsAllHaveAKnownBit(t *testing.T) {
	for _, name := range policy.EngineCapBounding {
		if _, ok := engineCapBit[name]; !ok {
			t.Errorf("policy.EngineCapBounding names %s, but engineCapBit does not know its bit", name)
		}
	}
}

// TestDropCapsToExactlyProducesTheEngineCapabilitySet is the real-execution
// check: fork a child into a fresh, SELF-mapped user namespace (root-in-U,
// full caps — exactly the shape the engine forked by the stage starts from),
// have it call dropCapsToExactly(policy.EngineCapBounding) on itself, and read
// back what the kernel actually recorded. This is the positive control for
// the constant's own doc comment: here is proof that asking for the 12-cap
// set produces exactly the 12-cap set on a real kernel, with CAP_SYS_PTRACE
// and CAP_NET_ADMIN gone from BOTH the effective and the bounding set — the
// second is the part a naive capset(2)-only implementation would miss,
// because capset alone cannot touch the bounding set at all.
//
// Uses the plain single-uid self-map (unprivileged, no newuidmap needed) —
// this test is about the CAPABILITY mechanism, not the subuid one, which
// TestStartDelegatesTheFullSubuidRange already covers on its own.
func TestDropCapsToExactlyProducesTheEngineCapabilitySet(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/proc/self/exe", "__debug-dropcaps")
	cmd.Args[0] = "snug"
	cmd.ExtraFiles = []*os.File{r}
	hostUID, hostGID := os.Getuid(), os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: hostUID, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: hostGID, Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	statusPath := os.TempDir() + "/snug-test-dropcaps-status-" + strconv.Itoa(os.Getpid())
	defer os.Remove(statusPath)
	cmd.Env = []string{"SNUG_TEST_DROPCAPS_STATUS_PATH=" + statusPath}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot create a user namespace on this host: %v", err)
	}
	w.Write([]byte("x")) // release the child immediately; nothing to synchronise here
	w.Close()
	if err := cmd.Wait(); err != nil {
		msg := strings.TrimSpace(errBuf.String())
		if isUnprivilegedUsernsRefusal(fmt.Errorf("%s", msg)) {
			// Same class as isUnprivilegedUsernsRefusal's own doc comment:
			// the fork itself can succeed on a host whose AppArmor policy
			// still refuses the FOLLOW-ON syscalls a fresh user namespace
			// needs (PR_CAPBSET_DROP here) — CI's plain `gate` lane is
			// exactly this shape (see ci.yml). Skip, do not fail: this test
			// exists to check the MECHANISM works where the host allows it,
			// not to assert every CI runner allows it.
			t.Skipf("this host refuses the capability drop: %s", msg)
		}
		t.Fatalf("child exited with an error: %v (stderr: %s)", err, msg)
	}

	data, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatalf("reading the child's reported status: %v", err)
	}
	capEff, capBnd := parseCapLines(t, string(data))

	wantMask := uint64(0)
	for _, name := range policy.EngineCapBounding {
		wantMask |= 1 << uint(engineCapBit[name])
	}
	if capEff != wantMask {
		t.Errorf("CapEff = %#x, want %#x (the engine capability set)", capEff, wantMask)
	}
	if capBnd != wantMask {
		t.Errorf("CapBnd = %#x, want %#x — the BOUNDING set must be reduced too, not just Effective", capBnd, wantMask)
	}
	ptraceBit := uint64(1) << uint(engineCapBit["CAP_SYS_PTRACE"])
	if capBnd&ptraceBit != 0 {
		t.Error("CAP_SYS_PTRACE survived in the bounding set — the standing gate is not held")
	}
	netAdminBit := uint64(1) << uint(engineCapBit["CAP_NET_ADMIN"])
	if capBnd&netAdminBit != 0 {
		t.Error("CAP_NET_ADMIN survived in the bounding set — the settled NET_ADMIN decision is not held")
	}
}

// runDebugDropCaps is the __debug-dropcaps hidden verb's body
// (mainprocess_test.go): it is test-only support code, not production stage
// behaviour, which is why it lives beside the test that is its only caller
// rather than in capdrop.go.
func runDebugDropCaps() error {
	if err := dropCapsToExactly(policy.EngineCapBounding); err != nil {
		return err
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	return os.WriteFile(os.Getenv("SNUG_TEST_DROPCAPS_STATUS_PATH"), data, 0o644)
}

func parseCapLines(t *testing.T, status string) (eff, bnd uint64) {
	t.Helper()
	for _, ln := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(ln, "CapEff:\t"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				t.Fatalf("parsing CapEff line %q: %v", ln, err)
			}
			eff = n
		}
		if v, ok := strings.CutPrefix(ln, "CapBnd:\t"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				t.Fatalf("parsing CapBnd line %q: %v", ln, err)
			}
			bnd = n
		}
	}
	return eff, bnd
}
