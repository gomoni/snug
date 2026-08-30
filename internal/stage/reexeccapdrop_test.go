package stage

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// capSysPtraceBit and capSysAdminBit are capability(7)'s own numbers,
// spelled out here rather than reached through engineCapBit: these two tests
// read a status file that Start() produced through a REAL clone+execve, and
// checking that read against the same package's own bit map would let a
// mistake in engineCapBit (unlikely — TestEngineCapBoundingCapsAllHaveAKnownBit
// already guards it) hide behind a matching mistake here.
const (
	capSysPtraceBit = 19
	capSysAdminBit  = 21
)

// startBareStage starts P1 with the minimal Config TestTheStageReadsNoRequestAfterStart
// already establishes as sufficient to reach a real "ready" — an offline
// info-fd pipe and no engine — and returns once Start has returned, which
// only happens after __stage-serve's own requireCapDropped call has already
// passed (serve.go: the refusal runs before "ready" is ever sent). Skips,
// rather than fails, on a host that refuses unprivileged user namespaces —
// the same distinction TestTheStageReadsNoRequestAfterStart draws.
func startBareStage(t *testing.T) *Stage {
	t.Helper()
	infoR, infoW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { infoR.Close() })

	st, err := Start(Config{
		Topology:  policy.Topology{Netns: policy.NetnsStage, Subuid: policy.SubuidNone},
		Sandbox:   []*os.File{infoW},
		BwrapInfo: infoR,
		Stdin:     devNullFile(t), Stdout: devNullFile(t), Stderr: devNullFile(t),
	})
	infoW.Close()
	if err != nil {
		if isUnprivilegedUsernsRefusal(err) {
			t.Skipf("this host refuses unprivileged user namespaces: %v", err)
		}
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// readCapWord parses one CapBnd/CapPrm/CapEff line out of a /proc status
// file, by field name, the same 16-hex-digit-no-prefix format
// internal/stage/capdrop.go's own readCapField parses — duplicated rather
// than called, because that function reads only /proc/self/task/<tid>/status
// (HOSTREAD-EXEMPT for exactly that reason) and these two tests read a
// DIFFERENT process's status from across the control socket relationship,
// which is not the case that exemption covers.
func readCapWord(t *testing.T, path, field string) uint64 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || name != field {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil {
			t.Fatalf("parsing %s from %s (%q): %v", field, path, value, err)
		}
		return mask
	}
	t.Fatalf("%s names no %s line", path, field)
	return 0
}

// TestTheStageDropsPtraceFromItsBoundingSetAcrossTheReExec catches a
// regression that would break the whole gate silently: PR_CAPBSET_DROP not
// surviving the __stage-setup -> __stage-serve execve (a wrong argv0, a
// dropped ExtraFiles slot reordering the locked-thread step, anything that
// makes dropFromBounding's prctl land on a thread that is not the one about
// to exec). __stage-serve's own requireCapDropped is the enforcement; this
// test is what would notice if that enforcement itself went missing or
// stopped checking the right thing, by reading P1's real /proc/<pid>/status
// from OUTSIDE it, independently of whatever __stage-serve believes about
// itself.
func TestTheStageDropsPtraceFromItsBoundingSetAcrossTheReExec(t *testing.T) {
	st := startBareStage(t)

	statusPath := "/proc/" + strconv.Itoa(st.Pid()) + "/status"
	bnd := readCapWord(t, statusPath, "CapBnd")
	prm := readCapWord(t, statusPath, "CapPrm")
	eff := readCapWord(t, statusPath, "CapEff")

	for _, w := range []struct {
		name string
		mask uint64
	}{{"CapBnd", bnd}, {"CapPrm", prm}, {"CapEff", eff}} {
		if w.mask&(1<<capSysPtraceBit) != 0 {
			t.Errorf("P1's %s (%#x) still holds CAP_SYS_PTRACE — the drop did not survive "+
				"the __stage-setup -> __stage-serve execve", w.name, w.mask)
		}
	}

	// POSITIVE CONTROL: an all-zero CapBnd would also have no bit 19 set, and
	// would pass the loop above while actually meaning the stage never
	// finished becoming root-in-U (or is already dead) rather than meaning
	// the drop worked. CAP_SYS_ADMIN — which policy.StageCapDrop does not
	// touch — must still be present in all three words, or this test cannot
	// tell "the gate held" from "there is nothing here to gate".
	for _, w := range []struct {
		name string
		mask uint64
	}{{"CapBnd", bnd}, {"CapPrm", prm}, {"CapEff", eff}} {
		if w.mask&(1<<capSysAdminBit) == 0 {
			t.Fatalf("P1's %s (%#x) does not hold CAP_SYS_ADMIN: this run is not exercising "+
				"a full-capability P1 at all, so the CAP_SYS_PTRACE check above proves nothing",
				w.name, w.mask)
		}
	}
}

// TestEveryThreadOfTheStageHasTheReducedBoundingSet is the regression test
// for dropFromBounding's own measurement: PR_CAPBSET_DROP is per-THREAD, and
// a caller that ran it anywhere other than on the locked thread immediately
// before the execve (say, a "simplification" that moved the call into
// MainServe, after the Go runtime has already spun up its usual pool) would
// leave every thread but the caller's still holding the bit while
// /proc/<pid>/status — which reports only the group leader — reads clean.
// This is what catches that: it reads every entry under
// /proc/<pid>/task/*/status directly, the same file requireCapDropped itself
// sweeps, but from OUTSIDE the process being checked.
func TestEveryThreadOfTheStageHasTheReducedBoundingSet(t *testing.T) {
	st := startBareStage(t)

	taskDir := "/proc/" + strconv.Itoa(st.Pid()) + "/task"
	tids, err := os.ReadDir(taskDir)
	if err != nil {
		t.Fatalf("reading %s: %v", taskDir, err)
	}
	if len(tids) == 0 {
		t.Fatal("PRECONDITION: /proc/<pid>/task listed zero threads — the sweep below would " +
			"pass vacuously")
	}

	for _, tid := range tids {
		path := taskDir + "/" + tid.Name() + "/status"
		bnd := readCapWord(t, path, "CapBnd")
		if bnd&(1<<capSysPtraceBit) != 0 {
			t.Errorf("thread %s: CapBnd=%#x still holds CAP_SYS_PTRACE — a per-thread drop "+
				"that missed this thread would leave it able to ptrace a peer in U even "+
				"though /proc/%d/status (the group leader) reads clean",
				tid.Name(), bnd, st.Pid())
		}
	}
}
