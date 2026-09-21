package sigseal

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The child half of TestSealClearsWhatExecveWouldOtherwiseCarry, selected by
// an environment variable rather than by a verb in cmd/snug: this package's
// property is about execve and needs no sandbox, no namespace and no
// privilege, so it must stay runnable in the plainest CI lane there is.
const (
	childEnv   = "SNUG_TEST_SIGSEAL_CHILD"
	childSeal  = "seal"
	childPlain = "plain"
)

func TestMain(m *testing.M) {
	switch os.Getenv(childEnv) {
	case childSeal, childPlain:
		child()
	default:
		os.Exit(m.Run())
	}
}

// child stands in for an exec verb. It BLOCKS a signal — the stand-in for a
// mask inherited from whatever started snug, which no shell can set for us —
// and then either seals or does not before exec'ing the reporter.
func child() {
	// LOCKED BEFORE THE MASK IS TOUCHED, and this line is the test's whole
	// correctness. A signal mask is per-THREAD, and execve preserves the mask
	// of the thread that CALLS it — so without the lock the Go scheduler is
	// free to move this goroutine between the block below and the exec at the
	// bottom, and the child then reports the mask of a thread that never
	// blocked anything.
	//
	// It failed exactly that way: the unsealed control expected SigBlk 0x200
	// and got 0x0 on CI (run 35636253285) while passing locally, which is the
	// signature of a race that one scheduler loses and another wins. Seal()
	// itself has always locked first, for this reason; the test did not, so
	// the bug was in the control rather than in the thing under test — and a
	// control that silently reports "nothing was blocked" is one that cannot
	// fail.
	runtime.LockOSThread()

	var block unix.Sigset_t
	// SIGUSR1 is signal 10, bit 9, so 0x200 in the mask words below.
	block.Val[0] = 1 << (uint(syscall.SIGUSR1) - 1)
	if err := unix.PthreadSigmask(unix.SIG_BLOCK, &block, nil); err != nil {
		os.Stderr.WriteString("child: blocking SIGUSR1: " + err.Error() + "\n")
		os.Exit(2)
	}
	if os.Getenv(childEnv) == childSeal {
		if err := Seal(); err != nil {
			os.Stderr.WriteString("child: Seal: " + err.Error() + "\n")
			os.Exit(2)
		}
	}
	err := syscall.Exec("/bin/sh", []string{"sh", "-c",
		`grep -E '^Sig(Blk|Ign):' /proc/self/status`}, []string{})
	os.Stderr.WriteString("child: exec: " + err.Error() + "\n")
	os.Exit(2)
}

// TestSealClearsWhatExecveWouldOtherwiseCarry is the whole of this package's
// claim, and it is written with its own POSITIVE CONTROL in the same run.
//
// "The payload's SigIgn and SigBlk are zero" is exactly the assertion that
// passes when the test never managed to set them in the first place — a
// `trap ""` that the shell declined, a mask the child failed to block — so the
// unsealed arm runs the identical setup and must show BOTH bits set. Without
// it this test cannot fail, which is the failure mode sigseal exists to
// prevent in the product and would be embarrassing to reproduce in its test.
func TestSealClearsWhatExecveWouldOtherwiseCarry(t *testing.T) {
	// 0x2 is SIGINT (signal 2, bit 1); 0x200 is SIGUSR1 (signal 10, bit 9).
	const (
		wantIgnUnsealed = 0x2
		wantBlkUnsealed = 0x200
	)
	for _, tc := range []struct {
		mode         string
		wantIgn      uint64
		wantBlkBits  uint64
		wantBlkExact bool
	}{
		{mode: childPlain, wantIgn: wantIgnUnsealed, wantBlkBits: wantBlkUnsealed},
		{mode: childSeal, wantIgn: 0, wantBlkBits: 0, wantBlkExact: true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			// `trap "" INT` in a shell is the only portable way to hand a
			// child a genuinely IGNORED disposition: Go cannot set SIG_IGN on
			// itself without the rt_sigaction struct this package exists to
			// avoid. The shell execs us, so the dispositions arrive on the
			// process under test rather than on a parent of it.
			cmd := exec.Command("/bin/sh", "-c", `trap "" INT; exec "$0"`, self)
			cmd.Env = append(os.Environ(), childEnv+"="+tc.mode)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child (%s) failed: %v\n%s", tc.mode, err, out)
			}
			ign, blk := parseSigLines(t, string(out))

			if got := ign & wantIgnUnsealed; got != tc.wantIgn {
				t.Errorf("%s: SigIgn SIGINT bit = %#x, want %#x\n"+
					"  full output: %s", tc.mode, got, tc.wantIgn, strings.TrimSpace(string(out)))
			}
			if got := blk & wantBlkUnsealed; got != tc.wantBlkBits {
				t.Errorf("%s: SigBlk SIGUSR1 bit = %#x, want %#x\n"+
					"  full output: %s", tc.mode, got, tc.wantBlkBits, strings.TrimSpace(string(out)))
			}
			// The sealed arm clears the WHOLE mask, not only the bit this
			// test set, because a mask is inherited whole and a seal that
			// cleared one bit would be a seal in name only.
			if tc.wantBlkExact && blk != 0 {
				t.Errorf("%s: SigBlk = %#x, want 0 — Seal clears the whole mask, not one bit\n"+
					"  full output: %s", tc.mode, blk, strings.TrimSpace(string(out)))
			}
		})
	}
}

func parseSigLines(t *testing.T, out string) (ign, blk uint64) {
	t.Helper()
	var sawIgn, sawBlk bool
	for line := range strings.SplitSeq(out, "\n") {
		for _, f := range []struct {
			name string
			dst  *uint64
			seen *bool
		}{{"SigIgn", &ign, &sawIgn}, {"SigBlk", &blk, &sawBlk}} {
			v, cut := strings.CutPrefix(line, f.name+":")
			if !cut {
				continue
			}
			n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				t.Fatalf("parsing %s from %q: %v", f.name, line, err)
			}
			*f.dst, *f.seen = n, true
		}
	}
	if !sawIgn || !sawBlk {
		t.Fatalf("PRECONDITION: the child did not report both SigIgn and SigBlk, so this "+
			"test is checking nothing:\n%s", out)
	}
	return ign, blk
}

func TestStatusSigMaskRefusesAnAbsentField(t *testing.T) {
	// "The file did not say" is not "nothing is ignored": a parse that
	// defaulted to zero here would make Seal a silent no-op on any kernel
	// whose /proc/self/status names the field differently.
	if _, err := statusSigMask("SigDefinitelyNotAField"); err == nil {
		t.Fatal("statusSigMask accepted a field that is not in /proc/self/status")
	}
}

func TestIgnoredSignalsNeverNamesTheTwoThatCannotBeIgnored(t *testing.T) {
	// SIGKILL and SIGSTOP cannot be ignored, so they cannot appear in SigIgn —
	// but signal.Notify on either is a silent no-op in Go, which is exactly
	// the kind of thing that hides a bad mask read. Assert the filter rather
	// than trusting the kernel to keep the bits clear.
	got, err := ignoredSignals()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		if s == syscall.SIGKILL || s == syscall.SIGSTOP {
			t.Errorf("ignoredSignals named %v, which cannot be ignored", s)
		}
	}
}
