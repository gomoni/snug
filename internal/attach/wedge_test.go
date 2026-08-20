//go:build forkstress

// Package attach's stress arm, behind the `forkstress` build tag and run as its
// own CI job (`make forkstress`) rather than in `go test ./...`.
//
// The tag is about COST, not about confidence: the test below deliberately runs
// a stop-the-world storm and forks up to 240 processes, which is seconds of a
// loaded machine to re-prove a property that changes only when internal/attach's
// fork path changes. Its structural twin — TestEveryFunctionOnTheChildPathIsNosplit
// in nosplit_test.go, untagged, 0.00s — is the one that guards the everyday
// regression (a pragma dropped, a splittable call added), and that one stays in
// the default suite.

package attach

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestForkChildNeverWedgesUnderPreemptionPressure is issue #221's permanent
// regression test, and the failure it reproduces is a HANG rather than a
// wrong answer — so read the control arm first: without it this test passes
// on a machine that never provoked the condition at all, which is the exact
// "test that cannot fail" CLAUDE.md warns about.
//
// THE DEFECT. B is created by a raw clone(2) from a multithreaded Go program
// (see the package comment for why it must be). The child inherits the
// forking goroutine's stackguard0 — which the runtime POISONS with
// stackPreempt on every stop-the-world and on any sysmon retake of a
// goroutine that has run for 10ms. An ordinary Go function's prologue
// compares SP against that value before its first statement, calls
// runtime.newstack when it loses the comparison, and asks the scheduler for
// threads the fork did not copy. Measured on the two `snug attach` clients
// found alive hours after their caller died: Threads=1, wchan=futex_do_wait,
// SigBlk=0, NoNewPrivs=0, Seccomp=0, the caller's own namespaces — a B that
// had not executed one instruction of child()'s step 1, which is also before
// step 2's PDEATHSIG, which is why killing C did not clean it up. C, for its
// part, was still blocked in its report-pipe read: the visible symptom, a
// `snug attach` that never returns.
//
// THE ARMS.
//
//   - Control: a fork child whose first call is an ordinary splittable
//     function, forked by this same harness under this same pressure. At
//     least one round MUST wedge. If none does, the pressure is not
//     provoking preemption on this host and the real arm below would pass
//     for the wrong reason — that is a failure of this test, and it says so.
//   - Real: Start's own child, which runs child() for real as far as the
//     setns (refused, because the pidfd names this very process, so the
//     namespace to join is the one we are in). Every round must reach that
//     refusal — exit status 3 — and none may wedge. Exit status 3 is the
//     marker: it can only be reached by executing steps 1 through 5, so a
//     round that merely "exited" cannot be mistaken for one that ran.
func TestForkChildNeverWedgesUnderPreemptionPressure(t *testing.T) {
	stop := preemptionPressure(t)
	defer stop()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// CONTROL, first: prove this harness provokes the condition at all.
	const controlRounds = 200
	wedgedAt := -1
	for i := range controlRounds {
		if wedgedAt >= 0 {
			break
		}
		if forkSplittableChildWedges(t) {
			wedgedAt = i
		}
	}
	if wedgedAt < 0 {
		t.Fatalf("control: %d fork children whose first call is an ordinary splittable "+
			"function all completed under stop-the-world pressure, so this host did not "+
			"provoke the preempt request issue #221 depends on and the assertion below "+
			"proves nothing. Repair the harness (more pressure, more rounds) — do NOT "+
			"delete the control, and do not read this as the defect being fixed",
			controlRounds)
	}
	t.Logf("control: a splittable fork child wedged on round %d — the pressure is real", wedgedAt)

	// REAL: the production path, same pressure, same thread.
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatalf("pidfd_open on this very process: %v", err)
	}
	defer unix.Close(pidfd)

	reportR, reportW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reportR.Close()
	defer reportW.Close()
	gateR, gateW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer gateR.Close()
	defer gateW.Close()

	const realRounds = 40
	for i := range realRounds {
		cfg := &Config{
			PidFD:      pidfd,
			CapLastCap: 40,
			Chdir:      "/",
			Argv0:      "/nonexistent",
			Argv:       []string{"/nonexistent"},
			Envp:       []string{},
			Stdin:      int(reportW.Fd()),
			Stdout:     int(reportW.Fd()),
			Stderr:     int(reportW.Fd()),
			ReportW:    int(reportW.Fd()),
			GateR:      int(gateR.Fd()),
		}
		pid, err := Start(cfg)
		if err != nil {
			t.Fatalf("round %d: Start: %v", i, err)
		}
		status, ok := reapWithin(pid, 10*time.Second)
		if !ok {
			state := procField(pid, "State")
			wchan, _ := os.ReadFile("/proc/" + itoa(pid) + "/wchan")
			sigblk := procField(pid, "SigBlk")
			unix.Kill(pid, unix.SIGKILL)
			var ws unix.WaitStatus
			unix.Wait4(pid, &ws, 0, nil)
			t.Fatalf("round %d: the bridge process (pid %d) never exited: State=%q wchan=%q "+
				"SigBlk=%q. This is issue #221: a fork child that entered the Go runtime "+
				"before running one instruction of its own sequence. Check that child() and "+
				"everything it calls still carry //go:nosplit",
				i, pid, state, strings.TrimSpace(string(wchan)), sigblk)
		}
		if !status.Exited() || status.ExitStatus() != 3 {
			t.Fatalf("round %d: the bridge exited %v, want exit status 3 (setns refused, the "+
				"only way out of child() for a pidfd naming this same process). Some other "+
				"status means the child stopped somewhere earlier, and this round proved "+
				"nothing about the path it was supposed to run", i, status)
		}
	}
}

// preemptionPressure starts the stop-the-world storm the control arm needs:
// a goroutine calling runtime.GC() (every STW calls preemptall, which is what
// poisons a running goroutine's stackguard0) plus enough spinners to keep
// other goroutines genuinely running when it does. Returns the stop function.
func preemptionPressure(t *testing.T) func() {
	t.Helper()
	done := make(chan struct{})
	spinners := max(runtime.NumCPU()/2, 1)
	for range spinners {
		go func() {
			x := 0
			for {
				select {
				case <-done:
					return
				default:
				}
				for range 100000 {
					x++
				}
				runtime.Gosched()
			}
		}()
	}
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			runtime.GC()
		}
	}()
	var once bool
	return func() {
		if !once {
			once = true
			close(done)
		}
	}
}

// forkSplittableChildWedges is the control: the same raw clone Start makes,
// with a child whose first call is deliberately an ORDINARY function. It
// reports whether that child failed to write its one byte within a bound —
// i.e. whether it wedged the way issue #221's B did.
func forkSplittableChildWedges(t *testing.T) bool {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	fd := int(w.Fd()) // in the PARENT: os.File.Fd() takes locks of its own

	pid, _, errno := unix.RawSyscall6(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0, 0, 0, 0)
	if errno != 0 {
		t.Fatalf("control: clone: %v", errno)
	}
	if pid == 0 {
		splittableChild(fd)
		for {
			unix.RawSyscall(unix.SYS_EXIT_GROUP, 127, 0, 0)
		}
	}

	_, ok := reapWithin(int(pid), 2*time.Second)
	if !ok {
		unix.Kill(int(pid), unix.SIGKILL)
		var ws unix.WaitStatus
		unix.Wait4(int(pid), &ws, 0, nil)
		return true
	}
	return false
}

// splittableChild is everything child() is not: an ordinary Go function, so
// its prologue consults the stackguard0 the fork carried over. //go:noinline
// because an inlined body has no prologue and would make this control unable
// to demonstrate the very thing it exists to demonstrate.
//
//go:noinline
func splittableChild(fd int) {
	var b [1]byte
	b[0] = 'C'
	unix.RawSyscall(unix.SYS_WRITE, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), 1)
	for {
		unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
	}
}

// reapWithin polls waitpid(WNOHANG) until pid is reaped or d elapses. Polling
// rather than blocking: a wedged child never exits, and the whole point is to
// notice that within a bound instead of joining it.
func reapWithin(pid int, d time.Duration) (unix.WaitStatus, bool) {
	deadline := time.Now().Add(d)
	for {
		var ws unix.WaitStatus
		got, err := unix.Wait4(pid, &ws, unix.WNOHANG, nil)
		if err == nil && got == pid {
			return ws, true
		}
		if time.Now().After(deadline) {
			return ws, false
		}
		time.Sleep(time.Millisecond)
	}
}

func procField(pid int, key string) string {
	b, err := os.ReadFile("/proc/" + itoa(pid) + "/status")
	if err != nil {
		return "?"
	}
	for ln := range strings.SplitSeq(string(b), "\n") {
		if strings.HasPrefix(ln, key+":") {
			return strings.TrimSpace(ln[len(key)+1:])
		}
	}
	return "(absent)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
