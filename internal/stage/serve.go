package stage

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"

	"github.com/gomoni/snug/internal/fdseal"
)

// MainServe is __stage-serve: P1 after the move — same pid, same mount/user/cgroup
// namespaces, a fresh empty netns of its own, and ONE descriptor (fdNetnsN) on
// N. THE ORDER IS THE SPECIFICATION:
//
//  1. mark fdNetnsN CLOEXEC — the first moment CLOEXEC means what the plan
//     intends: from here the only way that descriptor reaches a child is by
//     being named in ExtraFiles.
//  2. sweep /proc/self/task/*/ns/net and refuse unless ZERO threads remain in
//     the pinned namespace — reading /proc/self/ns/net here checks nothing;
//     measured, it reports the OLD namespace, scheduler-dependently.
//  3. validate the descriptor with NS_GET_NSTYPE.
//  4. start the lifeline watcher.
//  5. send "ready" on the control socket, carrying the pinned netns id, the
//     userns id and the fd number.
//  6. serve exactly one request, then exit — whatever that request's outcome.
//     everRan does not exist as a concept: this function returns after one
//     request, full stop.
func MainServe() error {
	requireFD(fdControl, "control")
	requireFD(fdLife, "lifeline")

	if err := setCloexec(fdNetnsN); err != nil {
		return fmt.Errorf("__stage-serve: marking fd %d CLOEXEC: %w", fdNetnsN, err)
	}

	pinned := fdNS(fdNetnsN)
	if pinned == "" {
		return fmt.Errorf("__stage-serve: fd %d does not name a namespace", fdNetnsN)
	}
	if err := validateNetnsFD(fdNetnsN); err != nil {
		return fmt.Errorf("__stage-serve: %w", err)
	}

	stuck, err := threadsInNamespace(pinned)
	if err != nil {
		return fmt.Errorf("__stage-serve: %w", err)
	}
	if len(stuck) > 0 {
		return fmt.Errorf("__stage-serve: %d thread(s) are still in the pinned namespace %s "+
			"(tids %v) — the move did not survive the exec into __stage-serve", len(stuck), pinned, stuck)
	}

	control := os.NewFile(fdControl, "control")
	life := os.NewFile(fdLife, "lifeline")
	go watchLifeline(life)

	userns := nsID("user")
	if err := sendEvent(control, event{Op: "ready", Netns: pinned, Userns: userns, NetnsFD: fdNetnsN}); err != nil {
		return fmt.Errorf("__stage-serve: reporting ready: %w", err)
	}

	req, err := recvRequest(control)
	if err != nil {
		return fmt.Errorf("__stage-serve: reading control request: %w", err)
	}
	switch req.Op {
	case "stop":
		return nil
	case "start":
		return runOneSandbox(control, req)
	default:
		return fmt.Errorf("__stage-serve: unknown control op %q", req.Op)
	}
}

// watchLifeline is the teardown trigger for the case where P1 can still run
// code. P0 holds the write end of the lifeline pipe and never writes to it, so
// the read end closing (EOF) says P0 is gone however it went — including
// SIGKILL, which gives it no chance to signal anyone. os.Exit terminates P1
// immediately regardless of what the main goroutine is doing, which in turn
// makes bwrap's OWN --die-with-parent fire: bwrap's real parent, across every
// exec in this chain, is P1.
//
// This comment used to claim the lifeline is the ONLY signal, because
// Pdeathsig does not survive the setup->serve re-exec (secureexec zeroing
// pdeath_signal when the permitted set is not a subset of the old one).
// MEASURED FALSE, round 3 — capabilities do not widen at that exec, so there is
// no secureexec and Pdeathsig is preserved. Keep both mechanisms and keep them
// distinct: this one covers a LIVE P1, and Pdeathsig covers a stopped one,
// which cannot read anything and so can never see this EOF. See the comment on
// Pdeathsig in stage.go.
func watchLifeline(f *os.File) {
	buf := make([]byte, 1)
	for {
		n, err := f.Read(buf)
		if n == 0 || err != nil {
			break
		}
	}
	fmt.Fprintln(os.Stderr, "snug: stage: lifeline closed, tearing down")
	os.Exit(1)
}

// runOneSandbox is the fork: __innetns is the ONLY way a child of P1 gets back
// into N, and it runs on a locked OS thread so the fork and the seal that
// precedes it are atomic with no lock discipline to remember — Phase 1 has
// exactly one fork, so a dedicated persistent forker goroutine buys nothing
// today; Phase 2 adding more forks is why the discipline is established now
// rather than later.
func runOneSandbox(control *os.File, req request) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if req.Bwrap == "" {
		err := fmt.Errorf("__stage-serve: malformed start request: no bwrap path")
		_ = sendEvent(control, event{Op: "started", Err: err.Error()})
		return err
	}
	// Passthrough arrives over the control socket, so it is INPUT here, not a
	// local fact — P0 checked the same bound against the resolved policy, and
	// this side checks it again because the two are different trust positions.
	// An over-large count would make the loop below wrap an *os.File around
	// fd 63 and pass the pinned netns descriptor to bwrap as though it were one
	// of the sandbox's own.
	if err := checkFDBudget(req.Passthrough); err != nil {
		err = fmt.Errorf("__stage-serve: %w", err)
		_ = sendEvent(control, event{Op: "started", Err: err.Error()})
		return err
	}

	sandboxFDs := make([]*os.File, req.Passthrough)
	for i := range sandboxFDs {
		sandboxFDs[i] = os.NewFile(uintptr(fdSandboxBase+i), fmt.Sprintf("sandbox-fd-%d", i))
	}
	netnsN := os.NewFile(uintptr(fdNetnsN), "netns-N")

	// ExtraFiles puts the sandbox's descriptors at 3..3+K-1 in the FINAL bwrap
	// child — exactly the numbers P0 baked into the args memfd — and the netns
	// descriptor last, so __innetns's own argument is the only number that has
	// to be computed.
	argv := append([]string{"__innetns", strconv.Itoa(3 + len(sandboxFDs)), req.Bwrap}, req.Argv...)
	cmd := exec.Command("/proc/self/exe", argv...)
	cmd.Args[0] = "snug"
	cmd.ExtraFiles = append(append([]*os.File{}, sandboxFDs...), netnsN)
	cmd.Env = []string{}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	// No SysProcAttr{PidFD: ...} here. It used to request one into a local that
	// went out of scope unread and unclosed, so P1 held two pidfds for its one
	// child: Go's own (os.Process is pidfd-backed, and every kill and wait
	// already goes through it) and a second with no consumer. Phase 2's pidfd
	// table is the thing that would justify one; it can request it at the point
	// it has something to do with it.

	if err := fdseal.SealFor(cmd); err != nil {
		_ = sendEvent(control, event{Op: "started", Err: err.Error()})
		return err
	}

	startErr := cmd.Start()

	// P1 closes its OWN copies of the sandbox's descriptors the instant the
	// fork returns — whatever the outcome — leaving exactly four open: control,
	// lifeline, netns, and the pidfd Go's own os.Process holds for the child.
	// TestTheStageHoldsFourDescriptorsAtTheFork is the positive-controlled
	// assertion of this line.
	for _, f := range sandboxFDs {
		_ = f.Close()
	}

	if startErr != nil {
		_ = sendEvent(control, event{Op: "started", Err: startErr.Error()})
		return startErr
	}
	if err := sendEvent(control, event{Op: "started"}); err != nil {
		return fmt.Errorf("__stage-serve: reporting started: %w", err)
	}

	waitErr := cmd.Wait()
	var ws syscall.WaitStatus
	if cmd.ProcessState != nil {
		if s, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			ws = s
		}
	}
	ev := event{Op: "exited", WaitStatus: uint32(ws)}
	if waitErr != nil {
		if _, ok := waitErr.(*exec.ExitError); !ok {
			// A genuine failure to reap (not just a non-zero exit), which
			// exec.ExitError already carries in ProcessState.
			ev.Err = waitErr.Error()
		}
	}
	return sendEvent(control, ev)
}
