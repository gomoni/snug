package stage

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"

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
//  6. serve AT MOST THREE requests, then exit: one "netready" (optional to
//     send, mandatory to have succeeded before "startengine" or "start" is
//     accepted), one "startengine" (issue #63, Tier B — optional, and does
//     NOT end the loop), and one "start", after which this function returns
//     whatever the outcome. everRan does not exist as a concept — there is no
//     fourth request and no way back.
func MainServe() error {
	requireFD(fdControl, "control")
	requireFD(fdLife, "lifeline")

	if err := setCloexec(fdNetnsN); err != nil {
		return fmt.Errorf("__stage-serve: marking fd %d CLOEXEC: %w", fdNetnsN, err)
	}
	// Same instant, same reason, for the socket that still speaks to N: from
	// here it reaches a child only by being named in ExtraFiles, and nothing
	// ever names it. A descriptor that can query N is not something bwrap or a
	// payload has any business inheriting.
	requireFD(fdNetSock, "N socket")
	if err := setCloexec(fdNetSock); err != nil {
		return fmt.Errorf("__stage-serve: marking fd %d CLOEXEC: %w", fdNetSock, err)
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

	// Hoisted here, once, rather than created fresh per fork: issue #63, Tier B
	// adds a SECOND fork to this process's life (the engine, before the
	// sandbox), and both need fd 63 to still be a live, open descriptor when
	// their own turn comes. os.NewFile sets a runtime finalizer that closes
	// the underlying fd when the *os.File is garbage collected; a short-lived
	// local recreated per fork (the pre-Tier-B shape) would risk that
	// finalizer firing on the FIRST one before the SECOND fork ever reads it.
	// Keeping the single value alive in this function's own frame for the
	// whole loop below is what rules that out.
	netnsN := os.NewFile(uintptr(fdNetnsN), "netns-N")

	userns := nsID("user")
	if err := sendEvent(control, event{Op: "ready", Netns: pinned, Userns: userns, NetnsFD: fdNetnsN}); err != nil {
		return fmt.Errorf("__stage-serve: reporting ready: %w", err)
	}

	// At most three requests, and the shape is a small state machine rather
	// than a loop ON PURPOSE. "start" is still strictly one-shot — it runs the
	// sandbox and this function returns, whatever the outcome, exactly as
	// before. "netready" is the one thing that may legitimately precede it,
	// and it may be asked ONCE. "startengine" (issue #63, Tier B) may also be
	// asked once, strictly after "netready" and strictly before "start" — and,
	// unlike both of those, answering it does NOT end this function: the
	// engine is a second long-lived child of P1, alongside bwrap, not this
	// stage's one payload.
	//
	// A loop would have been shorter and would have quietly turned a one-shot
	// stage into a server. The channel has no name and no listener, so nothing
	// could reach it to abuse that today — which is precisely the argument that
	// would let it rot into Phase 2, when there IS a second client.
	netReadyAsked, netReadyOK := false, false
	engineAsked := false
	for {
		req, err := recvRequest(control)
		if err != nil {
			return fmt.Errorf("__stage-serve: reading control request: %w", err)
		}
		switch req.Op {
		case "stop":
			return nil
		case "netready":
			if netReadyAsked {
				return fmt.Errorf("__stage-serve: \"netready\" asked twice; this stage answers it once")
			}
			netReadyAsked = true
			iface := req.NetIface
			if iface == "" {
				iface = NetIfaceName
			}
			ev := event{Op: "netready"}
			if err := waitForIface(fdNetSock, iface, netReadyTimeout); err != nil {
				ev.Err = err.Error()
			}
			if err := sendEvent(control, ev); err != nil {
				return fmt.Errorf("__stage-serve: reporting netready: %w", err)
			}
			if ev.Err != "" {
				// Answered honestly, then stop: there is no point holding a
				// namespace open for a sandbox whose network never arrived, and
				// P0 is about to tear us down anyway.
				return fmt.Errorf("__stage-serve: %s", ev.Err)
			}
			netReadyOK = true
		case "startengine":
			// Same enforcement, same reasoning, as "start" below: the engine
			// shares N, so it must not exist before N is confirmed either
			// (issue #63, Tier B; ENGINE-WIRING.md §1 item 2 — invariant 5
			// lands the refusal before any payload, or engine, exists).
			if !netReadyOK {
				err := fmt.Errorf("__stage-serve: refusing \"startengine\" before a successful " +
					"\"netready\": the engine must not join a network that is not confirmed up")
				_ = sendEvent(control, event{Op: "enginestarted", Err: err.Error()})
				return err
			}
			if engineAsked {
				err := fmt.Errorf("__stage-serve: \"startengine\" asked twice; this stage answers it once")
				_ = sendEvent(control, event{Op: "enginestarted", Err: err.Error()})
				return err
			}
			engineAsked = true
			if err := startEngine(control, netnsN, req); err != nil {
				return err
			}
		case "start":
			// The property this whole ordering exists to establish — no payload
			// exists before its network is confirmed — must be enforced HERE and
			// not only by the order of calls in P0.
			//
			// A red team found it stated nowhere but in runStaged's call
			// sequence, which is the wrong place: proto.go's own header calls
			// this "the enforcement point Phase 2 inherits", and Phase 2 gives
			// the stage a pathname socket and a second client. A stolen or
			// confused client that sends "start" first would otherwise get a
			// sandbox in an unconfigured namespace, with no netready ever asked.
			if !netReadyOK {
				err := fmt.Errorf("__stage-serve: refusing \"start\" before a successful " +
					"\"netready\": a payload must not exist before its network is confirmed")
				_ = sendEvent(control, event{Op: "started", Err: err.Error()})
				return err
			}
			return runOneSandbox(control, netnsN, req)
		default:
			return fmt.Errorf("__stage-serve: unknown control op %q", req.Op)
		}
	}
}

// NetIfaceName is the interface pasta creates inside N. It is not a guess: snug
// passes `--ns-ifname snug0` itself (internal/policy/net.go), so the name is
// snug's own and the readiness check can be an exact lookup rather than an
// enumeration. If that flag ever changes, this must change with it —
// TestStageWaitsForTheInterfaceSnugItselfNames is what makes that fail loudly.
//
// Exported (issue #63, Tier B): internal/sandbox's runStaged is what now
// decides, from the resolved policy's Net.Mode, whether "netready" should
// wait for THIS interface or for "lo" — see WaitNetReady's own doc comment.
const NetIfaceName = "snug0"

// netReadyTimeout bounds how long the stage waits for pasta to configure its
// interface. Generous against a loaded host, and it is an upper bound rather
// than an expectation: measured, the interface appears in well under 100ms.
const netReadyTimeout = 10 * time.Second

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
// precedes it are atomic with no lock discipline to remember. netnsN is the
// single *os.File MainServe keeps alive at fd 63 for this process's whole
// life (issue #63, Tier B added a SECOND fork, the engine's, ahead of this
// one, and both need the same live descriptor — see MainServe's own comment
// on why it is hoisted rather than created fresh here).
func runOneSandbox(control, netnsN *os.File, req request) error {
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
	// TestTheStageClosesTheSandboxsDescriptorsAtTheFork is the positive-controlled
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
