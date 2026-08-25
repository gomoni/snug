package stage

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gomoni/snug/internal/bwrapinfo"
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
//  6. serve AT MOST TWO requests, then exit: one "netready" (optional to send,
//     mandatory to have succeeded before "start" is accepted), and one "start",
//     after which this function returns whatever the outcome. "start" now emits
//     TWO events rather than one — "enginestarted" while the payload is still
//     parked, then "exited" — because P0 must arm the container reaper between
//     them. THE NUMBER OF REQUESTS is what one-shot means here: there is no
//     third request and no way back, and the loop is not re-entered once a
//     sandbox exists.
func MainServe() error {
	requireFD(fdControl, "control")
	requireFD(fdLife, "lifeline")
	// bwrap's --info-fd read end (issue #125): P1 reads it, P0 no longer holds
	// it. Same instant, same CLOEXEC reasoning as the two descriptors below —
	// from here it reaches a child only by being named in ExtraFiles, and
	// nothing ever names it.
	requireFD(fdBwrapInfo, "bwrap info")
	if err := setCloexec(fdBwrapInfo); err != nil {
		return fmt.Errorf("__stage-serve: marking fd %d CLOEXEC: %w", fdBwrapInfo, err)
	}

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
	// Same reasoning, same frame: bwrap's --info-fd read end must still be a
	// live descriptor when the one "start" request arrives, however long
	// "netready" took.
	infoR := os.NewFile(uintptr(fdBwrapInfo), "bwrap-info")

	userns := nsID("user")
	if err := sendEvent(control, event{Op: "ready", Netns: pinned, Userns: userns, NetnsFD: fdNetnsN}); err != nil {
		return fmt.Errorf("__stage-serve: reporting ready: %w", err)
	}

	// At most two requests, and the shape is a small state machine rather than
	// a loop ON PURPOSE. "start" is strictly one-shot: it runs the sandbox and
	// this function returns, whatever the outcome. "netready" is the one thing
	// that may legitimately precede it, and it may be asked ONCE.
	//
	// The engine's start used to be a third request, answered without ending
	// this function (issue #63, Tier B). Issue #125's gate folded it INTO
	// "start", and that is a security property regained rather than a tidy-up:
	// a request answered without returning is a request after which recvRequest
	// runs AGAIN, with a fully built sandbox on the other side. A loop would
	// have been shorter and would have quietly turned a one-shot stage into a
	// server. The channel has no name and no listener, so nothing could reach
	// it to abuse that today — which is precisely the argument that would let
	// it rot into Phase 2, when there IS a second client.
	netReadyAsked, netReadyOK := false, false
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
		case "start":
			// The property this whole ordering exists to establish — no payload
			// exists before its network is confirmed — must be enforced HERE and
			// not only by the order of calls in P0. It covers the engine too,
			// now that the engine's fork happens inside this request: the engine
			// shares N, so it must not exist before N is confirmed either (issue
			// #63, Tier B; ENGINE-WIRING.md §1 item 2).
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
				_ = sendEvent(control, event{Op: "enginestarted", Err: err.Error()})
				return err
			}
			return runOneSandbox(control, netnsN, infoR, req)
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
//
// parked.kill() first, and it is not covered by bwrap's --die-with-parent
// (issue #125). On a gated run the sandbox's init is blocked on --block-fd and
// has not armed its pdeathsig yet — measured: it survives the death of the
// bwrap that forked it, still parked, still releasable. Two paths reach here
// and both need it: P0 abandoning a run between "the engine is up" and the
// release byte (it returns an error and its deferred Close() drops the
// lifeline), and P0 being SIGKILLed outright, where this goroutine is racing
// P1's own Pdeathsig and — measured 20/20 — wins, because do_exit closes P0's
// descriptors before it delivers signals. Delete this line and exactly one
// process survives such a kill, 5/5: the parked init, holding N and the whole
// mount tree.
func watchLifeline(f *os.File) {
	buf := make([]byte, 1)
	for {
		n, err := f.Read(buf)
		if n == 0 || err != nil {
			break
		}
	}
	fmt.Fprintln(os.Stderr, "snug: stage: lifeline closed, tearing down")
	parked.kill()
	os.Exit(1)
}

// bwrapInfoTimeout bounds how long P1 waits for bwrap's --info-fd answer.
// bwrap writes it after building the whole mount tree and BEFORE parking on
// --block-fd (measured), so this is generous against a slow host rather than
// against anything a payload could do — on a gated run no payload exists yet.
//
// The cost of the wait falls on P0, which is blocked on the "enginestarted"
// event until this returns. On an UNGATED run that means a bwrap which never
// answers stalls P0 for this long with the payload already running; the signal
// guard is armed by then, so a Ctrl-C in that window is queued rather than
// lost, and the run then reports itself unattachable exactly as it did when P0
// read this descriptor itself.
const bwrapInfoTimeout = 10 * time.Second

// runOneSandbox is the fork: __innetns is the ONLY way a child of P1 gets back
// into N, and it runs on a locked OS thread so the fork and the seal that
// precedes it are atomic with no lock discipline to remember. netnsN is the
// single *os.File MainServe keeps alive at fd 63 for this process's whole
// life (issue #63, Tier B added a SECOND fork, the engine's, and both need the
// same live descriptor — see MainServe's own comment on why it is hoisted
// rather than created fresh here).
//
// THE ORDER IS THE SPECIFICATION, and under issue #125's gate it is the whole
// of invariant 5 for a container run:
//
//  1. fork bwrap. On a gated run its init builds the mount tree and PARKS on
//     --block-fd; no payload exists and none will until P0 writes the release
//     byte.
//  2. arm the gate — before anything below can fail, and while the init's pid
//     is still unknown, because a failure at step 3 must still take the
//     sandbox with it.
//  3. read bwrap's --info-fd answer, which is where the init's pid comes from.
//  4. fork the engine into N and wait for its socket, if one was requested.
//  5. report "enginestarted", carrying the info. THE PAYLOAD IS STILL PARKED at
//     this point: P0 arms the container reaper and only then releases it.
//  6. reap the payload, report "exited".
//
// Every failure in 1-4 kills bwrap AND the init and reports the error, so the
// payload never existed rather than existing briefly on a run that was already
// doomed.
func runOneSandbox(control, netnsN, infoR *os.File, req request) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// One failure shape for every way this request can fail to produce a
	// payload — see the event schema in proto.go on why "enginestarted" is the
	// name even for a run with no engine.
	fail := func(err error) error {
		_ = sendEvent(control, event{Op: "enginestarted", Err: err.Error()})
		return err
	}

	if req.Bwrap == "" {
		return fail(fmt.Errorf("__stage-serve: malformed start request: no bwrap path"))
	}
	// Passthrough arrives over the control socket, so it is INPUT here, not a
	// local fact — P0 checked the same bound against the resolved policy, and
	// this side checks it again because the two are different trust positions.
	// An over-large count would make the loop below wrap an *os.File around
	// fd 63 and pass the pinned netns descriptor to bwrap as though it were one
	// of the sandbox's own.
	if err := checkFDBudget(req.Passthrough); err != nil {
		return fail(fmt.Errorf("__stage-serve: %w", err))
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
		return fail(err)
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
		return fail(startErr)
	}

	// A sandbox exists from here on, and on a gated run its payload does not.
	// Armed BEFORE the info read, with the init's pid still unknown, because a
	// failure in that read is exactly the abort path that has no pid to name —
	// see parkedSandbox.kill's PPid fallback.
	if req.Gated {
		parked.arm(cmd.Process, 0)
	}

	// bwrap is reaped ONCE, by this goroutine, and everything below waits on
	// waitDone rather than calling cmd.Wait() itself — a second Wait is an
	// error, and the abort paths and the ordinary exit path both need the reap.
	// waitErr is written before the close and read only after a receive, which
	// is what makes it race-free.
	var waitErr error
	waitDone := make(chan struct{})
	go func() { waitErr = cmd.Wait(); close(waitDone) }()

	// Whatever went wrong from here on, the sandbox goes with it. Kill and reap
	// before answering, so that P0's error and the death of the sandbox are not
	// two things a reader has to hope happen in the right order.
	takeDown := func() {
		if req.Gated {
			parked.kill()
		}
		_ = cmd.Process.Kill()
		<-waitDone
		parked.disarm()
	}
	abort := func(err error) error {
		takeDown()
		return fail(err)
	}

	// The info read is raced against bwrap's own death, and that race is not a
	// nicety: bwrap answers --info-fd or it exits, and waiting out the timeout
	// for an answer from a process that is already gone turns a fast failure
	// into a ten-second one. Measured as a regression when it was not raced —
	// TestTheStageExitsWhenTheSandboxFailsToStart, a fake bwrap that exits 7,
	// went from instant to bwrapInfoTimeout.
	type infoResult struct {
		info bwrapinfo.Info
		err  error
	}
	infoCh := make(chan infoResult, 1)
	go func() {
		i, e := bwrapinfo.Read(infoR, bwrapInfoTimeout)
		infoCh <- infoResult{i, e}
	}()

	var info bwrapinfo.Info
	var infoErr error
	select {
	case r := <-infoCh:
		info, infoErr = r.info, r.err
	case <-waitDone:
		infoErr = fmt.Errorf("bwrap exited before answering on --info-fd")
	}

	if req.Gated {
		parked.setInit(info.InitPID)
		// Fatal on a gated run, and only there. Without the init's pid this
		// process cannot promise to take the parked payload down with it, and
		// releasing a payload nobody can supervise is worse than refusing the
		// run — invariant 5. On an ungated run the same failure has always been
		// warn-only ("this run will not be attachable"): the payload is already
		// running and there is nothing left to gate.
		if infoErr != nil {
			return abort(fmt.Errorf("__stage-serve: the sandbox's payload is parked and this "+
				"stage cannot learn which process to release or kill: %w", infoErr))
		}
		if info.InitPID <= 1 {
			return abort(fmt.Errorf("__stage-serve: bwrap's --info-fd answer named child-pid %d, "+
				"which is not a process this stage can hold", info.InitPID))
		}
	}

	// The engine, EAGERLY and inside this one request: it shares N with the
	// sandbox, and on a gated run it starts while the payload is still parked,
	// so "the engine is confined to N" is a precondition of the payload
	// existing at all rather than a race against it (issue #63 Tier B, issue
	// #125 C2). Absent EnginePodman means no container profile is selected and
	// there is simply no engine in this run.
	if req.EnginePodman != "" {
		// WAIT FIRST, and this is not a nicety. bwrap answers --info-fd long
		// before it has finished: MEASURED at that moment, the init's mount
		// namespace held 816 mounts with the whole HOST TREE at /oldroot and a
		// writable root, settling ~150ms later to 44 mounts rooted at
		// /newroot, read-only. An engine that joined at the early moment and
		// unshared would keep a private copy of the host tree FOREVER — in the
		// one namespace the derived view exists to keep host-free.
		if err := waitForSandboxMounts(info.InitPID, sandboxMountsTimeout); err != nil {
			return abort(err)
		}
		if err := startEngine(netnsN, info.InitPID, req); err != nil {
			return abort(err)
		}
	}

	// Last look before reporting success on a gated run: a bwrap that has died
	// in the meantime has taken the release pipe's reader with it (or left the
	// init parked behind it), and reporting "ready to release" for it would put
	// P0's byte nowhere. Non-blocking — this asks whether it is ALREADY gone,
	// never waits for it to go.
	if req.Gated {
		select {
		case <-waitDone:
			return abort(fmt.Errorf("__stage-serve: bwrap exited before its parked payload " +
				"could be released"))
		default:
		}
	}

	if err := sendEvent(control, event{
		Op:         "enginestarted",
		InitPID:    info.InitPID,
		Namespaces: info.Namespaces,
	}); err != nil {
		// The one failure that cannot be REPORTED, so it has to be acted on. On
		// a gated run P0 will now never write the release byte — it never
		// learned there was one to write — and a payload parked forever behind
		// a stage that is about to exit is precisely the orphan this file kills
		// explicitly everywhere else.
		takeDown()
		return fmt.Errorf("__stage-serve: reporting enginestarted: %w", err)
	}

	<-waitDone
	// bwrap has been reaped, so its pid names nothing from here on. Dropped
	// immediately: see parkedSandbox.disarm.
	parked.disarm()
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

// sandboxMountsTimeout bounds waitForSandboxMounts. Measured on this host at
// 115ms and 184ms across runs, so ten seconds is not a performance target: it
// is the point at which "bwrap is still setting up" stops being a plausible
// explanation and the run should say so rather than keep polling.
const sandboxMountsTimeout = 10 * time.Second

// waitForSandboxMounts blocks until bwrap has performed every mount snug asked
// for, so the engine can join the sandbox's mount namespace and get the view
// the payload will get — rather than the half-built one bwrap is still holding
// when it answers --info-fd.
//
// THE SIGNAL IS SNUG'S OWN, which is what makes it sound rather than a sleep
// with a justification. `--remount-ro /` is the LAST filesystem operation
// BwrapFlags emits (see its own comment: every --dir, every bind and every
// tmpfs precedes it, because nothing could be created afterwards), so the
// init's ROOT MOUNT turning read-only means the argv's filesystem section has
// been executed to the end and pivot_root is done.
//
// It reads the target's mountinfo from OUTSIDE, without joining: a process that
// joined to look would be the very process this exists to keep out of the
// half-built namespace.
//
// MEASURED, and the numbers are the reason this function is not a comment
// saying "bwrap is probably ready by now" (issue #125's derived-view pass):
//
//	t+0ms     816 mounts, root "/"        rw   <- the whole host tree, /oldroot present
//	t+300ms    44 mounts, root "/newroot" ro   <- the sandbox's own view
//
// A timeout here is FATAL to the run (invariant 5). The alternative — start the
// engine anyway — is exactly the case above: an engine holding the host tree,
// with nothing on screen saying so.
func waitForSandboxMounts(initPID int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		ro, err := rootMountIsReadOnly(initPID)
		if err == nil && ro {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("__stage-serve: the sandbox's mounts were not finished %s after "+
				"bwrap reported its init (pid %d): its root mount is still writable, which means "+
				"`--remount-ro /` has not run and the namespace may still hold the host tree.\n"+
				"      Refusing to start the container engine rather than joining a half-built "+
				"view (last error: %v)", timeout, initPID, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// rootMountIsReadOnly reports whether pid's mount namespace has its ROOT mount
// mounted read-only. Parsed from /proc/<pid>/mountinfo field 5 (the mount
// point) and field 6 (the per-mount options), which is the only place the
// distinction is visible without joining.
func rootMountIsReadOnly(pid int) (bool, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return false, err
	}
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) < 6 || f[4] != "/" {
			continue
		}
		for _, opt := range strings.Split(f[5], ",") {
			if opt == "ro" {
				return true, nil
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("no mount at / in /proc/%d/mountinfo", pid)
}
