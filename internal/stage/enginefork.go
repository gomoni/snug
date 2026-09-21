package stage

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/gomoni/snug/internal/fdseal"
	"github.com/gomoni/snug/internal/runstop"
)

// engineSocketWaitTimeout bounds how long P1 waits for podman's own socket to
// appear on disk after the fork, before reporting the engine as failed to
// start. Generous against a cold overlay-store init (ENGINE-WIRING.md §1:
// "podman system service coming up, ~1-2s, plus overlay store init").
const engineSocketWaitTimeout = 30 * time.Second

// buildEnterEngineArgv is the encode half of __inengine's positional wire
// protocol; parseEnterEngineArgv (inengine.go) is the decode half, and a test
// exercising both is a genuine round trip through the one place either is
// spelled out — not a second, hand-written copy of the encoding that could
// drift from it.
//
// Everything __inengine needs travels on ITS OWN argv, never in an
// environment variable — the same discipline fds.go states for descriptor
// numbers ("nothing travels in the environment") applied to the engine's
// env too: fd 3 (the netns descriptor), fd 4 (the sandbox's mount namespace),
// then the env count and the env pairs themselves, then the two tmpfs size
// bounds (/run, /var/tmp — issue #281), then the graft count and the grafts,
// then the podman path, then podman's own argv.
func buildEnterEngineArgv(req request) []string {
	argv := []string{"__inengine", "3", "4", strconv.Itoa(len(req.EngineEnv))}
	argv = append(argv, req.EngineEnv...)
	argv = append(argv,
		strconv.FormatUint(req.EngineRunSizeBytes, 10),
		strconv.FormatUint(req.EngineVarTmpSizeBytes, 10))
	argv = append(argv, strconv.Itoa(len(req.EngineGrafts)))
	for _, g := range req.EngineGrafts {
		access := "rw"
		if g.ReadOnly {
			access = "ro"
		}
		argv = append(argv, g.Host, g.Guest, access)
	}
	argv = append(argv, req.EnginePodman)
	argv = append(argv, req.EngineArgv...)
	return argv
}

// startEngine forks the container engine (podman `system service`) as a
// SECOND long-lived child of P1, alongside bwrap — EAGERLY, inside the one
// "start" request and while the sandbox's payload is still parked on
// --block-fd (see serve.go's runOneSandbox, issue #125's C2 gate; issue #63
// Tier B is where it came from). See EnterEngine (__inengine, inengine.go) for
// the fork+setns+confine sequence this triggers, and policy.EngineCapBounding
// for the capability set the engine is reduced to.
//
// It reports NOTHING on the control socket. Its caller composes the single
// "enginestarted" event out of this outcome and bwrap's --info-fd answer, and
// — this is the part that must not be moved back in here — kills bwrap and its
// parked init before reporting a failure. A function that answered P0 itself
// would answer before that kill had happened.
//
// It does NOT wait for the engine to EXIT — that would block the state
// machine from ever reaching "start" — only for its socket to appear on
// disk, which is this run's confirmation that setns+mount+capdrop+exec all
// succeeded (podman itself reports nothing back over the control socket; it
// does not know this protocol exists). The engine's own eventual exit — its
// idle timeout firing, or dying WITH P1 via Pdeathsig — is reaped by a
// background goroutine so it never sits as a zombie under P1 for the
// (possibly long) remainder of this run; teardown's own verification is by
// socket path (internal/engine/reap.go), not by this reap.
func startEngine(netnsN *os.File, initPID int, req request, p0 int) error {
	if req.EngineSock == "" {
		return fmt.Errorf("__stage-serve: malformed start request: an engine with no socket path to wait for")
	}
	// The label the graceful stop will scope itself by (issue #174), refused
	// HERE rather than at the reap. A refusal at the reap would be useless:
	// the run has already happened and its containers were never stoppable.
	// Invariant 5 wants a run that cannot keep a capability to say so before
	// it starts, not to lose it quietly at the end.
	//
	// Split's own comment carries the sharp half — an empty VALUE matches
	// every container carrying no such label at all, because the answer-side
	// check is a Go map lookup and a missing key yields "".
	key, value, err := runstop.Split(req.EngineRunLabel)
	if err != nil {
		return fmt.Errorf("__stage-serve: malformed start request: %w", err)
	}
	// AND IT MUST BE THIS RUN'S LABEL, which is the same shape of check as
	// the one runOneSandbox applies to req.Bwrap and for the same stated
	// reason: P0 and P1 are different trust positions, and the door should not
	// be wider than the room. After it, a P0 that is confused or taken over
	// can still decide WHETHER this stage stops its own containers; it cannot
	// point the stop at a peer sandbox's.
	//
	// BE HONEST ABOUT THE SIZE OF IT. req.Bwrap's check removes the step from
	// that premise to "P1 execve's an arbitrary program as root-in-U". This
	// one removes the step to "P1 stops a container belonging to another run
	// of the same uid" — a same-uid denial of service against a store that uid
	// already owns, with no namespace crossed, and a P0 in that state has
	// worse options one field over. It is cheap because the stage already
	// knows both halves: runstop.Key is the only key snug stamps, and p0 was
	// read from getppid() at the top of MainServe.
	if key != runstop.Key || value != strconv.Itoa(p0) {
		return fmt.Errorf("__stage-serve: refusing a \"start\" whose run label is %q: this stage "+
			"stops the containers of the run that forked it, which is %s=%d — a label naming "+
			"anything else is a caller bug or a confused client, and acting on it would let one "+
			"run reach into another's containers",
			req.EngineRunLabel, runstop.Key, p0)
	}
	// An engine implies a GATED run, structurally: internal/sandbox/exec.go
	// creates the --block-fd/--sync-fd pipe only when an EngineSpec is
	// present, and passes release != nil as gated. That implication is what
	// makes "the abort paths need no graceful stop" true — every abort is
	// reached before "enginestarted", so P0 never wrote the release byte, so
	// bwrap's init is still parked and no payload has run, so no container
	// this run created can exist. Checked rather than assumed, because the
	// whole of issue #174 is what happens when an ordering argument is left
	// as prose.
	if !req.Gated {
		return fmt.Errorf("__stage-serve: malformed start request: an engine on an ungated run, " +
			"which would leave this stage's abort paths with containers they cannot account for")
	}
	if len(req.EngineGrafts) == 0 {
		// Fatal, not a silent fallback (invariant 5). Since Tier C the
		// engine's view is DERIVED from the sandbox's, which contains none of
		// this run's store, runroot, socket or configuration — an engine
		// started with no grafts would exec into a namespace where its own
		// binary and every path on its argv resolve to nothing.
		return fmt.Errorf("__stage-serve: malformed start request: an engine with no grafts, " +
			"which cannot see its own store, runroot, socket directory or configuration")
	}

	// The SANDBOX's mount namespace, opened HERE and handed over as a
	// descriptor rather than as a pid: __inengine must not have to trust, or
	// re-resolve, a pid — and by the time this runs the caller has already
	// waited for bwrap to finish every mount snug asked for (see
	// waitForSandboxMounts, and issue #125's measurement of what joining too
	// early hands the engine).
	mntNS, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", initPID))
	if err != nil {
		return fmt.Errorf("__stage-serve: opening the sandbox's mount namespace (pid %d): %w",
			initPID, err)
	}
	defer mntNS.Close()

	argv := buildEnterEngineArgv(req)

	cmd := exec.Command("/proc/self/exe", argv...)
	cmd.Args[0] = "snug"
	cmd.ExtraFiles = []*os.File{netnsN, mntNS}
	cmd.Env = []string{}
	// podman `system service` reads nothing from stdin (Go substitutes
	// /dev/null when Stdin is nil); its stdout is not useful without a
	// terminal attached (discarded, same reason). Stderr is P1's own
	// inherited stderr — ultimately P0's — so an engine that fails after this
	// function has already reported success is not silently invisible.
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr

	// A fresh mount+cgroup+pid namespace at CLONE TIME, not via unshare(2)
	// inside EnterEngine: unshare(CLONE_NEWNS) from a multithreaded Go process
	// returns EINVAL (fs->users != 1, CLAUDE.md's own measured fact), and Go's
	// fork/exec does the clone in the child BEFORE the runtime starts its
	// threads there — exactly how stageCloneflags already gets CLONE_NEWNS for
	// P1 itself. CLONE_NEWUSER is deliberately ABSENT: the engine must
	// INHERIT U (root-in-U, full effective caps from the moment it exists),
	// not create a sibling that would then have no CAP_SYS_ADMIN over N to
	// setns with. CLONE_NEWNET is deliberately ABSENT too: N is joined by
	// setns in EnterEngine, per-task and multithread-safe, never at clone
	// time.
	//
	// CLONE_NEWPID (issue #125's "C0" piece): the engine becomes pid 1 of a
	// FRESH pid namespace, owned by U because this clone carries no
	// CLONE_NEWUSER of its own — exactly the ownership a procfs mount inside
	// it needs (MEASURED: mount(2) of "proc" fails EPERM in a pid namespace
	// with no owning userns of its own; succeeds in one, like this one, that
	// has one). Without this the engine's /proc stays the STAGE's own private
	// COPY of the host's — a live, readable view of every host pid — which is
	// both useless to podman (measured: it reports no processes at all
	// against a foreign pid namespace's numbering) and the precondition
	// issue #55 acceptance item 2 names for reaching a co-resident process's
	// descriptors through /proc/<pid>/fd/N. This flag is the pid-namespace
	// half; the derived mount VIEW and the grafts are EnterEngine's step 4
	// (inengine.go), and C0 is the precondition for them rather than a piece
	// that shipped without them — a procfs mount inside this namespace is what
	// makes the view buildable at all. The stage's own P1 keeps the sandbox's
	// pid namespace unaffected; this flag applies only to the engine's own
	// clone, here.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// CLONE_NEWIPC | CLONE_NEWUTS (issue #182): the engine gets its OWN
		// System V IPC namespace and its OWN UTS namespace, rather than sharing
		// the machine's. Measured before this change (issue #146 inventory):
		// /proc/<engine>/ns/ipc and /ns/uts were byte-for-byte the HOST's,
		// while the payload had its own of each (bwrap --unshare-ipc
		// --unshare-uts). podman reads no host SysV segment and needs no host
		// hostname, so the engine had no use for either — the hole was never
		// argued for, it was simply what this clone flag set happened not to
		// include. It closes a channel that does NOT go through checkCreate: an
		// OCI hook, an unenumerated containers.conf key (#136), or an image
		// config carrying an ipc mode could supply the namespace without the
		// HostConfig field the proxy filters. With this, IpcMode=host and
		// UTSMode=host name the ENGINE's own namespaces, not the machine's, and
		// their proxy refusals drop from sole-guard to defence-in-depth
		// (namespaceModeReason, kept in sync by
		// TestIpcAndUtsReasonsMatchTheEnginesActualCloneflags).
		Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWCGROUP | syscall.CLONE_NEWPID |
			syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		// Cascades the engine's death to whenever P1 dies, however it dies —
		// exit, panic, SIGKILL — exactly as P1's OWN Pdeathsig cascades from
		// P0 (stage.go). Survives the execve into podman below because that
		// exec DROPS capabilities (dropCapsToExactly runs before it): no
		// widening, no secureexec transition, so pdeath_signal is preserved —
		// the same measured fact that keeps P1's own Pdeathsig alive across
		// its own setup->serve re-exec.
		Pdeathsig: syscall.SIGKILL,
	}

	if err := fdseal.SealFor(cmd); err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	// Reap it whenever it eventually exits, in the background — nothing here
	// needs the exit status, and teardown's own verification (by socket path,
	// internal/engine/reap.go) is what actually confirms it is gone, not this
	// reap. Its only job is to stop this process's child from sitting as a
	// zombie under P1 for the rest of what may be a long-lived run.
	go func() { _ = cmd.Wait() }()

	return waitForSocket(req.EngineSock, engineSocketWaitTimeout)
}

// waitForSocket polls for a UNIX socket to appear at path, or the deadline to
// pass. "the process started" and "podman finished getting to a listening
// socket" are different facts — the engine leg of "start" has to
// mean the second one, or a run could release its parked payload believing an
// engine exists that never actually came up.
func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the container engine did not create its socket at %s within %s",
				path, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
