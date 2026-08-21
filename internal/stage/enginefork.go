package stage

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/gomoni/snug/internal/fdseal"
)

// engineSocketWaitTimeout bounds how long P1 waits for podman's own socket to
// appear on disk after the fork, before reporting the engine as failed to
// start. Generous against a cold overlay-store init (ENGINE-WIRING.md §1:
// "podman system service coming up, ~1-2s, plus overlay store init").
const engineSocketWaitTimeout = 30 * time.Second

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
func startEngine(netnsN *os.File, initPID int, req request) error {
	if req.EngineSock == "" {
		return fmt.Errorf("__stage-serve: malformed start request: an engine with no socket path to wait for")
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

	// Everything __inengine needs travels on ITS OWN argv, never in an
	// environment variable — the same discipline fds.go states for descriptor
	// numbers ("nothing travels in the environment") applied to the engine's
	// env too: the resolv.conf path to bind over /etc/resolv.conf, then fd 3
	// (the netns descriptor), then the env count and the env pairs
	// themselves, then the podman path, then podman's own argv. See
	// EnterEngine for the matching decode.
	argv := []string{"__inengine", "3", "4", strconv.Itoa(len(req.EngineEnv))}
	argv = append(argv, req.EngineEnv...)
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
	// descriptors through /proc/<pid>/fd/N. This is the pid-namespace
	// MECHANISM only: no derived mount VIEW, no grafts — those are issue
	// #125's later pieces, tracked on the issue itself. The stage's own P1
	// keeps the sandbox's pid namespace unaffected; this flag applies only to
	// the engine's own clone, here.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWCGROUP | syscall.CLONE_NEWPID,
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
