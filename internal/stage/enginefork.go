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
// SECOND long-lived child of P1, alongside bwrap — EAGERLY, between
// "netready" and "start" (see serve.go's state machine), issue #63 Tier B.
// See EnterEngine (__inengine, inengine.go) for the fork+setns+confine
// sequence this triggers, and policy.EngineCapBounding for the capability set
// the engine is reduced to.
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
func startEngine(control, netnsN *os.File, req request) error {
	if req.EnginePodman == "" {
		err := fmt.Errorf("__stage-serve: malformed startengine request: no podman path")
		_ = sendEvent(control, event{Op: "enginestarted", Err: err.Error()})
		return err
	}
	if req.EngineSock == "" {
		err := fmt.Errorf("__stage-serve: malformed startengine request: no socket path to wait for")
		_ = sendEvent(control, event{Op: "enginestarted", Err: err.Error()})
		return err
	}
	if req.EngineResolvConf == "" {
		// Fatal, not a silent fallback (invariant 5): without this path
		// EnterEngine has nothing to bind over /etc/resolv.conf, and the
		// engine's private tree copy would carry the HOST's real one straight
		// through to every container it starts (issue #126).
		err := fmt.Errorf("__stage-serve: malformed startengine request: no resolv.conf path to bind over " +
			"the engine's own /etc/resolv.conf")
		_ = sendEvent(control, event{Op: "enginestarted", Err: err.Error()})
		return err
	}

	// Everything __inengine needs travels on ITS OWN argv, never in an
	// environment variable — the same discipline fds.go states for descriptor
	// numbers ("nothing travels in the environment") applied to the engine's
	// env too: the resolv.conf path to bind over /etc/resolv.conf, then fd 3
	// (the netns descriptor), then the env count and the env pairs
	// themselves, then the podman path, then podman's own argv. See
	// EnterEngine for the matching decode.
	argv := []string{"__inengine", req.EngineResolvConf, "3", strconv.Itoa(len(req.EngineEnv))}
	argv = append(argv, req.EngineEnv...)
	argv = append(argv, req.EnginePodman)
	argv = append(argv, req.EngineArgv...)

	cmd := exec.Command("/proc/self/exe", argv...)
	cmd.Args[0] = "snug"
	cmd.ExtraFiles = []*os.File{netnsN}
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
		_ = sendEvent(control, event{Op: "enginestarted", Err: err.Error()})
		return err
	}

	if err := cmd.Start(); err != nil {
		_ = sendEvent(control, event{Op: "enginestarted", Err: err.Error()})
		return err
	}

	// Reap it whenever it eventually exits, in the background — nothing here
	// needs the exit status, and teardown's own verification (by socket path,
	// internal/engine/reap.go) is what actually confirms it is gone, not this
	// reap. Its only job is to stop this process's child from sitting as a
	// zombie under P1 for the rest of what may be a long-lived run.
	go func() { _ = cmd.Wait() }()

	if err := waitForSocket(req.EngineSock, engineSocketWaitTimeout); err != nil {
		_ = sendEvent(control, event{Op: "enginestarted", Err: err.Error()})
		return err
	}

	return sendEvent(control, event{Op: "enginestarted"})
}

// waitForSocket polls for a UNIX socket to appear at path, or the deadline to
// pass. "the process started" and "podman finished getting to a listening
// socket" are different facts — startengine's own success/failure has to
// mean the second one, or a run could proceed to StartSandbox believing an
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
