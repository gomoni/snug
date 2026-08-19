package sandbox

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// Two topologies produce a sandbox with a private netns, and this file is where
// a reader finds out which one a given run used — policy.Topology.Netns says,
// and startPasta's target (a policy.PastaTarget) is built accordingly by the
// caller.
//
// NetnsSandbox (today's shape, policy.NetnsOwner floor): bwrap creates the
// network namespace itself, pasta joins it directly.
//
//	snug                                     (host userns/netns/mountns)
//	├── bwrap --unshare-user --unshare-ipc --unshare-pid --unshare-uts
//	│         --unshare-cgroup-try --unshare-net --die-with-parent
//	│         --json-status-fd J --block-fd B ... -- <agent>
//	│      └── the sandbox: own userns, netns, pidns, ipcns, utsns, mountns
//	└── pasta --netns /proc/<child>/ns/net --userns /proc/<child>/ns/user
//
// The alternative — pasta creating the netns and spawning bwrap inside it — was
// rejected because pasta's command mode builds a user namespace with exactly one
// uid mapped, which forecloses a subuid range later (podman) and puts a process
// snug does not control at the root of the tree.
//
// NetnsStage (policy.NetnsStage, SUPERVISOR-DESIGN.md §2): a second
// long-lived process, P1, creates the netns, pins it with a descriptor, LEAVES
// it, and forks bwrap back into it through a setns shim. bwrap's own argv is
// byte-identical to the NetnsSandbox case except for the enumerated
// --unshare-* set (internal/policy/bwrap.go, Topology.Netns == NetnsStage) —
// which process called fork, not the argv, is what determines the topology.
// pasta's target is a descriptor P1 pinned before it moved
// (policy.PastaTargetStage), never P1's own /proc/<pid>/ns/net, which after the
// move names the wrong (empty) namespace and which pasta accepts silently. See
// internal/stage for P1 itself.
//
// Why the netns cannot leak, in EITHER topology: it is referenced only as
// /proc/<pid>/ns/net or a pinned descriptor, never bind-mounted to a filesystem
// path. When the last reference goes away the kernel destroys it. This is the
// difference from `ip netns add`, which bind-mounts under /run/netns and leaks
// exactly that way.

// netHelper supervises pasta for the lifetime of a sandbox.
type netHelper struct {
	cmd    *exec.Cmd
	stderr *strings.Builder

	// done is CLOSED when cmd.Wait returns, and waitErr is written before the
	// close so every reader sees it (the close is the happens-before edge).
	//
	// It used to be a buffered channel carrying the wait error, and that was a
	// deadlock waiting for a slow pasta: THREE places read it — waitForNetDevice,
	// watch and stop — and a value in a channel can be received exactly once.
	// A pasta that started and then died was received by waitForNetDevice,
	// which returned the error; stop() then blocked forever on a second
	// receive that could never arrive, and snug hung with the payload parked.
	// MEASURED, from a goroutine dump of a hung snug: netns.go's `<-h.done`
	// after the kill. watch() worked around it by putting the value BACK,
	// which is the shape of the bug rather than a fix.
	//
	// A closed channel is a fact any number of readers can observe any number
	// of times. That is the property this needs, so that is what it is now.
	done    chan struct{}
	waitErr error

	// stopping distinguishes "we are tearing down" from "pasta died on us", so
	// a normal exit does not print an alarming warning at the end of every run.
	stopping atomic.Bool
}

// startPasta launches pasta against the sandbox's netns. It does NOT wait for
// the interface, and there is nothing to park while it does not: at this point
// no payload exists, because the sandbox is not forked until the stage confirms
// the network is up (see runStaged).
func startPasta(p *policy.Policy, target policy.PastaTarget) (*netHelper, error) {
	pasta, err := exec.LookPath("pasta")
	if err != nil {
		return nil, fmt.Errorf("profile requires networking but pasta is not installed "+
			"(package: passt).\n"+
			"      snug will not silently run you with no network, or worse, the host's.\n"+
			"      Install pasta, or drop the net profile to run offline: %w", err)
	}

	args := p.PastaArgs(target)
	cmd := exec.Command(pasta, args...)
	cmd.Env = []string{}
	var errbuf strings.Builder
	cmd.Stderr = &errbuf
	cmd.Stdout = nil

	// If snug is SIGKILLed, the kernel kills pasta too. Teardown must not
	// depend on snug getting the chance to clean up.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting pasta: %w", err)
	}

	h := &netHelper{cmd: cmd, stderr: &errbuf, done: make(chan struct{})}
	go func() {
		h.waitErr = cmd.Wait()
		close(h.done)
	}()

	// Readiness is NOT checked here any more, and the caller must not assume it.
	// pasta is now started against a namespace with no process in it, so there
	// is no /proc/<pid>/net/dev to poll — internal/stage answers the question
	// instead, through a socket it created inside the namespace before leaving
	// it. See runStaged's ordering comment and stage.WaitNetReady.
	//
	// What this function still guarantees is only that pasta was EXECED. Its
	// having exited is caught by watch(); its having failed to configure
	// anything is caught by the stage.
	return h, nil
}

func hasNonLoopback(procNetDev string) bool {
	sc := bufio.NewScanner(strings.NewReader(procNetDev))
	for i := 0; sc.Scan(); i++ {
		if i < 2 {
			continue // two header lines
		}
		name, _, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if ok && strings.TrimSpace(name) != "lo" {
			return true
		}
	}
	return false
}

// died is closed when pasta has exited, however it exited. It exists so a
// caller can RACE a slow readiness check against the helper dying, rather than
// waiting out a timeout for a process that is already gone: a pasta that starts
// and immediately fails is the shape a crashing or OOM-killed helper has, and
// the difference between reporting that in 300ms and reporting it in ten
// seconds is the difference between an error a human reads and an error a human
// interrupts.
func (h *netHelper) died() <-chan struct{} { return h.done }

// failure describes why pasta is gone, for the message a human sees. Safe to
// call only after died() has fired — waitErr is written before the close.
func (h *netHelper) failure() string {
	msg := strings.TrimSpace(h.stderr.String())
	if msg == "" && h.waitErr != nil {
		msg = h.waitErr.Error()
	}
	if msg == "" {
		msg = "no output"
	}
	return msg
}

// markStopping says "this teardown is ours" without doing any of it.
//
// stop() below sets the same flag, but stop() also SIGTERMs pasta and waits for
// it, and there is one path where that is far too late: a caught signal.
// confirmTeardown SIGKILLs every descendant, pasta among them, and it runs
// from the teardown guard — while runStaged's `defer helper.stop()` has not
// been reached yet. watch() then sees a pasta that died with nobody claiming
// responsibility and prints "the sandbox now has loopback only" on the way out
// of every Ctrl-C'd @net run (issue #112). The notice is false, it lands on
// the trust artifact, and it would mask a real pasta failure at teardown.
//
// So the guard claims the death first and lets the sweep do the killing. It is
// deliberately NOT the other obvious fix — excluding pasta's pid from the sweep
// — because the sweep exists precisely so that nothing has to trust orderly
// teardown, and an exclusion is a promise that something else will do the job.
func (h *netHelper) markStopping() {
	if h == nil {
		return
	}
	h.stopping.Store(true)
}

// stop tears pasta down. Called on every exit path, including the failure ones.
func (h *netHelper) stop() {
	if h == nil || h.cmd == nil || h.cmd.Process == nil {
		return
	}
	h.stopping.Store(true)
	_ = h.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		_ = h.cmd.Process.Kill()
		<-h.done
	}
	// Both receives above are on a channel that is CLOSED rather than written
	// to, so neither can consume anything another reader still needs, and the
	// last one returns immediately on a pasta that was already dead when stop
	// was called — which is precisely the case that used to hang.
}

// watch reports pasta dying mid-run.
//
// This is the FAIL-SAFE direction and it is worth being explicit about: when
// pasta dies the tap device vanishes and the sandbox is left with loopback
// only. It loses connectivity; it never gains reachability. So snug warns and
// keeps going rather than killing an agent that may be mid-edit, and does not
// restart pasta (a restart would race a new port set).
func (h *netHelper) watch(warn func(string)) {
	go func() {
		<-h.done
		if h.stopping.Load() {
			return // ordinary teardown, not a failure
		}
		warn(fmt.Sprintf("the network helper exited (%v); the sandbox now has loopback only.\n"+
			"      %s", h.waitErr, strings.TrimSpace(h.stderr.String())))
	}()
}
