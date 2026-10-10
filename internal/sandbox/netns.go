package sandbox

import (
	"bufio"
	"fmt"
	"io"
	"os"
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
// NetnsSandbox (policy.NetnsOwner floor): bwrap creates the network namespace
// itself and NOTHING joins it. This is the offline shape — no @net, no
// container profile — so startPasta is never called for it; a run that reaches
// this file has already been routed through runStaged.
//
//	snug                                     (host userns/netns/mountns)
//	└── bwrap --unshare-user --unshare-ipc --unshare-pid --unshare-uts
//	          --unshare-cgroup-try --unshare-net --die-with-parent
//	          ... -- <agent>
//	       └── the sandbox: own userns, netns, pidns, ipcns, utsns, mountns
//
// It used to be pasta's target too, joined directly at /proc/<child>/ns/net
// once bwrap had reported the pid over --json-status-fd and parked its payload
// on --block-fd. That handshake is gone — the netns now exists before bwrap
// does, so there is nothing to park — and with it went both flags, both pipes,
// readChildPID and the whole parked type. Do not re-derive the ordering from
// this diagram.
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

	// configuredCh is closed by readReady when pasta's pid line arrives.
	configuredCh chan struct{}

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

	// pasta's stdout is the readiness pipe: PastaArgs passes
	// --pid policy.PastaReadyPath, which is pasta's own fd 1, so the pid line
	// pasta writes there once pasta_ns_conf has returned arrives on readyR.
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("starting pasta: creating its readiness pipe: %w", err)
	}
	cmd.Stdout = readyW

	// Pdeathsig: if snug is SIGKILLed, the kernel kills pasta too. Teardown
	// must not depend on snug getting the chance to clean up.
	//
	// Setpgid: pasta leaves the terminal's foreground process group, and that
	// is about the GRACE rather than about teardown. pasta is an ordinary
	// member of that group with the default disposition, so a Ctrl-C killed it
	// outright — MEASURED, during the payload's own grace window: "snug: the
	// network helper exited (signal: interrupt); the sandbox now has loopback
	// only." A payload given a second to flush was losing its egress inside
	// that second, which makes the second worth much less than it looks.
	//
	// It costs nothing that teardown relies on. Pdeathsig above is unchanged,
	// and confirmTeardown's sweep finds pasta by walking snug's DESCENDANTS,
	// not by process group, so it is still SIGKILLed with everything else —
	// the one helper deliberately exempt from that sweep is the container
	// reaper, and it is exempt by pid (see teardown.go's exclude), not by
	// being in its own group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}

	// Bounds Wait's copy of stderr once pasta itself has exited: a descendant
	// that inherited the pipe (a wrapper's background child, say) would
	// otherwise hold died() — and teardown's stop() — open for as long as it
	// lives. Measured: with a fake pasta that backgrounds `sleep 5` and exits,
	// died() had not fired after 3s without this, and fired at 1.0s with it
	// (TestPastaDeathIsReportedWhileADescendantHoldsItsStderr).
	cmd.WaitDelay = time.Second

	err = cmd.Start()
	// pasta holds its own copy now; ours must go, or EOF on readyR could never
	// report a pasta that exited without writing its pid.
	readyW.Close()
	if err != nil {
		readyR.Close()
		return nil, fmt.Errorf("starting pasta: %w", err)
	}

	h := &netHelper{cmd: cmd, stderr: &errbuf, done: make(chan struct{}),
		configuredCh: make(chan struct{})}
	go h.readReady(readyR)
	go func() {
		h.waitErr = cmd.Wait()
		close(h.done)
	}()

	// Readiness is NOT waited for here, and the caller must not assume it:
	// configured() says pasta has finished, and died() says it never will.
	// runStaged races the two before it lets the stage touch snug0.
	return h, nil
}

// readReady closes configured once pasta has written a line to its pid file
// (policy.PastaReadyPath), then drains the pipe until pasta exits so a later
// write can never block it. EOF before a line means pasta is gone without
// having configured anything; died() reports that, so nothing is closed here.
func (h *netHelper) readReady(r *os.File) {
	defer r.Close()
	br := bufio.NewReader(r)
	if line, err := br.ReadString('\n'); err == nil && strings.TrimSpace(line) != "" {
		close(h.configuredCh)
	} else {
		return
	}
	_, _ = io.Copy(io.Discard, br)
}

// configured is closed once pasta reports that it has finished configuring the
// namespace — addresses and routes of both families on snug0, not merely the
// link up. See policy.PastaReadyPath for why "UP and RUNNING" is not this.
func (h *netHelper) configured() <-chan struct{} { return h.configuredCh }

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
	return policy.VisibleText(msg)
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
			"      %s", h.waitErr, policy.VisibleText(strings.TrimSpace(h.stderr.String()))))
	}()
}
