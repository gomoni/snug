package sandbox

import (
	"bufio"
	"encoding/json"
	"fmt"
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
// NetnsSandbox (today's shape, policy.NetnsOwner floor): bwrap creates the
// network namespace itself, pasta joins it directly.
//
//	snug                                     (host userns/netns/mountns)
//	├── bwrap --unshare-all --die-with-parent
//	│         --json-status-fd J --block-fd B ... -- <agent>
//	│      └── the sandbox: own userns, netns, pidns, ipcns, utsns, mountns
//	└── pasta --netns /proc/<child>/ns/net --userns /proc/<child>/ns/user
//
// The alternative — pasta creating the netns and spawning bwrap inside it — was
// rejected because pasta's command mode builds a user namespace with exactly one
// uid mapped, which forecloses a subuid range later (podman) and puts a process
// snug does not control at the root of the tree.
//
// NetnsStage (policy.NetnsStage, SUPERVISOR-PHASE1-SPEC.md §2): a second
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

// bwrapStatus is the single-line JSON document bwrap writes to --json-status-fd.
type bwrapStatus struct {
	ChildPID int `json:"child-pid"`
}

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

// startPasta launches pasta against the sandbox's netns and waits until the
// interface is actually up.
//
// The payload is still blocked on bwrap's --block-fd at this point. That is the
// whole reason for the handshake: if the agent ran first, its opening request
// would race the tap device. There is no window in which the payload runs with a
// half-configured network, and none in which it runs with the host's.
func startPasta(p *policy.Policy, target policy.PastaTarget, childPID int) (*netHelper, error) {
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

	if err := waitForNetDevice(childPID, h); err != nil {
		h.stop()
		return nil, err
	}
	return h, nil
}

// waitForNetDevice polls the sandbox's own /proc/<pid>/net/dev until an
// interface other than loopback appears. Readable from here because we share a
// uid and own the enclosing user namespace.
func waitForNetDevice(childPID int, h *netHelper) error {
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case <-h.done:
			return fmt.Errorf("pasta exited before the network came up (%v): %s",
				h.waitErr, strings.TrimSpace(h.stderr.String()))
		default:
		}

		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/dev", childPID))
		if err == nil && hasNonLoopback(string(data)) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pasta did not bring up an interface within 3s: %s",
				strings.TrimSpace(h.stderr.String()))
		}
		time.Sleep(10 * time.Millisecond)
	}
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

// readChildPID reads bwrap's status document. bwrap writes it after the
// namespaces exist and before it releases the payload.
func readChildPID(r *os.File) (int, error) {
	dec := json.NewDecoder(r)
	var st bwrapStatus
	if err := dec.Decode(&st); err != nil {
		return 0, fmt.Errorf("reading bwrap status: %w", err)
	}
	if st.ChildPID == 0 {
		return 0, fmt.Errorf("bwrap reported no child pid")
	}
	return st.ChildPID, nil
}
