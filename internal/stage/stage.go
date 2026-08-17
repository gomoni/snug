// Package stage implements Phase 1's supervisor: a second long-lived process
// (P1) that creates the sandbox's network namespace, pins it, leaves it, and
// forks bwrap back into it — so that a hostile process inside the sandbox
// gains no new reach, while the sandbox's own user namespace gains a
// privileged ancestor for the whole run. See SUPERVISOR-DESIGN.md §2 for
// the topology diagram this package builds, and §1 for what was measured
// before any of it was written.
//
// A bare `snug <dir>` starts no stage: NeedsStage() is false at both ends of
// the NetnsOwner lattice and true only in the middle (policy.NetnsStage), so
// this package is reached only when a policy actually asks for it.
package stage

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/fdseal"
	"github.com/gomoni/snug/internal/policy"
)

// Config is what Start needs to create the stage.
type Config struct {
	// Topology is the RESOLVED policy's own, passed whole rather than picked
	// apart by the caller, and that is invariant 6 applied to this package: one
	// Policy, one author. Start refuses every field it does not implement, so
	// what --dry-run prints about the process shape and what the stage actually
	// builds cannot drift apart silently.
	//
	// Before this, Config carried Netns alone and the stage hardcoded the
	// single-uid map independently. `subuid none` on screen was then true by
	// COINCIDENCE: nothing connected the rendering to the code, so a
	// deriveTopology that started returning SubuidFull would have changed the
	// screen and nothing else, leaving --dry-run — the one artifact by which a
	// human can trust snug at all — making a claim no code keeps. Issue #25.
	//
	// Netns must be policy.NetnsStage and Subuid must be policy.SubuidNone.
	// Anything else is a programming error and Start refuses rather than
	// guessing.
	Topology policy.Topology

	// Sandbox are the descriptors bwrap needs, in the exact order P0 put them
	// in ExtraFiles when it built the argv.
	//
	// What is unchanged is the numbering bwrap FINALLY sees — 3..3+K-1, the
	// numbers already baked into the args memfd — not the numbering along the
	// way. They do get renumbered: they arrive in P1 at fdSandboxBase+i and are
	// installed in the bwrap child at 3+i. Go's fork/exec machinery does that
	// with dup3 and, crucially, does not close the sources. That is the whole
	// reason internal/fdseal exists; see its package comment before changing
	// anything here.
	Sandbox []*os.File

	Stdin, Stdout, Stderr *os.File
}

// Stage is opaque and only Start can produce one. That is the type-level half
// of exit criterion 2: internal/sandbox.Run requires a *Stage on its stage
// arm, so "bwrap forked from P0 into a topology that says NetnsStage" does not
// compile without going through Start.
type Stage struct {
	cmd     *exec.Cmd // P1
	control *os.File  // P0's end of the socketpair
	life    *os.File  // P0's end of the lifeline pipe (write end)

	pid         int
	netns       string
	userns      string
	netnsFD     int
	sandboxSize int

	closeOnce sync.Once
	waited    bool
}

// readyTimeout bounds how long Start waits for P1 to report readiness. Once
// the clone() underneath Start has returned, everything up to sending "ready"
// is CPU-bound namespace setup with no I/O and no reason to take more than a
// fraction of a second; this is generous against a loaded CI host, not a
// tuning knob for a slow operation.
const readyTimeout = 5 * time.Second

// Start creates P1: a socketpair for control, a pipe for the lifeline, and a
// clone with a single-uid map (SUPERVISOR-DESIGN.md §3.6 — Step 0
// measured this against snug's own BwrapFlags-produced argv and it held, so
// there is no stage0 privileged re-exec and no newuidmap/newgidmap here).
func Start(cfg Config) (*Stage, error) {
	if cfg.Topology.Netns != policy.NetnsStage {
		return nil, fmt.Errorf("stage.Start: Config.Topology.Netns must be policy.NetnsStage, got %s",
			cfg.Topology.Netns)
	}
	// Refusing, not ignoring, and this is invariant 5 rather than defensive
	// programming. The clone below installs a SINGLE-uid map and nothing here
	// reads /etc/subuid or calls newuidmap; a policy that asked for a delegated
	// range and silently got one uid would be a user believing a guarantee that
	// no longer holds. Phase 3 is where this stops being an error — and it will
	// be a deliberate edit here, made by whoever teaches the stage to delegate,
	// rather than a screen that quietly disagreed with the process it describes.
	if cfg.Topology.Subuid != policy.SubuidNone {
		return nil, fmt.Errorf("stage.Start: Config.Topology.Subuid is %s, but the stage "+
			"delegates no subuid range — it maps exactly one uid (see the clone below and "+
			"SUPERVISOR-DESIGN.md §3.6). Teach Start to delegate before deriveTopology "+
			"returns %s, or --dry-run will describe a range that does not exist",
			cfg.Topology.Subuid, cfg.Topology.Subuid)
	}
	// Before anything is created: a policy whose descriptor block would reach
	// fdNetnsN must fail here, where the message can name the fix, rather than
	// as a bwrap parse error two processes further in.
	if err := checkFDBudget(len(cfg.Sandbox)); err != nil {
		return nil, err
	}

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("stage: creating the control socketpair: %w", err)
	}
	p0Control := os.NewFile(uintptr(fds[0]), "stage-control-p0")
	p1Control := os.NewFile(uintptr(fds[1]), "stage-control-p1")

	lifeR, lifeW, err := os.Pipe()
	if err != nil {
		p0Control.Close()
		p1Control.Close()
		return nil, fmt.Errorf("stage: creating the lifeline pipe: %w", err)
	}

	cmd := exec.Command("/proc/self/exe", "__stage-setup")
	cmd.Args[0] = "snug"
	cmd.ExtraFiles = append([]*os.File{p1Control, lifeR}, cfg.Sandbox...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = cfg.Stdin, cfg.Stdout, cfg.Stderr

	// bwrap runs with an empty environment already (internal/sandbox.Run's
	// "the /proc/1/environ lesson" comment); P1 is one process further out
	// than bwrap in this topology, and it needs nothing from the host's
	// environment either.
	cmd.Env = []string{}

	hostUID, hostGID := os.Getuid(), os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 stageCloneflags,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: hostUID, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: hostGID, Size: 1}},
		GidMappingsEnableSetgroups: false,
		// LOAD-BEARING. Do not delete this line as redundant with the lifeline.
		//
		// An earlier comment here claimed Pdeathsig does not survive the
		// setup->serve re-exec, because that exec is a secureexec transition
		// where capabilities widen. MEASURED FALSE, round 3: capabilities do not
		// widen at that exec — P1 already holds a full set in U from the moment
		// it becomes the userns creator — so there is no secureexec and the
		// signal is preserved.
		//
		// That matters because the two mechanisms cover DIFFERENT failures. The
		// lifeline pipe needs P1 to run a goroutine to notice EOF. A stopped
		// process runs no user code at all, so for a SIGSTOPped stage tree
		// Pdeathsig is the ONLY thing that collapses it when P0 dies. Measured
		// 3/3: freeze P1, both bwraps and pasta, SIGKILL P0, zero survivors and
		// no leaked netns. Remove this and that case becomes an orphaned sandbox
		// holding a netns with no parent left to tear it down.
		Pdeathsig: syscall.SIGKILL,
	}

	if err := fdseal.SealFor(cmd); err != nil {
		p0Control.Close()
		p1Control.Close()
		lifeR.Close()
		lifeW.Close()
		return nil, fmt.Errorf("stage: %w", err)
	}
	if err := cmd.Start(); err != nil {
		p0Control.Close()
		p1Control.Close()
		lifeR.Close()
		lifeW.Close()
		// This clone can fail for four reasons and the message used to name one,
		// which is CLAUDE.md's "errors name the fix" inverted into "errors name
		// the wrong fix". snug doctor probes bwrap's namespaces, not this one,
		// so on a host where the stage cannot start doctor is still green.
		return nil, fmt.Errorf("stage: starting P1: %w\n"+
			"  This clone asks for three namespaces at once (user, network, mount).\n"+
			"  Check, in this order:\n"+
			"    unprivileged user namespaces  /proc/sys/kernel/unprivileged_userns_clone (and max_user_namespaces)\n"+
			"    a nesting limit               you may already be at the maximum depth, e.g. inside a container\n"+
			"    network namespaces            /proc/sys/user/max_net_namespaces\n"+
			"  A quick check that reproduces all three: unshare --user --net --mount -- true", err)
	}
	p1Control.Close()
	lifeR.Close()

	st := &Stage{
		cmd:         cmd,
		control:     p0Control,
		life:        lifeW,
		pid:         cmd.Process.Pid,
		sandboxSize: len(cfg.Sandbox),
	}

	ev, err := recvEventTimeout(p0Control, readyTimeout)
	if err != nil {
		st.killAndClose()
		return nil, fmt.Errorf("stage: waiting for the stage to report ready: %w", err)
	}
	if ev.Op != "ready" {
		st.killAndClose()
		return nil, fmt.Errorf("stage: expected a \"ready\" event, got %q", ev.Op)
	}
	// An empty string is != every real namespace id, which is exactly how a
	// stage that never started would read as PASS if this were skipped
	// (SUPERVISOR-DESIGN.md's review §3.2, restated in §6 item 9).
	if ev.Netns == "" || ev.Userns == "" {
		st.killAndClose()
		return nil, fmt.Errorf("stage: \"ready\" event named an empty namespace (netns=%q userns=%q)",
			ev.Netns, ev.Userns)
	}
	if ev.NetnsFD != fdNetnsN {
		st.killAndClose()
		return nil, fmt.Errorf("stage: \"ready\" event reported netns_fd=%d, want %d", ev.NetnsFD, fdNetnsN)
	}

	st.netns, st.userns, st.netnsFD = ev.Netns, ev.Userns, ev.NetnsFD
	return st, nil
}

func (s *Stage) killAndClose() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_, _ = s.cmd.Process.Wait()
	}
	_ = s.control.Close()
	_ = s.life.Close()
}

// Target is what pasta must be aimed at. NetnsPath names /proc/<P1>/fd/63 —
// the descriptor P1 pinned BEFORE it moved — never /proc/<P1>/ns/net, which
// after the move names P1's own empty namespace and which pasta accepts
// SILENTLY (measured, SUPERVISOR-DESIGN.md §1, --pasta-naive).
func (s *Stage) Target() policy.PastaTarget {
	return policy.PastaTargetStage(s.pid, s.netnsFD)
}

// PinnedNetns is the "net:[...]" id P1 reported for N at readiness — what
// every namespace assertion compares against.
func (s *Stage) PinnedNetns() string { return s.netns }

// WaitNetReady blocks until the network helper's interface is up INSIDE the
// sandbox's network namespace, and is the reason bwrap no longer has to be
// started before the network exists.
//
// P0 cannot answer this question itself. It is not in N, and the old answer —
// poll /proc/<pid>/net/dev of a process inside N — required a process inside N,
// which is exactly the bwrap-first ordering that made a parked payload
// necessary. The stage can answer it, because the socket it opened in N before
// it left still speaks to N (a socket's network namespace is fixed at
// creation, measured).
//
// So the order becomes: start pasta, ask this, THEN fork bwrap. Nothing is ever
// parked, and there is no window in which a payload exists but its network
// guarantee does not.
//
// The timeout here is P0's patience with the STAGE; the stage applies its own,
// shorter, bound to the interface itself, so a hang here means the stage is
// wedged rather than the network being slow.
func (s *Stage) WaitNetReady(timeout time.Duration) error {
	if err := sendRequest(s.control, request{Op: "netready"}); err != nil {
		return fmt.Errorf("stage: asking whether the sandbox's network is up: %w", err)
	}
	ev, err := recvEventTimeout(s.control, timeout)
	if err != nil {
		return fmt.Errorf("stage: waiting for the network to come up in the sandbox's "+
			"namespace: %w", err)
	}
	if ev.Op != "netready" {
		return fmt.Errorf("stage: expected a \"netready\" event, got %q", ev.Op)
	}
	if ev.Err != "" {
		return fmt.Errorf("stage: %s", ev.Err)
	}
	return nil
}

// StartSandbox sends the one request this phase's protocol has, and blocks
// until P1 reports the fork happened. The stage will not serve a second one —
// this is a ONE-SHOT design; everRan does not exist as a concept here, unlike
// the proof of concept it replaces.
func (s *Stage) StartSandbox(bwrapPath string, argv []string) error {
	req := request{Op: "start", Bwrap: bwrapPath, Argv: argv, Passthrough: s.sandboxSize}
	if err := sendRequest(s.control, req); err != nil {
		return fmt.Errorf("stage: sending the start request: %w", err)
	}
	ev, err := recvEvent(s.control)
	if err != nil {
		return fmt.Errorf("stage: waiting for the fork to be reported: %w", err)
	}
	if ev.Op != "started" {
		return fmt.Errorf("stage: expected a \"started\" event, got %q", ev.Op)
	}
	if ev.Err != "" {
		return fmt.Errorf("stage: bwrap did not start: %s", ev.Err)
	}
	return nil
}

// Wait blocks until the payload exits and returns its raw wait status, so
// internal/sandbox.Run can convert it identically to today's wait(): P1
// reaps bwrap itself (it is bwrap's real parent across every exec in this
// chain) and reports the status back over the control socket, because P0 is
// not bwrap's parent under this topology and cannot waitpid() on it directly.
func (s *Stage) Wait() (syscall.WaitStatus, error) {
	ev, err := recvEvent(s.control)
	if err != nil {
		return 0, fmt.Errorf("stage: waiting for the payload to exit: %w", err)
	}
	s.waited = true
	if ev.Op != "exited" {
		return 0, fmt.Errorf("stage: expected an \"exited\" event, got %q", ev.Op)
	}
	if ev.Err != "" {
		return 0, fmt.Errorf("stage: %s", ev.Err)
	}
	return syscall.WaitStatus(ev.WaitStatus), nil
}

// Close drops the lifeline: P1 reads EOF and tears down, whatever it was
// doing. Safe to call more than once, and safe to call after Wait() already
// returned normally — at that point P1 is already exiting on its own, so this
// is closing descriptors that are about to be orphaned.
func (s *Stage) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if !s.waited {
			// Best-effort: P1 may already be gone (bwrap failed to start, say),
			// in which case this write fails and is ignored — the lifeline
			// close below is what actually matters.
			_ = sendRequest(s.control, request{Op: "stop"})
		}
		err = s.life.Close()
		_ = s.control.Close()
		if s.cmd != nil {
			_, _ = s.cmd.Process.Wait()
		}
	})
	return err
}

// recvEventTimeout bounds a read with a deadline, in the shape of
// internal/sandbox/netns.go's waitForNetDevice: a goroutine does the blocking
// read, the caller selects against time.After, because *os.File wrapping a
// raw socketpair fd does not reliably support SetReadDeadline the way a
// net.Conn does.
func recvEventTimeout(f *os.File, timeout time.Duration) (event, error) {
	type result struct {
		ev  event
		err error
	}
	ch := make(chan result, 1)
	go func() {
		ev, err := recvEvent(f)
		ch <- result{ev, err}
	}()
	select {
	case r := <-ch:
		return r.ev, r.err
	case <-time.After(timeout):
		return event{}, fmt.Errorf("timed out after %s", timeout)
	}
}
