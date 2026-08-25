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

	"github.com/gomoni/snug/internal/bwrapinfo"
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

	// BwrapInfo is the READ end of bwrap's --info-fd pipe. Its write end is one
	// of the descriptors in Sandbox above, exactly as it always was; what moved
	// into the stage is the READING of it (issue #125's C2 gate, and fds.go's
	// fdBwrapInfo for why).
	//
	// Required, and required on EVERY staged run rather than only on a gated
	// one: it lands at a FIXED descriptor number ahead of the Sandbox block, so
	// making it optional would make every later number depend on the policy —
	// the exact class of drift checkFDBudget exists to refuse. On a run with no
	// engine the stage reads it, forwards what bwrap said, and nothing is gated.
	BwrapInfo *os.File

	Stdin, Stdout, Stderr *os.File

	// OnSandboxForked, if non-nil, is called with bwrap's init pid the moment
	// P1 reports it, synchronously, before StartSandbox waits for anything
	// else. It is the earliest point at which the host can name a process that
	// could be orphaned; blocking the handshake for one small file write is
	// the point, not a cost.
	OnSandboxForked func(pid int)
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

	onSandboxForked func(pid int)

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
	// Refusing anything this package does not implement, rather than guessing —
	// invariant 5, same as the removed single-value check this replaces. Two
	// values now: SubuidNone (the original single-uid map) and SubuidFull (the
	// two-range delegated map a container engine needs, issue #63 Tier B).
	if cfg.Topology.Subuid != policy.SubuidNone && cfg.Topology.Subuid != policy.SubuidFull {
		return nil, fmt.Errorf("stage.Start: Config.Topology.Subuid is %s, which this package "+
			"does not implement", cfg.Topology.Subuid)
	}
	// Before anything is created: a policy whose descriptor block would reach
	// fdNetnsN must fail here, where the message can name the fix, rather than
	// as a bwrap parse error two processes further in.
	if err := checkFDBudget(len(cfg.Sandbox)); err != nil {
		return nil, err
	}
	if cfg.BwrapInfo == nil {
		return nil, fmt.Errorf("stage.Start: Config.BwrapInfo is nil — the stage reads bwrap's " +
			"--info-fd answer itself, and without it a gated run has no way to learn which " +
			"process to release or kill")
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
	// The fixed block first, in fds.go's order (fdControl, fdLife,
	// fdBwrapInfo), then the policy-dependent pass-through block.
	cmd.ExtraFiles = append([]*os.File{p1Control, lifeR, cfg.BwrapInfo}, cfg.Sandbox...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = cfg.Stdin, cfg.Stdout, cfg.Stderr

	// bwrap runs with an empty environment already (internal/sandbox.Run's
	// "the /proc/1/environ lesson" comment); P1 is one process further out
	// than bwrap in this topology, and it needs nothing from the host's
	// environment either.
	cmd.Env = []string{}

	hostUID, hostGID := os.Getuid(), os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 stageCloneflags,
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

	// The uid/gid map. Two shapes, chosen by cfg.Topology.Subuid:
	//
	//   - SubuidNone (the original, still the default for every non-podman
	//     run): a single line mapping namespace id 0 to this process's own
	//     real id. Go writes it ITSELF, unprivileged, using the one
	//     self-mapping the kernel allows a non-CAP_SETUID writer to make —
	//     the same shape `unshare --map-root-user` produces. No external tool,
	//     no /etc/subuid read, exactly as SUPERVISOR-DESIGN.md §3.6 measured.
	//
	//   - SubuidFull (issue #63, Tier B — a container engine is selected):
	//     UidMappings/GidMappings are left NIL here on purpose. A two-range
	//     map (namespace 0 -> this process's real id, PLUS namespace
	//     1..size -> the delegated /etc/subuid range) is NOT the
	//     single-self-map special case, so an unprivileged Go write of it
	//     would fail with EPERM — this is exactly why newuidmap/newgidmap
	//     exist. __stage-setup (setup.go) notices its uid is still the
	//     overflow id after the clone, asks P0 for the map over the control
	//     socket, and blocks until it arrives; P0 answers below, after
	//     cmd.Start() returns, by calling delegateSubuid (subuid.go), which
	//     execs newuidmap/newgidmap against this pid. The map can be written
	//     only ONCE per user namespace, ever — there is no "self-map now,
	//     widen later" — which is why the whole delegated range has to be
	//     requested at clone time rather than added after the fact.
	if cfg.Topology.Subuid == policy.SubuidNone {
		cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: hostUID, Size: 1}}
		cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: hostGID, Size: 1}}
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
		cmd:             cmd,
		control:         p0Control,
		life:            lifeW,
		pid:             cmd.Process.Pid,
		sandboxSize:     len(cfg.Sandbox),
		onSandboxForked: cfg.OnSandboxForked,
	}

	// The delegated-map handshake (issue #63, Tier B): one extra request/event
	// round trip BEFORE the "ready" one below, present only when
	// UidMappings/GidMappings were deliberately left nil above. __stage-setup
	// blocks on this — its own uid is still the overflow id until the map
	// lands — so this MUST complete before "ready" can ever arrive; there is
	// no risk of racing the recvEventTimeout call below against it.
	if cfg.Topology.Subuid == policy.SubuidFull {
		if err := satisfyDelegatedMapRequest(p0Control, cmd.Process.Pid, hostUID, hostGID); err != nil {
			st.killAndClose()
			return nil, err
		}
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

// satisfyDelegatedMapRequest waits for __stage-setup's "needmap" event, calls
// newuidmap/newgidmap against pid (subuid.go), and answers "mapped" so
// __stage-setup can proceed. Fatal and unwound entirely on any failure —
// invariant 5: a policy that asked for a delegated range and could not get
// one must not fall back to the single-uid map it did not ask for, so the
// caller kills the child rather than let it continue half-mapped.
func satisfyDelegatedMapRequest(control *os.File, pid, hostUID, hostGID int) error {
	ev, err := recvEventTimeout(control, readyTimeout)
	if err != nil {
		return fmt.Errorf("stage: waiting for the stage to ask for its delegated subuid map: %w", err)
	}
	if ev.Op != "needmap" {
		return fmt.Errorf("stage: expected a \"needmap\" event, got %q", ev.Op)
	}
	if err := delegateSubuid(pid, hostUID, hostGID); err != nil {
		return err
	}
	if err := sendRequest(control, request{Op: "mapped"}); err != nil {
		return fmt.Errorf("stage: telling the stage its delegated subuid map is ready: %w", err)
	}
	return nil
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

// Pid is P1's own pid — the process P0 directly forked for this run. It is
// what a caller signals to kill the stage, and what issue #13's teardown
// confirmation (internal/sandbox.confirmTeardown) treats as the "outer"
// process for the @net topology: bwrap itself is forked BY P1, not by P0, so
// P0 never learns bwrap's pid directly and has nothing else of its own to
// kill.
func (s *Stage) Pid() int { return s.pid }

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
//
// iface names which interface's UP+RUNNING state answers the question
// (issue #63, Tier B): NetIfaceName ("snug0", pasta's own) for a run with
// pasta attached, or "lo" for a stage that owns no pasta at all — an
// offline @podman-socket run, which still needs a stage for the container
// engine's own U even though N carries no egress. The caller picks it from
// the resolved policy's Net.Mode; this package never guesses.
func (s *Stage) WaitNetReady(timeout time.Duration, iface string) error {
	if err := sendRequest(s.control, request{Op: "netready", NetIface: iface}); err != nil {
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

// startRoundTripTimeout bounds P0's patience for the WHOLE "start" round trip:
// bwrap's fork, its --info-fd answer, and — when an engine is selected — the
// fork, setns+mount+capdrop+exec inside __inengine and the bounded wait for
// podman's own socket to appear.
//
// DERIVED from the two bounds the stage applies internally, never written down
// as a number: the whole point of P0's bound is to sit ABOVE the stage's, so
// that a real timeout is reported by the stage with its own specific message
// ("the container engine did not create its socket at …") rather than by this
// one, which can only say the stage went quiet. Issue #125 folded the engine's
// start into this request and so ADDED bwrapInfoTimeout to what P0 waits for;
// a hand-typed 40s that used to have ten seconds of headroom silently had
// none.
const startRoundTripTimeout = bwrapInfoTimeout + engineSocketWaitTimeout + 10*time.Second

// StartSandbox sends the ONE request this protocol has, and blocks until P1
// reports that everything which happens before a payload exists has happened:
// bwrap forked, bwrap's own --info-fd answer parsed, and — when spec is
// non-nil — the container engine forked into this sandbox's N with its socket
// confirmed. The stage will not serve a second request; this is a ONE-SHOT
// design, and everRan does not exist as a concept here.
//
// One request, up to THREE replies: an optional "forked" — cfg.OnSandboxForked
// is called with its InitPID synchronously, and reading resumes — arrives
// first when bwrap answered at all (issue #236), then the "enginestarted" this
// function returns from. Anything else is a protocol violation and a hard
// error.
//
// On a GATED run (gated true, meaning P0 put --block-fd and --sync-fd in the
// argv) the payload is still PARKED when this returns, and the caller owns two
// obligations, in this order:
//
//	OnEngineReady()   — arm whatever must exist before a payload does
//	release the gate  — one byte on the write end P0 kept for itself
//
// with any error between them abandoning the run rather than releasing it. A
// returned error means P1 has ALREADY killed bwrap and its parked init: the
// payload never existed.
//
// The engine's spec travels in this request rather than in one of its own
// (issue #125's C2 gate). A second request would mean "start" was no longer the
// request after which MainServe returns — and it would have to carry bwrap's
// child pid from P0 to P1, which is the one thing proto.go's schema refuses.
// Under one request the pid comes back the other way, in the event.
func (s *Stage) StartSandbox(bwrapPath string, argv []string, spec *EngineSpec, gated bool) (bwrapinfo.Info, error) {
	req := request{Op: "start", Bwrap: bwrapPath, Argv: argv, Passthrough: s.sandboxSize, Gated: gated}
	if spec != nil {
		req.EnginePodman = spec.Podman
		req.EngineArgv = spec.Argv
		req.EngineEnv = spec.Env
		req.EngineSock = spec.Sock
		req.EngineGrafts = spec.Grafts
	}
	if err := sendRequest(s.control, req); err != nil {
		return bwrapinfo.Info{}, fmt.Errorf("stage: sending the start request: %w", err)
	}
	forked := false
	for {
		ev, err := recvEventTimeout(s.control, startRoundTripTimeout)
		if err != nil {
			return bwrapinfo.Info{}, fmt.Errorf("stage: waiting for the sandbox to reach the starting line: %w", err)
		}
		switch ev.Op {
		case "forked":
			// AT MOST ONE, and the count is enforced rather than documented:
			// each event read renews startRoundTripTimeout, so a P1 that sent
			// "forked" repeatedly would keep this loop alive indefinitely and
			// re-run the caller's hook on every one. One init is forked per
			// stage, so a second report is a protocol violation.
			if forked {
				return bwrapinfo.Info{}, fmt.Errorf("stage: a second %q event for one start request", ev.Op)
			}
			forked = true
			if s.onSandboxForked != nil {
				s.onSandboxForked(ev.InitPID)
			}
			continue
		case "enginestarted":
			if ev.Err != "" {
				return bwrapinfo.Info{}, fmt.Errorf("stage: %s", ev.Err)
			}
			return bwrapinfo.Info{InitPID: ev.InitPID, Namespaces: ev.Namespaces}, nil
		default:
			return bwrapinfo.Info{}, fmt.Errorf("stage: expected an \"enginestarted\" event, got %q", ev.Op)
		}
	}
}

// EngineSpec is what the "start" request asks the stage to fork podman with —
// every
// field chosen by P0 (preflight P1-P6, the hardened /tmp paths engine.New
// computed, the explicit minimal environment), none of it inherited or
// guessed by the stage itself (issue #63, Tier B; ENGINE-WIRING.md §2.6).
type EngineSpec struct {
	// Podman is the resolved, preflight-checked path to a REAL podman binary
	// — never a host-escape shim (P0's own preflight already refused that).
	Podman string
	// Argv is exactly what follows Podman on the command line — e.g.
	// "--root", store, "--runroot", runroot, "system", "service", "--time",
	// idle, "unix://"+sock.
	Argv []string
	// Env is the explicit, minimal environment for the exec'd podman (PATH,
	// HOME, XDG_RUNTIME_DIR, CONTAINERS_*), chosen entirely by P0 — never the
	// stage's own os.Environ(), which is empty, and never the host's.
	Env []string
	// Sock is the pathname socket podman is expected to bind. The stage polls
	// for it (its own mount namespace is a private COPY of
	// the host tree and therefore sees the identical /tmp superblock) rather
	// than trusting the fork alone: "the process started" and "podman
	// finished getting to a listening socket" are different facts.
	Sock string
	// Grafts is what the engine's derived view is BUILT from: the host
	// directories this run's engine works out of, each with the guest path it
	// is attached at and the access it is attached with (issue #125, Tier C).
	//
	// The stage clones each one with open_tree(2) BEFORE it joins the
	// sandbox's mount namespace and attaches it with move_mount(2) after —
	// measured, and the ordering is not a preference: after the join a host
	// path resolves inside the SANDBOX, so an openat2 on the far side gets
	// ENOENT (issue #125's derived-view measurement).
	//
	// P0 authors this list from the resolved Policy's own p.Grafts, so the
	// engine's view and the model of it have one author (invariant 6).
	Grafts []EngineGraft
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

// EngineGraft is one host directory attached into the engine's derived view.
//
// A flat triple rather than a policy.Graft: the stage must not import the
// policy model, and what it needs is exactly what mount(2) needs — a source, a
// destination and whether to make it read-only. Everything the model knows
// beyond that (the abuse sentence, the provenance, which G-rule admitted it)
// has already done its work by the time P0 writes this down.
type EngineGraft struct {
	Host     string `json:"host"`
	Guest    string `json:"guest"`
	ReadOnly bool   `json:"ro,omitempty"`
}
