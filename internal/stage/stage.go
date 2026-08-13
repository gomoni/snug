// Package stage implements Phase 1's supervisor: a second long-lived process
// (P1) that creates the sandbox's network namespace, pins it, leaves it, and
// forks bwrap back into it — so that a hostile process inside the sandbox
// gains no new reach, while the sandbox's own user namespace gains a
// privileged ancestor for the whole run. See SUPERVISOR-PHASE1-SPEC.md §2 for
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
	// Netns must be policy.NetnsStage. Anything else is a programming error
	// and Start refuses rather than guessing.
	Netns policy.NetnsOwner

	// Sandbox are the descriptors bwrap needs, in the exact order P0 put them
	// in ExtraFiles when it built the argv. The stage passes them through
	// UNCHANGED; it never renumbers them, because the numbers are already
	// baked into the args memfd.
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
// clone with a single-uid map (SUPERVISOR-PHASE1-SPEC.md §3.6 — Step 0
// measured this against snug's own BwrapFlags-produced argv and it held, so
// there is no stage0 privileged re-exec and no newuidmap/newgidmap here).
func Start(cfg Config) (*Stage, error) {
	if cfg.Netns != policy.NetnsStage {
		return nil, fmt.Errorf("stage.Start: Config.Netns must be policy.NetnsStage, got %s", cfg.Netns)
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

	cmd := exec.Command("/proc/self/exe", "__stage1")
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
		// Belt-and-braces only: measured (SUPERVISOR-PHASE1-SPEC.md §1) that
		// Pdeathsig does not survive the stage1->stage2 re-exec, because that
		// exec is a secureexec transition (capabilities widen). The lifeline
		// pipe is the mechanism that actually holds; this cannot be relied on
		// alone.
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
		return nil, fmt.Errorf("stage: starting P1 (are unprivileged user namespaces enabled? "+
			"see /proc/sys/kernel/unprivileged_userns_clone): %w", err)
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
	// (SUPERVISOR-PHASE1-SPEC.md's review §3.2, restated in §6 item 9).
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
// SILENTLY (measured, SUPERVISOR-PHASE1-SPEC.md §1, --pasta-naive).
func (s *Stage) Target() policy.PastaTarget {
	return policy.PastaTargetStage(s.pid, s.netnsFD)
}

// PinnedNetns is the "net:[...]" id P1 reported for N at readiness — what
// every namespace assertion compares against.
func (s *Stage) PinnedNetns() string { return s.netns }

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
