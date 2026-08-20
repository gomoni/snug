package stage

import (
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// The gate is issue #125's C2 piece: on a container run, bwrap is handed
// --block-fd (and --sync-fd on the same pipe) and its init PARKS after building
// the whole mount tree and before forking any payload. P0 writes the release
// byte only once the engine is confirmed, so a run whose engine never came up
// is a run whose payload never existed — invariant 5, at the one moment it can
// still be enforced for free.
//
// This file is the other half of that: while the gate is closed, P1 owns
// KILLING what is behind it. Two measured facts make that an obligation rather
// than tidiness:
//
//   - A parked init has NOT yet armed --die-with-parent. Measured on bwrap
//     0.11.2: SIGKILL the outer bwrap while its payload is parked and the init
//     stays alive, still parked, and a release byte written afterwards STILL
//     runs the payload. So "kill bwrap" is not "kill the sandbox" here, and the
//     kernel's own cascade does not cover it.
//   - The pipe cannot be used to abort. --sync-fd is deliberately the same
//     pipe's write end, held by the sandbox's own pid 1, precisely so that no
//     death anywhere else produces an EOF that releases the payload (measured:
//     5/5 PAYLOAD_RAN without it, 0/5 with it). The property that makes a dying
//     snug safe is exactly the property that makes closing a descriptor useless
//     as a teardown signal.
//
// So the kill is explicit, it is P1's (bwrap's parent, and the only process
// that learns the init's pid — from bwrap's own --info-fd answer), and it runs
// on every abort path AND on P1's own teardown.
//
// MEASURED, with the control that makes the measurement mean something: a
// SIGKILL of P0 during the parked window leaves ZERO processes behind, 20/20 —
// P1's lifeline watcher wins the race against its own Pdeathsig, because
// do_exit closes P0's descriptors before it delivers signals. Remove the
// parked.kill() call from watchLifeline and exactly one process survives, 5/5:
// the parked init. That is this file, being load-bearing.

// parkedSandbox is P1's handle on a sandbox whose payload has not been forked
// yet. There is at most one per stage, for the same reason there is at most one
// "start" request, which is why it is a package-level value rather than
// something threaded through: watchLifeline runs on its own goroutine, has no
// access to runOneSandbox's frame, and is the path that fires when P0 dies in a
// way that still lets P1 run code.
type parkedSandbox struct {
	mu sync.Mutex

	bwrap    *os.Process // P1's own child; nil until the fork returns
	bwrapPID int
	// initFD is a PIDFD on bwrap's init, not a pid. A pid is only a stable name
	// for a process until something reaps it, and P1 does not reap the init —
	// bwrap does. Signalling through the descriptor cannot reach a stranger that
	// inherited the number; on an already-dead init it is simply ESRCH.
	initFD int
	armed  bool
}

// parked is the one gate this process can have. Armed only when the "start"
// request said Gated: an ungated run (no container engine, so no --block-fd)
// keeps exactly the teardown it had before this file existed.
var parked parkedSandbox

// arm records what must die if this run is abandoned before the release byte.
// initPID may be 0 — bwrap never answered on --info-fd — in which case kill()
// falls back to finding bwrap's children by PPid.
func (p *parkedSandbox) arm(proc *os.Process, initPID int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bwrap, p.armed = proc, true
	if proc != nil {
		p.bwrapPID = proc.Pid
	}
	p.initFD = -1
	p.pinInitLocked(initPID)
}

// setInit adds the init's pid once bwrap has reported it. Split from arm
// because the ORDER matters: arm runs the instant the fork returns, when the
// init's pid is still unknown, so that a failure between the fork and the
// --info-fd answer still takes the sandbox down (through the PPid fallback in
// kill). Learning the pid narrows that kill; it does not create it.
func (p *parkedSandbox) setInit(initPID int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.armed || p.initFD >= 0 {
		return
	}
	p.pinInitLocked(initPID)
}

func (p *parkedSandbox) pinInitLocked(initPID int) {
	if initPID <= 1 {
		return
	}
	if fd, err := unix.PidfdOpen(initPID, 0); err == nil {
		p.initFD = fd
	}
}

// kill takes the whole sandbox down: the init first, then bwrap. The init
// first because it is the one that can still be RELEASED — while it is alive,
// one byte from anywhere with a copy of the write end runs the payload, and the
// order here is the difference between "the payload never existed" and "the
// payload existed for a moment during teardown".
//
// Safe to call more than once and safe to call after the payload has already
// exited: every signal goes through a pidfd or through os.Process, both of
// which refuse to signal a number they no longer name.
func (p *parkedSandbox) kill() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.armed {
		return
	}
	if p.initFD >= 0 {
		_ = unix.PidfdSendSignal(p.initFD, unix.SIGKILL, nil, 0)
	}
	// The fallback, and the reason it is not redundant: the one abort path that
	// does NOT know the init's pid is "bwrap never answered on --info-fd", which
	// is also a path on which bwrap may well have forked the init already. A
	// pidfd we could not open is not an orphan we get to ignore.
	//
	// ONLY when the pidfd is missing, and that guard is load-bearing rather than
	// an optimisation. This branch identifies its victims by PPid, which is a
	// PID comparison, and a pid stops naming a process the moment something
	// reaps it. Restricting it to the window in which the init's pid was never
	// learned confines it to the window in which bwrap has certainly not been
	// waited on — runOneSandbox has not reached cmd.Wait() on any path that can
	// get here with initFD < 0. See disarm for the other end of the same
	// argument.
	if p.initFD < 0 && p.bwrapPID > 1 {
		for _, child := range childrenOf(p.bwrapPID) {
			fd, err := unix.PidfdOpen(child, 0)
			if err != nil {
				continue
			}
			// Re-read through the pin, exactly as internal/sandbox's killPinned
			// does: if the number was recycled between the scan and now, the
			// new occupant has a different parent and is skipped rather than
			// killed.
			if ppid, ok := parentOf(child); ok && ppid == p.bwrapPID {
				_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			}
			_ = unix.Close(fd)
		}
	}
	if p.bwrap != nil {
		_ = p.bwrap.Kill()
	}
}

// disarm forgets this sandbox, and it is called the instant bwrap has been
// REAPED. Until then bwrap's pid names bwrap, because a live (or zombie) process
// still holds its own number; after the reap it names nothing, or worse,
// something else. Everything this type does is either pidfd-based (safe across a
// reap by construction) or bounded by this call.
func (p *parkedSandbox) disarm() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.armed = false
	p.bwrap, p.bwrapPID = nil, 0
	if p.initFD >= 0 {
		_ = unix.Close(p.initFD)
		p.initFD = -1
	}
}

// childrenOf returns every process on this host whose PPid is ppid. P1's mount
// namespace is a private COPY of the host tree and it is in the host's pid
// namespace, so /proc here is the host's own and these are host pids — the same
// numbers bwrap reports on --info-fd.
func childrenOf(ppid int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}
		if p, ok := parentOf(pid); ok && p == ppid {
			out = append(out, pid)
		}
	}
	return out
}

// parentOf reads PPid from /proc/<pid>/status — far easier to parse reliably
// than /proc/<pid>/stat, whose comm field can contain spaces and parens and
// shifts every fixed-position field after it.
func parentOf(pid int) (int, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		v, cut := strings.CutPrefix(line, "PPid:")
		if !cut {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
