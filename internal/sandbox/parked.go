package sandbox

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// parked is the interval between bwrap forking the payload and snug releasing
// it — the window in which a process exists inside the sandbox, blocked on
// bwrap's --block-fd, with the network not yet up.
//
// # Why this is a type and not three lines at each call site
//
// bwrap releases that process on EOF just as readily as on a byte, so the
// write end of the block pipe is itself a release signal: ANY exit of snug
// while a payload is parked runs the payload. The rule has always been "the
// child has to be dead before any close" (see abort below, and the redteam
// finding it came from), and it was written out by hand at the call sites that
// existed at the time. The stage arm was then added, one of its five return
// paths did not repeat it, and a red team walked straight back in: a pasta
// that started and then died left snug deadlocked with the payload parked, and
// the human's only available response — killing the hung snug — EXECUTED the
// payload and wrote to the target, on a run snug never reported as successful.
// MEASURED, before this type existed.
//
// So the guarantee is expressed once, as a deferred call registered the
// instant the pid is known. Every return path is covered including the ones a
// future edit adds, and the ordering against snug's own deferred closes falls
// out of defer's LIFO discipline rather than out of remembering.
//
// # What this closes, and what it does not
//
//   - Every code path in snug, present and future, including a panic.
//   - The catchable termination signals. "The human kills the hung snug" means
//     SIGINT or SIGTERM in practice, and both used to release the payload:
//     snug died, its blockW closed, EOF released the parked child, and the
//     payload ran with no network on a run that reported failure. While a
//     payload is parked those signals now kill the parked child first and then
//     re-raise with the default disposition, so snug's own exit status is
//     exactly what the signal would have produced. Outside the parked window
//     nothing is installed and Ctrl-C reaches an interactive payload exactly
//     as before — which matters, because snug deliberately keeps the whole
//     tree in the terminal's foreground process group.
//   - SIGKILL of snug during the parked window is NOT closed, and cannot be
//     from inside snug: bwrap's --die-with-parent has to travel two process
//     hops (bwrap, then the sandbox's own init) while the EOF is immediate, so
//     it loses the race. The window is now bounded by pasta's own startup
//     rather than being indefinite, and closing it for real means starting
//     pasta before any payload exists — which the stage topology makes
//     possible and Phase 1 deliberately does not do. TODO.md carries it with
//     its severity.
type parked struct {
	childPID int
	teardown func()

	mu   sync.Mutex
	over bool // released or aborted, whichever happened first
	sigs chan os.Signal
}

// parkSignals are the termination signals a human or a supervisor actually
// sends. SIGKILL is absent because it cannot be caught, not because it does
// not matter.
var parkSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

// park arms the guard. teardown is what to do about the process that owns the
// sandbox once the parked child itself is dead — reaping bwrap on the
// single-process path, dropping the stage's lifeline on the stage path — and
// may be nil.
func park(childPID int, teardown func()) *parked {
	p := &parked{childPID: childPID, teardown: teardown}
	p.sigs = make(chan os.Signal, 1)
	signal.Notify(p.sigs, parkSignals...)
	go func() {
		sig, ok := <-p.sigs
		if !ok {
			return // released; the channel was closed by disarm
		}
		p.abort()
		// Re-raise with the default disposition rather than calling os.Exit:
		// a process that dies of SIGTERM should look like one, to a shell and
		// to whatever automation is watching.
		s, ok := sig.(syscall.Signal)
		if !ok {
			os.Exit(1)
		}
		signal.Reset(s)
		_ = syscall.Kill(os.Getpid(), s)
	}()
	return p
}

// release lets the payload run. It is the ONLY thing that ends the parked
// window without killing the child, and it refuses if the window has already
// been ended by an abort — releasing a payload snug has decided to abandon is
// the exact failure this type exists to make unreachable.
func (p *parked) release(blockW *os.File) error {
	p.mu.Lock()
	if p.over {
		p.mu.Unlock()
		return fmt.Errorf("refusing to release the payload: the run was already aborted")
	}
	p.over = true
	p.disarmLocked()
	p.mu.Unlock()

	if _, err := blockW.Write([]byte{0}); err != nil {
		return fmt.Errorf("releasing the sandbox: %w", err)
	}
	// The close is deliberately not reported: once the byte is written the
	// payload IS running, and failing the run after that point would report a
	// failure snug did not have and did not act on. Run's own deferred close
	// covers the descriptor either way.
	_ = blockW.Close()
	return nil
}

// abort kills the parked child and then tears the sandbox down. Idempotent,
// and a no-op after release — so `defer pk.abort()` is correct on the success
// path as well, which is what makes it safe to register once and forget.
func (p *parked) abort() {
	p.mu.Lock()
	if p.over {
		p.mu.Unlock()
		return
	}
	p.over = true
	p.disarmLocked()
	p.mu.Unlock()

	// The parked child by pid, FIRST. Killing the enclosing bwrap alone does
	// not do it: --die-with-parent's PR_SET_PDEATHSIG has to travel down the
	// tree and the delivery races the release, measured — a stalled pasta once
	// produced a payload that ran six seconds later, during cleanup, on a run
	// that reported exit 69. This pid is the one bwrap reported through
	// --json-status-fd; it is the init of the sandbox's pid namespace, so
	// killing it collapses the namespace and takes the payload with it.
	if p.childPID > 0 {
		_ = syscall.Kill(p.childPID, syscall.SIGKILL)
		// And then WAIT for it, because kill(2) only queues the signal and
		// snug's very next act is to die — which closes the block pipe and
		// releases anything not yet dead. MEASURED at 1 run in 5 with the kill
		// alone: the signal was sent, snug exited first, and the payload ran.
		// See awaitCollapsed for what is being waited for and why it is a
		// sufficient condition.
		if !awaitCollapsed(p.childPID, collapseTimeout) {
			fmt.Fprintf(os.Stderr, "snug: the sandbox's init (pid %d) did not die within %s of "+
				"SIGKILL; the payload may still be parked and may run as snug exits.\n"+
				"      Nothing snug can do from here changes that — say so rather than exit "+
				"quietly claiming the run was aborted.\n", p.childPID, collapseTimeout)
		}
	}
	if p.teardown != nil {
		p.teardown()
	}
}

// collapseTimeout bounds the wait below. The whole operation is a SIGKILL to a
// process blocked in read(2) and the kernel reaping its namespace peers, which
// is microseconds; this is generous against a loaded CI host, and its
// expiry is reported rather than swallowed.
const collapseTimeout = 2 * time.Second

// awaitCollapsed waits until the sandbox's pid-namespace init is dead, and
// reports whether it got there.
//
// The pid is bwrap's own child — pid 1 of the sandbox's pid namespace — and the
// parked payload is a process inside that namespace, so it is NOT the thing
// being signalled and not the thing being waited for. What makes waiting for
// the init sufficient is the kernel's own ordering: when a pid namespace's init
// exits, zap_pid_ns_processes SIGKILLs every remaining member and reaps them
// BEFORE the init itself becomes a zombie. So "the init is a zombie or gone"
// implies every other member of that namespace is already dead — including a
// payload parked on bwrap's --block-fd, which cannot return to user mode with a
// SIGKILL pending and therefore cannot reach its execve.
//
// A zombie counts, and must: snug is not the init's parent (bwrap is), so
// nothing here can reap it, and on the abort path bwrap is usually dying at the
// same moment. Waiting for the directory to disappear would be waiting for
// whoever reaps it, which is not the question being asked.
func awaitCollapsed(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return true // gone entirely
		}
		if procState(data) == 'Z' {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Microsecond)
	}
}

// procState pulls the state character out of /proc/<pid>/stat. The comm field
// is parenthesised and may itself contain spaces and parentheses, so the parse
// starts at the LAST ')' — the one place this is routinely got wrong.
func procState(stat []byte) byte {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 || i+2 >= len(stat) {
		return 0
	}
	return stat[i+2]
}

func (p *parked) disarmLocked() {
	signal.Stop(p.sigs)
	close(p.sigs) // signal.Stop guarantees no further sends, so this is safe
}
