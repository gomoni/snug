package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// sweepOrphanedSandboxes is invariant 4 enforced by the NEXT run: "no process
// the user did not start and no state that survives them".
//
// A `snug` killed with SIGKILL runs no handler, so between bwrap forking the
// sandbox's init and that init arming its own `PR_SET_PDEATHSIG` there is a
// window in which the init survives its whole process tree — reparented to
// the nearest subreaper, holding a pid, net, user and mount namespace, and on
// the wider end of the window still RUNNING THE PAYLOAD and still writing to
// the target. Issue #13 measured the window and refuted every real-time fix
// except making the stage's own Pdeathsig catchable, which trades away the
// frozen-tree teardown; issue #236 measured the accumulation (23 leftovers on
// one development box, the oldest 12 h old).
//
// This is the deferred half of that answer, and it is the same trade issue
// #85 made for the run DIRECTORY: nothing can be cleaned up at the instant of
// a SIGKILL, so the next run cleans it up instead.
//
// WHY IT CANNOT KILL A LIVE SANDBOX. Three independent conditions, all
// required:
//
//   - The per-target lock is not held. A live run takes that lock in run()
//     BEFORE it starts anything and holds it for the whole run; the kernel
//     releases it when that process dies, however it dies. So "not held"
//     means the owning snug is gone — the same fact `snug <dir>`'s own
//     refusal and `snug attach`'s liveness check already read.
//   - The state file's NAME matches the target it names. The name is
//     sha256(realpath), derived and never stored, so a file hand-placed to
//     make this function kill an arbitrary pid has to carry a target whose
//     hash is its own filename.
//   - The recorded start time still matches /proc/<pid>/stat field 22. This
//     is the pid-reuse guard `snug attach` already relies on: a pid that has
//     been recycled since the state was written has a different start time
//     and is left alone.
//
// WHAT IT STILL DOES NOT CATCH: an init that never answers --info-fd at all,
// parked in read() on one of BWRAP's OWN eventfds (its uid-map sync). No
// record can name it — the pid it would carry is the one bwrap has not
// reported yet — and this is upstream's window, closable only by arming the
// init's PDEATHSIG before that read.
//
// The wide gap that used to follow it is issue #236: exec.go's OnInfo
// publishes state.json only AFTER the mount settle and, on a container run,
// the engine's whole cold start (1-2s typical, engineSocketWaitTimeout 30s) —
// deliberately, on a GATED run, only after the release byte too (issue #125)
// — so for that whole interval no record named an init the stage had already
// learned. initstate.go's ".starting" record closes it: written the instant
// sandbox.Options.OnInit fires, before any of that waiting, and removed only
// once state.json is actually published. sweepOneStartingOrphan below judges
// it through the SAME killOrphanInit, so a leftover from either window is
// killed the same way.
//
// It also removes the stale state file itself, which nothing did before:
// a state file was published per run and removed by nobody, so a development
// box accumulated 1099 of them.
func sweepOrphanedSandboxes() {
	snugRoot, snugPath, err := openTargetStateDir(false)
	if err != nil {
		// No state directory yet (or one we may not open): nothing to sweep.
		// Not a warning — the ordinary first run on a fresh machine is here.
		return
	}
	defer snugRoot.Close()
	sweepOrphanedSandboxesIn(snugRoot, snugPath)
}

// sweepOrphanedSandboxesIn is the body, taking the directory rather than
// finding it. The split exists so this is testable at all: the state
// directory is resolved from the UID alone and deliberately not from
// $XDG_RUNTIME_DIR (issue #122), so a test that could only call the wrapper
// would have to operate on the developer's own live runs.
func sweepOrphanedSandboxesIn(snugRoot *os.Root, snugPath string) {
	entries, err := fs.ReadDir(snugRoot.FS(), ".")
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "target-") {
			continue
		}
		switch {
		case strings.HasSuffix(name, ".json"):
			sweepOneOrphan(snugRoot, snugPath, name)
		case strings.HasSuffix(name, ".starting"):
			sweepOneStartingOrphan(snugRoot, snugPath, name)
		}
	}
}

// sweepOneOrphan is one state file's worth of the decision above. Split out so
// that a `continue` in the loop cannot skip the file-closing, and so the
// conditions can be read in one screen.
func sweepOneOrphan(snugRoot *os.Root, snugPath, name string) {
	full := filepath.Join(snugPath, name)

	f, err := snugRoot.Open(name)
	if err != nil {
		return
	}
	st, decErr := decodeRunState(f)
	f.Close()
	if decErr != nil {
		// A file this version cannot parse is left alone rather than removed:
		// it may have been written by a NEWER snug whose run is still live,
		// and deleting another run's record would break its `snug attach`.
		return
	}

	// The name is the index (targetKeyPrefix), so this is checkable rather
	// than trusted — see the doc comment's second condition.
	if targetStateName(st.Target) != name {
		return
	}

	held, err := targetLockIsHeld(snugRoot, snugPath, st.Target)
	if err != nil || held {
		return // a live run, or a lock we could not probe: not our business
	}

	// The record is the only thing that names this init — pid, start time,
	// six namespace inodes — and nothing else on the host does (a sweep
	// hunting the process itself would have to key on a process NAME, which
	// on a developer box is also Flatpak's bwrap). Remove it only once the
	// init is provably gone: delete it while the orphan lives and every later
	// sweep is blind to it, which is issue #236's accumulation again.
	if killOrphanInit(st, full) == orphanUnresolved {
		return
	}

	if err := snugRoot.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		// A file snug could not remove is state that survives the user, and
		// the user may have to remove it by hand.
		fmt.Fprintf(os.Stderr, "snug: could not remove stale run state %s: %v\n", full, err)
	}
}

// sweepOneStartingOrphan is sweepOneOrphan's twin for a ".starting" record
// (issue #236): a run that never reached state.json, or reached it and then
// was SIGKILLed before removeInitState ran. All three conditions from this
// file's own doc comment apply unchanged — only the record's shape differs,
// built here into the same runState killOrphanInit already knows how to
// judge, so the kill and the removal go through exactly one implementation of
// each rather than a second copy that could disagree with it.
func sweepOneStartingOrphan(snugRoot *os.Root, snugPath, name string) {
	full := filepath.Join(snugPath, name)

	f, err := snugRoot.Open(name)
	if err != nil {
		return
	}
	st, decErr := decodeInitState(f)
	f.Close()
	if decErr != nil {
		return
	}

	if initStateName(st.Target) != name {
		return
	}

	held, err := targetLockIsHeld(snugRoot, snugPath, st.Target)
	if err != nil || held {
		return
	}

	rs := runState{
		Target: st.Target,
		Sandbox: runStateSandbox{
			InitPID:       st.InitPID,
			InitStarttime: st.InitStarttime,
			Namespaces:    st.Namespaces,
		},
	}
	if killOrphanInit(rs, full) == orphanUnresolved {
		return
	}

	if err := snugRoot.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "snug: could not remove stale sandbox-starting record %s: %v\n", full, err)
	}
}

// orphanVerdict exists because the record's two consumers fail closed in
// OPPOSITE directions: the kill must refuse anything not provably our init,
// while the removal must keep any record whose init might still be alive.
// Collapsing both into "we did not kill it" deleted the only thing naming
// each survivor.
type orphanVerdict int

const (
	// orphanGone: no such pid, or the number is held by a task with a
	// different start time or different namespaces — the init this file
	// named is gone and the record is spent.
	orphanGone orphanVerdict = iota
	// orphanKilled: provably ours, and dead now.
	orphanKilled
	// orphanUnresolved: a /proc read or a syscall failed for a reason that is
	// not "no such process", so the init may be alive. Keep the record.
	orphanUnresolved
)

// killOrphanInit SIGKILLs the sandbox init a dead run left behind, if it is
// still there, still the same process, and still in the same namespaces.
//
// SIGKILL rather than SIGTERM, and it is not impatience: this is bwrap's own
// init, which either has not reached its signal handling yet (the wedged
// case) or is pid 1 of its own pid namespace, where an unhandled SIGTERM from
// outside is simply discarded by the kernel. Killing the init collapses the
// namespace, which is what takes the payload with it.
//
// A pidfd carries the identity check, and what it guarantees is narrower than
// "no reuse window" — MEASURED on this kernel, in a fresh user+pid namespace
// writing ns_last_pid:
//
//	pinned pid           = 7 (reaped, pidfd still open)
//	fdinfo says          = Pid: -1  NSpid: -1
//	next child got pid   = 7  (collision=true)
//	signal through pin   = no such process
//	new occupant alive   = true
//
// So the NUMBER is recyclable while the fd is held. What the pin actually
// guarantees is the other half, and it is the half this sweep needs: the pidfd
// refers to the task it opened and dies with it, so a signal through it can
// never reach whatever holds that number later — it returns ESRCH instead
// (#303). That is what makes the kill below fail CLOSED rather than land on a
// stranger, and it is why the kill goes through the pin and never through the
// number.
//
// The consequence for everything else in this function: anything reading
// /proc/<pid> BY NUMBER after the open may be describing a different task.
// The starttime and namespace-inode checks below are exactly that, and they are
// what turns "some process holds this number" into "this is provably our init".
// reap.go and teardown.go state the same guarantee the same way — "pins the
// task the number named AT OPEN TIME" — and a future edit that acts on the
// NUMBER inside this window (a kill(2) fallback, a cgroup lookup, a
// /proc/<pid> write) is not made safe by the pin.
//
// pidfd_open will also happily pin a pid that was ALREADY reused before we
// opened it, so identity must still be confirmed after the open, in two parts
// (#285):
//
//   - starttime, which proves the pinned pid is the one the state file named
//     and not a pre-open reuse of that number;
//   - the six namespace inodes, because starttime alone does NOT prove the
//     process is a sandbox init — a forged or hostile state file naming any
//     live same-uid process would otherwise turn this sweep into an
//     arbitrary-pid kill. Require the process to live in exactly the namespaces
//     the file recorded, the same identity `attach` checks before it joins
//     (attach.go, procNamespaceInodes).
//
// Fail CLOSED throughout: ESRCH or any mismatch means "not provably our init",
// and leaving an orphan is the less-bad outcome than killing a process we
// cannot confirm.
//
// The VERDICT answers a different question, and the caller deletes the record
// on that one: ESRCH or a mismatch says the init is gone, while any OTHER
// failure says nothing about whether it is alive — orphanUnresolved there, and
// the record survives for the next run to retry.
func killOrphanInit(st runState, statePath string) orphanVerdict {
	pid := st.Sandbox.InitPID
	if pid <= 1 {
		return orphanGone // 0 means the run never published one; 1 is never a host init
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			return orphanGone // already gone, which is the ordinary case
		}
		// EMFILE and friends: the process may well be sitting there, and a
		// silent sweep would read as "there was nothing to do".
		fmt.Fprintf(os.Stderr, "snug: could not open a pidfd on the sandbox init pid %d named by "+
			"%s: %v (left for the next run)\n", pid, statePath, err)
		return orphanUnresolved
	}
	defer unix.Close(pidfd)
	// The TASK is pinned from here; the NUMBER is not (issue #345). Measured on
	// this kernel — see this function's doc comment: a reaped pid's number is
	// handed out again while the fd is still open. What the pidfd guarantees is
	// that a signal THROUGH IT reaches the task it opened or returns ESRCH, so
	// the kill below fails closed.
	//
	// So the checks between here and that kill do NOT all name the same task by
	// virtue of the pin — procStartTime and procNamespaceInodes below read
	// /proc/<pid> BY NUMBER, and it is what they COMPARE (the recorded start
	// time, the recorded namespace inodes) that establishes identity, not the
	// pin. This comment claimed otherwise for as long as the doc comment above
	// did, and was left behind when that one was corrected: a rule fixed at the
	// site the reporter quoted while a second copy survived twelve lines below
	// it, inside the function the corrected header governs.
	start, err := procStartTime(pid)
	if err != nil {
		// ENOENT: it exited between the open and the stat. Anything else is a
		// /proc we could not read about a pid that may still be there.
		if errors.Is(err, fs.ErrNotExist) {
			return orphanGone
		}
		return orphanUnresolved
	}
	if start != st.Sandbox.InitStarttime {
		return orphanGone // the number was reused: our init exited
	}
	nsIno, err := procNamespaceInodes(pid)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return orphanGone
		}
		return orphanUnresolved
	}
	for _, k := range runStateNamespaceKinds {
		if nsIno[k] != st.Sandbox.Namespaces[k] {
			// The namespaces are created before the pid is published and a
			// process never leaves them, so this is not our init.
			return orphanGone
		}
	}
	if err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0); err != nil {
		fmt.Fprintf(os.Stderr, "snug: could not kill the orphaned sandbox init pid %d named by "+
			"%s: %v\n", pid, statePath, err)
		if errors.Is(err, unix.ESRCH) {
			return orphanGone // it died between the checks and the signal
		}
		// EPERM is the case that matters: the init is still there and this
		// record is the only thing that names it.
		return orphanUnresolved
	}
	// Behind --verbose, like the stale-directory notice: it reports
	// housekeeping that SUCCEEDED, about a process the user never knew
	// existed. Unlike that one it names a KILL, so it says whose.
	verboseHousekeeping(fmt.Sprintf("killed orphaned sandbox init pid %d for target %s "+
		"(its snug is gone; left behind by a run that did not exit cleanly)", pid, st.Target))
	return orphanKilled
}
