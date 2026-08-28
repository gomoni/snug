package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

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
// AN INIT THAT NEVER ANSWERS --info-fd AT ALL — parked in read() on one of
// BWRAP's OWN eventfds, its uid-map sync — used to be listed here as
// uncatchable, on the ground that no record can name it because its pid is
// the one bwrap has not reported yet. That ground is false, and was measured
// so: the init is the DIRECT CHILD of the bwrap process snug started, so
// /proc/<bwrap>/task/*/children names it with bwrap reporting nothing.
// internal/sandbox's initwatch.go walks it and publishes the same ".starting"
// record, guarded by the one thing that separates an init from any other
// child — it lives in a user namespace that is not ours.
//
// WHAT IS STILL NOT CAUGHT is the STAGED arm of that same window: there the
// stage forks bwrap, so P0 has no pid to walk from and no watcher is started.
// The same walk would close it, one process further in.
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
// It also removes the FILES a dead run left behind, which nothing did before:
// a state file was published per run and removed by nobody, so a development
// box accumulated 1099 of them; sweepOneStaleLock does the same for the
// per-target lock (738 measured beside 2 live records) and for the leftover of
// a state write a SIGKILL interrupted.
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
	// Two passes, and the ORDER is load-bearing rather than tidy: the record
	// sweeps below probe the per-target lock through targetLockIsHeld, which
	// opens it with O_CREATE. A lock removed before them is recreated behind
	// them, and the sweep would leave the directory exactly as full as it
	// found it.
	interrupted := map[string][]string{}
	var locks []string
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
		case strings.HasSuffix(name, ".lock"):
			locks = append(locks, name)
		case strings.Contains(name, ".tmp-"):
			// writeTargetFile's temporary name. The stem is everything before
			// the first dot: targetKeyPrefix is "target-sha256_<64 hex>" and
			// legacyTargetKeyPrefix is "target-<64 hex>", neither of which
			// contains one, so this splits both generations correctly.
			stem, _, _ := strings.Cut(name, ".")
			interrupted[stem] = append(interrupted[stem], name)
		}
	}
	for _, name := range locks {
		stem := strings.TrimSuffix(name, ".lock")
		sweepOneStaleLock(snugRoot, snugPath, name, interrupted[stem])
		delete(interrupted, stem)
	}
	// Whatever is LEFT has no lock file beside it, and nothing can be writing
	// it: writeTargetFile only ever produces one of these while holding the
	// target lock, and holding a lock requires a lock file to hold. So the
	// stems still in this map name writes whose lock has already been swept —
	// by an earlier run, or by the pass above after one Remove failed — and
	// they were unreachable until now, because the whole .tmp- cleanup hung
	// off a .lock the same pass deletes.
	for _, names := range interrupted {
		for _, tmp := range names {
			if rerr := snugRoot.Remove(tmp); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
				fmt.Fprintf(os.Stderr, "snug: could not remove the leftover of an interrupted run-state write %s: %v\n",
					filepath.Join(snugPath, tmp), rerr)
			}
		}
	}
}

// nameStillNames reports whether name, resolved without following a final
// symlink, is the very file f refers to — same device, same inode.
//
// An flock says nothing about the NAME: it is held on the open file
// description, and the directory entry that produced it can be renamed over,
// hardlinked and swapped, or replaced entirely while the lock is held. So
// "we locked it" and "this name is it" are two facts, and only the second
// licenses an unlink of that name.
func nameStillNames(snugRoot *os.Root, name string, f *os.File) bool {
	var onFd unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &onFd); err != nil {
		return false
	}
	fi, err := snugRoot.Lstat(name)
	if err != nil {
		return false
	}
	onName, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return uint64(onName.Dev) == onFd.Dev && onName.Ino == onFd.Ino
}

// sweepOneStaleLock removes a per-target lock file nobody holds, and any
// interrupted state write sitting beside it.
//
// Neither was removed by anything before this function. The lock file is
// created once per target ever sandboxed and kept for the life of the boot,
// and writeTargetFile's temporary only ever removes the name carrying its OWN
// pid, so a write interrupted by a SIGKILL leaves a file no later run's name
// can match. Measured on one development box after two days: 738 lock files
// against 2 live records, and one `target-<hash>.json.tmp-<pid>`.
//
// That is invariant 4 — "no state that survives them" — and the same answer
// #85 gave for the run directory and issue #236 gave for state.json: nothing
// can be cleaned up at the instant of a SIGKILL, so the next run does it.
//
// WHY REMOVING A LOCK FILE IS SAFE, in the two halves lockRunDir already
// splits it into one directory up:
//
//   - THIS side unlinks only while HOLDING the exclusive flock, and only after
//     confirming that the NAME still resolves to the inode it locked. The
//     flock alone is not that guarantee, which a redteam round measured: a
//     planted hardlink plus a rename swaps a different file under the name
//     between the lock and the unlink, and `Nlink > 0` reads the same either
//     way. It is st_dev/st_ino that separates them.
//   - The CREATING side revalidates. flock on an unlinked descriptor succeeds
//     exactly as it does on a live one, so openAndHoldTargetLock and
//     targetLockIsHeld both check Nlink after their own flock and retry
//     against the NAME when it is zero. Without that half, two runs would
//     serialise on two different inodes for one target and both proceed —
//     issues #119 and #122.
//
// The interrupted writes go first and go through the SAME held lock, because
// the only thing that writes them is a process holding it.
func sweepOneStaleLock(snugRoot *os.Root, snugPath, name string, interrupted []string) {
	// No O_CREATE, unlike every other opener of this name: a lock file that
	// vanished between the readdir and here is not one to bring back.
	lock, err := snugRoot.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return
	}
	defer lock.Close()

	if flockErr := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); flockErr != nil {
		return // a live run holds it, or a lock this process may not probe
	}
	if linked, lerr := stillLinked(lock); lerr != nil || !linked {
		return // another process's sweep got here first
	}
	if !nameStillNames(snugRoot, name, lock) {
		// Something replaced the name between the open and here. Unlinking
		// now would remove a file this function never locked — a live run's,
		// if that is what now carries the name.
		return
	}

	for _, tmp := range interrupted {
		if rerr := snugRoot.Remove(tmp); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "snug: could not remove the leftover of an interrupted run-state write %s: %v\n",
				filepath.Join(snugPath, tmp), rerr)
		}
	}
	if rerr := snugRoot.Remove(name); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "snug: could not remove the stale target lock %s: %v\n",
			filepath.Join(snugPath, name), rerr)
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
	// than trusted — see the doc comment's second condition. Either
	// generation of the prefix counts (targetStateNameMatches, issue #349):
	// a record a pre-upgrade binary named is still this target's record.
	if !targetStateNameMatches(st.Target, name) {
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

	if !initStateNameMatches(st.Target, name) {
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
