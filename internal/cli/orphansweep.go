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
// WHAT IT DOES NOT CATCH, measured rather than assumed: a run killed before
// its state file lands (186 ms on this host, and the orphan window opens at
// ~150 ms) has published no pid at all, and the narrower wedge — an init
// blocked in bwrap's uid-map sync `read()` on an eventfd, pre-exec, which
// never answers `--info-fd` — never gets a state file for the same reason.
// Those leftovers stay until something else removes them. This closes the
// half that CAN be closed with the record that already exists; it is not a
// claim to have closed issue #236's window.
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
		if e.IsDir() || !strings.HasPrefix(name, "target-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		sweepOneOrphan(snugRoot, snugPath, name)
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

	killOrphanInit(st, full)

	if err := snugRoot.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		// UNCONDITIONAL, the same split sweepStaleRunDirs draws: a file snug
		// could not remove is state that survives the user, and the user may
		// have to remove it by hand.
		fmt.Fprintf(os.Stderr, "snug: could not remove stale run state %s: %v\n", full, err)
	}
}

// killOrphanInit SIGKILLs the sandbox init a dead run left behind, if it is
// still there and still the same process.
//
// SIGKILL rather than SIGTERM, and it is not impatience: this is bwrap's own
// init, which either has not reached its signal handling yet (the wedged
// case) or is pid 1 of its own pid namespace, where an unhandled SIGTERM from
// outside is simply discarded by the kernel. Killing the init collapses the
// namespace, which is what takes the payload with it.
func killOrphanInit(st runState, statePath string) {
	pid := st.Sandbox.InitPID
	if pid <= 1 {
		return // 0 means the run never published one; 1 is never a host init
	}
	start, err := procStartTime(pid)
	if err != nil {
		return // already gone, which is the ordinary case
	}
	if start != st.Sandbox.InitStarttime {
		return // pid reused since the state was written: not our process
	}
	if err := unix.Kill(pid, unix.SIGKILL); err != nil {
		fmt.Fprintf(os.Stderr, "snug: could not kill the orphaned sandbox init pid %d named by "+
			"%s: %v\n", pid, statePath, err)
		return
	}
	// Behind --verbose, like the stale-directory notice: it reports
	// housekeeping that SUCCEEDED, about a process the user never knew
	// existed. Unlike that one it names a KILL, so it says whose.
	verboseHousekeeping(fmt.Sprintf("killed orphaned sandbox init pid %d for target %s "+
		"(its snug is gone; left behind by a run that did not exit cleanly)", pid, st.Target))
}
