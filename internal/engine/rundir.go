package engine

import (
	"fmt"
	"os"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// runSeq disambiguates the run directory name when New is called more than
// once in the same process: a real snug invocation creates exactly one
// Engine per run, so the FIRST call gets the plain, spec-shaped name
// (ENGINE-WIRING.md §3.2: "/tmp/snug-<uid>-<runid>/", runid = this process's
// own pid) and every call after it — which only ever happens in this
// package's own tests — gets a numbered suffix so it does not collide with
// (and get refused by createRunDir's own no-reuse rule against) a directory
// an earlier call in the same test binary already claimed.
var runSeq atomic.Int64

func runDirName(uid, pid int) string {
	n := runSeq.Add(1)
	if n == 1 {
		return fmt.Sprintf("snug-%d-%d", uid, pid)
	}
	return fmt.Sprintf("snug-%d-%d-%d", uid, pid, n)
}

// createRunDir creates the per-run directory the engine's socket and runroot
// live under, hardened the way commit dfe6ac8 (#61, #85) hardened snug's
// $XDG_RUNTIME_DIR-based runtime directory — because /tmp is a REAL new
// exposure that one did not have (ENGINE-WIRING.md §3.2): it is commonly
// world-writable+sticky, so a same-uid process on a shared host can plant an
// entry at a guessable path before this one gets there.
//
// Two guards:
//
//   - mkdir, which FAILS if the path already exists — never a blind
//     os.MkdirAll into a directory this process did not just create, and
//     never a reuse of whatever is already there. The path is unique per run
//     (it carries this process's own pid), so an existing entry at that exact
//     name is itself suspicious: either a planted symlink, or a leftover
//     from a run whose pid was reused, and either way the right answer is to
//     refuse, not repair.
//   - open with O_DIRECTORY|O_NOFOLLOW immediately after, then fstat the
//     resulting descriptor (never the path a second time) to confirm owner
//     and mode. This is what defeats the TOCTOU where something races the
//     mkdir above: if the directory this process just created was removed
//     and replaced with a symlink before this open runs, O_NOFOLLOW refuses
//     to follow it rather than silently operating on whatever it now points
//     at.
func createRunDir(dir string) error {
	if err := unix.Mkdir(dir, 0o700); err != nil {
		return fmt.Errorf("engine run directory %s: %w — refusing to reuse an existing entry at "+
			"this path. /tmp is commonly world-writable, and a pre-planted directory or symlink "+
			"there is exactly the shape a same-host attacker would use; if you are sure nothing is "+
			"using it, remove it by hand and re-run snug", dir, err)
	}

	fd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("engine run directory %s: opening the directory just created: %w", dir, err)
	}
	defer unix.Close(fd)

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("engine run directory %s: checking it: %w", dir, err)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("engine run directory %s: owned by uid %d, not this process's own uid "+
			"%d — refusing to use a directory something else on this host created", dir, st.Uid, os.Getuid())
	}
	if mode := st.Mode & 0o777; mode != 0o700 {
		return fmt.Errorf("engine run directory %s: mode is %#o, must be exactly 0700 — check the "+
			"umask that created it", dir, mode)
	}
	return nil
}
