package engine

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/vdir"
)

// engineRunDirPrefix is the name prefix sweepStaleEngineRunDirs claims, and it
// is written here once so the sweep and runDirName cannot drift apart. The
// TRAILING DASH is load-bearing twice over:
//
//   - "snug-<uid>" with no dash is internal/cli's runtime directory when
//     $XDG_RUNTIME_DIR is unset (runtimeBase), which this sweep must never
//     touch — sweepStaleRunDirs owns it and sweeps one level further down.
//   - "snug-engines-<uid>-<key>" is the per-TARGET runroot (paths.go), which is
//     not per-run state at all: it is keyed by sha256(target), shared across
//     runs in time, and reclaimed by `snug engine gc` rather than here.
//
// Both live in the same os.TempDir() as the entries this does claim, so a
// looser prefix would have this function deleting another mechanism's state.
func engineRunDirPrefix() string { return fmt.Sprintf("snug-%d-", os.Getuid()) }

// sweepStaleEngineRunDirs removes /tmp/snug-<uid>-<pid>[-<n>]/ directories
// whose owning process is gone.
//
// It is the engine's half of what sweepStaleRunDirs does for
// $XDG_RUNTIME_DIR/snug, and it exists because that function structurally
// could not see these: its base is runtimeBase() + "snug-<uid>"
// (internal/cli/runtimedir.go), while these are os.TempDir() + the name
// runDirName allocates, one level UP from the directory it walks. Measured
// on issue #425: `go test ./internal/engine/` took /tmp/snug-1000-* from 855
// to 896 in one run, and 100 distinct pids were represented across those 896
// directories.
//
// Why the run directory stays under /tmp rather than moving where the
// existing sweep already reaches: a root-in-userns podman masks
// $XDG_RUNTIME_DIR with its own tmpfs on /run, so the engine's socket cannot
// live there. New's own comment carries that reasoning.
//
// The liveness test is the flock inside each directory and nothing else — no
// /proc, no start-time comparison, no parsing the pid back out of the name.
// SIGKILL releases an flock along with everything else the dying process
// held, which is precisely the case Stop cannot cover and the reason this
// function is not redundant with it.
//
// WHAT IT DELIBERATELY LEAVES: an entry with no lock file at all. A lock is
// the first thing lockEngineRunDir writes, before conf/ and sock/ exist, so
// "no lock" means either a run that has not claimed it yet — removing that
// would be this sweep destroying a live sibling's directory — or a leftover
// from a snug that predates the lock. The second case is real litter this
// cannot reclaim, and it is left rather than guessed at: os.TempDir() is
// commonly world-writable and sticky, and a heuristic that removes
// unlocked directories there is a heuristic aimed at a shared directory.
//
// Errors are SILENT here, unlike sweepStaleRunDirs' removal failure. That
// function names what it could not remove because the user may have to do it
// by hand; this one runs before an engine starts, on a directory the user has
// never heard of, and every reason to skip an entry (a live lock, a foreign
// owner, a symlink) is an ordinary outcome rather than something to act on.
// A removal that fails leaves exactly what was already there.
func sweepStaleEngineRunDirs() {
	base := os.TempDir()
	parent, err := os.OpenRoot(base)
	if err != nil {
		return
	}
	defer parent.Close()

	entries, err := fs.ReadDir(parent.FS(), ".")
	if err != nil {
		return
	}
	prefix := engineRunDirPrefix()
	for _, e := range entries {
		// IsDir() on a ReadDir entry does not follow symlinks, so a symlink
		// pointing at a directory is already excluded here; OpenForRemoval
		// refuses one again from its own Lstat, which is the check that
		// matters if this loop is ever restructured.
		if !e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		if err := removeIfStale(parent, base, e.Name()); err != nil {
			continue
		}
	}
}

// removeIfStale is one entry's decision, split out so the reasons to leave a
// directory alone are a list rather than nested control flow. It returns nil
// only when the directory was actually removed.
func removeIfStale(parent *os.Root, base, name string) error {
	// Refuses a symlink and refuses an entry this uid does not own, from
	// Lstat, before attempting to open it. /tmp is shared, so "someone else's
	// snug-<uid>-<pid>" is a shape that can exist; a foreign owner is not
	// ours to reclaim.
	child, _, err := vdir.OpenForRemoval(parent, base, name)
	if err != nil {
		return err
	}
	defer child.Close()

	lock, err := child.OpenFile("lock", os.O_RDWR, 0)
	if err != nil {
		// No lock file, or something else unreadable about it. See the
		// "WHAT IT DELIBERATELY LEAVES" paragraph above.
		return errNotStale
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close() // a live run; not this function's business
		return errNotStale
	}
	// Releases the flock this call just proved nobody else needed. Done
	// BEFORE the removal so the descriptor is not left open on an inode that
	// is about to lose its name.
	lock.Close()

	return parent.RemoveAll(name)
}
