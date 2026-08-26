package engine

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/vdir"
)

// isEngineRunDirName reports whether name is one runDirName could have
// produced: "snug-<uid>-<pid>" or "snug-<uid>-<pid>-<n>", every component
// after the uid being decimal digits.
//
// IT MATCHES THE SHAPE, NOT A PREFIX, AND THAT IS THE WHOLE OF ISSUE #425's
// RED-TEAM FINDING F1. A prefix of "snug-<uid>-" also matches
// internal/cli's hostTmpDirPath (tmpdir.go) — `@tmp-shared`'s per-project host
// directory, `os.TempDir()/snug-<uid>-sha256_<64hex>` — which is 0700, owned by
// this uid, and therefore indistinguishable to vdir.OpenForRemoval. Worse, that
// profile grants the PAYLOAD rw on it ("{host_tmpdir}:/tmp" in base.toml), so a
// sandbox only had to write a file called `lock` — the single most ordinary
// name in /tmp, and what `flock /tmp/lock`, python filelock and any build
// script produce — to have the next container-enabled run on the machine
// delete another project's persistent shared /tmp, contents and all. MEASURED
// end to end: a `@podman-socket` run on project B destroyed project A's
// directory, and a live `@tmp-shared` sandbox had its /tmp unlinked underneath
// it mid-run (nlink 0, every subsequent write ENOENT).
//
// So the filter is derived from the ONE function that authors these names,
// and a `snug-<uid>-<anything-else>` mechanism added later fails it
// structurally rather than needing to be remembered here. The trailing dash
// still matters — it is what separates "snug-<uid>" and
// "snug-engines-<uid>-<key>" — but a dash alone was never enough.
func isEngineRunDirName(name string) bool {
	rest, ok := strings.CutPrefix(name, fmt.Sprintf("snug-%d-", os.Getuid()))
	if !ok {
		return false
	}
	// At most two components: runDirName emits "<pid>" for the first engine in
	// a process and "<pid>-<n>" for every one after it.
	parts := strings.Split(rest, "-")
	if len(parts) > 2 {
		return false
	}
	for _, p := range parts {
		if !allDigits(p) {
			return false
		}
	}
	return true
}

// allDigits is deliberately not strconv.Atoi: Atoi accepts a leading "+" or
// "-" and silently overflows on a long run of digits, and neither is a name
// runDirName can produce. The question here is "could this string have come
// out of %d", which is exactly one or more ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

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
	for _, e := range entries {
		// IsDir() on a ReadDir entry does not follow symlinks, so a symlink
		// pointing at a directory is already excluded here; OpenForRemoval
		// refuses one again from its own Lstat, which is the check that
		// matters if this loop is ever restructured.
		if !e.IsDir() || !isEngineRunDirName(e.Name()) {
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
