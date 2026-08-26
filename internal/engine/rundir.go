package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/vdir"
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

// runDirs is this engine's own run directory: the verified handle, its
// verified parent, and the path string podman's argv still needs.
//
// It replaces createRunDir, which hand-rolled what internal/vdir now does for
// everyone — mkdir-that-refuses-to-reuse, then O_DIRECTORY|O_NOFOLLOW, then
// fstat on the descriptor rather than a second walk of the path. That code was
// right, and #233 is about what happened NEXT: the descriptor was closed, the
// path became a string, and every later operation on the most exposed
// directory snug creates re-derived it by name.
//
// /tmp is why this matters more here than for the $XDG_RUNTIME_DIR directory:
// it is commonly world-writable and sticky, so a same-uid process on a shared
// host can plant an entry at a guessable path before this one gets there
// (ENGINE-WIRING.md §3.2).
//
// THE LIMIT, stated rather than left to be discovered: podman is a separate
// process taking --root and --runroot as ARGV, and the paths in this struct
// are handed to it as strings. A descriptor cannot be passed there. What the
// handles buy is everything on THIS side — creation that cannot follow a
// planted symlink, verification of the thing actually opened, and a removal
// that finds this run's directory by inode rather than by a route that may no
// longer lead there.
type runDirs struct {
	parent *os.Root // os.TempDir(), held open for the life of the engine
	root   *os.Root // the run directory itself
	name   string
	path   string
	// lock is held for the life of the engine and never released explicitly.
	// Closing it is what tells a LATER process's sweepStaleEngineRunDirs that
	// this run's owner is gone, so releasing it early would be
	// indistinguishable from dying — the same contract internal/cli's
	// runtimeDirs documents for the runtime directory's own lock.
	lock *os.File
}

// openRunDirs creates and verifies the run directory, and keeps both handles.
//
// The name carries this process's own pid, so an entry already at it is
// suspicious by construction — vdir.MustCreateSubdir refuses reuse, which is
// the rule the old createRunDir enforced with a bare unix.Mkdir and the
// reason it never called MkdirAll.
func openRunDirs(base, name string) (*runDirs, error) {
	parent, err := os.OpenRoot(base)
	if err != nil {
		return nil, fmt.Errorf("engine run directory: opening %s: %w — snug puts this run's "+
			"engine socket and generated config under it; check that it exists and is a "+
			"directory you can write to", base, err)
	}
	root, err := vdir.MustCreateSubdir(parent, base, name)
	if err != nil {
		parent.Close()
		return nil, fmt.Errorf("engine run directory: %w", err)
	}
	path := filepath.Join(base, name)
	lock, err := lockEngineRunDir(root, path)
	if err != nil {
		root.Close()
		parent.Close()
		return nil, err
	}
	return &runDirs{parent: parent, root: root, name: name, path: path, lock: lock}, nil
}

// lockEngineRunDir takes the flock that makes this directory's LIVENESS a
// question the kernel answers, and it is the whole reason
// sweepStaleEngineRunDirs can exist.
//
// Before this, /tmp/snug-<uid>-<pid>/ was reclaimed only by Stop and by the
// error paths container.go arms a deferred Stop for. A SIGKILL runs neither,
// so the directory survived the run that made it — invariant 4's "helpers
// leave nothing behind", false for exactly the case issue #85 fixed for the
// runtime directory and #425 measured still open here. It is not only litter:
// the name carries this process's pid and MustCreateSubdir refuses to reuse an
// existing entry, so a leftover is a landmine for a later run whose pid
// recycles onto it.
//
// The lock file is the FIRST thing written into the directory, before conf/
// and sock/ exist and long before a socket is bound, so a directory carrying
// no lock is one nobody has claimed yet rather than one whose owner died.
// That is what lets the sweep skip a lock-less entry instead of racing a
// concurrent run that is mid-creation.
//
// stillLinked closes the remaining window, the same way internal/cli's
// lockRunDir does: flock succeeds identically on a file that still has a name
// and on one a concurrent sweep already unlinked, so the link count is the
// only thing that tells those apart. Unlike that function this one does not
// retry — MustCreateSubdir has already refused reuse, so a swept directory
// here means a sweep removed a directory THIS process created microseconds
// earlier, and refusing with that sentence is more use than a retry that
// hides it (invariant 5).
func lockEngineRunDir(root *os.Root, path string) (*os.File, error) {
	lock, err := root.OpenFile("lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("engine run directory: creating %s/lock: %w — check free space "+
			"and inodes on that filesystem", path, err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("engine run directory: locking %s/lock: %w — a directory named "+
			"after this process's own pid is already locked by something else, which should be "+
			"impossible on a live system (pids are unique); refusing rather than reusing it",
			path, err)
	}
	linked, lerr := stillLinked(lock)
	if lerr != nil {
		lock.Close()
		return nil, fmt.Errorf("engine run directory: checking whether %s/lock is still linked: "+
			"%w — snug needs to know whether a concurrent sweep removed it, and refuses rather "+
			"than returning a path that may already be gone", path, lerr)
	}
	if !linked {
		lock.Close()
		return nil, fmt.Errorf("engine run directory: %s was removed by a concurrent sweep while "+
			"this process was still creating it — refusing rather than running an engine out of a "+
			"directory that no longer exists", path)
	}
	return lock, nil
}

// stillLinked reports whether f still has a name in the filesystem. An flock
// succeeds identically on a live file and on one unlinked out from under the
// descriptor holding it, so Nlink is the only thing that separates them.
func stillLinked(f *os.File) (bool, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return false, err
	}
	return st.Nlink > 0, nil
}

// errNotStale is returned by the per-entry arm of sweepStaleEngineRunDirs for
// every ordinary reason an entry is left alone — a live lock, no lock at all,
// a foreign owner. It exists so the sweep's own loop stays a list of reasons
// rather than a chain of bare continues.
var errNotStale = errors.New("not a stale engine run directory")

// sub creates one of the run directory's own children — sock/ and conf/,
// which #125's C2b split by writability — through the already-verified
// handle, and verifies it the same way.
func (d *runDirs) sub(name string) (*os.Root, string, error) {
	child, err := vdir.MustCreateSubdir(d.root, d.path, name)
	if err != nil {
		return nil, "", fmt.Errorf("engine run directory: %w", err)
	}
	return child, filepath.Join(d.path, name), nil
}

// remove takes the run directory away through the verified parent handle.
//
// The difference from os.RemoveAll(d.path) is not stylistic and is measured
// the same way #103's was: a descriptor names an inode, a path names a route,
// and os.RemoveAll on a route that no longer leads here reports success having
// removed nothing — which would leave this run's engine socket and generated
// config on disk while snug reported a clean teardown.
func (d *runDirs) remove() error {
	if d == nil {
		return nil
	}
	// The lock goes with the directory it lives in, so this closes it rather
	// than leaving a descriptor open on an unlinked inode. Closing BEFORE the
	// removal is deliberate and safe: MustCreateSubdir already refused to
	// reuse this name, so no other process is waiting on this lock to claim
	// it — the only reader of the released lock is a sweep, and a sweep that
	// wins the race removes the directory this call was about to remove.
	if d.lock != nil {
		d.lock.Close()
		d.lock = nil
	}
	return d.parent.RemoveAll(d.name)
}

// close releases the handles without removing anything. The engine holds them
// for its whole life, so this runs only on a construction path that fails
// after they were opened.
func (d *runDirs) close() {
	if d == nil {
		return
	}
	if d.lock != nil {
		d.lock.Close()
		d.lock = nil
	}
	d.root.Close()
	d.parent.Close()
}
