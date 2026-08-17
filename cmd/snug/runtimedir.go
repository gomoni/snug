package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// runtimeDir is a private per-run directory for sockets: the ssh-agent
// proxy's and the container proxy's. Both are named things a same-uid
// process reaching them can use as a signing oracle or a container-creation
// oracle, so the directory holding them has to resist being redirected
// before snug gets there, not just after.
//
// Two guards, both load-bearing (issue #61 part (c), which promoted this
// from #31's low-severity list once it became the prerequisite for `snug
// attach`):
//
//   - Every directory this function creates or reuses — the shared "snug"
//     directory and this run's own subdirectory — is opened through
//     *os.Root, which refuses to resolve ANY name outside the tree it was
//     opened on, structurally rather than by convention. os.MkdirAll, what
//     this function used to call, has no such property: it follows a
//     pre-planted symlink-to-directory and never inspects an existing
//     directory's owner or mode at all.
//   - os.Root's own documented contract is weaker at exactly one point: its
//     methods "follow symbolic links, but symbolic links may not reference a
//     location outside the root" — so an in-root symlink planted at one of
//     the two names snug itself creates ("snug"/"snug-<uid>", and the
//     per-run directory) would still be followed. secureSubroot narrows that
//     at exactly those two names with an Lstat-based refusal before opening
//     either one; it is not a distrust of os.Root generally, only of what
//     it explicitly leaves following.
//   - Every directory this function touches — even one it just created,
//     because a hostile umask can weaken the mode Mkdir asked for — has its
//     owner and mode checked afterwards, on the open *os.Root itself
//     (Root.Stat(".")) rather than by path, so what is checked is the thing
//     that was actually opened. A mismatch is refused rather than repaired.
//     Invariant 5: a chmod here would be a silent downgrade of whatever
//     guarantee the wrong mode already broke.
//
// The fallback when $XDG_RUNTIME_DIR is unset changes shape along with this
// fix: it used to be the fixed name "snug" directly under os.TempDir(),
// which is commonly /tmp — world-writable, so any user on a shared host
// could pre-create that exact path before the real owner's first run and
// would then own every socket placed under it. The directory name is now
// uid-scoped ("snug-<uid>"), so a squatter cannot pass the ownership check
// even if they win the race to create it first.
//
// On its way in, runtimeDir also sweeps run-* directories left behind by a
// run that ended abnormally (issue #85). See sweepStaleRunDirs for how a
// directory no longer relies on /proc/<pid>/stat to tell a live run from a
// dead one.
//
// runtimeDir is idempotent within a process (both the ssh-agent proxy and
// the container proxy call it independently) and memoized by the resolved
// path rather than a single cached value: the lock this function takes below
// is an flock, which is scoped to the OPEN FILE DESCRIPTION rather than the
// process, so a second unguarded open+flock from this same process would
// contend with its own first one. Keying the cache by path — rather than
// caching "have we ever succeeded" — is also what keeps this function's
// tests independent of each other: each test points $XDG_RUNTIME_DIR at its
// own temp directory, so each gets its own cache entry and its own fresh run
// through every check.
func runtimeDir() (string, error) {
	base, snugName := runtimeBase()

	root, err := os.OpenRoot(base)
	if err != nil {
		return "", fmt.Errorf("runtime directory: opening %s: %w", base, err)
	}
	defer root.Close()

	snugRoot, created, err := secureSubroot(root, base, snugName)
	if err != nil {
		return "", fmt.Errorf("runtime directory: %w", err)
	}
	defer snugRoot.Close()
	snugPath := filepath.Join(base, snugName)

	if !created {
		// A freshly-created directory has nothing in it; sweeping one is a
		// correct no-op, so this is an optimisation, not a correctness call.
		sweepStaleRunDirs(snugRoot, snugPath)
	}

	// The name is a human-readable label ONLY — nothing parses it back out.
	// The lock taken below is what tells a live run's directory apart from a
	// dead one; the pid in the name is not load-bearing the way it used to
	// be when a stale directory was identified by parsing this string.
	runName := fmt.Sprintf("run-%d", os.Getpid())
	runPath := filepath.Join(snugPath, runName)

	if err := runLock(runPath, snugRoot, snugPath, runName); err != nil {
		return "", err
	}

	return runPath, nil
}

// runtimeBase computes $XDG_RUNTIME_DIR (or the uid-scoped fallback under
// os.TempDir()) and the name of the directory snug owns directly under it.
// Pure string computation — no I/O — so runtimeDir can compute the same
// candidate path twice without touching the filesystem twice.
func runtimeBase() (base, snugName string) {
	base = os.Getenv("XDG_RUNTIME_DIR")
	snugName = "snug"
	if base == "" {
		// os.TempDir() is frequently mode 1777 (world-writable, sticky)
		// rather than private to us, and it is provided by the OS the same
		// way $XDG_RUNTIME_DIR is — this function does not own it and does
		// not second-guess its mode. What it owns, and therefore verifies,
		// starts one level down: the "snug"/"snug-<uid>" directory and
		// everything under it.
		base = os.TempDir()
		snugName = fmt.Sprintf("snug-%d", os.Getuid())
	}
	return base, snugName
}

// runLocks holds the flock this process took on each run directory it has
// claimed, keyed by the resolved path. The descriptor is never closed and
// never unlocked for the lifetime of this process: closing it is what tells
// a later sweep (in a different, later process) that the owner is gone, so
// closing it early would be indistinguishable from this run having crashed.
//
// It must never be handed to the sandboxed payload. It already is not: every
// os.File this package opens gets O_CLOEXEC from the os package by default,
// and internal/fdseal.Seal marks every remaining non-stdio descriptor
// close-on-exec again immediately before bwrap is forked, belt and braces —
// so the fd this map holds is closed automatically the moment bwrap execs,
// without ever being enumerated in cmd.ExtraFiles or otherwise offered to
// it.
var (
	runLocksMu sync.Mutex
	runLocks   = map[string]*os.File{}
)

// runLock takes the per-run flock exactly once per path per process. On a
// second call for the same path (this process's own idempotent re-entry) it
// is a cache hit and touches nothing.
//
// It retries once on errLockFileSwept — see lockRunDir for what that means
// and why one retry is enough in practice — and refuses outright rather than
// retrying forever, because a caller asking "where do my sockets go" needs an
// answer, not a loop.
func runLock(runPath string, snugRoot *os.Root, snugPath, runName string) error {
	runLocksMu.Lock()
	defer runLocksMu.Unlock()

	if _, ok := runLocks[runPath]; ok {
		return nil
	}

	lock, err := lockRunDir(snugRoot, snugPath, runName)
	if errors.Is(err, errLockFileSwept) {
		lock, err = lockRunDir(snugRoot, snugPath, runName)
	}
	if err != nil {
		if errors.Is(err, errLockFileSwept) {
			return fmt.Errorf("runtime directory: %s: a concurrent sweep removed this run's "+
				"own directory twice in a row while this process was trying to lock it — "+
				"refusing rather than returning a path that may no longer exist", runPath)
		}
		return err
	}

	runLocks[runPath] = lock
	return nil
}

// errLockFileSwept means the lock file this call just locked had already
// been unlinked by the time it checked — see lockRunDir. It is internal:
// runLock retries on it once and never lets it escape as a final answer,
// because a path to a directory that no longer exists is not a runtime
// directory.
var errLockFileSwept = errors.New("lock file was removed by a concurrent sweep before this process finished locking it")

// lockRunDir creates (or reuses) this run's own directory, and takes the
// flock on the lock file inside it — before that directory is used for
// anything else, which is the whole point: the lock file is the very first
// thing written into it, before a single socket is bound.
//
// Between opening the lock file and taking the flock on it there is a window
// this process does not control: a DIFFERENT, concurrently starting snug
// process running sweepStaleRunDirs over the same shared "snug" directory
// can open that SAME lock file, find it present but not yet held — which is
// indistinguishable, from the sweep's side, from "the owner died holding
// it" — and RemoveAll the whole run directory out from under us. flock on an
// already-unlinked descriptor still succeeds, so the lock alone cannot tell
// this apart from an ordinary success. What can: the descriptor's link
// count. Zero means nothing points to this file any more, which can only
// happen here if the directory it lived in was removed while we were mid-
// creation of it.
func lockRunDir(snugRoot *os.Root, snugPath, runName string) (*os.File, error) {
	runPath := filepath.Join(snugPath, runName)

	runRoot, _, err := secureSubroot(snugRoot, snugPath, runName)
	if err != nil {
		return nil, fmt.Errorf("runtime directory: %w", err)
	}
	defer runRoot.Close()

	lock, err := runRoot.OpenFile("lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("runtime directory: opening %s/lock: %w", runPath, err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("runtime directory: locking %s/lock: %w — a directory named "+
			"after this process's own pid is already locked by something else, which should be "+
			"impossible on a live system (pids are unique); refusing rather than reusing it", runPath, err)
	}

	if linked, lerr := stillLinked(lock); lerr != nil {
		lock.Close()
		return nil, fmt.Errorf("runtime directory: checking whether %s/lock is still linked: %w", runPath, lerr)
	} else if !linked {
		lock.Close()
		return nil, errLockFileSwept
	}

	return lock, nil
}

// stillLinked reports whether the open file f still has a name in the
// filesystem — Nlink > 0. An flock succeeds identically on a file that still
// exists and on one that has been unlinked out from under the descriptor
// holding it, so this is the only reliable way to tell those two apart.
func stillLinked(f *os.File) (bool, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return false, err
	}
	return st.Nlink > 0, nil
}

// sweepStaleRunDirs removes run-* directories whose owning process is gone —
// invariant 4 says helpers "leave nothing behind", and that was false the
// moment a run ended in a SIGKILL rather than a clean exit: nothing that
// process does on its way out can run, so the only place left to remove its
// directory is the next run's way in (issue #85).
//
// This used to tell a live run apart from a dead one by reading
// /proc/<pid>/stat and comparing start times, to survive pid reuse. That is
// gone: an flock on a lock file inside the run's own directory is a
// liveness test the kernel already performs correctly, including on the
// exact case #85 is about — SIGKILL releases an flock along with everything
// else the dying process held, no signal handler required, no /proc parsing
// required, and no pid-reuse reasoning required either, because the lock
// says nothing about identity, only about whether anyone still holds it.
//
//   - Lock acquired means the owner is gone: this function is now the only
//     thing holding the file open, so nothing else can have been holding
//     the lock a moment ago.
//   - Lock refused (EWOULDBLOCK) means a live run; leave it alone.
//   - No lock file at all means the directory may be mid-creation by a run
//     that has not reached lockRunDir yet — left alone rather than guessed
//     at. Being conservative here costs one stale directory; being wrong
//     costs a live run its sockets.
//
// Those three are correct FROM THIS FUNCTION'S SIDE, and they are also not
// the whole story: "lock file present, owner alive, lock not yet taken" is a
// real fourth state — this function's own OpenFile+Flock lands in the same
// window a concurrent lockRunDir is trying to get through — and from here it
// is indistinguishable from "owner died holding it", which is exactly the
// case this function exists to act on. That is not a bug in the three-way
// read above; it means the fourth case cannot be resolved on the SWEEPING
// side at all, because nothing here can see whether a lock is merely
// "not yet taken" versus "never going to be taken again". It is resolved on
// the CREATING side instead: lockRunDir checks, after it takes its own
// flock, that the file it locked is still linked, and treats "no longer
// linked" — meaning a sweep did land in that window and removed the
// directory — as a reason to retry rather than hand back a path to a
// directory that no longer exists.
//
// This reads snugPath by NAME (through snugRoot, not a cached fd from a
// previous check) — by this point the "snug" directory's existence and
// ownership have already been verified by the caller, its identity cannot
// be redirected by anything other than the same uid this process runs as,
// and same-uid tampering is outside what this guard — or #61's threat notes
// — cover.
func sweepStaleRunDirs(snugRoot *os.Root, snugPath string) {
	entries, err := fs.ReadDir(snugRoot.FS(), ".")
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		full := filepath.Join(snugPath, name)

		lock, err := snugRoot.OpenFile(name+"/lock", os.O_RDWR, 0)
		if err != nil {
			// No lock file (or something else unreadable about this entry):
			// leave it alone. Could be mid-creation by a run that has not
			// reached runLock yet.
			continue
		}
		flockErr := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if flockErr != nil {
			lock.Close() // a live run; not this function's business
			continue
		}
		lock.Close() // releases the flock we just proved nobody else needed

		if rmErr := snugRoot.RemoveAll(name); rmErr != nil {
			fmt.Fprintf(os.Stderr, "snug: could not remove stale run directory %s: %v\n", full, rmErr)
			continue
		}
		fmt.Fprintf(os.Stderr, "snug: removed stale run directory %s (its owning process is gone; "+
			"left behind by a run that did not exit cleanly)\n", full)
	}
}

// secureSubroot opens (creating it if absent) a directory named `name`
// inside the already-verified root `parent`, and returns it as its own
// *os.Root so nothing opened through it can walk back out or past it.
//
// It never trusts an existing entry: found means checked, and — per
// invariant 5 — a check that fails is refused rather than repaired.
//
// The Lstat immediately below is the deliberate narrowing described on
// runtimeDir: os.Root's documented behaviour is to follow an in-root
// symlink, and this is one of the two names ("snug"/"snug-<uid>", and the
// per-run directory) where that is one degree more permissive than this
// function wants. It runs AFTER Mkdir, not before: Mkdir is the atomic
// step — either it creates a fresh directory (nothing could have raced a
// symlink into that exact name in between, because the parent directory
// this create just happened in has already passed the ownership+mode 0700
// check below, and 0700 owned by this uid is the only thing that can write
// there), or it reports EEXIST, in which case the Lstat is what tells apart
// "a directory left by an earlier run" from "a symlink something planted
// before snug got here".
func secureSubroot(parent *os.Root, parentDesc, name string) (child *os.Root, created bool, err error) {
	mkErr := parent.Mkdir(name, 0o700)
	created = mkErr == nil
	if mkErr != nil && !errors.Is(mkErr, fs.ErrExist) {
		return nil, false, fmt.Errorf("creating %s: %w", filepath.Join(parentDesc, name), mkErr)
	}

	full := filepath.Join(parentDesc, name)

	if fi, lerr := parent.Lstat(name); lerr != nil {
		return nil, false, fmt.Errorf("checking %s: %w", full, lerr)
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("refusing %s: it is a symlink — something on this host "+
			"planted it before snug got here; remove it by hand and re-run snug", full)
	}

	child, err = parent.OpenRoot(name)
	if err != nil {
		return nil, false, fmt.Errorf("opening %s: %w", full, err)
	}

	if verr := verifyOwnedAndPrivate(child, full); verr != nil {
		child.Close()
		return nil, false, verr
	}
	return child, created, nil
}

// verifyOwnedAndPrivate refuses a directory that is not ours, or that is
// readable, writable or searchable by anyone else — the two properties that
// make it safe to place a unix socket inside without asking who else could
// already be watching that path.
//
// It checks the open HANDLE (root.Stat(".")), not a path string, so what
// gets checked is exactly the directory that was just opened — os.Root
// prevents this handle from having been redirected out of the tree it was
// opened on, but says nothing on its own about who owns what is inside it.
func verifyOwnedAndPrivate(root *os.Root, desc string) error {
	fi, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("checking %s: %w", desc, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("checking %s: could not read its owner on this platform", desc)
	}
	if uid := int(st.Uid); uid != os.Getuid() {
		return fmt.Errorf("refusing %s: owned by uid %d, not you (uid %d) — "+
			"something else on this host created it; remove it by hand if you are sure "+
			"it is not in use — snug will not use a directory it does not own for sockets",
			desc, uid, os.Getuid())
	}
	if mode := fi.Mode().Perm(); mode != 0o700 {
		return fmt.Errorf("refusing %s: mode is %#o, must be exactly 0700 — "+
			"check the umask that created it and fix the permissions by hand; "+
			"snug will not repair it silently", desc, mode)
	}
	return nil
}
