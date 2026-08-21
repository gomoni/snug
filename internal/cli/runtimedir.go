package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gomoni/snug/internal/vdir"
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
//     per-run directory) would still be followed. vdir.SecureSubdir narrows that
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
// openRuntimeDir is idempotent within a process (both the ssh-agent proxy
// and the container proxy call it independently) and memoized by the
// resolved path rather than a single cached value: the lock it takes below
// is an flock, which is scoped to the OPEN FILE DESCRIPTION rather than the
// process, so a second unguarded open+flock from this same process would
// contend with its own first one. Keying the cache by path — rather than
// caching "have we ever succeeded" — is also what keeps this function's
// tests independent of each other: each test points $XDG_RUNTIME_DIR at its
// own temp directory, so each gets its own cache entry and its own fresh run
// through every check.
//
// It returns a *runtimeDir rather than a string, and that is issue #103's
// whole point: at the return statement of the old `runtimeDir() (string,
// error)` every guarantee above was gone. What came back was, to the
// compiler and to a reader, indistinguishable from any other string — so
// `filepath.Join(dir, "podman.sock")` at each call site re-derived a path by
// NAME from a directory that had been verified once, at a moment now past,
// and nothing stopped some other string being passed where this one was
// meant. The checks were real; nothing carried them forward. A type does.
func openRuntimeDir() (*runtimeDir, error) {
	base, snugName := runtimeBase()

	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, fmt.Errorf("runtime directory: opening %s: %w - snug keeps its per-run state "+
			"there; check that it is a directory you own with mode 0700", base, err)
	}
	defer root.Close()

	snugRoot, created, err := vdir.SecureSubdir(root, base, snugName)
	if err != nil {
		return nil, fmt.Errorf("runtime directory: %w - snug refuses to keep run state anywhere "+
			"it cannot verify it owns", err)
	}
	// NOT closed here any more: the returned value keeps it, because removing
	// this run's directory at the end of the run goes back through this
	// verified parent descriptor rather than re-walking the path by name (see
	// runtimeDir.Remove).
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
	runName := runDirName()
	runPath := filepath.Join(snugPath, runName)

	d, err := claimRunDir(runPath, snugRoot, snugPath, runName)
	if err != nil {
		snugRoot.Close()
		return nil, err
	}
	return d, nil
}

// runtimeDir is one run's own directory, already verified and already
// locked: the value form of what the checks above establish.
//
// It holds the verified PARENT descriptor (snugRoot) plus this run's name
// rather than only a path, so the one operation that outlives the checks —
// removing the directory when the run ends — goes through that descriptor
// instead of handing a path string back to os.RemoveAll to walk again.
//
// THE SOCKET IS THE HONEST LIMIT, and it was measured rather than assumed
// (issue #103 asks for exactly that). bind(2) has no *at variant, so the
// last step of both call sites is net.Listen("unix", <path string>) and a
// path string has to exist somewhere. The candidate answer — hand out
// /proc/self/fd/<fd>/<name>, so the bind resolves through the already-open
// descriptor — WORKS: measured here, net.Listen on such a path succeeds, the
// socket appears at the real path, a peer dialling the real path connects,
// and the name is 22 bytes rather than a long absolute path, which matters
// against sun_path's 108-byte limit.
//
// It is deliberately NOT adopted yet, for two measured reasons rather than
// caution. First, bwrap needs the REAL host path anyway (policy.BindSocket
// mounts it), so the /proc path would have to travel next to the real one
// through both proxies — two paths for one socket, which is how the wrong
// one gets used. Second, the listener then reports that path as its own
// address: measured, both ln.Addr() and the peer's RemoteAddr() read
// /proc/self/fd/4/x.sock, a string meaningless outside this process and
// wrong in any message that prints it. Both proxies own their own
// net.Listen today (dockerproxy.New, sshproxy.New take a path), so adopting
// it means changing their signatures to take a listener — the next site,
// with its own test diff, which is how issue #103 says to do this.
type runtimeDir struct {
	path     string
	snugRoot *os.Root
	runName  string
	lock     *os.File
}

// Path is the real host path of this run's directory — for a message, and
// for the one caller that still needs a string. Prefer Socket for anything
// under it.
func (d *runtimeDir) Path() string { return d.path }

// Socket is the host path a proxy binds for name, and it is the reason the
// call sites no longer say filepath.Join: "what may be created in here" is
// now a method on the value that owns the directory rather than a string
// operation anyone can perform on any string.
//
// The name is checked rather than trusted. Nothing in snug passes a
// non-literal today, so this is not defending against a caller that exists;
// it is what keeps the guarantee the type carries from being lost the first
// time someone joins a variable onto it.
func (d *runtimeDir) Socket(name string) (string, error) {
	if err := checkSocketName(name); err != nil {
		return "", err
	}
	return filepath.Join(d.path, name), nil
}

func checkSocketName(name string) error {
	if name == "" || name == "." || name == ".." ||
		strings.ContainsRune(name, filepath.Separator) || strings.Contains(name, "\x00") {
		return fmt.Errorf("runtime directory: %q is not a name this run's directory may "+
			"create - snug's sockets are single path elements inside it, never a path", name)
	}
	return nil
}

// runDirName is this run's directory name, computed the same way for the run
// that CREATES it and for the dry run that only NAMES it. One function rather
// than two spellings of the same fmt.Sprintf, because the whole value of
// plannedSocket is that --dry-run shows the path a real run would use.
func runDirName() string { return fmt.Sprintf("run-%d", os.Getpid()) }

// plannedSocket names the host path a proxy WOULD bind for name, creating,
// verifying and locking NOTHING. It is the --dry-run counterpart of
// openRuntimeDir().Socket, and it exists because a dry run that leaves a
// directory and a socket behind contradicts its own first line (issue #21).
// main.go already draws the same distinction one indirection up for the
// @tmp-shared host directory: name it, do not create it.
//
// None of runtimeDir's guarantees come with this string and none is needed:
// nothing is opened through it, so there is nothing for a planted symlink or
// a hostile mode to redirect. It is a label for a screen. That is also why it
// must never be handed to anything that binds, opens or removes — the type
// distinction (string here, *runtimeDir there) is the whole guard.
func plannedSocket(name string) (string, error) {
	if err := checkSocketName(name); err != nil {
		return "", err
	}
	base, snugName := runtimeBase()
	return filepath.Join(base, snugName, runDirName(), name), nil
}

// Remove deletes this run's directory, through the verified parent
// descriptor. main.go used to call os.RemoveAll on the returned string,
// which walks the whole path by name again at the end of a run — the exact
// re-derivation the checks on the way in exist to make unnecessary.
//
// Errors are returned rather than swallowed; the caller decides, and today
// it warns, because a directory snug could not remove is state that survives
// the user (invariant 4's neighbourhood) and saying nothing is how it goes
// unnoticed.
func (d *runtimeDir) Remove() error {
	if d == nil {
		return nil
	}
	return d.snugRoot.RemoveAll(d.runName)
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

// runtimeDirs holds the *runtimeDir this process has claimed for each run
// directory, keyed by the resolved path. The flock inside it is never
// released and the descriptor never closed for the lifetime of this process:
// closing it is what tells a later sweep (in a different, later process)
// that the owner is gone, so closing it early would be indistinguishable
// from this run having crashed.
//
// This replaces a map of runHandle{lock, root} plus a free function
// (runStateRoot) that looked entries up by path. The lock's lifetime now
// belongs to the value that owns the directory, which is issue #103's second
// stated measure.
//
// Nothing in here is ever handed to the sandboxed payload. Every os.File and
// os.Root this package opens gets O_CLOEXEC from the os package by default,
// and internal/fdseal.Seal marks every remaining non-stdio descriptor
// close-on-exec again immediately before bwrap is forked, belt and braces —
// so they are closed automatically the moment bwrap execs, without ever
// being enumerated in cmd.ExtraFiles or otherwise offered to it.
var (
	runtimeDirsMu sync.Mutex
	runtimeDirs   = map[string]*runtimeDir{}
)

// claimRunDir takes the per-run flock exactly once per path per process. On
// a second call for the same path (this process's own idempotent re-entry)
// it is a cache hit and touches nothing — the caller's freshly opened
// snugRoot is surplus and is closed by openRuntimeDir.
//
// It retries once on errLockFileSwept — see lockRunDir for what that means
// and why one retry is enough in practice — and refuses outright rather than
// retrying forever, because a caller asking "where do my sockets go" needs an
// answer, not a loop.
func claimRunDir(runPath string, snugRoot *os.Root, snugPath, runName string) (*runtimeDir, error) {
	runtimeDirsMu.Lock()
	defer runtimeDirsMu.Unlock()

	if d, ok := runtimeDirs[runPath]; ok {
		return d, nil
	}

	lock, err := lockRunDir(snugRoot, snugPath, runName)
	if errors.Is(err, errLockFileSwept) {
		lock, err = lockRunDir(snugRoot, snugPath, runName)
	}
	if err != nil {
		if errors.Is(err, errLockFileSwept) {
			return nil, fmt.Errorf("runtime directory: %s: a concurrent sweep removed this run's "+
				"own directory twice in a row while this process was trying to lock it — "+
				"refusing rather than returning a path that may no longer exist", runPath)
		}
		return nil, err
	}

	d := &runtimeDir{path: runPath, snugRoot: snugRoot, runName: runName, lock: lock}
	runtimeDirs[runPath] = d
	return d, nil
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

	runRoot, _, err := vdir.SecureSubdir(snugRoot, snugPath, runName)
	if err != nil {
		return nil, fmt.Errorf("runtime directory: %w - this is the run's own subdirectory, "+
			"and snug refuses to use one whose owner and mode it cannot verify", err)
	}
	// Closed once the lock inside it is held. It was kept open for a reader
	// that no longer exists: issue #123 moved `snug attach`'s state.json to
	// the TARGET-keyed path, so nothing writes into this directory through a
	// Root any more, and runStateRoot — the function that handed it out — had
	// no callers left at all. A descriptor held open for a dead reader is not
	// defence in depth, it is a fact nobody is checking.
	defer runRoot.Close()

	lock, err := runRoot.OpenFile("lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("runtime directory: creating %s/lock: %w - check free space and inodes on "+
			"that filesystem", runPath, err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("runtime directory: locking %s/lock: %w — a directory named "+
			"after this process's own pid is already locked by something else, which should be "+
			"impossible on a live system (pids are unique); refusing rather than reusing it", runPath, err)
	}

	if linked, lerr := stillLinked(lock); lerr != nil {
		lock.Close()
		return nil, fmt.Errorf("runtime directory: checking whether %s/lock is still linked: %w - snug needs "+
			"to know whether a concurrent sweep removed it, and refuses rather than returning a "+
			"path that may already be gone", runPath, lerr)
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
			// UNCONDITIONAL, unlike the success line below, and the split is
			// the point of issue #118 rather than an inconsistency: this one
			// names something the user may have to remove by hand, and a
			// directory snug could not clean up is state that survives them
			// (invariant 4's neighbourhood). Silence here would be snug
			// failing quietly at housekeeping it promised to do.
			fmt.Fprintf(os.Stderr, "snug: could not remove stale run directory %s: %v\n", full, rmErr)
			continue
		}
		// Behind --verbose. It reports work that SUCCEEDED, that the user did
		// not ask for and cannot act on, about a directory they never knew
		// existed — and it fires on the everyday path, after any abnormal
		// termination left something behind. Correct information in the wrong
		// register: it reads like a warning for something that is in fact snug
		// working as designed.
		verboseHousekeeping(fmt.Sprintf("removed stale run directory %s (its owning process is "+
			"gone; left behind by a run that did not exit cleanly)", full))
	}
}

// ── housekeeping notices (issue #118) ─────────────────────────────────────

// housekeepingVerbose is whether notices about work the user did not ask for
// — and that SUCCEEDED — reach stderr. Off until main's flag parsing turns it
// on, so a snug used as a library or a test that never parses flags is quiet
// by construction.
//
// A package variable rather than a parameter, deliberately, and the reason is
// where the notice comes from: sweepStaleRunDirs is reached from runtimeDir,
// which is memoized and called independently by the ssh-agent proxy, the
// container proxy and the run path itself. Threading a DISPLAY preference
// through three call chains whose signatures are otherwise about paths and
// ownership would put an ergonomics flag into functions that have no other
// business knowing about the terminal — and would have to be re-threaded
// every time a fourth subsystem needs a runtime directory.
//
// It is written exactly once, from main, before any of those subsystems
// start, and read from there on. That ordering is what makes a plain bool
// enough: there is no second writer to race, and the notices themselves are
// already serialised by the run's own startup.
var housekeepingVerbose bool

// setHousekeepingVerbose is main's one call. Separate from the variable so
// the assignment has a name in a stack trace and a single place to grep for.
func setHousekeepingVerbose(v bool) { housekeepingVerbose = v }

// verboseHousekeeping prints a notice about routine work that succeeded, and
// only when the human asked to see it.
//
// The line it does NOT cover is the failure case beside it in
// sweepStaleRunDirs: a stale directory snug could not remove is state that
// outlives the user, and that stays unconditional.
func verboseHousekeeping(msg string) {
	if !housekeepingVerbose {
		return
	}
	fmt.Fprintln(os.Stderr, "snug: "+msg)
}
