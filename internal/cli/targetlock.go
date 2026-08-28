package cli

// targetlock.go is issue #119: one live sandbox per target directory. A real
// `snug <dir>` run takes a per-target advisory flock before it creates
// anything, and refuses — naming `snug attach <dir>` — if another live run
// already holds it. It sits next to runtimedir.go because it reuses that
// file's *os.Root + flock machinery (vdir.SecureSubdir / verifyOwnedAndPrivate),
// which stays package-private on purpose: a runtime directory reached by a
// bare path lookup is exactly the shape issue #61(c)/#85 closed.
//
// The abuse sentence: a hostile process inside the sandbox can use this to
// ___ — nothing. The lock file lives on a host path (/run/user/<uid>/snug/…,
// or /tmp/snug-<uid>/… where that does not exist) that is never bound into the
// sandbox, and its name is the SHA-256 of the realpath the host user named,
// computed on the host before the sandbox exists. The payload can neither reach
// the file nor influence which file snug locks, so it can neither release the
// lock to race a second sandbox onto the same target nor steer snug to lock an
// unrelated path.
//
// Its DIRECTORY is resolved from the uid alone (targetLockBase), NOT from
// $XDG_RUNTIME_DIR/$TMPDIR the way the per-run socket directory (runtimedir.go)
// is. That difference is issue #122: the target lock's whole purpose is
// cross-run agreement, and a run in an interactive shell ($XDG_RUNTIME_DIR set)
// and a run under cron/systemd/ssh-non-login (unset) must land on the SAME lock
// inode or two live sandboxes acquire on one target — a fail-OPEN that needs no
// attacker. runtimedir.go's per-run lock never needs cross-run agreement, so it
// keeps the env-derived base; the target lock cannot.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gomoni/snug/internal/targetkey"
	"github.com/gomoni/snug/internal/vdir"
	"golang.org/x/sys/unix"
)

// canonicalRuntimeDir and fallbackTmpRoot are the two env-independent roots the
// per-target lock may live under, indirected through package variables so the
// tests can point them at a scratch directory instead of writing into the
// host's real /run/user/<uid>. Production never reassigns them.
//
//   - canonicalRuntimeDir(uid) is /run/user/<uid>, which is exactly what
//     $XDG_RUNTIME_DIR normally IS — so preferring it by uid makes a run with
//     the variable set and a run with it unset resolve the identical inode.
//   - fallbackTmpRoot is the literal "/tmp", NOT os.TempDir(): os.TempDir()
//     honours $TMPDIR, and a differing $TMPDIR is the same split by another
//     name (issue #122's reproduction hits it too).
var (
	canonicalRuntimeDir = func(uid int) string { return fmt.Sprintf("/run/user/%d", uid) }
	fallbackTmpRoot     = "/tmp"
)

// targetLockBase resolves, FROM THE UID ALONE, the directory the per-target
// lock lives in and the name of the snug-owned subdirectory under it. It reads
// no environment variable: $XDG_RUNTIME_DIR and $TMPDIR differ between an
// interactive shell and cron/systemd/ssh-non-login, and the target lock exists
// precisely to agree across those runs (issue #122).
//
// Preference order, both uid-scoped and deterministic:
//
//  1. /run/user/<uid> when it exists and is a directory — the canonical
//     per-user runtime dir, session-scoped, mode 0700 owned by the user.
//  2. otherwise /tmp/snug-<uid> — a uid-scoped name a squatter cannot pass the
//     later ownership check on, mirroring the fallback shape runtimeBase uses.
//
// Fail CLOSED (invariant 5): if neither root exists, it returns an error and
// lockTarget propagates it, so run() refuses the run. It never falls back to a
// per-env path, because doing so is exactly the split it removes. The snug
// subdirectory's owner and mode are still verified downstream by secureSubroot
// / verifyOwnedAndPrivate, so a canonical root that is not ours is refused
// there rather than trusted here.
func targetLockBase() (base, snugName string, err error) {
	uid := os.Getuid()

	canonical := canonicalRuntimeDir(uid)
	if fi, statErr := os.Stat(canonical); statErr == nil && fi.IsDir() {
		return canonical, "snug", nil
	}

	if fi, statErr := os.Stat(fallbackTmpRoot); statErr == nil && fi.IsDir() {
		return fallbackTmpRoot, fmt.Sprintf("snug-%d", uid), nil
	}

	return "", "", fmt.Errorf("target lock: no per-user runtime directory: neither %s nor %s "+
		"exists, so there is no env-independent place to serialise runs on this target — "+
		"refusing rather than using a $XDG_RUNTIME_DIR/$TMPDIR path that differs between an "+
		"interactive shell and cron/systemd and would let two sandboxes race one target (issue #122)",
		canonical, fallbackTmpRoot)
}

// targetBusyError is returned by lockTarget when another live run already
// holds the per-target lock. run() turns it into the invariant-5 refusal;
// its message names `snug attach` and identifies the live holder.
type targetBusyError struct {
	target string // canonical realpath of the target directory
	holder int    // pid of the live holder, 0 when it could not be read
}

func (e *targetBusyError) Error() string {
	if e.holder > 0 {
		return fmt.Sprintf("a sandbox is already live for %s (held by snug pid %d)", e.target, e.holder)
	}
	return fmt.Sprintf("a sandbox is already live for %s", e.target)
}

// message renders the full multi-line refusal. display is the directory
// argument the user actually typed (defaulting to "."), so the suggested
// `snug attach <dir>` copy-pastes.
func (e *targetBusyError) message(display string) string {
	holder := "snug"
	if e.holder > 0 {
		holder = fmt.Sprintf("snug (pid %d)", e.holder)
	}
	return fmt.Sprintf(`snug: a sandbox is already live for this directory.

      target:  %s
      held by: %s

      A second, independent sandbox writing the same target is a footgun: the
      target bind is the one writable thing that persists, and two runs racing
      writes to it is exactly what you do not want.

      To open another shell in the sandbox that is already running:
          snug attach %s
`, e.target, holder, display)
}

// targetLockName is the single path component the per-target lock lives at,
// inside the shared snug runtime directory. It is the SHA-256 of the target's
// realpath: fixed length, no path separators (so it cannot escape the
// directory), and collision-resistant (so two unrelated targets never share a
// lock).
// Exported to the package's tests, which must compute the identical name to
// seed a held lock from a helper process.
func targetLockName(realpath string) string {
	return targetKeyPrefix(realpath) + ".lock"
}

// targetKeyPrefix is the shared stem of every per-target file: the lock and,
// since issue #123, the run-state JSON beside it. One function so the two can
// never drift onto different hashes of the same path — a drift that would not
// fail loudly, it would simply mean `snug attach` looked up a state file no
// run had written.
//
// The hash itself is internal/targetkey's Hash — see that package's doc
// comment for why every target-derived name on disk, including the engine
// store's own key (internal/engine's KeyForTarget), now goes through the one
// function and uses the full, untruncated digest. Hash's own "sha256_" label
// uses an underscore, not a dash, so the "target-" here stays the only dash
// in the name and "target-sha256_<hex>.lock" splits on it unambiguously.
func targetKeyPrefix(realpath string) string {
	return "target-" + targetkey.Hash(realpath)
}

// legacyTargetKeyPrefix is the stem targetKeyPrefix produced before issue
// #349 labelled the digest: "target-" followed by the bare hex sha256, with
// no "sha256_" in between. Nothing derives a name in this shape any more —
// it exists only so sweepOrphanedSandboxesIn can still recognise a run-state
// or ".starting" record a pre-#349 binary wrote. It strips the label back
// off targetkey.Hash's own output rather than hashing independently, so the
// two stay one algorithm.
func legacyTargetKeyPrefix(realpath string) string {
	return "target-" + strings.TrimPrefix(targetkey.Hash(realpath), "sha256_")
}

// lockTarget takes the per-target advisory lock for abs, an already-absolute
// target path. On success it returns an unlock func the caller holds (via
// defer) for the life of the run; the returned *os.File is captured by that
// closure, which is what keeps the descriptor — and therefore the flock —
// alive until the process exits.
//
// Three outcomes:
//
//   - Acquired: unlock is non-nil, err is nil.
//   - Busy: err is a *targetBusyError naming the live holder; unlock is a
//     no-op. run() refuses.
//   - Target cannot be canonicalised (it does not exist yet): unlock is a
//     no-op and err is nil. There is nothing to serialise against — a
//     directory that does not exist cannot be sandboxed by any concurrent
//     run — so this defers the "no such directory" report to policy.Resolve,
//     which owns it and phrases it well.
//
// A hard error (a runtime directory that fails the ownership/mode checks, a
// filesystem error) is returned as-is.
func lockTarget(abs string) (unlock func(), err error) {
	noop := func() {}

	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// Not-yet-existing (or otherwise unresolvable) target: do not lock;
		// let policy.Resolve produce its fail-closed message.
		return noop, nil
	}

	base, snugName, err := targetLockBase()
	if err != nil {
		return noop, err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return noop, fmt.Errorf("target lock: opening the per-user runtime directory %s: %w - it exists but "+
			"cannot be opened, so this run cannot serialise against other runs on the same target; "+
			"check that it is a directory you own with mode 0700", base, err)
	}
	defer root.Close()

	snugRoot, _, err := vdir.SecureSubdir(root, base, snugName)
	if err != nil {
		return noop, fmt.Errorf("target lock: %w - this is where the per-target lock lives, so "+
			"the run is refused rather than started without one (issue #122)", err)
	}
	defer snugRoot.Close()

	lock, err := openAndHoldTargetLock(snugRoot, filepath.Join(base, snugName), targetLockName(real), real)
	if err != nil {
		return noop, err
	}

	// We hold it. Record our pid so the next contender can name us. The lock
	// is the truth; this write is only a courtesy for the refusal message, so
	// a failure to write it is not fatal.
	writeHolderPID(lock)

	return func() { lock.Close() }, nil
}

// targetLockAttempts bounds the retry below. Two would do — the only thing
// that unlinks a target lock is sweepOneStaleLock, which runs once per snug
// process, after that process already holds its own target lock — so a second
// sweep landing in the same window would have to come from a third process
// whose own sweep is also in flight. Four so that a pathological interleaving
// refuses with a message rather than spinning.
const targetLockAttempts = 4

// openAndHoldTargetLock opens the per-target lock file and takes LOCK_EX on
// it, returning the held descriptor. dir is the lock file's directory, used
// only for messages; real is the target, used only to name a live holder.
//
// The retry is the CREATING side of the argument in sweepOneStaleLock's doc
// comment, and it is lockRunDir's Nlink check one directory up rather than a
// new idea: between the open and the flock, a concurrently starting snug's
// sweep can hold this same file's lock and unlink it, and flock on an
// unlinked descriptor succeeds exactly as it does on a live one. Nlink is
// what separates them. Serialising on an inode nothing points at any more is
// how two runs would both "hold the lock" for one target — the failure issues
// #119 and #122 exist to prevent.
func openAndHoldTargetLock(snugRoot *os.Root, dir, name, real string) (*os.File, error) {
	for attempt := 0; attempt < targetLockAttempts; attempt++ {
		lock, err := snugRoot.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, fmt.Errorf("target lock: creating the lock file %s/%s: %w - the directory is usable but "+
				"this file is not; check free space and inodes on that filesystem", dir, name, err)
		}

		if flockErr := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); flockErr != nil {
			// EWOULDBLOCK: a live run holds it. Read its pid to name it, then
			// refuse. Any other flock error is reported verbatim rather than
			// guessed at.
			if errors.Is(flockErr, unix.EWOULDBLOCK) {
				holder := readHolderPID(lock)
				lock.Close()
				return nil, &targetBusyError{target: real, holder: holder}
			}
			lock.Close()
			return nil, fmt.Errorf("target lock: flock on %s/%s: %w - NOT the busy case, which is handled above "+
				"and names `snug attach`; this is flock itself failing, which usually means the "+
				"filesystem does not support it. Put the runtime directory on a local filesystem", dir, name, flockErr)
		}

		linked, lerr := stillLinked(lock)
		if lerr != nil {
			lock.Close()
			return nil, fmt.Errorf("target lock: checking whether %s/%s is still linked: %w - snug needs to know "+
				"whether a concurrent sweep removed it, and refuses rather than serialising on an inode "+
				"no name points at", dir, name, lerr)
		}
		if linked {
			return lock, nil
		}
		// Swept between our open and our flock. The name is free again;
		// go round and take the lock on whatever lives there now.
		lock.Close()
	}
	return nil, fmt.Errorf("target lock: %s/%s was removed by a concurrent sweep on %d consecutive attempts - "+
		"snug refuses rather than running unserialised against another run on the same target",
		dir, name, targetLockAttempts)
}

// writeHolderPID truncates the lock file and writes this process's decimal
// pid as the first line. Best effort: the flock, not the file content, is
// what tells a live run from a dead one.
func writeHolderPID(lock *os.File) {
	if err := lock.Truncate(0); err != nil {
		return
	}
	if _, err := lock.Seek(0, 0); err != nil {
		return
	}
	fmt.Fprintf(lock, "%d\n", os.Getpid())
}

// readHolderPID reads the decimal pid a live holder wrote. It returns 0 on
// any problem — an empty file (the holder acquired the lock but has not yet
// written its pid), a torn read, an unparseable line — because the message
// this feeds degrades cleanly to "held by: snug" without a pid.
func readHolderPID(lock *os.File) int {
	if _, err := lock.Seek(0, 0); err != nil {
		return 0
	}
	buf := make([]byte, 32)
	n, _ := lock.Read(buf)
	if n <= 0 {
		return 0
	}
	line := strings.TrimSpace(strings.SplitN(string(buf[:n]), "\n", 2)[0])
	pid, err := strconv.Atoi(line)
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}
