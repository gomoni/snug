package cli

// targetlock.go is the per-target advisory flock: the one fact that says
// whether ANY run is live on a target directory. A real `snug <dir>` run takes
// it SHARED before it creates anything and holds it for the whole run; the
// kernel releases it when that process dies, however it dies. It sits next to
// runtimedir.go because it reuses that file's *os.Root + flock machinery
// (vdir.SecureSubdir / verifyOwnedAndPrivate), which stays package-private on
// purpose: a runtime directory reached by a bare path lookup is exactly the
// shape issue #61(c)/#85 closed.
//
// SHARED, not exclusive, and that is the whole of the mode's meaning: several
// sandboxes on one directory are a supported shape, so a run must not refuse
// because another run got there first. What the lock still buys is the
// question every reader actually asks — "is anything live on this target" —
// because flock(2) refuses LOCK_EX while any LOCK_SH is held. So the two
// readers take LOCK_EX and read EWOULDBLOCK as "yes": `snug proxy`
// (targetLockIsHeld, via liveRunsFor in targetstate.go) and `snug engine gc`
// (targetLive, enginegc.go). A reader that took LOCK_SH would succeed against
// a live run and answer "nothing is live" — which for proxy reports no
// sandbox on a directory one is live on, and for gc licenses reclaiming a
// store out from under a running engine.
//
// The orphan sweep is deliberately NOT among them. It judges one record at a
// time, and this lock cannot answer about one record: it stays held until the
// LAST run on the target exits, so a shared answer would defer the sweep of a
// SIGKILLed run for the whole life of any peer beside it (orphansweep.go).
//
// The abuse sentence: a hostile process inside the sandbox can use this to
// ___ — nothing. The lock file lives on a host path (/run/user/<uid>/snug/…,
// or /tmp/snug-<uid>/… where that does not exist) that is never bound into the
// sandbox, and its name is the SHA-256 of the realpath the host user named,
// computed on the host before the sandbox exists. The payload can neither reach
// the file nor influence which file snug locks, so it can neither release its
// own run's hold — which would make `snug engine gc` reclaim the store its
// engine is writing — nor steer snug to lock an unrelated path.
//
// Its DIRECTORY is resolved from the uid alone (targetLockBase), NOT from
// $XDG_RUNTIME_DIR/$TMPDIR the way the per-run socket directory (runtimedir.go)
// is. That difference is issue #122: the target lock's whole purpose is
// cross-run agreement, and a run in an interactive shell ($XDG_RUNTIME_DIR set)
// and a reader under cron/systemd/ssh-non-login (unset) must land on the SAME
// lock inode, or the reader probes a file no live run holds — a fail-OPEN that
// needs no attacker, and one whose consequence is a store reclaimed under a
// running engine. runtimedir.go's per-run lock never needs cross-run
// agreement, so it keeps the env-derived base; the target lock cannot.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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
		"exists, so there is no env-independent place to announce this run on its target — "+
		"refusing rather than using a $XDG_RUNTIME_DIR/$TMPDIR path that differs between an "+
		"interactive shell and cron/systemd, which would leave this run invisible to the next "+
		"one's orphan sweep and to `snug engine gc` (issue #122)",
		canonical, fallbackTmpRoot)
}

// targetBusyError says that at least one run holds the per-target lock — A
// live run, never THE live run, because the run lock is shared and a target
// may carry several at once. It is a sentinel rather than a message: its one
// consumer, `snug engine gc`'s liveHoldForReclaim arm, reads it as "live" and
// discards the text. A run is never refused for it; runs no longer contend.
type targetBusyError struct {
	target string // canonical realpath of the target directory
}

func (e *targetBusyError) Error() string {
	return fmt.Sprintf("a run is live for %s", e.target)
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
// fail loudly, it would simply mean `snug proxy` and `snug engine gc` probed a
// lock beside a state file no run on that target had written, and read an idle
// target where a run was live.
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
// target path, SHARED — see this file's own comment for why the mode is the
// whole point. On success it returns an unlock func the caller holds (via
// defer) for the life of the run; the returned *os.File is captured by that
// closure, which is what keeps the descriptor — and therefore the flock —
// alive until the process exits.
//
// Two outcomes:
//
//   - Acquired: unlock is non-nil, err is nil. Another run already holding
//     the target is this case, not a refusal.
//   - Target cannot be canonicalised (it does not exist yet): unlock is a
//     no-op and err is nil. There is nothing to announce ourselves to — a
//     directory that does not exist cannot be sandboxed by any concurrent
//     run — so this defers the "no such directory" report to policy.Resolve,
//     which owns it and phrases it well.
//
// A hard error refuses the run: a runtime directory that fails the
// ownership/mode checks, a filesystem error, or an exclusive holder that
// outlasts the retry budget. The last is rephrased here rather than returned
// as-is, because targetBusyError's text is written for `snug engine gc`.
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

	lock, err := openAndHoldTargetLock(snugRoot, filepath.Join(base, snugName), targetLockName(real), real, unix.LOCK_SH)
	if err != nil {
		// The one thing that can hold a target EXCLUSIVELY for longer than the
		// retry budget is `snug engine gc` reclaiming this target's store, and
		// targetBusyError's own text — written for gc, which discards it —
		// says "a run is live", which would send the reader looking for a
		// sandbox that is not the problem.
		var busy *targetBusyError
		if errors.As(err, &busy) {
			return noop, fmt.Errorf("target lock: %s is held exclusively by something else, most "+
				"likely `snug engine gc` reclaiming this target's container store - another "+
				"`snug` run is NOT a reason for this (runs share the lock). Wait for the gc to "+
				"finish and start again: %w", real, err)
		}
		return noop, err
	}

	return func() { lock.Close() }, nil
}

// targetLockAttempts bounds the retry below. Two would do — the only thing
// that unlinks a target lock is sweepOneStaleLock, which runs once per snug
// process, after that process already holds its own target lock — so a second
// sweep landing in the same window would have to come from a third process
// whose own sweep is also in flight. Four so that a pathological interleaving
// refuses with a message rather than spinning.
const targetLockAttempts = 4

// targetLockRetryDelay separates the EWOULDBLOCK retries above. It is sized
// against what it is waiting out — sweepOneStaleLock's window is an fstat, an
// Lstat and an unlink on a tmpfs — not against a run, which holds the lock for
// minutes and is refused after the last attempt regardless.
const targetLockRetryDelay = 2 * time.Millisecond

// openAndHoldTargetLock opens the per-target lock file and takes mode
// (unix.LOCK_SH or unix.LOCK_EX) on it, returning the held descriptor. dir is
// the lock file's directory, used only for messages; real is the target, used
// only to name it in an error.
//
// The mode is a parameter because its two callers want opposite things from
// the same file. lockTarget passes LOCK_SH: a run announces itself and must
// coexist with every other run on the target. `snug engine gc`'s
// liveHoldForReclaim passes LOCK_EX, and needs BOTH halves of what that gives
// it — the failure tells it a run is live, and the success keeps the target
// not-live for as long as it holds the descriptor, which is the property a
// store reclaim cannot proceed without.
//
// The retry is the CREATING side of the argument in sweepOneStaleLock's doc
// comment, and it is lockRunDir's Nlink check one directory up rather than a
// new idea: between the open and the flock, a concurrently starting snug's
// sweep can hold this same file's lock and unlink it, and flock on an
// unlinked descriptor succeeds exactly as it does on a live one. Nlink is
// what separates them.
//
// The consequence of skipping it is unchanged by the mode, and it is not
// symmetric with what issues #119 and #122 first wrote it for. Holding an
// inode nothing points at any more is holding NOTHING a reader will look at:
// every reader opens by NAME, so this run would announce itself on an orphan
// while the name carried a fresh, unheld file — and `snug engine gc`, finding
// that name unheld, would reclaim the store under this run's engine.
func openAndHoldTargetLock(snugRoot *os.Root, dir, name, real string, mode int) (*os.File, error) {
	for attempt := 0; attempt < targetLockAttempts; attempt++ {
		lock, err := snugRoot.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, fmt.Errorf("target lock: creating the lock file %s/%s: %w - the directory is usable but "+
				"this file is not; check free space and inodes on that filesystem", dir, name, err)
		}

		if flockErr := unix.Flock(int(lock.Fd()), mode|unix.LOCK_NB); flockErr != nil {
			// EWOULDBLOCK: an EXCLUSIVE holder is in the way — for a LOCK_SH
			// caller that is the only thing that can be, since runs no longer
			// exclude each other. The short ones are snug's own housekeeping:
			// sweepOneStaleLock takes LOCK_EX on every unheld lock file it
			// finds, and both liveness probes take it for one flock pair, so a
			// concurrently starting snug can hold this file for the length of
			// an fstat and an unlink. A redteam round measured the false
			// refusal that came of believing the first EWOULDBLOCK: 401 lock
			// files, 3413 acquisitions, one spurious refusal in 20 ms.
			//
			// So it is retried on the same budget as the swept case. What
			// outlasts the budget is `snug engine gc` holding the target for a
			// whole store reclaim, which is what the message names.
			if errors.Is(flockErr, unix.EWOULDBLOCK) {
				if attempt < targetLockAttempts-1 {
					lock.Close()
					time.Sleep(targetLockRetryDelay)
					continue
				}
				lock.Close()
				return nil, &targetBusyError{target: real}
			}
			lock.Close()
			return nil, fmt.Errorf("target lock: flock on %s/%s: %w - NOT the contended case, which is "+
				"handled above; this is flock itself failing, which usually means the filesystem does "+
				"not support it. Put the runtime directory on a local filesystem", dir, name, flockErr)
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
