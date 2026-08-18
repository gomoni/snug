package cli

// targetlock.go is issue #119: one live sandbox per target directory. A real
// `snug <dir>` run takes a per-target advisory flock before it creates
// anything, and refuses — naming `snug attach <dir>` — if another live run
// already holds it. It sits next to runtimedir.go because it reuses that
// file's *os.Root + flock machinery (secureSubroot / verifyOwnedAndPrivate),
// which stays package-private on purpose: a runtime directory reached by a
// bare path lookup is exactly the shape issue #61(c)/#85 closed.
//
// The abuse sentence: a hostile process inside the sandbox can use this to
// ___ — nothing. The lock file lives on a host path ($XDG_RUNTIME_DIR/snug/…)
// that is never bound into the sandbox, and its name is the SHA-256 of the
// realpath the host user named, computed on the host before the sandbox
// exists. The payload can neither reach the file nor influence which file
// snug locks, so it can neither release the lock to race a second sandbox
// onto the same target nor steer snug to lock an unrelated path.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

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
// realpath: fixed length, no separators (so it cannot escape the directory),
// and collision-resistant (so two unrelated targets never share a lock).
// Exported to the package's tests, which must compute the identical name to
// seed a held lock from a helper process.
func targetLockName(realpath string) string {
	sum := sha256.Sum256([]byte(realpath))
	return "target-" + hex.EncodeToString(sum[:]) + ".lock"
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

	base, snugName := runtimeBase()
	root, err := os.OpenRoot(base)
	if err != nil {
		return noop, fmt.Errorf("target lock: opening %s: %w", base, err)
	}
	defer root.Close()

	snugRoot, _, err := secureSubroot(root, base, snugName)
	if err != nil {
		return noop, fmt.Errorf("target lock: %w", err)
	}
	defer snugRoot.Close()

	name := targetLockName(real)
	lock, err := snugRoot.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return noop, fmt.Errorf("target lock: opening %s/%s: %w", filepath.Join(base, snugName), name, err)
	}

	if flockErr := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); flockErr != nil {
		// EWOULDBLOCK: a live run holds it. Read its pid to name it, then
		// refuse. Any other flock error is reported verbatim rather than
		// guessed at.
		if errors.Is(flockErr, unix.EWOULDBLOCK) {
			holder := readHolderPID(lock)
			lock.Close()
			return noop, &targetBusyError{target: real, holder: holder}
		}
		lock.Close()
		return noop, fmt.Errorf("target lock: locking %s/%s: %w", filepath.Join(base, snugName), name, flockErr)
	}

	// We hold it. Record our pid so the next contender can name us. The lock
	// is the truth; this write is only a courtesy for the refusal message, so
	// a failure to write it is not fatal.
	writeHolderPID(lock)

	return func() { lock.Close() }, nil
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
