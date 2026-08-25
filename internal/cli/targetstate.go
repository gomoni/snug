package cli

// targetstate.go publishes and reads a run's state.json, KEYED BY THE TARGET
// DIRECTORY rather than by the run, in the same env-independent directory the
// per-target lock already lives in (issue #123).
//
// Why it moved. `snug attach` addresses a run BY DIRECTORY, and since #119
// there is at most one live run per directory. The lock that enforces that is
// already named `target-<sha256(realpath)>.lock` and already resolved from the
// uid alone (targetLockBase, issue #122). The state file was the odd one out:
// it lived under `runtimeBase()`, which reads $XDG_RUNTIME_DIR and $TMPDIR —
// variables that differ between an interactive shell and cron/systemd/ssh —
// so a run started under one environment published its state where an attach
// launched under another would never look. That is issue #123, and repointing
// only the READER could not fix it, because the writer was env-derived too.
//
// Three things follow from the move, and all three are simplifications:
//
//   - Discovery stops being a SCAN. There is no directory listing, no
//     per-entry parse-and-skip, and no "more than one live run matches" branch
//     to explain: the target's realpath hashes to exactly one filename.
//   - LIVENESS is the target lock itself, which is the same fact the refusal
//     in `snug <dir>` already consults. Previously it was a second, parallel
//     flock on each run directory, so "is a run live" had two answers that
//     could in principle disagree.
//   - A stale state file cannot be mistaken for a live run. The lock is the
//     truth; the JSON beside it is only what the live holder published.
//
// What did NOT move: the per-run directory under runtimeBase() still exists
// and is still env-derived. It holds this run's sockets (the ssh-agent proxy,
// the container proxy) and its own lock, and none of that needs cross-run
// agreement — a socket path is handed to the sandbox by the same process that
// created it.
//
// The abuse sentence is runstate.go's, unchanged: a hostile process with the
// same uid can read this file and learn a sandbox's init pid, its namespace
// ids and its seccomp digest, none of which grants it anything it could not
// already reach with `nsenter`. The uid-derived directory is verified owned
// and 0700 before anything here opens a file in it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/gomoni/snug/internal/vdir"
	"golang.org/x/sys/unix"
)

// targetStateName is targetLockName's sibling: the same sha256 of the same
// realpath, so the pair sort together and a human reading the directory can
// see that one names the other. Deliberately derived rather than stored — the
// name IS the index, and nothing has to be kept consistent with anything.
func targetStateName(realpath string) string {
	return targetKeyPrefix(realpath) + ".json"
}

// targetStateNameMatches reports whether name is realpath's run-state
// filename under either generation targetKeyPrefix has produced: the current
// "target-sha256_<hex>.json" or the pre-issue-#349 "target-<hex>.json" a
// binary written before the digest was labelled. sweepOrphanedSandboxesIn is
// the only caller — without this, every run-state record a pre-upgrade
// binary wrote is invisible to the sweep forever, and the orphan init it
// names is never killed.
func targetStateNameMatches(realpath, name string) bool {
	return name == targetStateName(realpath) || name == legacyTargetKeyPrefix(realpath)+".json"
}

// openTargetStateDir opens the uid-derived snug runtime directory the target
// lock lives in, creating it if needed, with the same ownership and mode
// verification vdir.SecureSubdir applies everywhere else.
//
// create=false is the reader's mode: it must never bring a directory into
// existence just by looking for a run, so a missing directory is reported as
// fs.ErrNotExist for the caller to read as "no live run".
func openTargetStateDir(create bool) (*os.Root, string, error) {
	base, snugName, err := targetLockBase()
	if err != nil {
		return nil, "", err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, "", fmt.Errorf("run state: opening %s: %w", base, err)
	}
	defer root.Close()

	snugPath := filepath.Join(base, snugName)
	if create {
		snugRoot, _, serr := vdir.SecureSubdir(root, base, snugName)
		if serr != nil {
			return nil, "", fmt.Errorf("run state: %w", serr)
		}
		return snugRoot, snugPath, nil
	}

	snugRoot, oerr := vdir.OpenExistingSubdir(root, base, snugName)
	if oerr != nil {
		return nil, "", oerr
	}
	return snugRoot, snugPath, nil
}

// writeTargetState publishes st for the target it names.
func writeTargetState(real string, st runState) error {
	return writeTargetFile(targetStateName(real), st)
}

// writeTargetFile publishes payload's JSON rendering at final, inside the
// uid-derived target-state directory (openTargetStateDir), for anything keyed
// by targetKeyPrefix — state.json (runState) and the orphan-kill record
// (initState) both go through this one function rather than through two
// copies of the same discipline.
//
// Written through a temporary file and renamed into place, both inside the
// already-verified Root. O_EXCL on the final name would be wrong here and
// that is the one real difference from the per-run file this replaces: the
// name is derived from the TARGET, so a previous run on the same directory
// has almost certainly left one behind. That file is not a conflict — its
// owner is dead, which the lock says — so the correct behaviour is to replace
// it. Replacing it by rename rather than by truncate-and-write is what stops
// a reader that arrives mid-write from reading half a file.
func writeTargetFile(final string, payload any) error {
	snugRoot, snugPath, err := openTargetStateDir(true)
	if err != nil {
		return err
	}
	defer snugRoot.Close()

	blob, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("rendering %s: %w", final, err)
	}
	blob = append(blob, '\n')

	// The pid keeps two concurrent writers apart. They cannot both hold the
	// target lock, so this is defence against a bug rather than against a
	// race the design allows.
	tmp := fmt.Sprintf("%s.tmp-%d", final, os.Getpid())
	_ = snugRoot.Remove(tmp) // a previous crash's leftover, not an error

	f, err := snugRoot.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("run state: creating %s: %w", filepath.Join(snugPath, tmp), err)
	}
	if _, werr := f.Write(blob); werr != nil {
		f.Close()
		_ = snugRoot.Remove(tmp)
		return fmt.Errorf("run state: writing %s: %w", filepath.Join(snugPath, tmp), werr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = snugRoot.Remove(tmp)
		return fmt.Errorf("run state: closing %s: %w", filepath.Join(snugPath, tmp), cerr)
	}
	if rerr := snugRoot.Rename(tmp, final); rerr != nil {
		_ = snugRoot.Remove(tmp)
		return fmt.Errorf("run state: renaming %s to %s: %w", tmp, final, rerr)
	}
	return nil
}

// removeTargetFile removes name from the target-state directory, if the
// directory exists at all. A missing directory or a missing file is not an
// error — there is nothing to remove either way, and the initState caller
// relies on that: a run whose init write itself failed has no ".starting"
// file to clean up, and this must not turn that into a second warning.
func removeTargetFile(name string) error {
	snugRoot, _, err := openTargetStateDir(false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer snugRoot.Close()
	if err := snugRoot.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// readTargetState returns the state a LIVE run published for real.
//
// live is false, with no error, for every ordinary way there is nothing to
// attach to: snug has never run on this host, this target has no state file,
// or the file is there but its run is gone (the lock is not held). Those are
// the zero case and the caller renders one message for them — the distinction
// issue #124 was about, applied to the new layout from the start.
//
// An error is reserved for a directory that fails the ownership or mode
// guard, or a state file that exists beside a HELD lock and cannot be read or
// does not validate. That last one is deliberately NOT the zero case: a live
// run whose published state is unreadable is a fault worth naming, not an
// absence to report as "nothing is sandboxing this directory".
func readTargetState(real string) (st runState, live bool, err error) {
	snugRoot, snugPath, err := openTargetStateDir(false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return runState{}, false, nil
		}
		return runState{}, false, err
	}
	defer snugRoot.Close()

	held, err := targetLockIsHeld(snugRoot, snugPath, real)
	if err != nil {
		return runState{}, false, err
	}
	if !held {
		// Either no run has ever locked this target, or the one that did is
		// gone. A state file may well still be sitting there; it describes a
		// corpse, and the next run on this target will replace it.
		return runState{}, false, nil
	}

	name := targetStateName(real)
	f, err := snugRoot.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The lock is held but nothing has been published yet: a run that
			// is still starting, or one whose OnInfo could not write (which
			// warns at the source — see internal/cli/main.go). Not attachable
			// yet, and not a fault of this reader's.
			return runState{}, false, nil
		}
		return runState{}, false, fmt.Errorf("run state: opening %s: %w", filepath.Join(snugPath, name), err)
	}
	defer f.Close()

	st, err = decodeRunState(f)
	if err != nil {
		return runState{}, false, fmt.Errorf("run state: %s: %w", filepath.Join(snugPath, name), err)
	}
	if st.Target != real {
		// The name is a hash of the target, so this can only mean a collision
		// or a hand-edited file. Refuse rather than attach to whatever it
		// names: the whole point of the realpath match (issue #119) is that
		// attach never joins a sandbox for a directory the user did not ask
		// about.
		return runState{}, false, fmt.Errorf("run state: %s names target %q, not %q — refusing to "+
			"attach to a run for a different directory", filepath.Join(snugPath, name), st.Target, real)
	}
	return st, true, nil
}

// targetLockIsHeld probes the per-target lock the same way runDirIsLive
// probes a run directory's: LOCK_SH|LOCK_NB, released immediately.
// EWOULDBLOCK means a live exclusive holder — the owning snug, which holds it
// for the whole run and whose death releases it in the kernel. Success means
// nobody holds it.
//
// It opens with O_CREATE for the same reason lockTarget does: the lock file is
// the thing being probed, and a probe that refused to create it would report
// "no live run" and "cannot tell" identically. The file it may create is
// empty, 0600, inside an already-verified 0700 directory, and is never
// unlinked — exactly the lifecycle the lock itself has.
func targetLockIsHeld(snugRoot *os.Root, snugPath, real string) (bool, error) {
	name := targetLockName(real)
	f, err := snugRoot.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false, fmt.Errorf("run state: opening %s: %w", filepath.Join(snugPath, name), err)
	}
	defer f.Close()

	if flockErr := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); flockErr != nil {
		if errors.Is(flockErr, unix.EWOULDBLOCK) {
			return true, nil
		}
		return false, fmt.Errorf("run state: probing %s: %w", filepath.Join(snugPath, name), flockErr)
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return false, nil
}
