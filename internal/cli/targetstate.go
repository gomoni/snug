package cli

// targetstate.go publishes and reads a run's state.json, KEYED BY THE TARGET
// DIRECTORY rather than by the run, in the same env-independent directory the
// per-target lock already lives in (issue #123).
//
// Why the target and not the run. Both readers arrive with a DIRECTORY and no
// run to speak of: the orphan sweep walks the directory of records looking for
// leftovers, and `snug proxy <dir>` is handed a path by a human. The state
// file used to live under `runtimeBase()`, which reads $XDG_RUNTIME_DIR and
// $TMPDIR — variables that differ between an interactive shell and
// cron/systemd/ssh — so a run started under one environment published its
// state where a reader launched under another would never look. That is issue
// #123, and repointing only the READER could not fix it, because the writer
// was env-derived too. The lock beside it was already named
// `target-<sha256(realpath)>.lock` and already resolved from the uid alone
// (targetLockBase, issue #122); the state file was the odd one out.
//
// Two things follow from the target key, and both are simplifications:
//
//   - Lookup is not a SCAN. There is no directory listing and no per-entry
//     parse-and-skip: the target's realpath hashes to exactly one filename.
//   - LIVENESS is the target lock itself, rather than a second parallel flock
//     on each run directory that could in principle disagree with it. A stale
//     state file cannot be mistaken for a live run: the lock is the truth, the
//     JSON beside it only what a live holder published.
//
// WHAT THE TARGET KEY COSTS, now that several runs may be live on one
// directory: the name identifies the TARGET, not a run, so the last run to
// publish overwrites its peers' records. `snug proxy` therefore reaches the
// most recently started sandbox rather than one the human chose, and the
// orphan sweep can only ever name one init per target.
//
// What did NOT move: the per-run directory under runtimeBase() still exists
// and is still env-derived. It holds this run's sockets (the ssh-agent proxy,
// the container proxy) and its own lock, and none of that needs cross-run
// agreement — a socket path is handed to the sandbox by the same process that
// created it.
//
// The abuse sentence is runstate.go's, unchanged: a hostile process with the
// same uid can read this file and learn a sandbox's init pid and its namespace
// ids, neither of which grants it anything it could not already reach with
// `nsenter`. The uid-derived directory is verified owned and 0700 before
// anything here opens a file in it.

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
// live is false, with no error, for every ordinary way there is nothing
// running: snug has never run on this host, this target has no state file, or
// the file is there but every run that wrote one is gone (the lock is not
// held). Those are the zero case and the caller renders one message for them —
// the distinction issue #124 was about, applied to the new layout from the
// start.
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
			// warns at the source — see internal/cli/main.go). Nothing to
			// report yet, and not a fault of this reader's.
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
		// or a hand-edited file. Refuse rather than hand back whatever it
		// names: every caller acts on this record against the directory it
		// asked about, and a record for a DIFFERENT directory would send
		// `snug proxy` at another project's run.
		return runState{}, false, fmt.Errorf("run state: %s names target %q, not %q — refusing to "+
			"report a run for a different directory", filepath.Join(snugPath, name), st.Target, real)
	}
	return st, true, nil
}

// targetLockIsHeld reports whether ANY run is live on real, by asking for
// LOCK_EX|LOCK_NB and releasing it immediately. EWOULDBLOCK means at least one
// live holder — a run holds the lock SHARED for its whole life and the kernel
// releases it on death, however that death arrives. Success means nobody holds
// it.
//
// EXCLUSIVE is what makes this a question about runs at all, and it is the one
// line in this function that cannot be relaxed. A LOCK_SH probe succeeds
// alongside every shared holder, so against a live run it would answer
// "nobody holds it" — and this answer is what licenses sweepOneOrphan to
// SIGKILL the init the record names.
//
// It opens with O_CREATE for the same reason lockTarget does: the lock file is
// the thing being probed, and a probe that refused to create it would report
// "no live run" and "cannot tell" identically. The file it may create is
// empty, 0600, inside an already-verified 0700 directory.
//
// The Nlink recheck is openAndHoldTargetLock's, for the same window and the
// same reason, and the CONSEQUENCE here is the sharper one: this probe's
// answer decides whether killOrphanInit fires. An exclusive lock taken on an
// inode sweepOneStaleLock has already unlinked would report "nobody holds
// it" while a live run holds the file that now carries the name — and the
// sweep would kill that live run's init. So a swept descriptor is retried
// against the name, and an exhausted retry is an ERROR, not "not held":
// every caller reads err as "not our business" and leaves the record alone.
//
// WHAT THAT RETRY DOES NOT COVER, stated because the paragraph above reads
// like a closed hole and is not one: it covers snug's OWN sweep, which
// unlinks only while holding LOCK_EX. It does not cover an unlink by anything
// else. One same-uid `rm` of a live run's lock file makes this function
// create a fresh inode, take LOCK_EX on it unopposed, see Nlink == 1, and
// answer "not held" while that run is very much alive. MEASURED, issue #489.
//
// AND `mv` IS THE SAME HOLE WITH NO TRAIL. A rename detaches the flock from
// the NAME exactly as an unlink does, and the fd follows it, so nothing
// anywhere reports a deleted file: the kernel appends " (deleted)" to
// /proc/<pid>/fd/N on unlink and appends nothing on rename. MEASURED against
// a live run, with the rename alone as the control:
//
//	victim snug=147894 init=147906, init alive BEFORE: YES (comm=bwrap)
//	after mv target-<hash>.lock decoy.lock, no sweep yet: YES-still-alive
//	victim fd5 -> /run/user/1000/snug/decoy.lock   <- no "(deleted)"
//	after a second snug on another target sweeps:   NO-KILLED-BY-SWEEP
//
// So this function's answer is not, on its own, a fact about whether a run is
// live, and no fix can make it one: a same-uid attacker owns the string that
// fd resolves to, however the name is compared. The record's other guards
// cannot help either — the name hash, the start time and the six namespace
// inodes establish IDENTITY, and a record genuinely names its live init, so
// all three pass by construction.
//
// WHAT THE CONSEQUENCE IS BOUNDED BY. The kill this answer used to license on
// its own is now gated on a second signal that lives outside the filesystem:
// killOrphanInit refuses to signal an init unless the snug that OWNED the run
// is provably gone (stateowner.go). An `rm` or an `mv` of the lock file still
// makes this function answer "not held", so `snug engine gc` will still
// reclaim that target's store — but it no longer reaches a live sandbox's
// init. Same-uid tampering is where runtimedir.go's own sweep already draws
// this line.
func targetLockIsHeld(snugRoot *os.Root, snugPath, real string) (bool, error) {
	name := targetLockName(real)
	for attempt := 0; attempt < targetLockAttempts; attempt++ {
		held, retry, err := probeTargetLockOnce(snugRoot, snugPath, name)
		if !retry {
			return held, err
		}
	}
	return false, fmt.Errorf("run state: %s was removed by a concurrent sweep on %d consecutive attempts",
		filepath.Join(snugPath, name), targetLockAttempts)
}

// probeTargetLockOnce is one attempt of the loop above. retry is true, and
// the other two results meaningless, exactly when the file it locked had
// already been unlinked.
func probeTargetLockOnce(snugRoot *os.Root, snugPath, name string) (held, retry bool, err error) {
	f, ferr := snugRoot.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if ferr != nil {
		return false, false, fmt.Errorf("run state: opening %s: %w", filepath.Join(snugPath, name), ferr)
	}
	defer f.Close()

	if flockErr := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); flockErr != nil {
		if errors.Is(flockErr, unix.EWOULDBLOCK) {
			return true, false, nil
		}
		return false, false, fmt.Errorf("run state: probing %s: %w", filepath.Join(snugPath, name), flockErr)
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()

	linked, lerr := stillLinked(f)
	if lerr != nil {
		return false, false, fmt.Errorf("run state: checking whether %s is still linked: %w",
			filepath.Join(snugPath, name), lerr)
	}
	if !linked {
		return false, true, nil
	}
	return false, false, nil
}

// selectLiveRun returns the state a live run published for real, or an error
// naming the ordinary "nothing is sandboxing this directory" case.
//
// Since issue #123 this is a LOOKUP, not a search: the state file is named
// from sha256(realpath) in the same uid-derived directory as the target lock,
// so there is exactly one candidate and no listing to walk.
//
// WHAT IT CANNOT TELL YOU, now that a target may carry several live runs at
// once: which one. The name is keyed by the target alone, so the run that
// published LAST is the run this returns, and an earlier run on the same
// directory is invisible here. Its one caller, `snug proxy`, therefore
// reaches the most recently started sandbox of that directory rather than a
// sandbox the human picked.
//
// real must already be canonicalised (filepath.EvalSymlinks, via
// canonicalTarget), because the file name is a hash OF that canonical form: a
// symlink to the target, or any other spelling, hashes elsewhere and finds
// nothing. That is the same coherence issue #119 fixed for the lock.
func selectLiveRun(real string) (runState, error) {
	st, live, err := readTargetState(real)
	if err != nil {
		return runState{}, err
	}
	if !live {
		return runState{}, fmt.Errorf("no live snug run found for %s — nothing is currently sandboxing "+
			"this directory", real)
	}
	return st, nil
}

// canonicalTarget resolves abs (already filepath.Abs'd) to the same realpath
// policy.Resolve and the target lock both use — see the comment above
// selectLiveRun. exists is false when abs, or a symlink it passes through,
// does not exist on disk: a directory with no on-disk presence cannot have a
// live run, so the caller reports that as "no live run" rather than surfacing
// a raw EvalSymlinks error. Any OTHER failure (permission denied on an
// intermediate component, a loop, ...) is returned as err with exists=false,
// and the caller must not treat that as "no live run" either — it is a
// different refusal with a different message.
func canonicalTarget(abs string) (real string, exists bool, err error) {
	real, err = filepath.EvalSymlinks(abs)
	if err != nil {
		// errors.Is, not os.IsNotExist: the predicate must survive a %w wrap,
		// and the one place it did not was issue #124.
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	return real, true, nil
}
