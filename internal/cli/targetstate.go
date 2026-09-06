package cli

// targetstate.go publishes and reads a run's state.json, NAMED FROM THE
// TARGET DIRECTORY it sandboxes and the pid that owns it, in the same
// env-independent directory the per-target lock already lives in (issue
// #123).
//
// Why the target is in the name. Both readers arrive with a DIRECTORY and no
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
// Two things follow from the target key:
//
//   - A reader never has to open a record to find out whose it is. The
//     target's realpath hashes to one stem, so the candidates are the names
//     matching that stem and nothing else in the directory is touched.
//   - "Is ANYTHING live on this target" is the target lock itself, rather than
//     a second parallel flock on each run directory that could in principle
//     disagree with it. A stale state file cannot be mistaken for a live run
//     on its own: the lock is the truth about the target, the JSON beside it
//     only what a holder published.
//
// WHY THE OWNING PID IS IN THE NAME. Several runs may be live on one target
// at once (TARGET-LOCK.md), so the target alone does not name a run. Keyed by
// the target alone the second run to publish OVERWROTE its peer's record, and
// the consequence was not cosmetic: the overwritten run's init was then named
// by nothing, so no later sweep could ever kill it — invariant 4 failing on a
// sequence that needs no attacker (SIGKILL run A while run B is live). The
// name is `target-<hash>.<pid>.json`, and `.starting` beside it, where pid is
// the OWNING SNUG process.
//
// THAT PID IS AN ADDRESS, NEVER A LIVENESS CLAIM, and the trap is the obvious
// one: a record whose owner died and whose pid number has since been handed
// to an unrelated process is indistinguishable, BY NAME, from a live run's.
// So no reader here treats the name as evidence of anything. Liveness is the
// target lock for the target, and stateowner.go's recorded pid + start time
// for the individual run — the same two checks as before this file learned to
// hold more than one record, applied per record instead of to the only one.
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
	"sort"
	"strconv"
	"strings"

	"github.com/gomoni/snug/internal/vdir"
	"golang.org/x/sys/unix"
)

// targetStateName is the filename of the run-state record published by the
// snug process pid for realpath: targetLockName's stem, so the whole of a
// target's files sort together, then the owning pid, then ".json". Derived
// rather than stored — the name IS the index — and see this file's own doc
// comment for why the pid is in it and why it establishes nothing about
// whether that run is still alive.
func targetStateName(realpath string, pid int) string {
	return fmt.Sprintf("%s.%d.json", targetKeyPrefix(realpath), pid)
}

// targetStateNameMatches reports whether name is a run-state record belonging
// to realpath, under any generation of the name snug has written.
// sweepOrphanedSandboxesIn and the readers below are the callers — without
// this, a record an older binary wrote is invisible to the sweep forever, and
// the orphan init it names is never killed.
func targetStateNameMatches(realpath, name string) bool {
	return targetRecordNameMatches(realpath, name, ".json")
}

// targetRecordNameMatches reports whether name is one of realpath's records
// with the given suffix. Three generations are recognised and only the first
// is ever written:
//
//	target-sha256_<hex>.<pid><suffix>   the current name
//	target-sha256_<hex><suffix>         before the owning pid was in it
//	target-<hex><suffix>                before issue #349 labelled the digest
//
// The older two are recognised for one reason: a record this function does
// not claim is a record no sweep will remove and an init no sweep will kill,
// forever. They cost nothing to keep — a run that wrote one is a run whose
// owner is not live, which killOrphanInit's gate already resolves.
//
// The pid component is checked for shape, not for meaning. Requiring it to
// round-trip through strconv keeps a hand-placed "target-<hash>.x.json" from
// reading as this target's record; whether the number belongs to anything
// alive is a question no filename can answer.
func targetRecordNameMatches(realpath, name, suffix string) bool {
	rest, ok := strings.CutSuffix(name, suffix)
	if !ok {
		return false
	}
	for _, stem := range []string{targetKeyPrefix(realpath), legacyTargetKeyPrefix(realpath)} {
		if rest == stem {
			return true
		}
		digits, cut := strings.CutPrefix(rest, stem+".")
		if !cut {
			continue
		}
		if n, err := strconv.Atoi(digits); err == nil && n > 0 && strconv.Itoa(n) == digits {
			return true
		}
	}
	return false
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

// writeTargetState publishes st for the target it names, at the name
// addressing st's own owner.
//
// The pid comes out of the record rather than from os.Getpid() so that the
// name and the record cannot disagree about whose run this is: every reader
// that finds a record by name goes on to judge it by st.Owner, and a name
// addressing one pid over a body naming another would send the sweep's
// liveness gate at the wrong process. It returns an error rather than
// publishing at pid 0 for the same reason a record with no owner is refused
// downstream — an unaddressable record is worse than none.
func writeTargetState(real string, st runState) error {
	if st.Owner.PID <= 0 {
		return fmt.Errorf("run state: refusing to publish a record for %s that names no owning "+
			"snug process (pid %d): the file name addresses that pid, and the orphan sweep's "+
			"liveness gate reads it", real, st.Owner.PID)
	}
	return writeTargetFile(targetStateName(real, st.Owner.PID), st)
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
// name is derived from the target and the OWNING PID, and a pid is reused, so
// a long-dead run on the same directory may have left this exact name behind.
// That file is not a conflict — nothing that could still be reading it can be
// this pid's run — so the correct behaviour is to replace it. Replacing it by
// rename rather than by truncate-and-write is what stops a reader that
// arrives mid-write from reading half a file.
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

	// The pid separates writers in different PROCESSES — which final's own pid
	// component already does, so this is belt and braces. What NEITHER
	// separates is two writers inside ONE process: they share the pid and
	// therefore this name, and internal/sandbox's initReporter measured what
	// that costs — the second writer's opening Remove deleted the first
	// writer's file, and the first's rename then failed with ENOENT.
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

// liveRunsFor returns the record of every run on real whose owning snug is
// not provably gone, sorted by that owner's pid so two calls list the same
// candidates in the same order.
//
// An empty slice with no error is every ordinary way there is nothing
// running: snug has never run on this host, this target has no record, or
// records are there but every run that wrote one is over. Those are the zero
// case and the caller renders one message for them — the distinction issue
// #124 was about.
//
// TWO LIVENESS QUESTIONS, because one no longer answers the other. The target
// lock says whether ANY run is live here and nothing is read while it is
// unheld: every record beside an unheld lock describes a corpse. With the
// lock held, a record still may not be its own run's — a peer's SIGKILL
// leaves a record behind that the sweep only removes once the whole target
// falls quiet — so each is put through stateowner.go's owner check, the same
// gate the sweep's kill uses and failing in the same direction: an owner that
// cannot be confirmed dead is listed.
//
// An error is reserved for a directory that fails the ownership or mode
// guard, or a record beside a HELD lock that cannot be read or does not
// validate. That last one is deliberately NOT the zero case, and with several
// runs it is deliberately not a skip either: dropping an unreadable record
// would hide a live sandbox from a human who asked what is running here.
func liveRunsFor(real string) ([]runState, error) {
	snugRoot, snugPath, err := openTargetStateDir(false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer snugRoot.Close()

	held, err := targetLockIsHeld(snugRoot, snugPath, real)
	if err != nil {
		return nil, err
	}
	if !held {
		return nil, nil
	}

	names, err := targetStateNamesIn(snugRoot, real)
	if err != nil {
		return nil, fmt.Errorf("run state: listing %s: %w", snugPath, err)
	}

	var runs []runState
	for _, name := range names {
		full := filepath.Join(snugPath, name)
		f, oerr := snugRoot.Open(name)
		if oerr != nil {
			if errors.Is(oerr, fs.ErrNotExist) {
				// Swept between the listing and here, which the sweep is
				// entitled to do to a record whose run is over.
				continue
			}
			return nil, fmt.Errorf("run state: opening %s: %w", full, oerr)
		}
		st, derr := decodeRunState(f)
		f.Close()
		if derr != nil {
			return nil, fmt.Errorf("run state: %s: %w", full, derr)
		}
		if st.Target != real {
			// The stem is a hash of the target, so this can only mean a
			// collision or a hand-edited file. Refuse rather than hand back
			// whatever it names: every caller acts on this record against the
			// directory it asked about, and a record for a DIFFERENT
			// directory would send `snug proxy` at another project's run.
			return nil, fmt.Errorf("run state: %s names target %q, not %q — refusing to "+
				"report a run for a different directory", full, st.Target, real)
		}
		if ownerProvablyGone(st.Owner) {
			continue
		}
		runs = append(runs, st)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].Owner.PID < runs[j].Owner.PID })
	return runs, nil
}

// targetStateNamesIn lists the run-state records in snugRoot belonging to
// real, by name alone: nothing is opened, so a directory full of other
// targets' records costs one readdir.
func targetStateNamesIn(snugRoot *os.Root, real string) ([]string, error) {
	entries, err := fs.ReadDir(snugRoot.FS(), ".")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if targetStateNameMatches(real, e.Name()) {
			names = append(names, e.Name())
		}
	}
	return names, nil
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

// selectLiveRun returns the one live run on real the caller asked for.
//
// wantPID is `snug proxy --pid`: 0 means the human named no run. With exactly
// one live run that is unambiguous and the run is returned. With SEVERAL it
// REFUSES and lists them, rather than picking the newest or the first — which
// sandbox a door is opened into is a decision, and snug making it silently is
// invariant 5's shape (the human would believe a hole was opened somewhere it
// was not). A wantPID matching no live run refuses with the same list, so a
// pid copied from a run that has since exited says so instead of quietly
// serving a different sandbox.
//
// The pid is the OWNING SNUG process, not the sandbox's init: it is the one
// number the human can see with `ps`, and the one the record's own owner
// field carries.
//
// real must already be canonicalised (filepath.EvalSymlinks, via
// canonicalTarget), because the record names are a hash OF that canonical
// form: a symlink to the target, or any other spelling, hashes elsewhere and
// finds nothing. That is the same coherence issue #119 fixed for the lock.
func selectLiveRun(real string, wantPID int) (runState, error) {
	runs, err := liveRunsFor(real)
	if err != nil {
		return runState{}, err
	}
	if len(runs) == 0 {
		return runState{}, fmt.Errorf("no live snug run found for %s — nothing is currently sandboxing "+
			"this directory", real)
	}
	if wantPID > 0 {
		for _, st := range runs {
			if st.Owner.PID == wantPID {
				return st, nil
			}
		}
		return runState{}, fmt.Errorf("no live snug run on %s has pid %d.\n%s",
			real, wantPID, liveRunCandidates(real, runs))
	}
	if len(runs) == 1 {
		return runs[0], nil
	}
	return runState{}, fmt.Errorf("%d snug runs are live on %s. Which sandbox a door is opened "+
		"into is not something snug should guess at, so name one with --pid.\n%s",
		len(runs), real, liveRunCandidates(real, runs))
}

// liveRunCandidates renders the runs a refusal is offering to choose between,
// one per line with the command that picks it — the fix has to be on screen,
// not merely the flag's name.
//
// The start time goes beside each pid because the pid alone does not identify
// a run for longer than the kernel takes to reuse the number: it is the pair
// that the records themselves are judged on, so it is the pair a human is
// shown deciding between two of them.
func liveRunCandidates(real string, runs []runState) string {
	var b strings.Builder
	for _, st := range runs {
		fmt.Fprintf(&b, "\n        pid %d  started %d      snug proxy %s --pid %d",
			st.Owner.PID, st.Owner.Starttime, real, st.Owner.PID)
	}
	b.WriteString("\n\n      \"started\" is /proc/<pid>/stat field 22, in clock ticks since boot.")
	return b.String()
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
