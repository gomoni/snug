package cli

// enginegc.go is `snug engine gc`, issue #308: the engine store persists
// across runs ON PURPOSE (it is an image cache; internal/engine/engine.go's
// own doc comment says so), so nothing removes it at teardown, and this is
// the explicit command that does — never automatically, never as a side
// effect of an ordinary `snug` run.
//
// # Liveness — the lock is HELD, not checked, and two arms, not a scan
//
// Removing a store's layer directory out from under a LIVE overlayfs
// produces silent corruption with no error on either side: `rm upper/b` then
// `ls merged` shows b absent while `cat merged/b` still returns its old
// contents, and `rm -rf upper` then leaves writes into merged failing ENOENT
// — nothing warns anybody. So this file never checks liveness and then acts;
// it takes the SAME per-target flock a live run holds for its whole run, and
// only renames the store aside while holding it (internal/engine.RenameAside
// is phase 1; the slow recursive delete, Purge, runs AFTER the lock is
// released, because the rename — not an assumption about how long deletion
// takes — is what makes the rest of the removal safe to run unlocked).
//
// TWO ARMS, because a store's own key alone cannot always name its lock:
//
//   - ARM A, the attributed path (a store whose breadcrumb names a real
//     target): targetLockName(bc.Target) computes the EXACT lock filename —
//     the same function a live run itself calls (targetlock.go) — so there
//     is no scan and nothing to drift. This replaces an earlier design that
//     scanned targetLockBase() for "target-<prefix>*.lock", matching on
//     engineKey being a PREFIX of targetKeyPrefix's hash — a coincidence
//     between two independently truncated hashes in two packages that issue
//     #349 (an algorithm-identifier prefix on both names) could break
//     silently: if the rename landed on one side and not the other, the scan
//     would find ZERO matches, which reads as "not live" and deletes a live
//     run's store. Both engineKey and targetKeyPrefix have since been
//     unified onto ONE full-length hash (internal/targetkey), which removes
//     the coincidence rather than merely working around it, but Arm A still
//     computes the exact name rather than trusting that unification to hold
//     forever — belt and braces costs one function call.
//   - ARM B, everything else (no breadcrumb, or one this file does not
//     trust, or an explicitly named key with no attribution): there is no
//     target string to derive an exact name from, so this asks a
//     deliberately CRUDER question that needs none — is ANY snug run live on
//     this host right now? — and refuses every unattributed removal if so.
//     Coarse on purpose: it cannot fail open the way a per-key check keyed
//     on an assumed name relationship could, because it does not depend on
//     one. The cost is that a human runs `snug engine gc --unattributed`
//     when nothing is sandboxing, not whenever they like; that is a smaller
//     cost than a corrupted store.
//
// A run-state JSON is a CORROBORATING refusal only, on Arm A, using the
// EXACT name (targetStateName(bc.Target), never a prefix): its PRESENCE,
// matched by full pid+starttime+namespace identity (the same chain
// orphansweep.go's killOrphanInit uses), refuses regardless of the flock.
// Its ABSENCE proves nothing — a run that has not yet published one is not
// thereby "not live" — so it is never read as evidence a target is safe.
//
// # Pre-flight ownership, and why it is incomplete
//
// Before phase 1, ScanStore walks the store READ-ONLY. Any entry not owned
// by this uid refuses the WHOLE store — see ScanStore's own doc comment for
// why this cannot see inside a mode-0000 directory it owns, and why that gap
// is closed at phase 2 instead, by leaving a self-describing ".gc-" leftover
// rather than silently retrying forever.
//
// # Three states, never two
//
// attributed: a breadcrumb whose Target checks out (KeyForTarget(Target)
// equals the directory's own name). unattributed: no breadcrumb at all —
// ordinary for a store older than this feature, or one whose write failed;
// EXPECTED TO BE LARGE right after this feature ships (every store created
// before it) and to drain on its own as real runs write breadcrumbs.
// untrustworthy: a breadcrumb IS present but fails the check (unknown
// schema, a forging rune in Target, or a key mismatch) — reported as
// unattributed AND FLAGGED, never silently folded into either bucket.
//
// # No selector, no removal — maintainer's ruling
//
// A bare `snug engine gc` REPORTS the aggregate (every store, bucketed by
// attribution, with a lower-bound size for each) and removes NOTHING —
// exit 0, not an error, because asking "what is there" is the common case
// and must be the safe one. This replaces an earlier design where a bare
// invocation removed every non-live ATTRIBUTED store: engine.go's own doc
// comment says warm-store reuse "is the point", and a default that reclaims
// all of it turns every project's next run into a cold pull. `docker system
// prune` closes the identical hazard with a confirmation prompt; snug has no
// prompt, so the SELECTOR is the confirmation instead — naming
// --older-than, --unattributed, or a key is the explicit "yes, this one".
//
// Three selectors, and they COMBINE (union by key): a named key always
// selects itself regardless of attribution; --unattributed selects every
// unattributed-or-untrustworthy store; --older-than selects attributed
// stores whose last_used is older than the duration. --older-than has NO
// EFFECT on unattributed stores — stated in --help and here rather than
// silently doing nothing on that subset, which is the shape this project
// keeps finding and closing (a rule applied to only one of its halves).
//
// ".gc-" leftovers are the one exception to "no selector, no removal": they
// are retried on EVERY invocation, selector or not, because they need no
// liveness question at all (RenameAside already ran, in an earlier
// invocation, and nothing looks that name up any more) — they are already
// snug's own garbage, not a store a human might still want. --dry-run still
// skips them, because --dry-run touches nothing, full stop.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/vdir"
	"golang.org/x/sys/unix"
)

func engineUsage() {
	fmt.Fprint(os.Stderr, `snug engine gc — reclaim the persistent container-engine image store

usage:
  snug engine gc [flags] [KEY...]

With NO flag and NO key, snug engine gc REPORTS what stores exist and their
lower-bound sizes, and removes NOTHING. Nothing is ever reclaimed without a
selector naming it.

selectors (combine — each one adds its own matches to what gets reclaimed):
  --older-than DUR    select ATTRIBUTED stores whose last recorded use is
                      older than DUR (e.g. "720h" for 30 days); has NO
                      EFFECT on unattributed stores, which carry no last-use
                      time to compare against
  --unattributed      select stores with no trustworthy breadcrumb —
                      excluded otherwise because snug cannot say what
                      project they belong to
  KEY...              select exactly the named store(s), regardless of
                      attribution

other flags:
  --dry-run          show what the selectors above WOULD reclaim; touches
                      nothing (no chmod, no rename, no delete)

A store whose target is still sandboxed (a live per-target lock, or a
run-state JSON naming a live process) is always skipped, regardless of any
selector — see this file's own doc comment for why liveness is a lock held,
not a check performed.
`)
}

// engineCmd is `snug engine`'s whole entry point — one subcommand today.
func engineCmd(argv []string) int {
	if len(argv) == 0 || strings.HasPrefix(argv[0], "-") {
		fmt.Fprintln(os.Stderr, "snug: `snug engine` takes one subcommand: gc")
		engineUsage()
		return exitUsage
	}
	switch argv[0] {
	case "gc":
		return engineGCCmd(argv[1:])
	default:
		fmt.Fprintf(os.Stderr, "snug: `snug engine` has no subcommand %s (only: gc)\n", visibleValue(argv[0]))
		return exitUsage
	}
}

type engineGCOptions struct {
	dryRun       bool
	unattributed bool
	olderThan    time.Duration
	olderThanSet bool
	keys         []string
}

// hasSelector reports whether this invocation named ANY of the three
// selectors. With none, engineGCCmd reports and removes nothing — see this
// file's package doc comment, "No selector, no removal".
func (o engineGCOptions) hasSelector() bool {
	return len(o.keys) > 0 || o.unattributed || o.olderThanSet
}

func parseEngineGCArgs(argv []string) (engineGCOptions, error) {
	var opts engineGCOptions
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--dry-run":
			opts.dryRun = true
		case a == "--unattributed":
			opts.unattributed = true
		case a == "--older-than":
			i++
			if i >= len(argv) {
				return opts, fmt.Errorf("--older-than needs a duration argument (e.g. 168h)")
			}
			d, err := time.ParseDuration(argv[i])
			if err != nil {
				return opts, fmt.Errorf("--older-than %s: %w", visibleValue(argv[i]), err)
			}
			opts.olderThan = d
			opts.olderThanSet = true
		case strings.HasPrefix(a, "--older-than="):
			d, err := time.ParseDuration(strings.TrimPrefix(a, "--older-than="))
			if err != nil {
				return opts, fmt.Errorf("--older-than %s: %w", visibleValue(a), err)
			}
			opts.olderThan = d
			opts.olderThanSet = true
		case strings.HasPrefix(a, "-"):
			return opts, fmt.Errorf("unknown flag %s", visibleValue(a))
		default:
			if !engine.StoreKey(a) {
				return opts, fmt.Errorf("%s is not shaped like a store key (64 lowercase hex "+
					"characters) — run `snug engine gc --dry-run` to list valid keys", visibleValue(a))
			}
			opts.keys = append(opts.keys, a)
		}
	}
	return opts, nil
}

// engineGCCandidate is one store this run considered, whatever it decided to
// do about it.
type engineGCCandidate struct {
	entry engine.EngineEntry
	bc    engine.Breadcrumb
	state engine.BreadcrumbState
}

func (c engineGCCandidate) attributed() bool { return c.state.Trustworthy() }

func engineGCCmd(argv []string) int {
	opts, err := parseEngineGCArgs(argv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n\n", err)
		engineUsage()
		return exitUsage
	}

	root, rootPath, ok, err := engine.EnginesRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitInternal
	}
	if !ok {
		fmt.Println("snug engine gc: nothing to reclaim — no container profile has ever started an engine on this host")
		return 0
	}
	defer root.Close()

	entries, err := engine.ListEngineEntries(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %v\n", err)
		return exitInternal
	}

	// Leftovers are retried on EVERY invocation, selector or not — see this
	// file's package doc comment on why they need no liveness question and
	// are the one exception to "no selector, no removal". --dry-run still
	// skips them: it touches nothing, full stop.
	for _, e := range entries {
		if !e.Leftover {
			continue
		}
		describeLeftover(root, rootPath, e, opts.dryRun)
	}

	var candidates []engineGCCandidate
	for _, e := range entries {
		if e.Leftover {
			continue
		}
		storeRoot, _, oerr := engine.OpenStore(root, rootPath, e.Name)
		if oerr != nil {
			fmt.Fprintf(os.Stderr, "snug: %s: %v\n", e.Name, oerr)
			continue
		}
		bc, state := engine.ReadBreadcrumb(storeRoot, e.Key)
		storeRoot.Close()
		candidates = append(candidates, engineGCCandidate{entry: e, bc: bc, state: state})
	}

	if !opts.hasSelector() {
		return engineGCReport(root, rootPath, candidates)
	}
	return engineGCSelect(root, rootPath, candidates, opts)
}

// describeLeftover reports (and, unless dryRun, retries phase 2 on) one
// ".gc-" leftover — a previous GC's phase 2 that stopped on a foreign-owned
// subtree (see internal/engine's ScanStore doc comment). Never gated by
// --unattributed or by a named key: it needs no liveness question at all,
// because RenameAside already ran and nothing looks this name up any more.
func describeLeftover(root *os.Root, rootPath string, e engine.EngineEntry, dryRun bool) {
	storeRoot, _, oerr := engine.OpenStore(root, rootPath, e.Name)
	target := "unknown"
	if oerr == nil {
		bc, state := engine.ReadBreadcrumb(storeRoot, e.Key)
		storeRoot.Close()
		if state.Trustworthy() {
			target = visibleValue(bc.Target)
		}
	}
	fmt.Printf("leftover  %s  (from a previous incomplete reclaim; target: %s)\n", e.Name, target)
	if dryRun {
		fmt.Println("          --dry-run: not retried")
		return
	}
	if perr := engine.Purge(root, rootPath, e.Name); perr != nil {
		fmt.Printf("          still stuck: %v\n", perr)
		return
	}
	fmt.Println("          reclaimed")
}

// engineGCReport is `snug engine gc` with NO selector at all: the aggregate,
// bucketed by attribution, with a lower-bound size for each — and it removes
// NOTHING. See this file's package doc comment for why report-only is the
// default rather than "remove every non-live attributed store" (maintainer's
// ruling): the selector IS the confirmation this command has no prompt for.
func engineGCReport(root *os.Root, rootPath string, candidates []engineGCCandidate) int {
	if len(candidates) == 0 {
		fmt.Println("snug engine gc: nothing to reclaim")
		return 0
	}

	var totalSize, unattrSize, attrSize int64
	var unattrCount, attrCount int
	for _, c := range candidates {
		storeRoot, storePath, oerr := engine.OpenStore(root, rootPath, c.entry.Name)
		var size int64
		if oerr == nil {
			scan, _ := engine.ScanStore(storeRoot, storePath)
			storeRoot.Close()
			size = scan.SizeBytes
		}
		totalSize += size
		if c.attributed() {
			attrCount++
			attrSize += size
		} else {
			unattrCount++
			unattrSize += size
		}
	}

	fmt.Printf("%d store(s), >= %s. Nothing selected, nothing removed.\n",
		len(candidates), humanBytes(totalSize))
	if unattrCount > 0 {
		fmt.Printf("  %d unattributed (target unknown)   >= %s   -> --unattributed\n",
			unattrCount, humanBytes(unattrSize))
	}
	if attrCount > 0 {
		fmt.Printf("  %d attributed                      >= %s   -> --older-than <dur>, or name a key\n",
			attrCount, humanBytes(attrSize))
	}
	fmt.Println("Select what to reclaim: --older-than <dur>, --unattributed, or one or more keys.")
	return 0
}

// engineGCSelect handles an invocation carrying at least one selector.
// Selectors COMBINE — union by key, not intersection: a named key always
// selects itself regardless of attribution, --unattributed adds every
// unattributed-or-untrustworthy store, and --older-than adds attributed
// stores whose last_used is older than the duration (and has NO EFFECT on
// unattributed stores — see this file's package doc comment and --help for
// why that is stated rather than silent).
func engineGCSelect(root *os.Root, rootPath string, candidates []engineGCCandidate, opts engineGCOptions) int {
	byKey := make(map[string]engineGCCandidate, len(candidates))
	for _, c := range candidates {
		byKey[c.entry.Key] = c
	}

	selected := make(map[string]bool)
	code := 0

	for _, key := range opts.keys {
		if _, ok := byKey[key]; !ok {
			fmt.Fprintf(os.Stderr, "snug: no store with key %s\n", key)
			code = exitUsage
			continue
		}
		selected[key] = true
	}

	if opts.unattributed {
		for _, c := range candidates {
			if !c.attributed() {
				selected[c.entry.Key] = true
			}
		}
	}

	if opts.olderThanSet {
		for _, c := range candidates {
			if !c.attributed() {
				continue // no last_used to compare against — stated in --help, not silent
			}
			lastUsed, perr := time.Parse(time.RFC3339, c.bc.LastUsed)
			if perr != nil {
				continue // an unparseable timestamp is treated conservatively: not selected
			}
			if time.Since(lastUsed) >= opts.olderThan {
				selected[c.entry.Key] = true
			}
		}
	}

	if len(selected) == 0 {
		fmt.Println("snug engine gc: the selector matched no store")
		return code
	}

	// Deterministic output order, not map iteration order.
	keys := make([]string, 0, len(selected))
	for k := range selected {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if !processCandidate(root, rootPath, byKey[key], opts) {
			code = exitInternal
		}
	}
	return code
}

// processCandidate is one store's whole lifecycle: liveness, pre-flight
// ownership, --dry-run's honest report, or the real two-phase removal. It
// returns false on a hard failure worth a non-zero exit; a live or
// foreign-owned store is reported and skipped, which is success, not
// failure — the store survives exactly as designed.
func processCandidate(root *os.Root, rootPath string, c engineGCCandidate, opts engineGCOptions) bool {
	key := c.entry.Key
	label := key
	if c.attributed() {
		label = fmt.Sprintf("%s  (target: %s)", key, visibleValue(c.bc.Target))
	} else {
		label = fmt.Sprintf("%s  (unattributed)", key)
	}

	var live bool
	var unlock func()
	var err error
	if c.attributed() {
		live, unlock, err = targetLive(c.bc.Target)
	} else {
		live, err = anyRunLive()
		unlock = func() {}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "snug: %s: %v\n", label, err)
		return false
	}
	if live {
		verb := "a run on this target"
		if !c.attributed() {
			verb = "some snug run"
		}
		fmt.Printf("skip      %s  (%s is live)\n", label, verb)
		unlock()
		return true
	}

	storeRoot, storePath, oerr := engine.OpenStore(root, rootPath, c.entry.Name)
	if oerr != nil {
		unlock()
		fmt.Fprintf(os.Stderr, "snug: %s: %v\n", label, oerr)
		return false
	}
	scan, serr := engine.ScanStore(storeRoot, storePath)
	storeRoot.Close()
	if serr != nil {
		unlock()
		fmt.Fprintf(os.Stderr, "snug: %s: %v\n", label, serr)
		return false
	}
	if scan.ForeignOwner() {
		unlock()
		fmt.Printf("refuse    %s  (owned by uid %d at %s — needs a userns carrying the same "+
			"delegated uid map to remove; store left intact)\n", label, scan.ForeignUID, scan.ForeignPath)
		return true
	}

	sizeNote := humanSizeNote(scan)
	if opts.dryRun {
		fmt.Printf("would reclaim  %s  %s\n", label, sizeNote)
		unlock()
		return true
	}

	leftover, rerr := engine.RenameAside(root, c.entry.Name)
	if rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		unlock()
		fmt.Fprintf(os.Stderr, "snug: %s: renaming aside: %v\n", label, rerr)
		return false
	}

	// The runroot goes with it, same key, same two phases — see
	// internal/engine.RunrootBaseName's own doc comment.
	tmpRoot, tmpErr := os.OpenRoot(os.TempDir())
	var runrootLeftover string
	if tmpErr == nil {
		runrootLeftover, _ = engine.RenameAside(tmpRoot, engine.RunrootBaseName(key))
	}

	// Phase 1 is done: the store (and its runroot) are wholly disconnected
	// from anything that could look them up again. Release the lock now —
	// phase 2 is a slow recursive delete that does not need it, per this
	// file's own doc comment.
	unlock()

	if rerr == nil {
		if perr := engine.Purge(root, rootPath, leftover); perr != nil {
			fmt.Printf("partial   %s  stopped mid-reclaim: %v (left as %s for a later run to "+
				"retry or describe)\n", label, perr, leftover)
		} else {
			fmt.Printf("reclaimed %s  %s\n", label, sizeNote)
		}
	}
	if tmpErr == nil {
		if runrootLeftover != "" {
			if perr := engine.Purge(tmpRoot, os.TempDir(), runrootLeftover); perr != nil {
				fmt.Printf("          runroot stopped mid-reclaim: %v\n", perr)
			}
		}
		tmpRoot.Close()
	}
	return true
}

// humanSizeNote renders a StoreScan the way --dry-run and the reclaimed
// notice both must: a LOWER BOUND, stated as one, never a number the walk
// could not actually measure.
func humanSizeNote(scan engine.StoreScan) string {
	if scan.UnreadableDirs == 0 {
		return fmt.Sprintf(">= %s", humanBytes(scan.SizeBytes))
	}
	return fmt.Sprintf(">= %s, plus %d unreadable subtree(s) containing at least %d "+
		"subdirector(y/ies); the real removal will chmod them",
		humanBytes(scan.SizeBytes), scan.UnreadableDirs, scan.UnreadableSubdirs)
}

func humanBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	units := "KMGT"
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), units[exp])
}

// ── liveness, the two arms ───────────────────────────────────────────────
//
// TESTING NOTE, earned the hard way (issue #308's implementation): setting
// $XDG_RUNTIME_DIR to a scratch directory does NOT isolate a test's fixture
// from targetLockBase() — issue #122 made that function derive its base from
// the uid ALONE, precisely so an interactive shell and cron/systemd land on
// the same lock inode, and that means no environment variable can redirect
// it. A manual smoke test that sets $XDG_RUNTIME_DIR and then calls the real
// targetLive/anyRunLive is silently testing against the REAL
// /run/user/<uid>/snug — reads only, in these two functions, but real reads
// and real (empty, unheld) lock files created by targetLive's own
// O_CREATE|O_RDWR probe. Reach for targetlock_test.go's useTargetLockBase(t)
// instead, which overrides the package-level canonicalRuntimeDir var these
// functions actually consult and points it at a t.TempDir().

// targetLive is Arm A: real, an EXACT target string a breadcrumb named. See
// this file's package comment for why it computes the lock's name directly
// rather than scanning, and why the run-state JSON is a corroborating
// refusal only. unlock is non-nil and must be called (whether or not live)
// once the caller is done with whatever it decided under the lock — a no-op
// when there was nothing to unlock.
func targetLive(real string) (live bool, unlock func(), err error) {
	noop := func() {}

	base, snugName, err := targetLockBase()
	if err != nil {
		return false, noop, fmt.Errorf("checking whether %s is live: %w — refusing rather than "+
			"guessing", real, err)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return false, noop, fmt.Errorf("checking whether %s is live: opening %s: %w", real, base, err)
	}
	defer root.Close()

	snugRoot, err := vdir.OpenExistingSubdir(root, base, snugName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// A run creates this directory (via lockTarget) before it does
			// anything else, so its absence means no run has EVER locked
			// any target on this host — nothing can possibly be live. This
			// is the one place this design fails open, and it is safe
			// because there is nothing left for it to fail open ABOUT.
			return false, noop, nil
		}
		return false, noop, fmt.Errorf("checking whether %s is live: %w", real, err)
	}

	name := targetLockName(real)
	snugPath := filepath.Join(base, snugName)
	// READ-ONLY, and NEVER O_CREATE. This is a query, and a query that
	// creates a file is not one: the lock directory is never unlinked (it
	// clears at reboot, which is what lets the guard fail closed), so an
	// O_CREATE probe here would leave one permanent lock file per attributed
	// store it examined — and it would do so under --dry-run, which promises
	// it "creates no file". MEASURED: an earlier O_CREATE|O_RDWR version of
	// this line left two 0-byte locks in /run/user/<uid>/snug/ for targets
	// that never existed.
	//
	// ENOENT therefore means not live, and that is sound rather than
	// convenient: lockTarget creates this file before a run does anything
	// else (targetlock.go), so a live run's lock necessarily exists. flock(2)
	// takes LOCK_EX on an O_RDONLY descriptor — unlike fcntl(2) POSIX locks,
	// it does not require write access — so the exclusive probe below is
	// unaffected.
	f, err := snugRoot.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		snugRoot.Close()
		return false, noop, nil
	}
	if err != nil {
		snugRoot.Close()
		return false, noop, fmt.Errorf("checking whether %s is live: opening %s: %w",
			real, filepath.Join(snugPath, name), err)
	}

	if flockErr := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); flockErr != nil {
		f.Close()
		snugRoot.Close()
		if errors.Is(flockErr, unix.EWOULDBLOCK) {
			return true, noop, nil
		}
		return false, noop, fmt.Errorf("checking whether %s is live: flock %s: %w",
			real, filepath.Join(snugPath, name), flockErr)
	}

	// We hold the lock exclusively: by the lock's own contract, nothing owns
	// it right now. Corroborate with the state file regardless — see this
	// function's doc comment on why its absence proves nothing but its
	// presence can still refuse.
	if targetProvablyLive(snugRoot, snugPath, real) {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		snugRoot.Close()
		return true, noop, nil
	}

	return false, func() {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		snugRoot.Close()
	}, nil
}

// targetProvablyLive is Arm A's corroborating signal: the run-state JSON at
// its EXACT name (targetStateName(real), never a prefix scan), checked by
// the identical pid+starttime+namespace identity chain orphansweep.go's
// killOrphanInit already uses. Any failure to confirm returns false — this
// function only ever REFUSES on a positive match; it never asserts safety.
func targetProvablyLive(snugRoot *os.Root, snugPath, real string) bool {
	name := targetStateName(real)
	f, err := snugRoot.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()

	st, err := decodeRunState(f)
	if err != nil {
		return false
	}
	if targetStateName(st.Target) != name {
		return false // the name is the index; a mismatch is not evidence of anything
	}
	pid := st.Sandbox.InitPID
	if pid <= 1 {
		return false
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return false // ESRCH: gone
	}
	defer unix.Close(pidfd)
	start, err := procStartTime(pid)
	if err != nil || start != st.Sandbox.InitStarttime {
		return false
	}
	nsIno, err := procNamespaceInodes(pid)
	if err != nil {
		return false
	}
	for _, k := range runStateNamespaceKinds {
		if nsIno[k] != st.Sandbox.Namespaces[k] {
			return false
		}
	}
	return true
}

// anyRunLive is Arm B: coarse and fail-closed, for a store this file cannot
// attribute to any target at all. See the package comment for why it scans
// every lock rather than one derived from a key: there is no target string
// to derive an exact name from, so this asks whether ANY snug run is live,
// which needs no name relationship whatsoever.
func anyRunLive() (bool, error) {
	base, snugName, err := targetLockBase()
	if err != nil {
		return false, fmt.Errorf("checking whether any run is live: %w", err)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return false, fmt.Errorf("checking whether any run is live: opening %s: %w", base, err)
	}
	defer root.Close()

	snugRoot, err := vdir.OpenExistingSubdir(root, base, snugName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil // nothing has ever locked anything: nothing can be live
		}
		return false, fmt.Errorf("checking whether any run is live: %w", err)
	}
	defer snugRoot.Close()
	snugPath := filepath.Join(base, snugName)

	entries, err := fs.ReadDir(snugRoot.FS(), ".")
	if err != nil {
		return false, fmt.Errorf("checking whether any run is live: reading %s: %w", snugPath, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "target-") || !strings.HasSuffix(name, ".lock") {
			continue
		}
		f, oerr := snugRoot.Open(name) // read-only probe, never O_CREATE: this file already exists
		if oerr != nil {
			continue
		}
		flockErr := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
		if flockErr == nil {
			unix.Flock(int(f.Fd()), unix.LOCK_UN)
			f.Close()
			continue
		}
		f.Close()
		if errors.Is(flockErr, unix.EWOULDBLOCK) {
			return true, nil
		}
		return false, fmt.Errorf("checking whether any run is live: probing %s: %w",
			filepath.Join(snugPath, name), flockErr)
	}
	return false, nil
}
