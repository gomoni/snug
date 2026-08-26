// Package engine computes the paths and launch spec for a container engine
// that belongs to one sandbox, and tears it down again.
//
// It is never the host's podman. A sandbox gets its own store, its own runroot
// and its own service process, so:
//
//   - the host's images, containers, volumes and networks are untouched, and
//     the sandbox cannot list or delete them
//   - two projects cannot see each other's containers — the store key is the
//     TARGET DIRECTORY alone (issue #276); a project's own images persist
//     across runs regardless of which profiles a given run selected, and
//     nothing about the profile set changes which store a run opens
//
// # The engine runs in the sandbox's own network namespace (issue #63, Tier B)
//
// It used to be a plain host process, on the host's own network namespace,
// meaning a container it started reached the internet even from an offline
// sandbox (ENGINE-NETNS.md §0, the finding this tier closes). The engine is
// now forked by internal/stage, EAGERLY, as a second long-lived child of the
// stage (P1) alongside bwrap — this package no longer starts it directly. It
// computes the paths (Engine.New), builds the stage.EngineSpec the stage's
// StartEngine consumes (Engine.Spec), and tears the result down again
// (Engine.Stop) — the fork, the setns into N, the private mount-namespace
// copy and the capability drop all live in internal/stage (EnterEngine,
// __inengine) because they need the stage's own raw-fork machinery and its
// membership in the sandbox's user namespace U.
//
// # Teardown, and why it is not just a kill
//
// The engine process itself dies WITH the stage: it is Pdeathsig'd to P1,
// which is itself Pdeathsig'd (and lifeline-held) to P0, so engine ⊂ P1 ⊂ P0
// and any death of snug cascades down to it. That REPLACES this package's old
// job of killing the engine process directly — Stop below no longer signals
// it at all. What Stop still owns:
//
//  1. lifeline.go — the engine runs with a finite idle timeout and snug holds
//     one streaming request open, dialled at its (now /tmp) socket. This is
//     what keeps a live run's engine up through idle stretches; its old
//     "keep a wrapper engine alive long enough to reap it" role is gone now
//     that preflight P1 refuses a wrapper outright and the engine is always a
//     real stage child.
//  2. reaper.go — a pipe-triggered helper stops this run's CONTAINERS (never
//     the engine process) when snug dies without cleaning up. Read the note
//     below on what issue #125's C0 did to the fact this helper was built
//     for: it is now REDUNDANT on every measured path, and it stays.
//  3. reap.go — Stop's own ordinary-path teardown: stop containers by label
//     while the engine is still live, THEN verify by sweeping for processes
//     that still name this run's socket path. "The kill returned no error" is
//     not evidence anything died; the sweep is.
//
// # Where containers live now, and what that did to the reaper (issue #125, C0)
//
// This package's teardown was designed around one sentence, and C0 falsified
// it: "containers are not the engine's children — conmon double-forks and its
// grandchild reparents in the HOST pid namespace, because the engine does not
// unshare pid — so they outlive the engine". C0 gave the engine CLONE_NEWPID
// at its own clone (internal/stage/enginefork.go) and a fresh procfs
// (internal/stage/inengine.go), which changed all three clauses. MEASURED on
// this host, A/B against C0's own parent commit, with a real pinned podman
// bundle and a long-running container (test/integration/testdata/holder):
//
//	                         pre-C0 (HEAD)              with C0
//	engine /proc/<p>/ns/pid  the HOST's own inode       its own, distinct
//	conmon's PPid (host      an ancestor init in the    the ENGINE itself,
//	  procfs)                  HOST pid namespace         which is pid 1 there
//	container init           a descendant pidns of      a descendant pidns of
//	                           the HOST's                 the ENGINE's
//	SIGKILL the engine,      container STILL RUNNING    container gone within
//	  nothing else             10s later                  one 250ms poll tick
//	recorded conmon.pid /    host pids, matching        SMALL numbers, valid
//	  pidfile in the runroot   /proc exactly              only inside the engine
//
// conmon still double-forks; what changed is which init adopts the orphan.
// Pid 1 of the engine's pid namespace is podman itself (execve does not change
// pid), so the orphan reparents ONTO THE ENGINE, and the kernel's rule that
// destroying a pid namespace SIGKILLs every member and every member of its
// descendant namespaces now covers the containers too.
//
// Consequences, in the order they matter:
//
//   - The reaper is REDUNDANT on every path measured, not wrong. The engine is
//     Pdeathsig'd to P1 and P1 to P0, so any death of snug — SIGKILL included —
//     fells the engine, and the namespace collapse takes the containers with
//     it. Measured end to end: SIGKILL snug, and the engine, the container and
//     the socket-path sweep were all clean inside 70ms — far faster than the
//     reaper could fork a `podman stop` even if it were the mechanism. It is
//     LEFT IN PLACE deliberately: removing a teardown mechanism is a
//     maintainer's call, not a side effect of correcting a comment, and this
//     one costs nothing on the clean path (Stop tells it to stand down).
//   - reap.go's host-/proc sweep is UNAFFECTED and still correct. A nested pid
//     namespace does not hide its members from an ancestor's procfs: every
//     process in the engine's namespace is still enumerable under
//     /proc/<host-pid>/ with a readable cmdline, which is all the sweep needs.
//     Measured: one process named this run's socket path while the engine was
//     live, zero after it died.
//   - FIXED by issue #167, not merely noted: the runroot's recorded
//     conmon.pid and pidfile are pids in the ENGINE's pid namespace now, not
//     the host's — measured on the same container in both eras: pre-C0 they
//     read 1954739/1954741 and matched /proc exactly, with C0 they read
//     168/170 while the host pids were seven digits. A HOST-side `podman
//     stop` reading those numbers reads numbers meaningless in its own
//     numbering, so stopLocked's step 1 and reaperScript's identical
//     invocation are DELETED rather than translated — see stopLocked's own
//     comment on step 1 for why translating them was rejected. The ORDERING
//     argument this used to rest on ("stop containers before anything
//     touches the engine, for a graceful stop instead of the kernel's
//     SIGKILL") no longer has a first step to order: dropping this run's
//     keepalive (step 2) is what now starts teardown, and the namespace
//     collapse is the only mechanism that stops a container at all.
package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/stage"
	"github.com/gomoni/snug/internal/vdir"
)

// idleTimeout is how long the engine outlives its last client. Never
// `--time 0`, which would disable the timeout and make the engine the daemon
// this project says it does not run. Short enough that a hard kill is cleaned
// up while the human is still looking at the terminal; long enough that a
// slow re-dial of the lifeline cannot expire it.
const idleTimeout = 10 * time.Second

// quietBudget bounds how long Stop waits for a SIGKILL that has ALREADY BEEN
// DELIVERED to take effect. Stop runs after the stage has been reaped, so the
// engine's Pdeathsig is queued before this constant is ever consulted, and all
// it covers is scheduling plus a walk of /proc.
//
// DELIBERATELY NOT RELATED TO idleTimeout ANY MORE (issue #344). It used to be
// idleTimeout + 5s, from a position where the engine was still alive: that made
// snug's own exit wait out a timeout whose entire purpose is to cover snug NOT
// BEING THERE. Nothing observed it for a milestone because the sweep was
// matching a string no process carried, so it never waited at all.
const quietBudget = 2 * time.Second

// killBudget is the second wait, after the sweep has escalated to SIGKILL
// itself. Anything still here has ignored two SIGKILLs — the cascade's and
// ours — and is named to the user rather than waited for.
const killBudget = 3 * time.Second

// RunLabelKey is the container label snug stamps every container it creates
// with, so the PROXY can tell this run's containers from an earlier run's.
//
// Its reader is internal/dockerproxy/ownership.go, which refuses a removal
// naming a container that carries anyone else's label (issue #339). NOT
// teardown: teardown is pid-namespace collapse and filters on nothing. The
// Engine literal in New() states the same thing at length.
//
// A dotted, namespaced key rather than a bare word: labels are a flat namespace
// shared with whatever the image and the user set, and `run` alone would be a
// plausible thing for someone else to mean.
const RunLabelKey = "snug.run"

type Engine struct {
	// dirs holds this run's own directory as a verified handle plus its
	// verified parent — see runDirs. The string fields below it are what
	// podman's argv and the generated config files still need.
	dirs *runDirs

	sock     string
	runroot  string
	store    string
	runDir   string
	sockDir  string
	confDir  string
	runLabel string

	// guestSock is the socket path as it appears in the ENGINE's argv — the
	// derived-view spelling Spec computes. It is what teardown matches on
	// (reap.go's paths()), recorded here by the one function that builds the
	// argv rather than derived a second time, because a second derivation of
	// the host->guest mapping would agree with Spec until the day it did not.
	// Empty until Spec has run, which means no engine was ever exec'd.
	guestSock string

	// dialled records that the lifeline was accepted at least once, i.e. that
	// an engine really answered on the socket. Kept separately from life,
	// which Detach clears: Stop needs to know an engine EXISTED in order to
	// tell "no engine this run" apart from "an engine ran and this sweep is
	// looking for nothing" (issue #344).
	dialled bool

	mu   sync.Mutex
	life *lifeline
	reap *reaper
	once sync.Once

	// BreadcrumbWarning is non-nil when this run could not write (or
	// refresh) engines/<key>/store.json — see verifyEngineStore. It is
	// deliberately NOT fatal to the run (a store snug cannot attribute is
	// still a perfectly good store), so it is exported for the one caller
	// that knows whether the human asked to see housekeeping notices
	// (internal/cli's startContainers, behind --verbose) rather than printed
	// unconditionally by a package that has no such flag of its own.
	BreadcrumbWarning error
}

// verifyEngineStore walks dataHome/snug/engines/<key>/storage through
// internal/vdir, creating any directory in that chain that is absent and
// refusing any that is not owned by this uid and mode exactly 0700 — reuse
// included, which is the property a bare os.MkdirAll never had (issue #276).
//
// It returns the walk's own path, built from the SAME components the walk
// actually opened, so New can compare it against planPaths' independently
// computed string rather than assuming the two arithmetics agree — the same
// defence the sockDir/confDir check above already applies. e.store itself
// stays the planned string (see New): this function verifies, it does not
// re-derive what the Engine uses.
//
// dataHome is opened with a BARE os.OpenRoot: a default ~/.local/share is
// 0755, snug does not own $XDG_DATA_HOME, and rooting the vdir walk there
// would refuse every run (VerifyOwnedAndPrivate demands exactly 0700). The
// first component this function OWNS, and therefore the first one it takes
// through SecureSubdir, is "snug". Every *os.Root opened along the way is
// closed before returning — vdir's ordering guarantee (nothing opened
// through a Root can be redirected out of the tree it was opened on) is what
// this walk needs; it is not a TOCTOU-free handle held for later use, and
// internal/vdir's own package doc asks each caller to say so.
//
// "snug" and "engines" are what makes a SYMLINKED
// ~/.local/share/snug/engines a hard refusal now rather than a silently
// followed one (issue #276, spec item 8) — a behaviour change with a real
// user, so the refusal at "engines" names the fix.
//
// It also writes (or refreshes) this key's breadcrumb — engines/<key>/store.json,
// beside storage/, never inside it — recording target and stamping LastUsed
// with THIS call's time (issue #308; see breadcrumb.go). That write is NOT
// allowed to fail this function: a store snug cannot attribute is still a
// perfectly good store, just one `snug engine gc` will report as
// unattributed until a later run's write succeeds. The failure, if any, is
// returned as a second value for New to decide what to do with (surfacing it
// behind --verbose), never folded into the hard error this function already
// has for a store it could not open at all.
func verifyEngineStore(dataHome, key, target string) (storagePath string, breadcrumbWarning, err error) {
	// os.MkdirAll follows a symlink — including one AT dataHome itself, not
	// just below it. That is a residual this call does not close: the vdir
	// walk below only starts protecting once os.OpenRoot(dataHome) succeeds,
	// so a $XDG_DATA_HOME pointed at a symlink into a WORLD-WRITABLE parent
	// (unlike the default ~/.local/share, which is 0755 victim-owned) is
	// still followed here, silently. It is user-inflicted — nobody but the
	// user who set $XDG_DATA_HOME can place that symlink — and out of scope
	// for issue #276's fix, which is about the top-level, uid-guessable
	// name under /tmp; naming the limit here rather than leaving MkdirAll
	// look covered by the walk that follows it.
	if merr := os.MkdirAll(dataHome, 0o755); merr != nil {
		return "", nil, fmt.Errorf("engine store: creating %s: %w", dataHome, merr)
	}
	root, err := os.OpenRoot(dataHome)
	if err != nil {
		return "", nil, fmt.Errorf("engine store: opening %s: %w", dataHome, err)
	}
	defer root.Close()

	snug, _, err := vdir.SecureSubdir(root, dataHome, "snug")
	if err != nil {
		return "", nil, fmt.Errorf("engine store: %w", err)
	}
	defer snug.Close()
	snugPath := filepath.Join(dataHome, "snug")

	engines, _, err := vdir.SecureSubdir(snug, snugPath, "engines")
	if err != nil {
		return "", nil, fmt.Errorf("engine store: %w — a symlinked engines directory used to be "+
			"followed silently; move the directory instead of symlinking it, or point "+
			"$XDG_DATA_HOME at the other filesystem", err)
	}
	defer engines.Close()
	enginesPath := filepath.Join(snugPath, "engines")

	// This directory is SHARED across runs of the same target on purpose —
	// see New's own doc comment on the store — so SecureSubdir, not
	// MustCreateSubdir: reuse is exactly the warm start this key exists to
	// produce, and MustCreateSubdir would refuse the second run outright.
	keyDir, _, err := vdir.SecureSubdir(engines, enginesPath, key)
	if err != nil {
		return "", nil, fmt.Errorf("engine store: %w", err)
	}
	defer keyDir.Close()
	keyPath := filepath.Join(enginesPath, key)

	storage, _, err := vdir.SecureSubdir(keyDir, keyPath, "storage")
	if err != nil {
		return "", nil, fmt.Errorf("engine store: %w", err)
	}
	storage.Close()

	var warning error
	if berr := writeBreadcrumb(keyDir, keyPath, key, target); berr != nil {
		warning = fmt.Errorf("engine store breadcrumb for %s: %w — this store will be reported "+
			"unattributed by `snug engine gc` until a later run writes one successfully", keyPath, berr)
	}
	return filepath.Join(keyPath, "storage"), warning, nil
}

// verifyEngineRunroot walks $TMPDIR/snug-engines-<uid>-<key>/rr through
// internal/vdir the same way verifyEngineStore does for the store, and for
// the same reason: the runroot must be REUSED across runs sharing the same
// store (podman's libpod database refuses a runroot that disagrees with the
// one it recorded), so this is SecureSubdir, not MustCreateSubdir, and it
// checks owner and mode on every call, reuse included.
//
// /tmp itself is opened with a bare os.OpenRoot: it is commonly 1777, snug
// does not own it, and — load-bearing, not merely a bare os.OpenRoot — the
// FIRST component this function owns, and the one that gets the vdir walk's
// in-root open plus the 0700+no-symlink discipline, is
// "snug-engines-<uid>-<key>" ITSELF, not something beneath it. Rooting the
// check one level lower (at "rr") would leave the top name wide open:
// os.MkdirAll on a pre-planted symlink at that exact path returns <nil> and
// creates "rr/tmp" INSIDE the attacker's own directory (measured — issue
// #276's part 3, sev:medium, redteam round 2).
//
// This is the load-bearing half of that finding, not defence in depth: the
// engine writes the OCI bundle's config.json, conmon's pid file and
// image_copy_tmp_dir into this runroot, so an attacker who wins the pre-plant
// gets those read (cross-uid disclosure) at minimum, and a TOCTOU write of
// config.json between podman authoring it and crun/runc reading it can inject
// hooks.prestart — an arbitrary program run as THIS run's uid, not the
// attacker's own. Once snug creates "snug-engines-<uid>-<key>" here, 0700 and
// owned by this uid, /tmp's own sticky bit is what stops any OTHER uid
// renaming or deleting it out from under a later run — the same reasoning
// internal/cli's runtimeDir (runtimedir.go) already applies to its own
// uid-scoped name directly under /tmp.
//
// With the check rooted here, a same-uid host process can pre-plant that
// name only as a symlink (refused by the Lstat this walk does before
// opening) or as a directory it owns (refused by VerifyOwnedAndPrivate's uid
// check, since an attacker cannot chown a directory to the victim's uid) —
// it can no longer have either silently adopted, which is what a bare
// os.MkdirAll used to do.
//
// It also creates rr/tmp, which containers.conf's image_copy_tmp_dir needs
// present before podman starts (podman STATS it rather than creating it).
//
// The return value is the RUNROOT itself (…/rr), not …/rr/tmp — the same
// convention verifyEngineStore uses, and what New compares against
// planPaths' Runroot.
func verifyEngineRunroot(key string) (string, error) {
	tmpDir := os.TempDir()
	root, err := os.OpenRoot(tmpDir)
	if err != nil {
		return "", fmt.Errorf("engine runroot: opening %s: %w", tmpDir, err)
	}
	defer root.Close()

	name := fmt.Sprintf("snug-engines-%d-%s", os.Getuid(), key)
	base, _, err := vdir.SecureSubdir(root, tmpDir, name)
	if err != nil {
		return "", fmt.Errorf("engine runroot: %w", err)
	}
	defer base.Close()
	basePath := filepath.Join(tmpDir, name)

	rr, _, err := vdir.SecureSubdir(base, basePath, "rr")
	if err != nil {
		return "", fmt.Errorf("engine runroot: %w", err)
	}
	defer rr.Close()
	rrPath := filepath.Join(basePath, "rr")

	tmp, _, err := vdir.SecureSubdir(rr, rrPath, "tmp")
	if err != nil {
		return "", fmt.Errorf("engine runroot: %w", err)
	}
	tmp.Close()
	return rrPath, nil
}

// New computes the paths for a sandbox's engine but starts nothing.
//
// It takes the resolved *policy.Policy rather than a (profiles, target) pair
// on purpose (issue #276): pol.Target is the ONLY thing engineKey hashes, and
// making that a parameter of its own type is what stops a caller handing it
// ctx.Target, a filepath.Abs, or a hand-rolled realpath instead of the
// canonical string policy.Resolve already produced — see engineKey's own doc
// comment for the soundness rule this exists to keep.
//
// The STORE key is derived from the target ALONE, so the same project
// reuses its images across runs (a warm start) regardless of which profiles
// a given run selected, while a different project gets a different store.
// It stays under XDG_DATA_HOME, unaffected by issue #63 Tier B: nothing
// about WHERE the engine runs changes what should persist across runs.
//
// The SOCKET lives under /tmp/snug-<uid>-<pid>/ (issue #63, Tier B,
// ENGINE-WIRING.md §3.1), hardened and unique to THIS run — createRunDir
// refuses to reuse an existing entry at that path, the same discipline
// commit dfe6ac8 (#61, #85) applied to snug's own runtime directory. That is
// what teardown matches on (see reap.go): the store is shared with every
// past and concurrent sandbox on the SAME TARGET, so killing "whatever names
// the store" would reach into a sibling sandbox that is still working — see
// reap.go's own doc comment for why that sibling can only be a PAST run in
// practice, never a concurrent one, because the per-target lock permits at
// most one live run per target.
//
// The RUNROOT, MEASURED, must NOT be pid-unique the way the socket is, and
// that is a correction of what ENGINE-WIRING.md §3.1 assumed: podman's own
// libpod database, which lives IN the persisted store, records the runroot
// path a run used and REFUSES a later run against the same store with a
// DIFFERENT one ("database run root ... does not match"). A store that
// persists across runs (by design, for a warm start) needs a runroot that is
// STABLE across those same runs — exactly like ordinary rootless podman's
// own default ($XDG_RUNTIME_DIR/containers, stable for a login session) — so
// it is keyed by the SAME target-only key as the store, not by pid, and
// verified through the same vdir walk the store now is (issue #276 — both
// used to be a bare, first-writer-wins MkdirAll(0o700), which never checked
// the OWNER of an existing directory, only created a fresh one that way).
// It still lives under /tmp, not $XDG_RUNTIME_DIR — that half of §3.1's
// reasoning (a root-in-userns podman masks $XDG_RUNTIME_DIR with its own
// tmpfs on /run) is unaffected by this correction.
func New(pol *policy.Policy) (*Engine, error) {
	pid := os.Getpid()
	// The name is allocated FIRST and the paths are computed from it, so that
	// what this function creates and what --dry-run predicts (PlannedPaths)
	// come out of one arithmetic rather than two copies of it — see paths.go.
	// Before this run claims a name, reclaim the directories of runs that
	// died holding theirs. It runs HERE, on the way in, because that is the
	// only place left: a SIGKILLed run executes nothing on its way out
	// (issue #85's argument, applied to the directory issue #425 measured
	// still leaking). It is also what keeps a leftover from being a landmine
	// for this very call — the name below carries our pid and
	// MustCreateSubdir refuses to reuse an existing entry.
	sweepStaleEngineRunDirs()

	name := runDirName(os.Getuid(), pid)
	planned, err := planPaths(pol, name)
	if err != nil {
		return nil, err
	}

	dirs, err := openRunDirs(os.TempDir(), name)
	if err != nil {
		return nil, err
	}
	runDir := dirs.path

	e := &Engine{
		// runLabel identifies THIS RUN rather than the store, and its
		// consumer is the PROXY, inbound: dockerproxy stamps it on every
		// container it creates and refuses a removal that names a container
		// carrying anyone else's (issue #339).
		//
		// RE-DERIVED. This used to say "teardown stops" and "Stop and the
		// reaper both filter on it" — false since issue #167 deleted the
		// host-side `podman stop`; teardown is pid-namespace collapse and
		// filters on nothing. It also rested on a CONCURRENT sibling sharing
		// the store, which issue #276 removed: engineKey is sha256(target)
		// alone and S = L exactly (paths.go), so at most one live run uses a
		// store. What the label separates is runs in TIME — the store
		// persists and teardown removes no container record, so a later run of
		// the same target opens a store holding every earlier run's.
		runLabel: fmt.Sprintf("%s=%d", RunLabelKey, pid),

		store:   planned.Store,
		dirs:    dirs,
		runDir:  runDir,
		runroot: planned.Runroot,
	}
	// The run directory is SPLIT by writability, not by topic (issue #125,
	// C2b). Everything in conf/ is a file snug generated and the engine only
	// ever READS; sock/ holds the one thing the engine creates.
	//
	// It exists for Tier C's derived view, where each of these becomes a graft
	// into the engine's own mount namespace and the graft carries an access:
	// without the split there is no directory that CAN be read-only, so the
	// AccessRO arm of the graft model would ship with nothing exercising it —
	// and §7's gate forbids emitting an AccessRO graft until a test proves it
	// is enforced. A model whose stricter half is never used is a model whose
	// stricter half is untested.
	//
	// It also makes a cost snug already states STRUCTURAL rather than merely
	// intended. writeAuthFile deliberately writes an EMPTY auth file, and its
	// own comment says "no registry login is possible from inside, so a
	// private image cannot be pulled". Under Tier C that file sits in a
	// read-only graft, so the sentence stops depending on nobody trying.
	//
	// Both are created with createRunDir rather than MkdirAll, so each gets the
	// same refuse-to-reuse, owner and 0700 checks the parent got — /tmp is
	// commonly world-writable and a pre-planted entry is the shape a same-host
	// attacker would use, and that reasoning does not weaken one directory
	// down.
	for _, split := range []struct {
		name string
		into *string
	}{{"sock", &e.sockDir}, {"conf", &e.confDir}} {
		root, path, err := dirs.sub(split.name)
		if err != nil {
			_ = dirs.remove()
			dirs.close()
			return nil, err
		}
		// The handle is not kept: nothing writes into these two through a
		// Root today (the socket is bound by podman, the config files are
		// written by path from generateConfigs), and a descriptor held for a
		// reader that does not exist is a fact nobody is checking — the shape
		// #103 found in runStateRoot. Verification of what was created is what
		// this call is for; #233 lists the writers as their own site.
		root.Close()
		*split.into = path
	}
	// The created paths must be the predicted ones. Not defensive: the whole
	// value of planPaths is that --dry-run shows what the run will use, and a
	// silent disagreement between the two would make that screen a lie about
	// the one graft set nobody can see any other way (issue #252).
	if e.sockDir != planned.SockDir || e.confDir != planned.ConfDir {
		_ = dirs.remove()
		dirs.close()
		return nil, fmt.Errorf("engine run directory: created %s and %s but planPaths predicted "+
			"%s and %s — --dry-run would name directories this run does not use",
			e.sockDir, e.confDir, planned.SockDir, planned.ConfDir)
	}
	e.sock = filepath.Join(e.sockDir, fmt.Sprintf("podman-%d.sock", pid))

	// The store and the runroot are the one place vdir's REUSE case applies
	// (SecureSubdir, not MustCreateSubdir): both are keyed by the target
	// alone, not by pid, so a warm start means a second run finds the first
	// run's store and reuses it, and the libpod database refuses a runroot
	// that disagrees with the one recorded in it. A refuse-to-reuse check
	// here would break the feature it is protecting.
	//
	// That reuse is exactly why this can no longer be a bare, first-writer-
	// wins os.MkdirAll(0o700): MkdirAll leaves an EXISTING directory's owner
	// and mode alone, so a shared, sticky /tmp that let something else plant
	// snug-engines-<uid>-<key> first (a symlink, or a directory some other
	// uid owns) went unnoticed forever — measured as part of issue #276's
	// part 3, sev:medium, because part 1 below made that name strictly MORE
	// predictable by removing the profile selection from engineKey's
	// preimage. verifyEngineStore/verifyEngineRunroot check owner and mode
	// EVERY time, reuse included, which is the property MkdirAll never had.
	//
	// e.runroot/tmp is created HERE rather than left to podman: it is
	// containers.conf's image_copy_tmp_dir (see writeContainersConf), and
	// podman STATS it rather than creating it — measured as `stat
	// /snug/engine/runroot/tmp: no such file or directory`, a 500 from every
	// build.
	dataHome, err := dataHomeDir()
	if err != nil {
		_ = dirs.remove()
		dirs.close()
		return nil, err
	}
	key := engineKey(pol)
	createdStore, breadcrumbWarning, err := verifyEngineStore(dataHome, key, pol.Target)
	if err != nil {
		_ = dirs.remove()
		dirs.close()
		return nil, err
	}
	e.BreadcrumbWarning = breadcrumbWarning
	createdRunroot, err := verifyEngineRunroot(key)
	if err != nil {
		_ = dirs.remove()
		dirs.close()
		return nil, err
	}
	// Same discipline as the sockDir/confDir check above, extended to the
	// other two grafts (issue #276): a silent disagreement here is exactly
	// what let sockDir/confDir go unchecked for a whole tier before issue
	// #252 named it, and part 3 gives the store and runroot a second way to
	// diverge (the vdir walk's own path arithmetic) that MkdirAll never had.
	if createdStore != planned.Store || createdRunroot != planned.Runroot {
		_ = dirs.remove()
		dirs.close()
		return nil, fmt.Errorf("engine store/runroot: created %s and %s but planPaths predicted "+
			"%s and %s — --dry-run would name directories this run does not use",
			createdStore, createdRunroot, planned.Store, planned.Runroot)
	}
	return e, nil
}

func (e *Engine) Socket() string { return e.sock }

// Store, Runroot, SockDir and ConfDir are the four host directories this run's
// engine works out of, and they are exported for ONE caller: the Tier C code
// that grafts each of them into the engine's derived view (internal/cli's
// engineview.go). They are deliberately not exported as a set or a struct —
// the graft of each carries its own access and its own abuse sentence, and a
// caller iterating a list would be a caller that writes one sentence for four
// different grants.
// guestPath is every path this file hands the ENGINE, put through the one
// question that matters once the engine's view is derived from the sandbox's:
// can the engine see it, and under what name?
//
// It is a thin wrapper on policy.EngineGuestPath and exists for the error, not
// for the mapping. A path no graft and no grant exposes is a REFUSAL that names
// the path and the variable it was about to be written into (invariant 5) —
// because the alternative is podman failing several layers down about a file
// that is not there, in a namespace nobody can look into, with nothing on
// screen connecting it to the boundary that removed it.
func (e *Engine) guestPath(pol *policy.Policy, what, host string) (string, error) {
	guest, ok := pol.EngineGuestPath(host)
	if !ok {
		return "", fmt.Errorf("the container engine cannot see %s (%s): nothing grafts it into "+
			"the engine's view and no grant of this sandbox exposes it.\n"+
			"       Since Tier C the engine's mount namespace is DERIVED from the sandbox's, so "+
			"a host path\n"+
			"       reaches it only through a graft — this is the boundary working, not a "+
			"missing file.", what, host)
	}
	return guest, nil
}

func (e *Engine) Store() string   { return e.store }
func (e *Engine) Runroot() string { return e.runroot }
func (e *Engine) SockDir() string { return e.sockDir }
func (e *Engine) ConfDir() string { return e.confDir }

// RunLabel is the `key=value` this run's containers are stamped with. The proxy
// applies it at create and refuses a removal naming another run's (issue #339);
// teardown filters on nothing, being pid-namespace collapse.
func (e *Engine) RunLabel() string { return e.runLabel }

// Spec builds the stage.EngineSpec that Stage.StartEngine consumes: exactly
// what this run's engine execs into, chosen entirely by P0. podman is the
// preflight-checked path to a real binary; baseEnv is the explicit, minimal
// environment the caller built — XDG_RUNTIME_DIR is added here, pointing at
// this run's own runroot, so the caller never has to know that path.
//
// baseEnv can no longer carry the engine's configuration. This comment used to
// name CONTAINERS_STORAGE_CONF as an example of "anything a pinned podman
// bundle needs", and that sentence WAS the defect issue #125 closed: it left the
// storage configuration to whatever the caller or the host supplied, so on a
// host with a pinned bundle the file in play was the bundle's. Spec now writes
// and points at that file itself, and every one of these variables is SET rather
// than appended (see setEnv), so a caller still passing one loses. PATH was
// already in that position for the same reason (issue #125's C2-path).
//
// HOME is Spec's, not the caller's, and so are CONTAINERS_REGISTRIES_CONF and
// REGISTRY_AUTH_FILE: everything podman reads out of a home directory is a
// second author of what a container IS or what it may authenticate as
// (issues #137, #142), and the files those variables point at are generated
// here beside the containers.conf below. Every one of them is SET rather than
// appended (see setEnv), because a duplicate loses to the caller's entry and
// the only symptom would be the feature not being there.
//
// cgroupsDisabled is preflight P5's own
// measured selection (ENGINE-WIRING.md §4): when this host's cgroup
// delegation does not survive even the private cgroup namespace __inengine's
// own fork creates, podman needs `cgroups = "disabled"` as its DEFAULT for
// every container it creates. That is a containers.conf setting, not an argv
// flag on `system service` — so it is GENERATED into a file under this run's
// own /tmp directory and pointed at by CONTAINERS_CONF, never handed over
// inline (the same "pointer, not inline value" rule CLAUDE.md states for
// GIT_CONFIG_GLOBAL, PIP_CONFIG_FILE and friends).
//
// Spec used to also remember podman and the final env on the Engine itself,
// so Stop's own host-side `podman stop` could use the IDENTICAL values —
// removed along with that invocation (issue #167): podman and baseEnv are
// consumed here and handed to the returned EngineSpec, which is all a caller
// needs.
//
// The engine's own /etc/resolv.conf needs nothing from this function since
// Tier C: its view is DERIVED from the sandbox's, so the file it reads is the
// one snug generated for the payload (policy.NetPolicy.ResolvConf), already
// mounted there. The bind that used to put it in place is gone with the host
// tree it existed to shadow — see __inengine's own note where step 11 was.
// What a CONTAINER gets is decided by the generated containers.conf and needs
// no mount at all (issue #126).
func (e *Engine) Spec(pol *policy.Policy, podman string, baseEnv []string, cgroupsDisabled bool, ociRuntime, ociRuntimePath string, sig *SignaturePolicy) (stage.EngineSpec, error) {
	if sig == nil {
		// A caller that skipped ProjectHostSignaturePolicy. Answering with a
		// permissive default here is precisely the fallback clause 3 forbids,
		// so it is an error naming the missing call instead — the same shape
		// checkEnginePATH uses for a policy with no grafts.
		return stage.EngineSpec{}, errors.New("the container engine's signature policy was " +
			"never projected: engine.ProjectHostSignaturePolicy must run before Spec, and " +
			"before engine.New, so that a host policy snug cannot reproduce refuses the run " +
			"before anything is created")
	}
	net := pol.Net

	// EVERY path below goes through guestPath. The engine's view is the
	// sandbox's plus this run's grafts (issue #125, Tier C), so a host path in
	// its argv, its environment or a configuration file it reads is a path
	// that resolves to nothing — or, worse, to something else with the same
	// name. The mapping is not cosmetic: it is the difference between naming
	// the store and naming a directory the payload could have created.
	guestRunroot, err := e.guestPath(pol, "$XDG_RUNTIME_DIR (the engine's runroot)", e.runroot)
	if err != nil {
		return stage.EngineSpec{}, err
	}
	finalEnv := setEnv(append([]string{}, baseEnv...), "XDG_RUNTIME_DIR", guestRunroot)

	// The engine's PATH is snug's, never the host's (issue #125). Under a
	// DERIVED mount view the host's PATH elements under $HOME are the
	// payload's own writable tmpfs (@home), so handing a caller-supplied PATH
	// to a process that is root-in-U with CAP_SYS_ADMIN and the full
	// delegated subuid range is handing the payload a shadow slot in front of
	// crun. Measured on the development host, os.Getenv("PATH") led with
	// /home/<user>/bin and contained .local/bin, .cargo/bin, go/bin and an
	// EMPTY element (= cwd) — every one of them writable by the payload.
	// /bin and /sbin are @sys's own symlinks into /usr, so all four elements
	// below resolve inside the same read-only bind. setEnv REPLACES rather
	// than appends, so a caller-supplied PATH in baseEnv cannot win.
	//
	// Pinning it is half the property; the other half is that the four
	// elements really are read-only IN THE ENGINE'S OWN VIEW, which is a
	// question about this run's resolved policy and not about the literal.
	// checkEnginePATH asks it.
	if err := checkEnginePATH(pol); err != nil {
		return stage.EngineSpec{}, err
	}
	finalEnv = setEnv(finalEnv, "PATH", PinnedPATH)

	// TMPDIR, and it is Tier C's key as much as image_copy_tmp_dir is.
	// containers/storage falls back to /var/tmp for the temporary directory it
	// creates while COMMITTING a layer, and reads TMPDIR first. The engine's
	// derived view has no /var/tmp — measured twice, once as a 500 from every
	// build and again, after image_copy_tmp_dir was set, from the commit step
	// alone, which is the half that config key does not cover.
	//
	// Same directory as image_copy_tmp_dir: this run's own runroot, writable,
	// grafted, and gone when the run's directories are.
	guestTmpDir, err := e.guestPath(pol, "$TMPDIR", filepath.Join(e.runroot, "tmp"))
	if err != nil {
		return stage.EngineSpec{}, err
	}
	finalEnv = setEnv(finalEnv, "TMPDIR", guestTmpDir)

	// HOME is snug's, not the host user's (issues #137, #142). Everything
	// podman reads out of a home directory — registries.conf, policy.json,
	// storage.conf, auth.json — is then a file this run authored or a file
	// that does not exist. The two channels that have an environment
	// variable of their own are ALSO pointed at explicitly below, because
	// which home a rootless podman believes in is a version-dependent
	// question (see writeEngineHome) and an environment variable is not.
	engineHome, err := e.writeEngineHome(pol, sig)
	if err != nil {
		return stage.EngineSpec{}, err
	}
	guestHome, err := e.guestPath(pol, "$HOME (the engine's own home)", engineHome)
	if err != nil {
		return stage.EngineSpec{}, err
	}
	finalEnv = setEnv(finalEnv, "HOME", guestHome)

	registriesPath, err := e.writeRegistriesConf()
	if err != nil {
		return stage.EngineSpec{}, err
	}
	guestRegistriespath, err := e.guestPath(pol, "$CONTAINERS_REGISTRIES_CONF", registriesPath)
	if err != nil {
		return stage.EngineSpec{}, err
	}
	finalEnv = setEnv(finalEnv, "CONTAINERS_REGISTRIES_CONF", guestRegistriespath)

	authPath, err := e.writeAuthFile()
	if err != nil {
		return stage.EngineSpec{}, err
	}
	guestAuthpath, err := e.guestPath(pol, "$REGISTRY_AUTH_FILE", authPath)
	if err != nil {
		return stage.EngineSpec{}, err
	}
	finalEnv = setEnv(finalEnv, "REGISTRY_AUTH_FILE", guestAuthpath)

	// SET, not left to the caller, and that is the change (issue #125). This
	// variable used to be one of the "anything a pinned engine bundle needs"
	// entries a caller supplied, so on a host with a bundle the storage
	// configuration in play was the BUNDLE's — naming its own graphroot,
	// runroot and mount_program. setEnv replaces rather than appends, so a
	// caller that still passes one loses to this, which is the direction that
	// makes the guarantee hold rather than the one that makes it polite.
	//
	// The variable replaces the file set: with it pointed here, podman opens no
	// /etc/containers/storage.conf, no $HOME one and no storage.conf.d drop-in
	// (STORAGE-CONF.md §2, measured on podman 5.8.4 and 6.0.2).
	//
	// What it carries is narrower than it reads, and the narrowing comes from
	// this run's own argv: --root/--runroot below pin graphroot and runroot
	// anyway, and they discard every [storage.options*] key in whatever file
	// this variable names (§3). The residual it alone is responsible for is
	// `driver` and the remaining [storage] scalars. That is also why no
	// CONTAINERS_STORAGE_CONF_OVERRIDE stands beside it the way one stands
	// beside CONTAINERS_CONF: a later export of this variable still loses the
	// store location to the flags, and its options to the same discard.
	storagePath, err := e.writeStorageConf(pol, podman)
	if err != nil {
		return stage.EngineSpec{}, err
	}
	guestStoragepath, err := e.guestPath(pol, "$CONTAINERS_STORAGE_CONF", storagePath)
	if err != nil {
		return stage.EngineSpec{}, err
	}
	finalEnv = setEnv(finalEnv, "CONTAINERS_STORAGE_CONF", guestStoragepath)

	confPath, err := e.writeContainersConf(pol, podman, cgroupsDisabled, ociRuntime, ociRuntimePath, net.Resolver())
	if err != nil {
		return stage.EngineSpec{}, err
	}
	// BOTH variables, and they are not redundant. CONTAINERS_CONF REPLACES
	// the host's /etc/containers/containers.conf and
	// $HOME/.config/containers/containers.conf, which is the structural half:
	// keys snug never thought to name cannot reach the engine at all.
	// CONTAINERS_CONF_OVERRIDE is loaded LAST, after everything else, which is
	// the half that survives a later export of CONTAINERS_CONF by something
	// between here and the engine (issue #133 is exactly that, in the test
	// wrapper). Setting only the first is defeated by such an export; setting
	// only the second leaves the host's files loaded underneath and reduces
	// the guarantee to "every key snug remembered to enumerate".
	guestConfPath, err := e.guestPath(pol, "$CONTAINERS_CONF", confPath)
	if err != nil {
		return stage.EngineSpec{}, err
	}
	finalEnv = setEnv(finalEnv, "CONTAINERS_CONF", guestConfPath)
	finalEnv = setEnv(finalEnv, "CONTAINERS_CONF_OVERRIDE", guestConfPath)

	guestStore, err := e.guestPath(pol, "--root (the image store)", e.store)
	if err != nil {
		return stage.EngineSpec{}, err
	}
	guestSock, err := e.guestPath(pol, "the socket the engine listens on", e.sock)
	if err != nil {
		return stage.EngineSpec{}, err
	}
	// RECORDED FOR TEARDOWN, here and nowhere else: this is the spelling the
	// engine's own command line will carry, so it is the only string a sweep
	// over /proc can match (reap.go, issue #344).
	e.guestSock = guestSock
	guestPodman, err := e.guestPath(pol, "the engine binary", podman)
	if err != nil {
		return stage.EngineSpec{}, err
	}

	argv := []string{
		"--root", guestStore,
		"--runroot", guestRunroot,
		// NOT --time 0. The idle timeout is the engine's own "my client went
		// away", and the lifeline (lifeline.go) is what keeps it from firing
		// while the sandbox lives.
		"system", "service", "--time", strconv.Itoa(int(idleTimeout.Seconds())),
		"unix://" + guestSock,
	}

	// Podman and Argv are what the ENGINE is exec'd with, so they are guest
	// paths. Sock is what P1 WAITS for on the host side (enginefork.go's
	// waitForSocket) and what the container proxy dials, so it stays the host
	// path — the same inode reached under two names, which is the whole point
	// of a graft and the one place this file must not "tidy" them into one.
	return stage.EngineSpec{
		Podman: guestPodman, Argv: argv, Env: finalEnv, Sock: e.sock,
		Grafts: engineGrafts(pol),
	}, nil
}

// engineGrafts flattens the resolved policy's HOST-tree grafts into what the
// stage needs to build them. Read out of p.Grafts rather than rebuilt from the
// paths this file knows: the model is the author of the engine's view
// (invariant 6), and a second list here would be a second author that agrees
// until the day it does not.
//
// The fresh-mount kinds are deliberately absent — the stage MOUNTS /proc,
// /sys/fs/cgroup and /run itself, and they carry no Host to clone. They are in
// p.Grafts for the model's sake (issue #125 §9.2) and would be a source of
// nothing here.
func engineGrafts(pol *policy.Policy) []stage.EngineGraft {
	guests := make([]string, 0, len(pol.Grafts))
	for guest, g := range pol.Grafts {
		if g.Kind != policy.KindGraft || g.Host == "" {
			continue
		}
		guests = append(guests, guest)
	}
	sort.Strings(guests)
	out := make([]stage.EngineGraft, 0, len(guests))
	for _, guest := range guests {
		g := pol.Grafts[guest]
		out = append(out, stage.EngineGraft{
			Host: g.Host, Guest: g.Guest, ReadOnly: g.Access != policy.AccessRW,
		})
	}
	return out
}

// writeContainersConf generates THE containers.conf this run's engine reads —
// the only one, because Spec points both CONTAINERS_CONF and
// CONTAINERS_CONF_OVERRIDE at it. It lives under this run's own (already
// hardened, 0700, host-uid-owned) /tmp directory, and it is a POINTER handed
// over as an environment variable, never an inline value: the same rule
// CLAUDE.md states for GIT_CONFIG_GLOBAL, PIP_CONFIG_FILE and friends.
//
// Three separate jobs, in one file because podman gives us one file:
//
//  1. cgroupsDisabled — preflight P5's measured selection (ENGINE-WIRING.md
//     §4). A containers.conf setting, not an argv flag on `system service`,
//     which is why this file existed before the other two jobs did.
//
//  2. DNS and hosts (issue #126). podman generates every container's
//     /etc/resolv.conf FROM the engine's own unless containers.conf names DNS
//     explicitly, and its /etc/hosts from the host's /etc/hosts unless
//     base_hosts_file says otherwise — so without these keys an OFFLINE
//     sandbox's container still learned the host LAN's nameservers, search
//     domain and hostname table. Neither is a client-requested mount, so the
//     proxy's bind filter (internal/dockerproxy/create.go) never sees them
//     and --dry-run never mentions them. Configuration rather than the
//     resolv.conf bind alone because the bind is best-effort: it needs a
//     mount over the engine's /etc/resolv.conf to succeed, which issue #128
//     measured can fail on a perfectly ordinary host, and a container must
//     not learn host DNS just because a mount did not take.
//
//  3. The keys a host containers.conf would otherwise have supplied (issue
//     #132) — mounts/volumes inject host PATHS, devices injects a host device
//     NODE, env injects variables and env_host passes the engine's whole
//     environment, hooks_dir names PROGRAMS run on every container's
//     lifecycle. All of them on EVERY container and none of them
//     client-requested. CONTAINERS_CONF already stops those files being read
//     at all; naming the keys anyway is CLAUDE.md's "never trust a helper's
//     default, in either direction".
//
//  4. The container network namespace (issue #401). podman's own default
//     moved under us between 5.8.4 and 6.0.2 — the former left a build's RUN
//     step in the engine's netns, the latter gives it a fresh one, and a
//     fresh netns needs CAP_NET_ADMIN to bring lo up, which
//     policy.EngineCapBounding withholds on purpose (2026-08-18). Pinning
//     netns = "host" is a decided policy choice, not a default this file
//     merely states: it commits every container to the engine's own network
//     namespace, which since Tier B is this sandbox's, rather than leaving
//     the choice to whichever podman happens to be installed.
//
//     BE PRECISE ABOUT WHAT THAT SECOND LINE OF DEFENCE COVERS, because the
//     first version of this comment claimed more than the code delivered and
//     a red-team pass measured the gap. The enumeration is NOT the complete
//     set of containers.conf keys that reach a container. It is the set that
//     can be closed WITHOUT choosing a value on podman's behalf.
//     default_capabilities, default_sysctls, default_ulimits, seccomp_profile
//     and userns are deliberately absent: emptying or pinning any of them
//     overrides podman's own default for every container, which is a policy
//     decision this file must not make silently. netns used to belong on
//     this list too — it is no longer absent, because issue #401 is exactly
//     that decision being made, deliberately and with a comment saying so,
//     rather than left to whichever podman default currently happens to work.
//
//     For those keys the guarantee is now MEASURED, not assumed.
//     CONTAINERS_CONF REPLACES the host's writable config layers, it does not
//     merge them (issue #136): measured on podman 5.8.4 with an invalid-TOML
//     probe — a broken ~/.config/containers/containers.conf IS read when
//     nothing sets CONTAINERS_CONF and is IGNORED when this file does, so a
//     hostile ~/.config or /etc config injects none of these keys, enumerated
//     or not. default_capabilities is bounded a SECOND way regardless of any
//     config: a container's DELIVERED set is its own default INTERSECTED with
//     policy.EngineCapBounding — measured 0x802405fb, the full 12-cap set, for
//     `CapAdd:["ALL"]` (issue #146).
//
//     That bounds the DELIVERED set only; it is NOT a ceiling on what a
//     container can HOLD, and an earlier version of this comment called it one
//     ("the capability ceiling answers that key by construction even if it
//     leaked" — issue #412). A container that unshares its own userns resets
//     the bounding set to full — measured, crun 1.28: delivered CapPrm
//     00000000800405fb, then 000001ffffffffff with CAP_NET_ADMIN after
//     `unshare -U -r`, which works only because CAP_SETFCAP is in the
//     delivered set (a CAP_CHOWN-only container fails at `write
//     /proc/self/uid_map: Operation not permitted`). That was crun with NO
//     seccomp profile in the bundle; podman would add one, and this host's
//     /usr/share/containers/seccomp.json allows clone/clone3/unshare with
//     `args: []` and no CLONE_NEWUSER mask, so it would not close it here
//     either — but the two were NOT measured together.
//
//     Why that is a defect in the sentence and not an escape: the regained
//     caps are namespace-relative. Measured from root in a child userns U'
//     with CapEff 000001ffffffffff, still in N — SIOCSIFFLAGS(lo,DOWN) EPERM,
//     setns(inherited netns fd, CLONE_NEWNET) EPERM, where the same fd and
//     syscall from a process that stayed in U succeed. So state the guarantee
//     precisely: the engine's own process in U, and any descendant that stays
//     in U, cannot reconfigure N. It is not a global denial of a capability to
//     everything the engine runs.
//
//     ONE layer is REASONED, not measured, and named here so a future reader
//     does not re-derive it wrongly: /usr/share/containers/containers.conf is
//     podman's always-read base, and its
//     default_sysctls=["net.ipv4.ping_group_range=0 0"] is containers/common's
//     OWN documented default (its config comment gives that exact value as the
//     example), present on every podman with or without a config — not an
//     injection, root-owned, outside the payload-writable threat this file
//     guards. Whether CONTAINERS_CONF suppresses /usr/share too is UNMEASURED
//     (it is root-owned, so the invalid-TOML probe cannot touch it); it does
//     not change the answer, because /usr/share is trusted.
//
//     What the enumeration IS worth was measured, against a hostile
//     containers.conf on CONTAINERS_CONF and this file on
//     CONTAINERS_CONF_OVERRIDE: `env = ["INJECTED_BY_CONF=leaked"]` reaches a
//     container when nothing closes it, and does not when `env = []` is
//     written here. That is the merge-future this list exists for, and it is
//     also the shape the test wrapper already produces today (issue #133).
//
// res is policy.NetPolicy.Resolver() — the SAME derivation the sandbox
// payload's own /etc/resolv.conf comes from, taken as VALUES rather than by
// parsing the rendered file back, so the two cannot diverge (invariant 6).
func (e *Engine) writeContainersConf(pol *policy.Policy, podman string, cgroupsDisabled bool, ociRuntime, ociRuntimePath string, res policy.ResolverConfig) (string, error) {
	path := filepath.Join(e.confDir, "containers.conf")

	var b strings.Builder
	b.WriteString("# snug: generated for this run. Pointed at by both CONTAINERS_CONF and\n" +
		"# CONTAINERS_CONF_OVERRIDE, so this is the ONLY containers.conf the engine reads:\n" +
		"# the host's /etc/containers/containers.conf and ~/.config/containers/containers.conf\n" +
		"# are not merged in (issue #132).\n" +
		"[containers]\n")

	if cgroupsDisabled {
		// The `runtime` key in the [engine] block below is the other half of
		// this one and is never absent when this is present (P10). runc does
		// not implement this mode, so writing it without naming a runtime
		// that does is what produced a container API that failed at create.
		b.WriteString("\n# preflight P5 measured that this host's cgroup delegation does not survive\n" +
			"# even the engine's own private cgroup namespace.\n" +
			"cgroups = \"disabled\"\n")
	}

	// dns_servers is never written EMPTY: podman reads an empty list as "not
	// configured" and falls back to the engine's own /etc/resolv.conf, which
	// is precisely the leak this closes. Offline therefore names a server
	// that cannot resolve anything instead of naming none — measured against
	// podman 5.8.4, which writes it through literally, so the container's
	// resolver has an unusable nameserver and fails fast rather than
	// inheriting the host's. Assert the EFFECT (no host resolver reaches a
	// container) rather than this file's bytes: a podman that starts treating
	// "none" as "no nameservers at all" satisfies the same requirement.
	servers := res.Servers
	if len(servers) == 0 {
		servers = []string{"none"}
	}
	b.WriteString("\n# DNS, from the resolved policy (issue #126) — the same derivation the\n" +
		"# sandbox payload's own /etc/resolv.conf comes from.\n")
	fmt.Fprintf(&b, "dns_servers = %s\n", tomlStringList(servers))
	// All three keys, as a set. dns_servers alone still leaked the host's
	// search domain, measured: podman copies `search` from the engine's own
	// resolv.conf when dns_searches does not name one.
	fmt.Fprintf(&b, "dns_searches = %s\n", tomlStringList(res.Searches))
	fmt.Fprintf(&b, "dns_options = %s\n", tomlStringList(res.Options))

	b.WriteString("\n# The host's /etc/hosts is a hostname table for the host's networks, and\n" +
		"# podman copies it into every container by default (issue #126).\n" +
		"base_hosts_file = \"none\"\n")

	// The container network namespace, pinned rather than left to podman's
	// default (issue #401). "host" in a containers.conf read by THIS engine
	// does not mean the machine: the engine runs inside this sandbox's own
	// network namespace N since issue #63 Tier B, so it means N — the same
	// place HostConfig.NetworkMode="host" lands a container
	// (internal/dockerproxy/create.go's inversion), and the only network a
	// container in this tier can have. Any other mode gives the container a
	// netns OF ITS OWN, which needs CAP_NET_ADMIN in that namespace;
	// policy.EngineCapBounding withholds it on purpose, so the container
	// dies at `ioctl SIOCSIFFLAGS: Operation not permitted` (crun) or
	// `netavark: Netlink error: Operation not permitted` (libpod) before it
	// runs a byte. Assert the EFFECT — a container that asks for nothing
	// shares the sandbox's network namespace — rather than this file's
	// bytes: a podman that reaches the same place by another key satisfies
	// the same requirement, and a podman that ignores this one passes a grep
	// of the generated file while every build stays broken.
	//
	// Podman's default moved under us, which is why this is written at all:
	// 5.8.4's default put a build's RUN step in N, 6.0.2's gives it one of
	// its own, and nothing here said which we wanted (CLAUDE.md, "never
	// trust a helper's default, in either direction"). MEASURED on both.
	//
	// This binds only a request nobody made. An explicit mode still wins:
	// NetworkMode="bridge" and a build's networkmode=1 both override this
	// and both still fail — build.go's allowlist is what refuses them, and
	// it is not made redundant by this line.
	b.WriteString("\n# Containers join the ENGINE's network namespace, which is THIS sandbox's\n" +
		"# own (issue #401). \"host\" here is not the machine's network.\n" +
		"netns = \"host\"\n")

	b.WriteString("\n# Nothing is mounted, no device is passed, no environment is inherited or\n" +
		"# injected, and no lifecycle hook runs, except what a client asks for and the\n" +
		"# proxy's own filter then allows (issue #132).\n" +
		"mounts = []\n" +
		"volumes = []\n" +
		"devices = []\n" +
		"env = []\n" +
		"env_host = false\n" +
		"http_proxy = false\n" +
		"annotations = []\n" +
		"privileged = false\n")

	// hooks_dir is an [engine] key, NOT a [containers] one, and it spent one
	// commit in the wrong table where podman silently ignored it — an unknown
	// key in containers.conf is not an error, so the only symptom of writing
	// it in the wrong place is the feature not being there. It names
	// DIRECTORIES OF PROGRAMS the OCI runtime executes for every container,
	// which is a command table rather than data, so it is the one key in this
	// file whose misplacement would have mattered most.
	// image_copy_tmp_dir, and it is Tier C's own key rather than a hardening
	// one. MEASURED: a build through the proxy returned 500 with `stat
	// /var/tmp: no such file or directory` — buildah's default scratch space
	// is /var/tmp, and the engine's DERIVED view has no /var/tmp, because the
	// sandbox has none. #125's design pass predicted both the failure and the
	// answer: /var/tmp is one of the three paths it named as "not grafts,
	// deliberately... the answer is configuration, not reshaping the
	// filesystem".
	//
	// It points inside the RUNROOT graft, which is this run's own writable
	// host directory: the engine can create it, it dies with the run's own
	// cleanup rather than accumulating under /var/tmp, and it is a path no
	// profile can name and the payload cannot reach.
	guestTmp, err := e.guestPath(pol, "containers.conf image_copy_tmp_dir", filepath.Join(e.runroot, "tmp"))
	if err != nil {
		return "", err
	}
	quotedTmp, err := tomlString(guestTmp)
	if err != nil {
		return "", fmt.Errorf("containers.conf image_copy_tmp_dir: %w", err)
	}
	b.WriteString("\n[engine]\n" +
		"# Scratch space for image copies. The default is /var/tmp, which the\n" +
		"# engine's derived view does not have (issue #125, measured as a 500\n" +
		"# from every build); this is inside the runroot snug grafts for it.\n" +
		"image_copy_tmp_dir = " + quotedTmp + "\n" +
		"# Directories of programs run for every container. A command table,\n" +
		"# not data (issue #132).\n" +
		"hooks_dir = []\n" +
		"\n" +
		"# Belt and braces on top of Spec's pinned PATH (issue #125): PATH is not\n" +
		"# podman's only lookup for conmon/crun/newuidmap and friends, so name the\n" +
		"# search list explicitly rather than let it fall back to inheritance.\n" +
		"helper_binaries_dir = [" + helperBinariesDirs() + "]\n")

	// runtime is an [engine] key and MUST be written inside this block: an
	// unknown key in containers.conf is not an error, so the same line under
	// [containers] would be silently ignored while every Contains assertion
	// still passed. hooks_dir sat in the wrong table for a milestone for
	// exactly that reason.
	//
	// Empty means "author nothing", which is the ordinary case: where cgroups
	// work, both crun and runc serve, and choosing between them here would
	// pin a runtime on hosts that do not need one pinned. Non-empty is P10's
	// answer and only ever "crun" — see preflightOCIRuntime, which owns the
	// decision and REFUSES the run rather than letting this be empty while
	// cgroups = "disabled" is written above.
	//
	// runtime_supports_nocgroups is deliberately NOT authored, in any arm.
	// Adding runc to it tells podman runc implements a mode it does not, which
	// converts a clean refusal into undefined behaviour. Nor is cgroups =
	// "disabled" ever dropped in favour of runc: that discards P5's
	// measurement and moves the failure to the first controller write.
	if ociRuntime != "" {
		quotedRuntime, err := tomlString(ociRuntime)
		if err != nil {
			return "", fmt.Errorf("containers.conf runtime: %w", err)
		}
		b.WriteString("# The only runtime that implements the cgroups = \"disabled\" mode\n" +
			"# selected above (preflight P10).\n" +
			"runtime = " + quotedRuntime + "\n")

		// [engine.runtimes] names the FILE, not just the name, and it is a
		// SUBTABLE so it goes last — every scalar [engine] key above it would
		// otherwise land inside it.
		//
		// Naming the path is what stops podman's own runtime search list being
		// a second author of this decision. The two lists genuinely differ:
		// P10's predicate stats podmanHelperDirs(), which includes
		// /usr/libexec/podman and friends, and podman does NOT search those for
		// a runtime — they are the HELPER lookup, which helper_binaries_dir
		// above covers, and a runtime is not a helper. A crun found only there
		// would otherwise have snug authoring a name podman cannot resolve.
		// Copying podman's list into snug was the alternative and is worse: a
		// copy of state that drifts silently on a podman upgrade.
		if ociRuntimePath != "" {
			quotedPath, err := tomlString(ociRuntimePath)
			if err != nil {
				return "", fmt.Errorf("containers.conf engine.runtimes: %w", err)
			}
			b.WriteString("\n[engine.runtimes]\n" +
				"# The file P10 actually found, so podman resolves this run's runtime\n" +
				"# from snug's answer rather than from its own search list.\n" +
				ociRuntime + " = [" + quotedPath + "]\n")
		}
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// tomlString renders one TOML basic string, and RETURNS AN ERROR rather than
// substituting a placeholder.
//
// It said "REFUSES rather than escapes" while doing neither: it returned
// `"snug-refused-unquotable-value"`, a perfectly valid TOML string, and its
// caller had an error return it did not use. That is invariant 5's silent
// downgrade, and the values are NOT unreachable — e.runroot and e.sock come
// from os.TempDir() ($TMPDIR), e.store from $XDG_DATA_HOME or $HOME, and
// mount_program from the resolved engine path. Measured with a quote in
// $TMPDIR: the argv carried the real runroot while storage.conf carried the
// placeholder, with no error, which is exactly the config-versus-argv
// divergence writeStorageConf's own comment calls not cosmetic. For
// mount_program, which has no argv duplicate, the engine would exec a relative
// name and die with the "can't stat program" failure the derivation exists to
// prevent.
//
// A quote is the hazard that matters: it closes the string early and the rest
// of the line is read as TOML, silently authoring settings nobody wrote.
func tomlString(v string) (string, error) {
	if strings.ContainsAny(v, "\"\\\n\r\x00") {
		return "", fmt.Errorf("cannot render %q as a TOML string: it contains a quote, a "+
			"backslash or a control character, which would close the string early and let the "+
			"rest of the line be read as configuration.\n"+
			"       This path comes from the environment snug was started with ($TMPDIR, "+
			"$XDG_DATA_HOME or $SNUG_PODMAN); use one without those characters.", v)
	}
	return fmt.Sprintf("%q", v), nil
}

// tomlStringList renders a TOML array of basic strings. The values it is given
// are addresses, `.` and resolver options that policy.NetPolicy produced, none
// of which can contain a quote or a backslash; it refuses rather than escaping
// so that a future caller with untrusted values does not get a silently
// mangled config file.
func tomlStringList(vs []string) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, v := range vs {
		if i > 0 {
			b.WriteString(", ")
		}
		if strings.ContainsAny(v, "\"\\\n\r\x00") {
			// Unreachable from policy.NetPolicy today; see the doc comment.
			v = "snug-refused-unquotable-value"
		}
		fmt.Fprintf(&b, "%q", v)
	}
	b.WriteByte(']')
	return b.String()
}

// setEnv sets one variable in a `KEY=VALUE` environment, REPLACING an
// existing entry rather than appending a second one.
//
// Appending is what this used to do, and it is wrong for a variable a caller
// might also have set: execve preserves duplicates in order and glibc's
// getenv returns the FIRST match, so an appended override is silently the
// loser. The failure mode is the one CLAUDE.md warns about — the flag is
// present in the argv (here: the variable is present in the environment) and
// the feature is not there.
func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

// writeEngineHome creates the home directory this run's engine is given
// INSTEAD of the host user's, and returns its path.
//
// The host's home is a second author of what a container IS (issue #137).
// CONTAINERS_CONF closed containers.conf outright, but podman reads more than
// one file out of a home directory and the rest have no such variable:
//
//   - $HOME/.config/containers/policy.json — the signature policy. It decides
//     whether an image may be used at all, it is REQUIRED (podman refuses to
//     pull without one), and it is the one file here with NO environment
//     variable and no flag that reaches it: MEASURED on podman 5.8.4,
//     --signature-policy is a HIDDEN flag on `pull` and `push` and exists on
//     neither `system service` nor the global command, so it cannot reach the
//     API-driven pull the container proxy makes (signaturepolicy.go, same
//     package, carries the same measurement). Stated PER SUBCOMMAND because
//     the flat version — "no --signature-policy at all" — is what let a false
//     claim stand next to the true one. A
//     home of our own is the only lever, which is the same conclusion
//     the research measurements reached independently. What that lever
//     carries is the HOST's own policy, projected — signaturepolicy.go — so
//     taking the file over is a change of author and not of posture.
//   - $HOME/.config/containers/registries.conf — where an image comes from.
//     Also closed by CONTAINERS_REGISTRIES_CONF below; both, for the reason
//     the next paragraph gives.
//   - $HOME/.config/containers/auth.json and $HOME/.docker/config.json — the
//     host user's REGISTRY CREDENTIALS (issue #142). Also closed by
//     REGISTRY_AUTH_FILE below.
//   - $HOME/.config/containers/storage.conf — where the store is. Already
//     overridden by the explicit --root/--runroot in the argv.
//
// BE PRECISE ABOUT WHAT THIS LEVER IS WORTH, because it is the weakest of the
// three used here. MEASURED against podman 5.8.4 (the pinned bundle this
// host gives snug through $SNUG_PODMAN): with the host's HOME the engine
// resolved a live credential out of ~/.docker/config.json, and with a home of
// its own it resolved none. But a rootless podman is free to derive "the
// user's home" from the passwd entry rather than from $HOME, in which case
// this closes nothing on that version — which is exactly why policy.json's
// two neighbours are ALSO pointed at by their own environment variables. The
// residual, stated plainly: on such a podman the host's policy.json is still
// read directly. That one costs nothing now that the generated file is a
// projection of it — the two agree, or the run has already refused. Nothing
// else survives.
func (e *Engine) writeEngineHome(pol *policy.Policy, sp *SignaturePolicy) (string, error) {
	home := filepath.Join(e.confDir, "home")
	containersDir := filepath.Join(home, ".config", "containers")
	if err := os.MkdirAll(containersDir, 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", containersDir, err)
	}

	// The signature policy is a PROJECTION of the host's, not a value this file
	// holds (signaturepolicy.go). It arrives already read and already
	// classified: everything that can refuse refused in
	// ProjectHostSignaturePolicy, which the caller runs BEFORE engine.New, so a
	// host policy snug cannot reproduce leaves no run directory behind and no
	// copy of a host key in /tmp. All that is left here is writing.
	if err := sp.write(e.confDir, containersDir, func(what, host string) (string, error) {
		return e.guestPath(pol, what, host)
	}); err != nil {
		return "", err
	}
	return home, nil
}

// writeRegistriesConf generates the registries.conf this run's engine reads,
// and returns its path for CONTAINERS_REGISTRIES_CONF.
//
// What a host registries.conf authors is IMAGE PROVENANCE, which is a
// different question from every other key snug has taken over so far:
// `unqualified-search-registries` decides what a bare `alpine:3.20` resolves
// to, and `[[registry]]` + `[[registry.mirror]]` redirect a FULLY QUALIFIED
// pull somewhere else entirely. So a file snug did not write decided which
// bytes became the image a container ran, and neither --dry-run nor the
// proxy's bind filter said a word about it (issue #137).
//
// The value is podman's own upstream default and nothing else. That is a
// deliberate choice between two defensible ones:
//
//   - EMPTY (no search registry) is the deny-by-default reading: a bare name
//     resolves to nothing, every image must be named in full. It is more in
//     keeping with the guiding principle, and it breaks `FROM alpine` in
//     every Dockerfile the sandbox builds.
//   - docker.io, written here, reproduces what a stock podman on a stock host
//     does. It is not a widening of anything: the alternative to snug naming
//     docker.io is the HOST file naming docker.io, which is what happens
//     today.
//
// The second was chosen because the security difference between them is
// small — either way the answer is deterministic and no longer the host's —
// while the ergonomic difference is not. It is one line to change, and
// --dry-run states the value, so nobody has to read this file to find out
// what a short name means inside.
//
// No [[registry]] block is written at all, so no mirror, no rewrite and no
// insecure (non-TLS) registry can be reached through configuration this run
// authored.
func (e *Engine) writeRegistriesConf() (string, error) {
	path := filepath.Join(e.confDir, "registries.conf")
	const content = `# snug: generated for this run. Pointed at by CONTAINERS_REGISTRIES_CONF, so
# the host's /etc/containers/registries.conf and
# ~/.config/containers/registries.conf are not read (issue #137).
#
# podman's own default, chosen so that a short image name means the same thing
# inside the sandbox as it does on a stock host — with snug as the author of
# that fact rather than a file snug does not control. No [[registry]] block:
# no mirror, no rewrite, no insecure registry.
unqualified-search-registries = ["docker.io"]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// writeStorageConf generates the container STORAGE configuration this run's
// engine reads, and returns its path for CONTAINERS_STORAGE_CONF.
//
// It is the third file to move from "whatever the host or the bundle happens
// to have" to "a file this run authored", after containers.conf (issue #133)
// and registries.conf (issue #137), and the argument is the same one a third
// time: a config file snug merely POINTS AT is someone else deciding on snug's
// behalf. What makes it load-bearing rather than tidy is Tier C (issue #125):
// under a derived mount view every path a config names has to be a path that
// still exists in that view, and snug cannot move a path it does not author.
//
// Until now CONTAINERS_STORAGE_CONF was caller-supplied — Spec's own doc
// comment says so ("anything a pinned podman bundle needs, e.g.
// CONTAINERS_STORAGE_CONF") — so on a host with a pinned bundle the file in
// play was the BUNDLE's, naming the bundle's own graphroot, runroot and
// mount_program. Every one of those is a fact about where containers live, and
// two of them are paths.
//
// graphroot and runroot are named here even though podman also gets --root and
// --runroot on its argv, and that duplication is deliberate: CLAUDE.md's
// standing rule is to pass every security-relevant setting explicitly even when
// it matches what something else already supplies, because the failure mode of
// relying on the other one is silence.
//
// mount_program is DERIVED FROM THE ENGINE rather than hardcoded or omitted,
// and it is the one line here that needs care. A pinned static bundle ships its
// own fuse-overlayfs and its storage.conf names it; a distribution podman
// expects the one on PATH. Naming a path that does not exist breaks every run
// ("can't stat program"), and omitting it on a host that needs it breaks
// rootless overlay instead — so it is named when it is found beside the engine
// binary and left out when it is not, which is the only choice that is right on
// both host shapes.
func (e *Engine) writeStorageConf(pol *policy.Policy, podman string) (string, error) {
	path := filepath.Join(e.confDir, "storage.conf")

	var b strings.Builder
	b.WriteString("# snug: generated for this run. Pointed at by CONTAINERS_STORAGE_CONF, so\n" +
		"# the host's /etc/containers/storage.conf, ~/.config/containers/storage.conf\n" +
		"# and any file a pinned engine bundle ships are not read (issue #125).\n" +
		"#\n" +
		"# NO `driver` KEY, deliberately. snug pins WHERE containers live because that\n" +
		"# is a boundary; it has no basis to choose HOW they are stored, which is a\n" +
		"# compatibility question about this host's kernel and filesystem that\n" +
		"# containers/storage answers better than snug can. Naming a driver here would\n" +
		"# also remove its fallback, so a host that cannot do rootless native overlay\n" +
		"# would fail at store init rather than degrade — and snug would have made that\n" +
		"# choice silently, on a screen that says nothing about storage drivers.\n" +
		"#\n" +
		"# THE COST, stated rather than hidden: a host that deliberately configured a\n" +
		"# driver in /etc/containers/storage.conf loses that choice, because this file\n" +
		"# replaces it. That is inherent to snug authoring the file at all and is the\n" +
		"# same trade issues #133 and #137 already made for containers.conf and\n" +
		"# registries.conf.\n" +
		"[storage]\n")
	// GUEST paths, not host ones. The file is read by the ENGINE, inside a
	// view derived from the sandbox's, so a host path here names nothing —
	// and a generated config is exactly the place where that failure is
	// hardest to read, because podman reports it as a storage error rather
	// than as a missing mount (issue #125, Tier C).
	guestStore, err := e.guestPath(pol, "storage.conf graphroot", e.store)
	if err != nil {
		return "", err
	}
	guestRunroot, err := e.guestPath(pol, "storage.conf runroot", e.runroot)
	if err != nil {
		return "", err
	}
	for _, kv := range []struct{ key, path string }{
		{"graphroot", guestStore},
		{"runroot", guestRunroot},
	} {
		v, err := tomlString(kv.path)
		if err != nil {
			return "", fmt.Errorf("storage.conf %s: %w", kv.key, err)
		}
		b.WriteString(kv.key + " = " + v + "\n")
	}

	// mount_program IS NOT WRITTEN, issue #390 — and it was the second spelling
	// of the same defect as helper_binaries_dir, not a separate one.
	// helperBesideEngine derives its value from filepath.Dir(podman), which
	// e.guestPath then maps through EngineGuestPath's Access-blind bind arm.
	// MEASURED on cd17ea0, with fuse-overlayfs beside an engine inside an
	// @cwd-rw target: `mount_program = "/proj/bin/fuse-overlayfs"` — a
	// payload-writable path written into the engine's storage configuration.
	//
	// Note what "inert" did and did not cover. The old comment here said the
	// key is discarded by podman whenever --root is on the argv, measured on
	// 5.8.4 and 6.0.2, and Spec's argv always passes --root. That answers "does
	// podman HONOUR it". It says nothing about "does snug WRITE it", and snug
	// did. Two questions, and only the first had been asked.
	//
	// Deleted rather than gated, because its own reasoning already pointed
	// elsewhere: the direction is toward less driver configuration, and the
	// real fix for a host that needs fuse-overlayfs for rootless overlay is
	// `--storage-opt overlay.mount_program=<guest path>` beside --root, which
	// changes the engine argv and its golden files. A key that is discarded
	// when written and dangerous in how it is derived has no argument left.
	// helperBesideEngine stays, unused here, because its absoluteness refusal
	// is asserted by its own test.
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// helperBesideEngine returns the path of a helper binary sitting next to the
// engine binary, or "" when there is none there.
//
// The engine's own directory is the right place to look and the only one: a
// pinned bundle keeps its helpers there, and a distribution podman's helpers
// are on the PATH Spec pins, where podman finds them without being told. It
// deliberately does NOT search, because a search is a rule about which of
// several candidates wins, and snug has no way to say why one would.
//
// THREE CHECKS, and each is a way the earlier version was wrong.
//
// ABSOLUTE, and an error rather than a skip when it is not. preflightPodmanBinary
// trusts $SNUG_PODMAN outright with os.Stat and !IsDir, so `SNUG_PODMAN=./podman`
// reaches here as a relative path; filepath.Dir is then "." and the candidate is
// the bare string "fuse-overlayfs", stat'd against SNUG's working directory and
// written verbatim into storage.conf as a RELATIVE mount_program that the ENGINE
// resolves against its OWN. Two different processes, two different meanings for
// one string. Refusing is right rather than skipping: a relative $SNUG_PODMAN is
// a mistake worth naming, not a host shape to accommodate.
//
// EXECUTABLE, not merely regular. A non-executable file of the right name — a
// tarball unpacked under a restrictive umask, a stray artifact — was named as
// mount_program and produced exactly the "can't stat program" failure this
// derivation exists to prevent. Checking IsRegular alone tested that something
// is there, not that it can run.
//
// The mode check is a HINT and is documented as one: it asks whether any
// execute bit is set, not whether THIS uid may execute it. A file that passes
// here and still cannot be run fails later in podman, which is the honest place
// for it — snug is choosing what to name, not promising it will work.
func helperBesideEngine(podman, name string) (string, error) {
	if podman == "" {
		return "", nil
	}
	if !filepath.IsAbs(podman) {
		return "", fmt.Errorf("the container engine %q is not an absolute path, so a helper "+
			"beside it cannot be named absolutely either — snug would write a RELATIVE path "+
			"into the engine's storage.conf, which the engine resolves against its own working "+
			"directory rather than snug's.\n"+
			"       Set $SNUG_PODMAN to an absolute path.", podman)
	}
	cand := filepath.Join(filepath.Dir(podman), name)
	fi, err := os.Stat(cand)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return "", nil
	}
	return cand, nil
}

// writeAuthFile generates the EMPTY registry authentication file// writeAuthFile generates the EMPTY registry authentication file this run's
// engine reads, and returns its path for REGISTRY_AUTH_FILE.
//
// Without it, containers/image walks its ordinary search order and lands on
// the host user's own credentials — $XDG_RUNTIME_DIR/containers/auth.json is
// absent by construction (snug points XDG_RUNTIME_DIR at this run's runroot),
// so the fall-through reaches $HOME/.config/containers/auth.json and then
// $HOME/.docker/config.json. MEASURED on this host: a live credential for a
// private registry resolved out of the latter (issue #142).
//
// That is not a configuration leak, it is a CREDENTIAL one, and it is
// payload-reachable: the proxy allows the images tree, so a payload with
// @net can make the engine pull — and PUSH — as the host user. It cannot read
// the credential's bytes, which is why #142 is medium rather than high; what
// it gets is use of the host user's identity against a system outside the
// sandbox.
//
// Empty rather than projected, deliberately. A subset would need a rule for
// WHICH registries a sandbox may authenticate to, and snug has no vocabulary
// for that; inventing one in order to hand over a credential is the wrong
// direction. The cost is stated plainly instead: no registry login is
// possible from inside, so a private image cannot be pulled.
func (e *Engine) writeAuthFile() (string, error) {
	path := filepath.Join(e.confDir, "auth.json")
	if err := os.WriteFile(path, []byte("{\n    \"auths\": {}\n}\n"), 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// ArmReaper starts the pipe-triggered teardown helper (reaper.go) that stops
// this run's containers if snug dies without cleaning up.
//
// Called by the caller BEFORE sandbox.Run even begins — deliberately not
// tied to whether the engine has actually started yet, unlike DialLifeline
// below, because arming it early is what covers a snug killed during the
// stage's own startup window (creating U+N, waiting for the network), before
// the engine has been forked at all. It needs only this run's DIRECTORY,
// already fixed on the Engine by New; it does not need the engine's socket to
// exist yet, nor the socket's path at all (issue #344 deleted the unread
// SNUG_REAP_SOCK), still less the engine's own binary path (issue #167 removed
// the reaper's own host-side `podman stop`, so it no longer needs one).
func (e *Engine) ArmReaper() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := startReaper(e.runDir)
	if err != nil {
		return err
	}
	e.reap = r
	return nil
}

// ReaperPIDs names the reaper process, if one is armed, for the ONE caller
// entitled to know: whatever is about to hand sandbox.Options a list of pids
// the signalled-teardown sweep must not kill (issue #113).
//
// A slice rather than an int because the answer is genuinely "zero or one" and
// a zero pid is a dangerous thing to pass to something that signals — see
// sandbox.Options.excludeSet, which drops it again as a second defence.
//
// The reaper is the only process snug starts that the sweep must spare, and
// the reason is the same one reaper.go gives for its missing Pdeathsig: its
// whole job is to outlive snug and clean up this run's stale state (the run
// directory — socket, containers.conf, registries.conf, auth.json,
// resolv.conf, generated home/) when snug did not get to. It no longer stops
// any container itself (issue #167 deleted the host-side `podman stop` that
// used to be its job; the kernel's own namespace collapse fells containers
// by the time the reaper's cleanup runs). A guard that killed it would be
// killing the thing that exists because the guard might not run.
func (e *Engine) ReaperPIDs() []int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.reap == nil || e.reap.cmd == nil || e.reap.cmd.Process == nil {
		return nil
	}
	return []int{e.reap.cmd.Process.Pid}
}

// DialLifeline opens the keepalive stream (lifeline.go) that ties the
// engine's lifetime to this sandbox. Unlike ArmReaper, this NEEDS the
// engine's socket to already exist, so the caller runs it from
// sandbox.Options.OnEngineReady — after Stage.StartEngine has confirmed the
// socket is there, before the payload is forked. A failure here is fatal to
// the whole run (invariant 5): without the lifeline a hard-killed snug would
// leave a finite-timeout-but-not-yet-expired engine running for up to
// idleTimeout with nothing to shorten it, so snug refuses to hand the
// sandbox an engine it cannot guarantee to reap promptly.
func (e *Engine) DialLifeline() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	life, err := dialLifeline(e.sock)
	if err != nil {
		if e.reap != nil {
			e.reap.standDown()
			e.reap = nil
		}
		return fmt.Errorf("the container engine came up but would not accept the keepalive\n"+
			"      stream that ties its lifetime to this sandbox (%v).\n"+
			"      Without it a hard-killed snug would leave the engine running, so snug\n"+
			"      refuses to hand the sandbox an engine it cannot guarantee to reap", err)
	}
	e.life = life
	e.dialled = true
	return nil
}

// Stop tears the engine's CONTAINERS down and verifies. The engine PROCESS
// itself is not signalled here at all: it is Pdeathsig'd to the stage (P1),
// which is Pdeathsig'd (and lifeline-held) to P0, so it dies with the stage
// on every path — clean exit, panic, SIGKILL. Since issue #125's C0,
// containers ARE inside the engine's own pid namespace, so dropping this
// process's own keepalive (step 2) and returning is what actually fells
// them: the engine dies once nothing holds it open, and the pid namespace
// collapse takes its containers with it. What this still does beyond that is
// VERIFY (step 3) — "the collapse should have killed them" is not evidence
// that it did — never a graceful stop of its own; issue #167 removed the
// host-side attempt at one (step 1's own comment says why).
func (e *Engine) Stop() {
	e.once.Do(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.stopLocked()
	})
}

// Detach drops the keepalive and returns. From here the engine is on its own
// idle timeout even if it somehow outlives the stage.
//
// SPLIT OUT OF Stop BY ISSUE #344, and the split is the whole of that fix's
// wiring half. Detach is what runs at payload exit — before the deferred
// st.Close() collapses the stage and, through P1's Pdeathsig, the engine. Stop
// runs from the caller's own deferred cleanup, which is strictly AFTER that
// collapse. Verification belongs there and only there: at payload exit the
// engine is ALIVE by construction, so a sweep for it can only answer "still
// running", and the previous wiring made snug's exit wait out the engine's idle
// timeout to get any other answer.
//
// Idempotent, and it must stay so: Stop calls the same logic, so an error path
// that never reached payload exit still closes the lifeline.
func (e *Engine) Detach() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.detachLocked()
}

func (e *Engine) detachLocked() {
	if e.life != nil {
		e.life.Close()
		e.life = nil
	}
}

func (e *Engine) stopLocked() {
	// Everything snug runs itself is excluded from the sweep, or teardown
	// would find its own cleanup and call it a leak.
	exclude := map[int]bool{os.Getpid(): true}
	if e.reap != nil && e.reap.cmd.Process != nil {
		exclude[e.reap.cmd.Process.Pid] = true
	}

	// 1. NO host-side `podman stop` here any more (issue #167). Pre-C0 this
	//    step ran a graceful stop while the engine was still live, reaching
	//    containers that were "not the engine's children" and would
	//    otherwise outlive it. Issue #125's C0 gave the engine its own pid
	//    namespace, so containers ARE inside it now and its death already
	//    fells them (see the package comment's measurement) — but that same
	//    change renumbered the runroot's recorded conmon.pid/pidfile INTO
	//    the engine's own pid namespace, so a HOST-side invocation reading
	//    them is reading numbers that mean nothing in the host's numbering.
	//    Measured pre-/post-C0: 1954739/1954741 (matched /proc exactly) vs
	//    168/170 (host pids were seven digits).
	//
	//    Translating those numbers through the engine's namespace before use
	//    was the alternative and was rejected: it is new teardown machinery
	//    built to make a mechanism land on numbers meaningful only inside
	//    the namespace doing the killing, for an outcome the kernel's own
	//    SIGKILL-at-collapse already delivers faster (measured under 70ms
	//    end to end from a SIGKILL of snug).
	//
	//    THE RENUMBERING ARGUMENT IS WHAT CARRIES THIS DELETION — not "the
	//    engine is already dead", which is not true of stopLocked's own
	//    call sites (a correction from a previous version of this comment,
	//    red team F5). stopLocked runs from live Go code inside snug's own
	//    process: on the clean path via sandbox.Options.OnPayloadExit,
	//    BEFORE the deferred st.Close() that starts the Pdeathsig cascade
	//    (internal/sandbox/exec.go's own comment says so explicitly — "while
	//    the engine's socket is still reachable"), so the engine is ALIVE
	//    here. "Already dead, nothing left to stop" describes the SEPARATE
	//    reaper PROCESS (reaper.go), which fires only on pipe EOF — i.e.
	//    only once snug's own process has actually died, which is what
	//    collapses the engine's pid namespace in the first place. The two
	//    call sites of "no host-side podman stop" are both right to delete
	//    the call, for the SAME renumbering reason, but for that one reason
	//    only: on this (stopLocked's) path a host-side stop would be racing
	//    a live engine and reading its numbers wrong; on the reaper's path
	//    there is additionally nothing left to reach at all. Do not conflate
	//    the two arguments onto one call site again.
	//
	//    The residual risk this deletion accepts is a stray signal, not a
	//    missed teardown: reading a small pid as a HOST pid and asking
	//    podman to stop it could hit an unrelated live process on a host
	//    sharing the boot pid namespace, or a container/CI runner handing
	//    low pids to the invoking uid (checked on this development host:
	//    the specific pids read here did not exist, so nothing was
	//    signalled — that is this host's absence of the risk, not a general
	//    proof it cannot happen). What is knowingly given up is a
	//    best-effort graceful SIGTERM on the clean path, for workloads that
	//    handle one — restorable later, if wanted, by issuing a stop
	//    through the engine's OWN socket, where the recorded pids are
	//    numbered in the namespace doing the killing, never by reading a
	//    host-side CLI against host-numbered pids again.

	// 2. Drop the keepalive, if payload exit did not already (Detach). From
	//    here the engine is on its own idle timeout even if it somehow
	//    outlives the stage.
	e.detachLocked()

	// 3. Verify. "The stop command returned no error" is not evidence anything
	//    died — that assumption is what let a wrapper-engine case leak
	//    silently in the pre-Tier-B design. The sweep is by SOCKET PATH, never
	//    by comm and never by the shared store path (which would reach a
	//    concurrent sibling).
	//
	//    THIS IS THE FIRST POSITION FROM WHICH THE SWEEP CAN ANSWER ANYTHING
	//    (issue #344). It ran at payload exit until then — before the deferred
	//    st.Close(), i.e. before the Pdeathsig cascade P1 -> engine has fired —
	//    so the engine was alive by construction and the only thing that could
	//    make the sweep go quiet was the engine's own idle timeout. Nobody
	//    observed the resulting 15s wait for a milestone because paths()
	//    returned the HOST socket spelling while the engine's argv carries the
	//    GUEST one, so step 3 returned on its first poll every time and has, in
	//    effect, never executed.
	//
	//    Here the SIGKILL is already queued: st.Close() does not return until
	//    P1 has been reaped, and the kernel delivers a child's pdeathsig in
	//    forget_original_parent BEFORE do_notify_parent wakes our Wait. So the
	//    question this asks can be answered wrong — "the mechanism that kills
	//    the engine has run; is anything still serving this run's socket?" A
	//    process the cascade killed is either gone or a zombie, and a zombie
	//    reads back an EMPTY cmdline, which cmdlineNamesPath already answers
	//    "not ours" to — correctly, since a zombie serves nothing. What
	//    survives is an engine outside the cascade's reach, which is the case
	//    this sweep was written for.
	//
	//    A dialled lifeline with no recorded mark is a wiring bug, not an
	//    engine-less run, and it is named rather than swept vacuously: the
	//    whole of #344 is a sweep that reported success because it was looking
	//    for nothing.
	if e.dialled && len(e.paths()) == 0 {
		fmt.Fprintf(os.Stderr,
			"snug: WARNING — an engine answered this run's keepalive, but teardown has\n"+
				"      no command-line mark to look for, so it verified nothing.\n"+
				"      This is a bug in snug's wiring (Spec must record the engine's\n"+
				"      socket path); the engine's own idle timeout is the only thing\n"+
				"      left holding.\n")
	}
	if left := waitQuiet(e.paths(), exclude, quietBudget); len(left) > 0 {
		signalOwned(e.paths(), exclude, syscall.SIGKILL)
		if left = waitQuiet(e.paths(), exclude, killBudget); len(left) > 0 {
			fmt.Fprintf(os.Stderr,
				"snug: WARNING — this sandbox's containers did not die with it.\n"+
					"      Still running:\n%s"+
					"      Reap them with:\n"+
					"        kill -9 %s\n"+
					"      and check the store with:\n"+
					"        podman --root %s --runroot %s ps\n",
				describe(left), joinPIDs(left), e.store, e.runroot)
		}
	}

	// 4. The reaper's job is done; tell it so and wait, so that snug
	//    returning means teardown has finished.
	e.reap.standDown()
	e.reap = nil

	if err := e.dirs.remove(); err != nil {
		// Named rather than swallowed, the same way sweepStaleRunDirs names a
		// stale directory it could not remove: this one holds this run's
		// engine socket and generated config, and a directory snug could not
		// clean up is state that survives the user (invariant 4).
		fmt.Fprintf(os.Stderr, "snug: could not remove this engine's run directory %s: %v\n",
			e.runDir, err)
	}
}

func joinPIDs(pids []int) string {
	parts := make([]string, 0, len(pids))
	for _, p := range pids {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, " ")
}

// helperBinariesDirs is the value of containers.conf's helper_binaries_dir,
// and it has to answer a question that only exists once the engine's view is
// derived: WHERE, inside that view, are conmon, crun, netavark and the rest?
//
// The three /usr entries are the distribution answer, and "always present" is
// what this said until it was MEASURED: on the development host (podman 6.0.2,
// openSUSE Tumbleweed) /usr/libexec/podman and /usr/bin exist and
// /usr/lib/podman does NOT. So the list is a SUPERSET of the spellings the
// distributions use, not three directories a host has — which is the right
// shape for a search list and the wrong claim to make about it. podman ignores
// an entry that is not there; @sys binding the OS runtime is what makes the
// ones that DO exist reachable inside the engine's view, and that half stands.
// A PINNED
// BUNDLE is the other case, and it needs its own directory named FIRST: its
// podman is statically built against its own helpers, and the /usr entries on
// this host hold the distribution's, which is a different set of versions
// answering to the same names. Silently mixing them is the failure this
// avoids — it does not announce itself as a mismatch, it announces itself as
// a container that will not start.
//
// The bundle's directory is the ENGINE BINARY's own, mapped into the engine's
// view, which is the same rule helperBesideEngine already applies to
// mount_program: "the engine's own directory is the right place to look and
// the only one". A binary the mapping cannot place is simply not named here —
// Spec has already refused the run by then, so this arm cannot silently drop
// a helper directory a working run needed.
func helperBinariesDirs() string {
	// ISSUE #390. This used to prepend EngineGuestPath(filepath.Dir(podman)) —
	// the engine binary's own directory, mapped into the engine's view. That is
	// a HOST string snug transformed, and EngineGuestPath's bind arm resolves
	// through any KindBind mount, WRITABLE ONES INCLUDED: it has no Access test
	// at all. MEASURED on cd17ea0 with $SNUG_PODMAN inside a target granted rw
	// by @cwd-rw, the generated file read
	//
	//     helper_binaries_dir = ["/proj/bin", "/usr/libexec/podman", …]
	//
	// with /proj payload-writable and FIRST. This list is not an incidental
	// lookup: writeContainersConf names it as snug's explicit search set so
	// podman does not fall back to inheritance, and the engine resolves
	// netavark, aardvark-dns, catatonit, rootlessport and pasta out of it as
	// root in the sandbox's user namespace. So the payload chose what the
	// engine executed.
	//
	// The guard is not a check on the derived string, it is a change of author:
	// every entry is now a literal snug wrote. The old `!strings.HasPrefix(
	// guest, "/usr/")` test was de-duplication wearing a security hat — a
	// prefix test on a guest path, which is the catalogue shape invariant 2
	// rejects, and it admitted every non-/usr path rather than refusing one.
	//
	// A real engine outside /usr that carries its OWN helpers is not served by
	// this today, and that is deliberate: with the static-bundle fallback
	// retired (#384) every supported configuration has them in the three
	// directories below, measured on this host. If one ever needs its own, the
	// entry comes back as policy.EngineToolchainGuest — the graft's guest
	// constant, a literal — never filepath.Dir(podman) mapped through
	// EngineGuestPath, and G4b has already refused a toolchain root the payload
	// can write.
	dirs := []string{"/usr/libexec/podman", "/usr/lib/podman", "/usr/bin"}
	quoted := make([]string, 0, len(dirs))
	for _, d := range dirs {
		v, err := tomlString(d)
		if err != nil {
			// UNREACHABLE, and now provably so: the three values above are
			// literals in this file, and tomlString only refuses a quote, a
			// backslash or a control character. It used to be reachable — the
			// list carried a path mapped from filepath.Dir(podman), where a
			// control character in a host path was the hazard — and #390
			// removed that entry, so nothing here comes from outside this
			// function any longer.
			//
			// Kept rather than deleted, and the `continue` is the part to look
			// at twice if that ever changes: silently dropping a helper
			// directory is invariant 5's silent downgrade, and the symptom
			// would be an engine that cannot find netavark rather than an
			// error naming the path. A future entry from outside wants an
			// error return here, not this branch.
			continue
		}
		quoted = append(quoted, v)
	}
	return strings.Join(quoted, ", ")
}

// GraftInto is the other half of the engine's view: the host
// directories this run's engine works out of, cloned into its namespace with
// open_tree(2) rather than mounted fresh.
//
// FOUR, and the count is the point — after Tier C a bind-filter bug in the
// container proxy reaches these and nothing else, where today it reaches the
// whole host tree. A fifth is added when this host's engine lives outside every
// grant the sandbox makes (a pinned bundle): its toolchain, read-only.
//
// Each of the four is declared to the policy TWICE and the two are different
// claims. OwnEngineHostPath says "snug created this host path for this run", so
// G4's second disjunct admits it even though no sandbox grant exposes it;
// Policy.Graft then installs the graft itself and runs G1-G5 over it. Skipping
// the first would make G4 refuse every one of them; skipping the second would
// leave a declared host path with nothing mounting it.
//
// THE TOOLCHAIN ROOT IS READ FROM THE POLICY, never taken as an argument, and
// that is the ordering trap removed rather than documented: G4 admits the
// toolchain graft only by exact membership in p.EngineToolchainRoot, so a
// caller that passed a root here without also recording it would get a refusal
// naming G4 rather than naming the missing call. One writer (preflight P9,
// through Policy.EngineToolchain), one reader.
//
// ORDER: after New (the paths must exist to be resolved) and before Spec (which maps every path it hands the engine through these grafts,
// and refuses a path no graft or grant exposes).
func (e *Engine) GraftInto(env policy.Environ, p *policy.Policy) error {
	return GraftPathsInto(env, p, Paths{
		Store: e.store, Runroot: e.runroot, SockDir: e.sockDir, ConfDir: e.confDir,
	})
}
