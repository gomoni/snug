package sandbox

import (
	"fmt"
	"time"

	"github.com/gomoni/snug/internal/initwalk"
)

// initwatch.go is the UNSTAGED arm's use of internal/initwalk: snug forks
// bwrap itself here, so it has the pid to walk from. That package's own doc
// comment carries the measurement, the two process trees and the reason the
// foreign-user-namespace test is the identity guard; none of it is repeated
// here.
//
// What is local to this arm: reportInfo is racing this walk for the same fact,
// and the order between them is not fixed — but the CALL is. Both go through
// one initReporter (exec.go), which fires OnInit once, because two concurrent
// OnInit calls in one process collided on a temp filename keyed by pid and
// left a run with no record at all. The staged arm reaches the same walk
// through internal/stage's serve.go instead, where the pid lives, and arrives
// at the same one-naming rule from its own protocol.

const (
	// initWatchInterval is the poll. The thing being waited for is a fork
	// that has usually already happened by the first read, so this is about
	// how long a WEDGED bwrap's init goes unnamed, not about throughput.
	initWatchInterval = time.Millisecond
	// initWatchTimeout bounds a walk that never finds anything — a bwrap that
	// died before forking, or a kernel without CONFIG_PROC_CHILDREN, where
	// the children file is absent and every read comes back empty. It is far
	// below infoFDTimeout on purpose: past this point reportInfo is the
	// better answer anyway, because bwrap answering at all outranks a walk.
	initWatchTimeout = 2 * time.Second
)

// watchForInit names the sandbox init from the host process tree, without
// waiting for bwrap to report it, and hands it to opts.OnInit.
//
// It returns immediately; the walk runs in its own goroutine and ends on the
// first of: an init found, bwrap gone, or initWatchTimeout. Nothing waits for
// it and nothing fails if it never finds anything — reportInfo still names the
// init from bwrap's own answer through the same reporter.
func watchForInit(bwrapPid int, opts Options, named *initReporter) {
	if opts.OnInit == nil {
		return
	}
	// BWRAP's user namespace, not snug's: see initwalk's package comment. On
	// the offline arm bwrap is in a namespace foreign to snug, so snug's id
	// would admit every child of bwrap rather than only the init it put in a
	// namespace of its own.
	ours, err := initwalk.NamespaceInode(bwrapPid, "user")
	if err != nil {
		// Without bwrap's user namespace id there is no identity test, and a
		// walk with no identity test is a pid picker. Do nothing rather than
		// name something on weaker grounds than the record deserves.
		opts.warn(fmt.Sprintf("cannot read bwrap's user namespace (%v); an init "+
			"orphaned before bwrap reports it will not be recorded", err))
		return
	}
	go func() {
		deadline := time.Now().Add(initWatchTimeout)
		for {
			pid, found, gone := initwalk.ForeignUsernsChild(bwrapPid, ours)
			if found {
				named.report(opts, pid)
				return
			}
			if gone || time.Now().After(deadline) {
				return
			}
			time.Sleep(initWatchInterval)
		}
	}()
}

// hostInitPID translates bwrap's --info-fd answer into a host pid.
//
// WHY A TRANSLATION EXISTS AT ALL: bwrap reports the init's pid as bwrap
// ITSELF sees it. Today that is a host pid on the staged arm, because the
// stage runs bwrap in the host's pid namespace. On the offline arm bwrap is
// pid 1 of the intermediate namespace snug creates (see exec.go's SysProcAttr,
// issue #101), so its init is pid 2 THERE and bwrap reports 2 — a number that
// on the host names kthreadd. MEASURED, before this translation existed:
//
//	snug: could not record this run's sandbox init (init state: reading
//	namespace ids of pid 2: open /proc/2/ns/mnt: permission denied)
//	snug: this run will not be attachable (run state: could not determine
//	the "mnt" namespace id (got 0))
//
// It failed loudly only by an accident of numbering — small host pids are
// kernel threads, so the read was EPERM rather than a successful read of the
// wrong process into a record killOrphanInit later SIGKILLs. That accident is
// not a guarantee, which is why the pid is translated rather than sanity-checked.
//
// TWO SOURCES, IN ORDER, and the order is the point. ChildWithReportedPID
// CONFIRMS the number bwrap produced, through NSpid; ForeignUsernsChild only
// SELECTS a candidate on structural grounds. Preferring the confirmation keeps
// the record built from bwrap's own answer wherever bwrap gave one, which is
// what it was before the nesting existed. The structural walk stays as the
// fallback it has always been (issue #236's wedged bwrap answers nothing at
// all), and it is handed BWRAP's user namespace rather than snug's: on this
// arm bwrap is itself in a namespace foreign to snug, so snug's would admit
// every child of bwrap instead of only the init. See initwalk's package
// comment.
//
// It blocks, because the caller is a goroutine whose whole job is to publish
// this record and there is nothing useful to publish without it.
func hostInitPID(bwrapPid, reported int, opts Options) (int, bool) {
	// Read once, outside the loop: bwrap's own user namespace cannot change,
	// and re-stat'ing it every 5ms would only add a way to fail late.
	theirs, err := initwalk.NamespaceInode(bwrapPid, "user")
	if err != nil {
		opts.warn(fmt.Sprintf("cannot read bwrap's user namespace (%v); this run will "+
			"not be attachable", err))
		return 0, false
	}
	deadline := time.Now().Add(initWatchTimeout)
	for {
		if pid, found, gone := initwalk.ChildWithReportedPID(bwrapPid, reported); found {
			return pid, true
		} else if !gone {
			if pid, found, _ := initwalk.ForeignUsernsChild(bwrapPid, theirs); found {
				return pid, true
			}
		} else {
			return 0, false
		}
		if time.Now().After(deadline) {
			return 0, false
		}
		time.Sleep(initWatchInterval)
	}
}
