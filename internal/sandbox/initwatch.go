package sandbox

import (
	"fmt"
	"os"
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
	ours, err := initwalk.NamespaceInode(os.Getpid(), "user")
	if err != nil {
		// Without our own user namespace id there is no identity test, and a
		// walk with no identity test is a pid picker. Do nothing rather than
		// name something on weaker grounds than the record deserves.
		opts.warn(fmt.Sprintf("cannot read this process's own user namespace (%v); an init "+
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
