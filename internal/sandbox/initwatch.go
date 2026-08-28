package sandbox

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// initwatch.go closes the last window issue #236 left open, and it closes it
// by refuting the reason the window was thought to be upstream's.
//
// The window: between bwrap forking the sandbox's init and bwrap answering
// --info-fd, no record on the host names that init, so a snug SIGKILLed in
// there leaves an init nothing can find — reparented, holding six namespaces,
// forever. The ordinary case is a few milliseconds. The case that matters is
// not bounded at all: the orphan issue #236 measured was parked in read(2) on
// one of BWRAP'S OWN eventfds, its uid-map sync, which means bwrap had forked
// the init and would never answer --info-fd. For that shape the window is the
// life of the machine.
//
// orphansweep.go called it "upstream's window, closable only by arming the
// init's PDEATHSIG before that read", on the ground that no record can name
// the init because its pid is the one bwrap has not reported yet. MEASURED on
// this host, offline arm, and the ground is false:
//
//	snug pid      = 621205
//	descend chain = [621216, 621217, 621218]
//	record init   = 621217 -> level 2
//
// The init the run-state record names is the DIRECT CHILD of the bwrap process
// snug itself started. snug has that pid from cmd.Start(), so the init is
// reachable through /proc/<bwrap>/task/*/children with bwrap reporting
// nothing, and its namespace inodes are readable from /proc/<init>/ns/* at
// that instant. A second run timed the appearances: outer bwrap visible at
// 116.7 ms, the init at 120.1 ms, the state record at 121.6 ms.
//
// THE UNSTAGED ARM ONLY, and that is a limit rather than a completion. On a
// staged run the STAGE forks bwrap (exec.go's runStaged; the --info-fd read
// end lives there, issue #125), so P0 does not have the pid to walk from and
// this watcher is not started. The same window is open on that arm and the
// same walk would close it, one process further in.
//
// WHY THE FOREIGN-USERNS TEST IS THE IDENTITY GUARD. A record built from a
// walked pid names a process bwrap PRODUCED rather than one bwrap REPORTED,
// and killOrphanInit will later SIGKILL whatever matches that record's pid,
// start time and six namespace inodes. So the walk must not hand back a
// process that is not a sandbox init. Two facts do that together: the
// candidate is a child of a bwrap this process started, which nothing but
// that bwrap can create; and it lives in a user namespace that is not ours,
// which the payload's own siblings and any helper snug starts do not.
// bwrap's clone creates the init already inside its new namespaces, so this
// is true from the child's first instruction, not after a settle.

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
// it and nothing fails if it never finds anything — reportInfo's own
// notifyInit still runs with bwrap's authoritative answer, and OnInit's
// consumer rewrites one record by target name rather than accumulating.
//
// Ordering between the two is deliberately not fixed. Whichever names the
// init first wins the write; if both run they write the same record, and if
// they somehow disagreed the LATER one is bwrap's own answer, which is the
// one to keep.
func watchForInit(bwrapPid int, opts Options) {
	if opts.OnInit == nil {
		return
	}
	ours, err := namespaceInode(os.Getpid(), "user")
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
			pid, found, gone := foreignUsernsChild(bwrapPid, ours)
			if found {
				notifyInit(opts, pid)
				return
			}
			if gone || time.Now().After(deadline) {
				return
			}
			time.Sleep(initWatchInterval)
		}
	}()
}

// foreignUsernsChild returns the first child of parent that lives in a user
// namespace other than ours. gone reports that parent itself is no longer
// there, which ends the walk — a bwrap that exited without forking has no
// init to find and never will.
func foreignUsernsChild(parent int, ours uint64) (pid int, found, gone bool) {
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", parent))
	if err != nil {
		return 0, false, true
	}
	for _, t := range tasks {
		blob, rerr := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", parent, t.Name()))
		if rerr != nil {
			continue
		}
		for _, f := range strings.Fields(string(blob)) {
			child, cerr := strconv.Atoi(f)
			if cerr != nil || child <= 1 {
				continue
			}
			theirs, nerr := namespaceInode(child, "user")
			if nerr != nil {
				// It exited between the read and here, or /proc denied us.
				// Either way it is not something to name.
				continue
			}
			if theirs != ours {
				return child, true, false
			}
		}
	}
	return 0, false, false
}

// namespaceInode is fillMissingNamespaceIDs' single-kind twin: fstat through
// /proc/<pid>/ns/<kind>, never readlink, for the same reason stated there —
// the inode is what a later setns actually joins, and a rendered string is a
// second representation of it that nothing checks.
func namespaceInode(pid int, kind string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, kind), &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}
