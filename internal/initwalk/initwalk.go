// Package initwalk names a sandbox init from the host process tree, without
// waiting for bwrap to report it on --info-fd.
//
// WHY IT EXISTS. Between bwrap forking the sandbox's init and bwrap answering
// --info-fd, no record on the host names that init, so a snug killed in there
// leaves an init nothing can find — reparented, holding six namespaces,
// forever. For a bwrap that answers, the window is a few milliseconds. For the
// wedged bwrap issue #236 actually measured — parked in read(2) on one of
// bwrap's OWN eventfds, its uid-map sync — bwrap never answers at all, and the
// window is the life of the machine.
//
// internal/cli's orphansweep.go called that upstream's window, on the ground
// that no record can name the init because its pid is the one bwrap has not
// reported yet. MEASURED on both arms, and the ground is false. Offline:
//
//	snug pid      = 621205
//	descend chain = [621216, 621217, 621218]
//	record init   = 621217 -> level 2
//
// Staged, where the STAGE forks bwrap rather than snug:
//
//	pid 663002 ppid 0        snug     user=4026533102
//	pid 663014 ppid 663002   exe      user=4026533424   <- the stage, P1
//	pid 663038 ppid 663014   bwrap    user=4026533424   <- P1's OWN user ns
//	pid 663045 ppid 663038   bwrap    user=4026533635   <- the recorded init
//	pid 663047 ppid 663045   sleep    user=4026533635   <- the payload
//
// On both arms the init the run-state record names is the DIRECT CHILD of the
// bwrap process its own parent started, and that parent has the pid from
// cmd.Start(). So /proc/<bwrap>/task/*/children names the init with bwrap
// reporting nothing.
//
// WHY THE FOREIGN-USER-NAMESPACE TEST IS THE IDENTITY GUARD, and it is the
// whole safety of this package. A record built from a walked pid names a
// process bwrap PRODUCED rather than one bwrap REPORTED, and internal/cli's
// killOrphanInit will later SIGKILL whatever matches that record's pid, start
// time and six namespace inodes. Two facts together keep it off a stranger:
// the candidate is a child of a bwrap the caller started, which nothing but
// that bwrap can create; and it is in a user namespace that is not the
// caller's. The staged measurement above is what makes the second one
// discriminating rather than lucky — bwrap ITSELF shares P1's user namespace
// (4026533424) and only the init has its own, so the test selects the init and
// skips the process that forked it. bwrap's clone puts the init inside its
// namespaces from its first instruction, so this is true from that child's
// first instruction and needs no settle.
package initwalk

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ForeignUsernsChild returns the first child of parent that lives in a user
// namespace other than ours.
//
// gone reports that parent itself is no longer there, which ends any walk
// built on this: a bwrap that exited without forking has no init to find and
// never will.
func ForeignUsernsChild(parent int, ours uint64) (pid int, found, gone bool) {
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", parent))
	if err != nil {
		return 0, false, true
	}
	for _, t := range tasks {
		blob, rerr := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", parent, t.Name()))
		if rerr != nil {
			// No CONFIG_PROC_CHILDREN, or the thread exited under us. Either
			// way this thread has nothing to say; a caller that finds nothing
			// anywhere gives up on its own timeout.
			continue
		}
		for _, f := range strings.Fields(string(blob)) {
			child, cerr := strconv.Atoi(f)
			if cerr != nil || child <= 1 {
				continue
			}
			theirs, nerr := NamespaceInode(child, "user")
			if nerr != nil {
				// It exited between the read and here, or /proc denied us —
				// pasta, in the staged topology, reads as a permission error
				// from this side. Not something to name either way.
				continue
			}
			if theirs != ours {
				return child, true, false
			}
		}
	}
	return 0, false, false
}

// NamespaceInode is internal/sandbox's fillMissingNamespaceIDs in single-kind
// form: fstat through /proc/<pid>/ns/<kind>, never readlink, for the reason
// stated there — the inode is what a later setns actually joins, and a
// rendered string is a second representation of it that nothing checks.
func NamespaceInode(pid int, kind string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, kind), &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}
