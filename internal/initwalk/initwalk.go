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
// that bwrap can create; and it is in a user namespace that is not BWRAP's.
//
// "Not bwrap's" — not "not the caller's", and the difference is the whole
// discrimination. In the staged measurement above bwrap ITSELF shares P1's
// user namespace (4026533424) and only the init has its own, so with either
// spelling the test selects the init and skips the process that forked it.
// They stop agreeing the moment bwrap does NOT share the caller's user
// namespace: then every child of bwrap is foreign to the CALLER, the test
// admits all of them, and the first one walked lands in a record
// killOrphanInit later SIGKILLs. Comparing against bwrap's own namespace is
// the spelling that cannot drift, because the property being tested is "bwrap
// put this child in a user namespace of its own", which is a fact about bwrap.
//
// bwrap's clone puts the init inside its namespaces from its first
// instruction, so this is true from that child's first instruction and needs
// no settle.
package initwalk

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ForeignUsernsChild returns the first child of parent that lives in a user
// namespace other than ours. Callers pass PARENT's own user namespace — see
// the package comment on why that spelling and not the caller's.
//
// gone reports that parent itself is no longer there, which ends any walk
// built on this: a bwrap that exited without forking has no init to find and
// never will.
func ForeignUsernsChild(parent int, ours uint64) (pid int, found, gone bool) {
	return walkChildren(parent, func(child int) bool {
		theirs, nerr := NamespaceInode(child, "user")
		if nerr != nil {
			// It exited between the read and here, or /proc denied us —
			// pasta, in the staged topology, reads as a permission error
			// from this side. Not something to name either way.
			return false
		}
		return theirs != ours
	})
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

// NSpidChain returns pid's NSpid line from /proc/<pid>/status: its pid in the
// caller's pid namespace first, then in each descendant namespace it belongs
// to. A kernel that does not export NSpid gives a one-element chain, which is
// exactly what a process in the caller's own namespace would give anyway.
func NSpidChain(pid int) ([]int, error) {
	blob, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(blob), "\n") {
		rest, ok := strings.CutPrefix(line, "NSpid:")
		if !ok {
			continue
		}
		var chain []int
		for _, f := range strings.Fields(rest) {
			n, cerr := strconv.Atoi(f)
			if cerr != nil {
				return nil, fmt.Errorf("NSpid of pid %d: unparseable field %q", pid, f)
			}
			chain = append(chain, n)
		}
		if len(chain) == 0 {
			return nil, fmt.Errorf("NSpid of pid %d: empty", pid)
		}
		return chain, nil
	}
	return nil, fmt.Errorf("NSpid of pid %d: no NSpid line", pid)
}

// ChildWithReportedPID translates a pid bwrap reported on --info-fd into a
// host pid, by finding the child of parent that carries that number at the
// depth of PARENT's own pid namespace.
//
// WHY A TRANSLATION IS NEEDED AT ALL. bwrap reports the init's pid as bwrap
// itself sees it. When bwrap runs in the caller's pid namespace those are the
// same number and this is an identity; when bwrap is pid 1 of a namespace the
// caller created (internal/sandbox's offline arm, issue #101) they are not,
// and the reported number names a kernel thread on the host.
//
// The depth is read from parent rather than assumed: NSpid's last entry is
// always the pid in the process's OWN namespace, so a child one level deeper
// carries its parent-namespace pid at index len(parentChain)-1. That
// arithmetic is what makes this correct on both arms rather than tuned for
// one — a bwrap in the caller's namespace gives a one-element chain and index
// 0, which is the child's host pid.
//
// This is a translation and not a guess, which is what separates it from
// ForeignUsernsChild: it CONFIRMS a number bwrap itself produced, rather than
// selecting a candidate on structural grounds.
func ChildWithReportedPID(parent, reported int) (pid int, found, gone bool) {
	parentChain, err := NSpidChain(parent)
	if err != nil {
		return 0, false, true
	}
	idx := len(parentChain) - 1
	each := func(child int) bool {
		chain, cerr := NSpidChain(child)
		if cerr != nil || len(chain) <= idx {
			return false
		}
		return chain[idx] == reported
	}
	return walkChildren(parent, each)
}

// walkChildren is ForeignUsernsChild's and ChildWithReportedPID's shared
// enumeration: every child of every thread of parent, in whatever order procfs
// gives them, stopping at the first one keep accepts. gone reports that parent
// itself is no longer there, which ends any walk built on this.
func walkChildren(parent int, keep func(child int) bool) (pid int, found, gone bool) {
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
			if keep(child) {
				return child, true, false
			}
		}
	}
	return 0, false, false
}
