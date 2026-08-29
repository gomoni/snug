package cli

// stateowner.go is the second liveness signal an unlink cannot detach
// (issue #489).
//
// The per-target flock is this design's only source of "is this run live",
// and its weakness is that a lock is held on an INODE while it is consulted
// by NAME. One same-uid `rm` — or an `mv`, which leaves no "(deleted)" trail
// at all — detaches the two, and targetLockIsHeld then creates a fresh inode,
// locks it unopposed and answers "not held" about a run that is very much
// alive. sweepOneOrphan reads that as "the owning snug is gone" and
// killOrphanInit SIGKILLs a live sandbox's init. MEASURED, issue #489:
//
//	after the unlink, targetLockIsHeld = false, <nil>   (a live run still holds the old inode)
//	FINDING C: `rm target-sha256_2286bd59….lock` made the sweep SIGKILL a live sandbox's init (pid 620273)
//
// No fix can be built on the lock file's name, however it is compared: a
// same-uid attacker owns the string that fd resolves to (targetstate.go
// measures the `mv` half). So the kill needs a signal that is not a file at
// all — the OWNING SNUG'S OWN PROCESS. It is the process that took the lock
// in run() and holds it for the whole run; if it is still there, the run is
// live whatever the directory now looks like.
//
// The identity chain is the one killOrphanInit already applies to the init:
// pid plus /proc/<pid>/stat field 22, so a recycled pid number is not
// mistaken for the owner. It is deliberately NOT a pidfd: nothing signals the
// owner, and the only question asked is whether that exact process is still
// running at the instant the sweep looks.
//
// WHAT THIS DOES NOT COVER, stated because the paragraphs above read like a
// closed hole. The owner record lives in the same same-uid file the init
// record does, so a process that EDITS state.json rather than unlinking the
// lock can still name a dead owner and get the kill it wanted. That is not a
// regression — every other signal in that file (init pid, start time, six
// namespace inodes) is writable by the same hand — and it is why the gate
// below fails CLOSED on a record with no owner at all: an unconfirmable
// owner leaves an orphan, which orphansweep.go's own doctrine already prefers
// to killing a process it cannot confirm.

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

// stateOwner names the snug process that owns a run: the one holding the
// per-target lock. Carried by BOTH records (state.json and the ".starting"
// record) because both reach killOrphanInit, and a gate present in only one
// of them would leave issue #489 open for whichever window the other covers.
type stateOwner struct {
	PID       int    `json:"pid"`
	Starttime uint64 `json:"starttime"`
}

// currentOwner is this process, read the same way the init's identity is
// read. Called from the two record writers, both of which run inside the snug
// that took the lock in run() — os.Getpid() is that process, not a child.
func currentOwner() (stateOwner, error) {
	pid := os.Getpid()
	starttime, err := procStartTime(pid)
	if err != nil {
		return stateOwner{}, fmt.Errorf("reading own start time (pid %d): %w", pid, err)
	}
	return stateOwner{PID: pid, Starttime: starttime}, nil
}

// ownerProvablyGone reports whether the snug that owned a run is confirmed
// dead. Only a positive confirmation returns true — an owner this function
// cannot resolve is treated as alive, which is what makes the sweep's kill
// fail closed.
func ownerProvablyGone(o stateOwner) bool {
	if o.PID <= 1 {
		// No owner recorded: a record written by a snug older than this
		// field, or one edited to remove it. Neither can be confirmed, and
		// the cost of the conservative answer is a leftover init that the
		// next boot clears (the record directory is uid-derived and lives on
		// tmpfs) rather than a live sandbox killed.
		return false
	}
	fields, err := procStatAfterComm(o.PID)
	if err != nil {
		// ENOENT is the ordinary case: the owner exited and was reaped,
		// which is exactly what an orphaned init means. Any other /proc
		// failure confirms nothing.
		return errors.Is(err, os.ErrNotExist)
	}
	if len(fields) == 0 {
		return false
	}
	// A ZOMBIE owner is gone for this purpose and the distinction is not
	// pedantic: the kernel releases an flock at exit, not at reap, so a snug
	// sitting unreaped has already let go of the target lock. Reading it as
	// alive would make one unreaped corpse block the sweep until the next
	// boot.
	if fields[0] == "Z" || fields[0] == "X" {
		return true
	}
	const starttimeIndex = 22 - 3
	if len(fields) <= starttimeIndex {
		return false
	}
	start, err := strconv.ParseUint(fields[starttimeIndex], 10, 64)
	if err != nil {
		return false
	}
	// A live process holds the number. If its start time is not the one the
	// record named, the number was recycled and our owner is gone.
	return start != o.Starttime
}
