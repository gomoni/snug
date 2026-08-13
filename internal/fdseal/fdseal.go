// Package fdseal marks every file descriptor a process holds close-on-exec
// before it forks, so that a child receives EXACTLY the descriptors the fork
// was asked to install and nothing else.
//
// It exists as its own package, rather than staying the one function it used
// to be in internal/sandbox, because SUPERVISOR-PHASE1-SPEC.md's stage (P1) is
// a LONG-LIVED process that forks more than once. internal/sandbox's snug is a
// one-shot process: it opens exactly the descriptors one sandbox needs and
// forks exactly once. A long-lived forker is a different animal — its own
// descriptor table drifts over its lifetime — and review finding F1 was never
// really "fd 5 was missed", it was that shape.
//
// # The keep-list is empty, and that IS the fix
//
// The first cut of this package derived a keep-list from the *exec.Cmd being
// forked (cmd.ExtraFiles) and exempted it from the sweep. That reads as the
// careful thing to do and it is exactly what let the args memfd into the
// payload, READ-WRITE, on the stage path — found independently by two red
// teams. The mechanism, read out of Go's own fork/exec implementation
// (syscall/exec_linux.go, "Pass 1"/"Pass 2" in forkAndExecInChild) and
// MEASURED:
//
//   - Go installs the child's descriptors by dup3(source, target, 0). The
//     comment on that line reads "The new fd is created NOT close-on-exec,
//     which is exactly what we want". Where source == target it clears
//     FD_CLOEXEC explicitly instead.
//   - Go does NOT close the SOURCE descriptors. Its own comment says so:
//     "Programs that know they inherit fds >= 3 will need to set them
//     close-on-exec."
//
// So whenever a source number is HIGHER than the target number it is dup'd
// onto — which is the normal case in P1, where P0's descriptors arrive at 5..N
// and bwrap wants them at 3..N-2 — the source survives into the child at its
// old number, as a second, fully usable copy. Exempting cmd.ExtraFiles from
// the sweep is therefore not conservative; it is precisely the leak.
//
// Sealing the sources costs nothing, because Go re-establishes the child's
// copies itself, in both of its two cases. The keep-list is empty by
// construction rather than by care, and that is what makes "a payload holds no
// descriptor it can open" true for every future fork of every future shape,
// instead of true for the forks somebody remembered to enumerate.
package fdseal

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"golang.org/x/sys/unix"
)

// SealFor marks every descriptor this process holds close-on-exec, except
// fds 0/1/2, immediately before cmd is started.
//
// Nothing is kept. cmd is taken so the call site reads as what it is — the
// seal belongs to one specific fork — and so this function can refuse a
// command whose ExtraFiles have already been closed, which in a long-lived
// forker is the other half of the same drift problem: a stale *os.File in
// ExtraFiles makes exec.Cmd hand the child a descriptor number that now means
// something else entirely.
//
// It SETS the flag rather than closing the descriptor: closing an arbitrary fd
// in a Go process risks the runtime's own netpoller or file-table bookkeeping,
// while setting FD_CLOEXEC is harmless on a descriptor that already carries it
// — which includes everything Go itself opens.
func SealFor(cmd *exec.Cmd) error {
	for i, f := range cmd.ExtraFiles {
		if f == nil {
			return fmt.Errorf("fdseal: ExtraFiles[%d] is nil; the child would be handed a "+
				"closed descriptor at fd %d, and every later fd number in that list means "+
				"something other than what the caller computed", i, 3+i)
		}
		if _, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0); err != nil {
			return fmt.Errorf("fdseal: ExtraFiles[%d] (fd %d, %s) is already closed; the child "+
				"would be handed a descriptor that now means something else: %w",
				i, int(f.Fd()), f.Name(), err)
		}
	}
	return Seal()
}

// Seal marks every descriptor this process holds close-on-exec except stdio.
// Use it before a fork whose child's descriptors are installed by Go's
// exec machinery (which re-clears the flag on the child's copies).
func Seal() error { return sealExcept(nil) }

// SealExcept is Seal for the RAW exec case: syscall.Exec replaces this process
// image in place, so nothing re-clears FD_CLOEXEC afterwards and the
// descriptors the next program must inherit have to be named here.
//
// The keep list is a list of NUMBERS on purpose. Its one caller — the
// __innetns shim in internal/stage — is handed its keep set as a contiguous
// block whose bound arrives in its own argv, so the list is derived from the
// request rather than written down, in the same spirit as Seal's empty one.
func SealExcept(keep ...int) error { return sealExcept(keep) }

func sealExcept(keep []int) error {
	dir, err := os.Open("/proc/self/fd")
	if err != nil {
		return nil // not fatal: Go already marks its own fds CLOEXEC
	}
	defer dir.Close()

	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil
	}

	spare := map[int]bool{int(dir.Fd()): true}
	for _, fd := range keep {
		spare[fd] = true
	}

	for _, n := range names {
		fd, err := strconv.Atoi(n)
		if err != nil || fd <= 2 || spare[fd] {
			continue
		}
		flags, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_GETFD, 0)
		if errno != 0 {
			continue
		}
		if flags&unix.FD_CLOEXEC != 0 {
			continue
		}
		unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC)
	}
	return nil
}
