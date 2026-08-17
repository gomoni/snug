package stage

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// MainSetup is __stage-setup: P1's first instant of life after the clone that created
// U (its own user namespace, ONE uid mapped) and N (the sandbox's private
// network namespace). It refuses immediately if the descriptors it requires —
// fdControl, fdLife — are not present, and is not reachable as ordinary CLI:
// internal/cli's hidden verb dispatch is the only caller.
//
// THE ORDER IS THE SPECIFICATION (SUPERVISOR-DESIGN.md §4 Step 4):
//
//  1. uid 0 / full caps, or refuse.
//  2. make / private.
//  3. open a socket IN N and bring lo up through it, then park that socket at
//     fdNetSock without CLOEXEC — both halves must happen while still in N,
//     because a socket's namespace is fixed at creation and lo is configured
//     in whichever namespace the caller is in.
//  4. lock the OS thread.
//  5. pin N via /proc/thread-self/ns/net.
//  6. dup3 it to fdNetnsN WITHOUT CLOEXEC — it must survive the exec that
//     follows.
//  7. unshare(CLONE_NEWNET); refuse if the calling thread did not move.
//  8. exec __stage-serve with NOTHING in between and an EMPTY environment.
func MainSetup() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("__stage-setup: uid is %d, expected 0 — the single-uid map did not land", os.Getuid())
	}
	if err := checkFullCaps(); err != nil {
		return fmt.Errorf("__stage-setup: %w", err)
	}
	requireFD(fdControl, "control")
	requireFD(fdLife, "lifeline")

	// Two reasons, both load-bearing: overlayfs (a future engine stage) refuses
	// to work in a shared mount tree, and a private tree is what stops the
	// sandbox's own mount events propagating back to the host.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("__stage-setup: making / private: %w", err)
	}

	// lo comes up in N, while P1 is still in it. After the move this would
	// configure the WRONG (empty) namespace — §3.5.
	//
	// The socket is KEPT, not closed, and that is what deletes the parked
	// window. A socket's network namespace is fixed at creation, so this one
	// still answers for N after the move — which is how __stage-serve can be
	// asked "is pasta's interface up?" with no process inside N. Before this,
	// readiness needed a process in N, so bwrap had to be started first and its
	// payload parked until pasta arrived, and that parking is what a SIGKILL of
	// snug could release early.
	netSock, err := openNetSocketInN()
	if err != nil {
		return fmt.Errorf("__stage-setup: %w", err)
	}
	// Same dup3-with-flags-0 discipline as the netns descriptor below: NOT
	// CLOEXEC, because it has to survive the execve into __stage-serve.
	if err := unix.Dup3(netSock, fdNetSock, 0); err != nil {
		unix.Close(netSock)
		return fmt.Errorf("__stage-setup: parking the N socket at fd %d: %w", fdNetSock, err)
	}
	unix.Close(netSock)

	runtime.LockOSThread()

	// /proc/thread-self, not /proc/self: see nsutil.go's doc comment.
	before := threadNS("net")
	f, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return fmt.Errorf("__stage-setup: pinning N: %w", err)
	}
	// dup3 with flags 0: the new descriptor is deliberately NOT CLOEXEC. It has
	// to survive the very execve that makes the move stick — marking it
	// CLOEXEC here, as a naive reading of the plan would, destroys the only
	// reference to N.
	if err := unix.Dup3(int(f.Fd()), fdNetnsN, 0); err != nil {
		f.Close()
		return fmt.Errorf("__stage-setup: pinning N at fd %d: %w", fdNetnsN, err)
	}
	f.Close()

	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("__stage-setup: unshare(CLONE_NEWNET): %w", err)
	}
	after := threadNS("net")
	if before == after || after == "" {
		return fmt.Errorf("__stage-setup: unshare(CLONE_NEWNET) reported success but the calling "+
			"thread is still in %s", before)
	}

	// syscall.Exec, not os/exec: this must be THE SAME PROCESS IMAGE re-executing
	// on the locked thread, with nothing in between — that collapse onto the
	// calling thread is the only join point at which a multithreaded Go process
	// moves as a whole (measured, SUPERVISOR-DESIGN.md §1). /proc/self/exe,
	// never a path from the environment: a path taken from the environment is a
	// same-uid replacement window the previous generation's review found.
	return execSelf("__stage-serve")
}

// requireFD refuses to continue if fd is not open — "refuses immediately when
// the descriptors it requires are absent" (SUPERVISOR-DESIGN.md §4 Step
// 4). It cannot return an error cleanly (this runs before any recover-and-log
// path exists), so it fails loudly and immediately: __stage-setup/__stage-serve/__innetns
// are unreachable except through the fork that sets these fds up, and a missing
// one means something is invoking them directly, which is not a supported entry
// point.
func requireFD(fd int, name string) {
	if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_GETFD, 0); errno != 0 {
		fmt.Fprintf(os.Stderr, "snug: internal error: fd %d (%s) is not open; this verb is not "+
			"a supported entry point on its own\n", fd, name)
		os.Exit(1)
	}
}
