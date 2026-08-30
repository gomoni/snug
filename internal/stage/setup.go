package stage

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/policy"
)

// MainSetup is __stage-setup: P1's first instant of life after the clone that created
// U (its own user namespace) and N (the sandbox's private
// network namespace). It refuses immediately if the descriptors it requires —
// fdControl, fdLife — are not present, and is not reachable as ordinary CLI:
// internal/cli's hidden verb dispatch is the only caller.
//
// THE ORDER IS THE SPECIFICATION (SUPERVISOR-DESIGN.md §4 Step 4, extended
// by issue #63 Tier B's step 0):
//
//  0. Reserve fdNetSock and fdNetnsN, before this process has allocated a
//     descriptor of its own. Both are parked onto later, and dup3 onto an
//     occupied descriptor closes it and reports success — so the numbers are
//     CLAIMED here rather than checked at the parking, where the allocator
//     that would collide with them is the Go runtime's and nothing orders it
//     against a check. See reserveParkingFDs.
//  1. IF the uid/gid map was left for P0 to write (Config.Topology.Subuid ==
//     SubuidFull — see stage.go's own comment on why), ask for it over the
//     control socket, block until it lands, and RE-EXEC __stage-setup itself
//     before doing anything else. The re-exec is not optional and not
//     cosmetic: capabilities are only ever recalculated AT execve, never as a
//     side effect of uid_map being written, so the FIRST execve into
//     __stage-setup (which necessarily happens before the map exists) computes
//     an ordinary, unprivileged, empty-permitted set — the kernel's usual
//     "transitioning TO uid 0" bypass that gives a newly-root process the full
//     bounding set as its effective set never fires, because at that moment
//     the process is not yet uid 0 in its own namespace. MEASURED: after the
//     map lands, CapBnd already reads full and Uid already reads 0, but
//     CapEff/CapPrm read all-zero regardless — until a SECOND execve, which
//     this time computes capabilities with uid 0 already in effect and the
//     bypass fires for real. Skipped entirely, with zero behaviour change,
//     when U already carries the single-uid map Go wrote itself during the
//     clone (SubuidNone, still the default) — that map exists before the
//     first and only execve, so the bypass already fires there.
//  2. uid 0 / full caps, or refuse.
//  3. make / private.
//  4. open a socket IN N and bring lo up through it, then park that socket at
//     fdNetSock without CLOEXEC — both halves must happen while still in N,
//     because a socket's namespace is fixed at creation and lo is configured
//     in whichever namespace the caller is in. Both parkings (this one and
//     step 7) dup3 onto a number step 0 already reserved, and both refuse if
//     that reservation is gone.
//  5. lock the OS thread.
//  6. pin N via /proc/thread-self/ns/net.
//  7. dup3 it to fdNetnsN WITHOUT CLOEXEC — it must survive the exec that
//     follows.
//  8. unshare(CLONE_NEWNET); refuse if the calling thread did not move.
//  9. drop policy.StageCapDrop from this THREAD's bounding set. It has to be
//     here, on the locked thread, with the execve immediately after it:
//     PR_CAPBSET_DROP is per-task, and the execve is the only join point at
//     which a multithreaded Go process's credentials become the whole
//     process's — the same fact step 5 exists for. Anywhere else it is a
//     no-op that looks like it worked (dropFromBounding's own comment carries
//     the measurement).
//  10. exec __stage-serve with the drop as the ONLY thing in between and an
//     EMPTY environment. __stage-serve verifies the drop landed on every
//     thread and refuses to serve if it did not.
func MainSetup() error {
	requireFD(fdControl, "control")
	requireFD(fdLife, "lifeline")

	// FIRST, before the control-socket exchange below or anything else in this
	// process can allocate a descriptor: claim the two numbers the parkings
	// need. reserveParkingFDs' own comment carries the measurement for why
	// this is a claim and not a check.
	if err := reserveParkingFDs(); err != nil {
		return fmt.Errorf("__stage-setup: %w", err)
	}

	if os.Getuid() != 0 {
		// The map was deliberately left unwritten by Start (SubuidFull): this
		// process is the overflow uid until P0 delegates the full range via
		// newuidmap/newgidmap. Ask, and block — there is nothing useful this
		// process can do before its own identity exists. The control socket
		// itself needs no uid mapping to work; sockets do not care about
		// uid_map.
		control := os.NewFile(fdControl, "control") // never Closed: see below
		if err := sendEvent(control, event{Op: "needmap"}); err != nil {
			return fmt.Errorf("__stage-setup: asking for the delegated subuid map: %w", err)
		}
		req, err := recvRequest(control)
		if err != nil {
			return fmt.Errorf("__stage-setup: waiting for the delegated subuid map: %w", err)
		}
		if req.Op != "mapped" {
			return fmt.Errorf("__stage-setup: expected a \"mapped\" request, got %q", req.Op)
		}
		if os.Getuid() != 0 {
			return fmt.Errorf("__stage-setup: uid is still %d after the delegated map arrived", os.Getuid())
		}
		// control is intentionally not Closed here: doing so would close the
		// underlying fd (3) out from under the re-exec below, which reopens
		// it (as the SAME descriptor, since it is not CLOEXEC) the instant
		// this process image is replaced — long before Go's GC could ever
		// run this *os.File's finalizer, so leaving it unclosed leaks
		// nothing.
		//
		// See the function doc comment for WHY this re-exec exists: nothing
		// below this line has run yet with real capabilities, because the
		// FIRST execve into __stage-setup happened before the map did.
		return execSelf("__stage-setup")
	}

	if err := checkFullCaps(); err != nil {
		return fmt.Errorf("__stage-setup: %w", err)
	}

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
	// The target is the number step 0 reserved, so it must still be OPEN —
	// the inverse of the check this used to make, and the one that matches
	// what the reservation guarantees (issue #525).
	if err := requireFDReserved(fdNetSock, "the N socket"); err != nil {
		unix.Close(netSock)
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
	// Same inverse check as the N socket's parking: fdNetnsN is reserved, so
	// its reservation must still be there at the instant of the dup3. f cannot
	// have taken the number — the reservation is what stopped it (issue #525).
	if err := requireFDReserved(fdNetnsN, "the pinned netns descriptor"); err != nil {
		f.Close()
		return fmt.Errorf("__stage-setup: %w", err)
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
	//
	// The one thing between the netns move and that execve, and it must be
	// between them rather than earlier or later: see step 9, and
	// dropFromBounding on why the locked thread is load-bearing.
	if err := dropFromBounding(policy.StageCapDrop); err != nil {
		return fmt.Errorf("__stage-setup: %w", err)
	}
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
