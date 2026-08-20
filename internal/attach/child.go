package attach

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// child is the WHOLE of B's job, and then A's: block signals, PDEATHSIG,
// NNP, seccomp, the one setns, drop the capability bounding set, capset
// zeroed, report and wait for the release gate, chdir, fork A, and (in A)
// dup the stdio into place, claim the pty as A's controlling terminal on
// the pty path, restore the signal mask and execve — while B waits for A
// and exits with its status.
//
// EVERY step below is a raw syscall. See the package comment for why: this
// function runs in a process that exists ONLY because it skipped the Go
// scheduler at fork(2), and it stays that way exactly until it calls
// execve or exit_group — nothing here may allocate, lock, defer, print, or
// otherwise ask the Go runtime for anything.
//
// On the pty path (m.pty), A also calls setsid() and ioctl(0, TIOCSCTTY)
// immediately before its execve — see the field comment on Config.PTY. Both
// are raw syscalls issued the same way as everything else here, and are
// skipped entirely on the pipe path, where fd 0 was never a tty.
//
// There is deliberately no error return and no panic recovery: a failure at
// any step means confinement was NOT fully applied, and the one correct
// response is to exit immediately without ever reaching the release gate or
// the exec, so the caller's gate (§4.2a) sees B either report success or die
// — never a B that is running unconfined.
//
// # Why every function here carries //go:nosplit
//
// "Nothing here may ask the Go runtime for anything" is not something a
// reader can uphold by inspection alone: an ORDINARY function's PROLOGUE
// asks, before its first statement runs, by comparing SP against a
// stackguard0 the runtime poisons whenever it wants this goroutine
// preempted. That is issue #221 — measured as a fork child wedged in
// futex_do_wait forever, having executed not one instruction of step 1.
// //go:nosplit removes the prologue; //go:norace and //go:nocheckptr remove
// the instrumentation a -race build would otherwise inject into the same
// path. Every one of these is load-bearing on EVERY function reachable from
// child, which is why the list is asserted mechanically
// (TestEveryFunctionOnTheChildPathIsNosplit) rather than left to review.
//
//go:nosplit
//go:norace
//go:nocheckptr
func child(m *marshalled) {
	// 1. Block every signal for the whole of B's raw-syscall sequence. A
	// signal delivered here would run whatever handler this process image
	// has installed — copied verbatim from the parent at fork — and Go's own
	// handlers reach into scheduler state that does not exist correctly in a
	// process that will never be scheduled by the Go runtime again. A
	// restores cfg.SignalMask immediately before its own execve (step 10).
	//
	// The mask is ALREADY blocked when control arrives here: Start blocks it
	// on the forking thread before the clone, because everything this
	// paragraph describes is equally true of the window BETWEEN the clone
	// and this line, which no statement inside child() can ever cover. This
	// line is therefore belt-and-braces, and stays because it is where a
	// reader of B's sequence looks for the property.
	var full [sigsetSize]byte
	for i := range full {
		full[i] = 0xff
	}
	rtSigprocmaskRaw(sigSetmask, &full, nil)

	// 2. C dies -> B dies. Armed before anything else so a killed attach
	// client cannot leave B running unconfined in the sandbox's namespaces.
	prctlRaw(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0)

	// 3. Required before seccomp (step 4): SECCOMP_SET_MODE_FILTER refuses
	// without NO_NEW_PRIVS or CAP_SYS_ADMIN, and B deliberately has neither
	// yet.
	if _, err := prctlRaw(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != 0 {
		exitGroupRaw(1)
	}

	// 4. Installed BEFORE the namespace join (step 5): a seccomp filter can
	// never be removed, so every syscall from here on — including the setns
	// itself and every failure path below it — runs with the filter already
	// active. Fail-closed. Nil Filter (m.sockFprog.Len == 0) means the run
	// was started with --no-seccomp; attach honours that rather than adding
	// a second weakening knob, and installs nothing.
	if m.sockFprog.Len != 0 {
		_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP,
			uintptr(unix.SECCOMP_SET_MODE_FILTER), 0, uintptr(unsafe.Pointer(&m.sockFprog)))
		if errno != 0 {
			exitGroupRaw(2)
		}
	}

	// 5. The one setns, all seven namespaces at once — see SevenNamespaceFlags'
	// doc comment for why one call and not several, and bridge.go's package
	// comment for why the pidfd names the sandbox's init and never the
	// payload, the outer bwrap, or (on the @net topology) the stage.
	if _, _, errno := unix.RawSyscall(unix.SYS_SETNS,
		uintptr(m.pidfd), uintptr(SevenNamespaceFlags), 0); errno != 0 {
		exitGroupRaw(3)
	}

	// 6. NOT optional, and not movable earlier: setns(CLONE_NEWUSER) resets
	// the capability bounding set to full (kernel: set_cred_user_ns sets
	// cap_bset = CAP_FULL_SET), so a drop before step 5 would be theatre —
	// exactly the shape internal/policy/bwrap.go's own --cap-drop ALL comment
	// records for --unshare-user. cfg.CapLastCap is read by the caller from
	// /proc/sys/kernel/cap_last_cap at run time, never hardcoded: a kernel
	// with more capabilities than this binary knows about would otherwise
	// leave the new ones in the bounding set silently.
	for c := 0; c <= m.capLastCap; c++ {
		if _, _, errno := unix.RawSyscall6(unix.SYS_PRCTL,
			uintptr(unix.PR_CAPBSET_DROP), uintptr(c), 0, 0, 0, 0); errno != 0 {
			exitGroupRaw(4)
		}
	}

	// 7. Effective, permitted and inheritable all zeroed; ambient empties
	// itself once permitted does. Issued raw rather than through
	// unix.Capset, which is RawSyscall-backed but is itself an ordinary
	// (splittable) Go function — and a splittable call anywhere on this path
	// is issue #221's hang, see Start's comment at the fork.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if _, _, errno := unix.RawSyscall(unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		exitGroupRaw(5)
	}

	// 8. The release gate (§4.2a). B reports it is fully confined and BLOCKS
	// until the caller (C), having read /proc/<B>/status and verified all
	// four lines plus the six namespace ids independently, releases it. This
	// is the answer to "--seccomp after bwrap's -- installed nothing, exit
	// code 0" one layer up: a security feature that was merely REQUESTED is
	// not the same claim as one VERIFIED active, and the program the user
	// asked for has not been exec'd yet at this point — a mismatch here
	// means C kills B and A never exists.
	reportByte := [1]byte{'C'} // "confined"
	writeRaw(m.reportW, reportByte[:])
	var gateByte [1]byte
	readRaw(m.gateR, gateByte[:])

	// 9. Resolved in the sandbox's own mount namespace, which is why this
	// runs after step 5, not before.
	if _, _, errno := unix.RawSyscall(unix.SYS_CHDIR,
		uintptr(unsafe.Pointer(&m.chdirC[0])), 0, 0); errno != 0 {
		exitGroupRaw(6)
	}

	// 10. The second fork. CLONE_NEWPID applies to CHILDREN of the caller,
	// not the caller itself (measured: B's own ns/pid stays the HOST's; only
	// ns/pid_for_children became the sandbox's at step 5) — so A, and only
	// A, is actually inside the sandbox's pid namespace. A inherits full
	// confinement by DESCENT from a B that is already fully confined, rather
	// than reproducing it a second time.
	apid, _, errno := unix.RawSyscall6(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0, 0, 0, 0)
	if errno != 0 {
		exitGroupRaw(7)
	}
	if apid == 0 {
		// A. Stdio into place, the caller's ORIGINAL signal mask restored
		// (so the exec'd program behaves like any other process instead of
		// one born with every signal blocked), PDEATHSIG on ITS OWN parent
		// (B) so a killed B does not leave A behind, then execve.
		dup3Raw(m.stdin, 0)
		dup3Raw(m.stdout, 1)
		dup3Raw(m.stderr, 2)
		if m.pty {
			// Job control (issue: attach's pty gave no controlling
			// terminal, so an interactive shell printed "cannot set
			// terminal process group" and "no job control in this
			// shell"). setsid() first: it makes A the leader of a brand
			// new session with no controlling terminal of its own, which
			// is the precondition ioctl(TIOCSCTTY) needs to succeed. Only
			// then does TIOCSCTTY on fd 0 — the pty slave just dup3'd
			// above — make that pty A's controlling terminal. Best-effort,
			// like dup3Raw above: this is interactive UX, not confinement
			// (that was already fully applied and released before A was
			// forked), so a failure here falls through to execve rather
			// than aborting the session.
			setsidRaw()
			ioctlSetCttyRaw(0)
		}
		rtSigprocmaskRaw(sigSetmask, &m.signalMask, nil)
		prctlRaw(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0)
		unix.RawSyscall(unix.SYS_EXECVE,
			uintptr(unsafe.Pointer(&m.argv0C[0])),
			uintptr(unsafe.Pointer(&m.argvPtrs[0])),
			uintptr(unsafe.Pointer(&m.envpPtrs[0])))
		// execve only returns on failure.
		exitGroupRaw(126)
	}

	// 11. B: wait for A, exit with its status. B never execs — its only job,
	// from here to the end of its life, is to be the process that was
	// allowed to have a child in the sandbox's pid namespace.
	var status uint32
	unix.RawSyscall6(unix.SYS_WAIT4, uintptr(apid), uintptr(unsafe.Pointer(&status)), 0, 0, 0, 0)
	exitGroupRaw(int(waitStatusToExitCode(status)))
}

// waitStatusToExitCode mirrors syscall.WaitStatus's own decoding without
// calling into it — that type's methods are ordinary Go and safe to call from
// anywhere BUT here, since this runs inside B, which must not call anything
// this package has not written itself. The shape (low byte 0 => exited,
// exit code in the next byte up; otherwise signalled, 128+signal) is the
// same convention every shell and every other wait4 caller in this tree
// already relies on.
//
//go:nosplit
//go:norace
//go:nocheckptr
func waitStatusToExitCode(status uint32) uint32 {
	if status&0x7f == 0 {
		return (status >> 8) & 0xff
	}
	return 128 + (status & 0x7f)
}

// The raw syscall helpers below exist because golang.org/x/sys/unix's own
// wrappers for prctl and setns are Syscall/Syscall6-backed (they call into
// the Go scheduler's entersyscall/exitsyscall), and there is no wrapper at
// all for seccomp(2). Every one of these takes only scalars and pointers
// into memory the caller already owns — none of them allocates.

//go:nosplit
//go:norace
//go:nocheckptr
func prctlRaw(option uintptr, a2, a3, a4, a5 uintptr) (uintptr, unix.Errno) {
	r, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, option, a2, a3, a4, a5, 0)
	return r, errno
}

//go:nosplit
//go:norace
//go:nocheckptr
func dup3Raw(oldfd, newfd int) {
	if oldfd == newfd {
		return
	}
	unix.RawSyscall(unix.SYS_DUP3, uintptr(oldfd), uintptr(newfd), 0)
}

// setsidRaw makes the caller the leader of a new session with no
// controlling terminal — setsid(2)'s only two possible outcomes are success
// or EPERM (the caller is already a process group leader), and there is
// nothing this doomed-to-never-schedule-again child could do about the
// latter beyond falling through, exactly as dup3Raw does above.
//
//go:nosplit
//go:norace
//go:nocheckptr
func setsidRaw() {
	unix.RawSyscall(unix.SYS_SETSID, 0, 0, 0)
}

// ioctlSetCttyRaw is ioctl(fd, TIOCSCTTY, 0): if fd refers to a tty and the
// caller has no controlling terminal, that tty becomes it. The third
// argument (0) is TIOCSCTTY's "arg" — nonzero would force the steal of a
// terminal already controlling another session, which A never wants.
//
//go:nosplit
//go:norace
//go:nocheckptr
func ioctlSetCttyRaw(fd int) {
	unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TIOCSCTTY), 0)
}

//go:nosplit
//go:norace
//go:nocheckptr
func writeRaw(fd int, b []byte) {
	if len(b) == 0 {
		return
	}
	unix.RawSyscall(unix.SYS_WRITE, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

//go:nosplit
//go:norace
//go:nocheckptr
func readRaw(fd int, b []byte) {
	if len(b) == 0 {
		return
	}
	unix.RawSyscall(unix.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}

// rtSigprocmaskRaw sets (SIG_SETMASK) or blocks (SIG_BLOCK) the calling
// thread's signal mask. old may be nil.
//
//go:nosplit
//go:norace
//go:nocheckptr
func rtSigprocmaskRaw(how uintptr, set *[sigsetSize]byte, old *[sigsetSize]byte) {
	var oldPtr uintptr
	if old != nil {
		oldPtr = uintptr(unsafe.Pointer(old))
	}
	unix.RawSyscall6(unix.SYS_RT_SIGPROCMASK, how, uintptr(unsafe.Pointer(set)), oldPtr, sigsetSize, 0, 0)
}

//go:nosplit
//go:norace
//go:nocheckptr
func exitGroupRaw(code int) {
	unix.RawSyscall(unix.SYS_EXIT_GROUP, uintptr(code), 0, 0)
	// exit_group does not return. If it somehow did, looping here is still
	// safer than falling back into Go code this process must not run.
	for {
		unix.RawSyscall(unix.SYS_EXIT_GROUP, uintptr(code), 0, 0)
	}
}
