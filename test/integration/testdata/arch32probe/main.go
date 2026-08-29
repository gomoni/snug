// Command arch32probe reports whether the seccomp filter reached the syscalls
// this process issues. It is built TWICE from this one file — once for GOARCH
// 386 and once for the native GOARCH — and the pair is the whole measurement
// for issue #529: the same source, the same host, the same sandbox, differing
// only in which audit arch its syscalls arrive under.
//
// It calls unshare(CLONE_NEWUSER) and ptrace, two calls snug's filter denies
// with EPERM on the native arch. What matters is not that they fail but WHOSE
// answer comes back: EPERM is the filter's, and anything else (EINVAL from
// unshare, success from a no-op ptrace) is the kernel's and means the call
// went past the filter untouched.
//
// It prints "name=RESULT" lines, the convention every probe in this suite
// shares (parseProbeFields, pidfd_test.go). "start" is printed first and
// deliberately: on the filtered 32-bit run nothing is printed at all, because
// the write(2) that would print it is itself killed, and an empty output has
// to be distinguishable from a probe that failed to launch.
package main

import (
	"fmt"
	"syscall"
)

// CLONE_NEWUSER. Not taken from x/sys/unix: this file is compiled for GOARCH
// 386 as well, and the constant is the same number on every architecture.
const cloneNewUser = 0x10000000

func main() {
	fmt.Println("start=OK")

	_, _, errno := syscall.Syscall(syscall.SYS_UNSHARE, cloneNewUser, 0, 0)
	fmt.Printf("unshare_errno=%d\n", errno)

	// PTRACE_TRACEME(0) against no target. Harmless, and it reaches the
	// syscall entry point, which is all this needs to observe.
	_, _, errno2 := syscall.Syscall(syscall.SYS_PTRACE, 0, 0, 0)
	fmt.Printf("ptrace_errno=%d\n", errno2)
}
