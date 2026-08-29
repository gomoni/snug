// Command int80probe issues a syscall through the i386 compat entry point
// `int $0x80` from a NATIVE 64-bit binary. That is issue #529's bypass in its
// strongest form, and it is the reason the arch rule is not merely a nicety
// for people who ship 32-bit binaries: reaching the compat syscall table needs
// no 32-bit toolchain, no 32-bit libc and no 32-bit ELF. It is two bytes of
// machine code inside an ordinary amd64 program.
//
// The kernel serves `int $0x80` from the i386 table and reports AUDIT_ARCH_I386
// to seccomp, so before the fix this call went straight past a filter whose
// every comparison is an x86_64 number.
//
// Found by the redteam round on the #529 fix, which ran the equivalent as a
// freestanding C binary. This is the committed form of that attack.
package main

import "fmt"

func main() {
	fmt.Println("start=OK")
	if !int80Supported {
		fmt.Println("supported=false")
		return
	}
	// i386 __NR_unshare is 310 — a DIFFERENT number from x86_64's 272, which
	// is the whole point: under AUDIT_ARCH_I386 the filter's numbers name
	// other syscalls entirely.
	//
	// The raw i386 return convention puts -errno in the return register, so
	// -1 is EPERM (what snug's filter returns for a denied NATIVE call) and
	// anything else is the kernel's own answer. It is EINVAL here because the
	// Go runtime is multithreaded and unshare(CLONE_NEWUSER) refuses that;
	// what matters is only that the call reached the kernel at all.
	r := int80(310, 0x10000000, 0, 0)
	fmt.Printf("int80_unshare_ret=%d\n", int64(r))
	fmt.Println("survived=OK")
}
