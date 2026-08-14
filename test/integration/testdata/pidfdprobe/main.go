// Command pidfdprobe is a self-contained regression probe for issue #23's
// seccomp fix (deniedSyscalls in internal/sandbox/seccomp.go now includes
// pidfd_getfd, process_vm_readv and process_vm_writev; pidfd_open is left
// allowed). None of the three denied syscalls is shell-reachable — no shell
// builtin or /bin/* utility calls them — so the integration test builds and
// runs this binary inside the sandbox rather than scripting bash, the same
// way TestMain builds cmd/snug itself.
//
// This directory is named testdata, so the Go toolchain ignores it for
// `go build ./...`, `go vet ./...` and `go test ./...` at every other
// location in the module; only the integration test compiles it, explicitly,
// the same way it compiles cmd/snug.
//
// With no arguments it runs selfProbe (below). Two more subcommands, "victim"
// and "attacker", exist for the issue #47 residual: a real sibling-to-sibling
// probe of /proc/<pid>/mem needs two separate processes coordinating through
// files in the shared target directory, which selfProbe's single-process
// shape cannot express. See test/integration/pidfd_test.go for how they are
// driven together.
//
// # Why selfProbe targets the CALLING PROCESS ITSELF
//
// On a host with kernel.yama.ptrace_scope=1 (this host, and most CI images by
// default), a SIBLING's call to any of these three syscalls already returns
// EPERM whether or not snug's seccomp filter is installed at all — Yama gets
// there first. A test built on the sibling case cannot tell "the filter did
// this" apart from "the host was always going to do this", which is exactly
// the shape of test that cannot fail: CLAUDE.md carries the scar of one
// (`pasta.avx2` never matching the literal string "pasta").
//
// task == current skips ptrace_may_access entirely for pidfd_getfd and for
// process_vm_readv/writev, so the SELF case succeeds on an unfiltered kernel
// and fails, specifically with EPERM, only once snug's seccomp filter is the
// thing doing the denying. See issues #23 and #47 for the measurements this
// probe mechanises.
//
// Output is one "name=RESULT" line per probe, RESULT being "OK" or an errno's
// short name, so the test asserts an exact token rather than matching prose.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// report prints "name=RESULT": OK, an errno's short name (unwrapped through
// however the standard library chose to wrap it — os.OpenFile/ReadAt/WriteAt
// return *fs.PathError, the raw unix.* wrappers return unix.Errno directly),
// or the error's own text as a last resort.
func report(name string, err error) {
	if err == nil {
		fmt.Printf("%s=OK\n", name)
		return
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		fmt.Printf("%s=%s\n", name, errno.Error())
		return
	}
	fmt.Printf("%s=OTHER:%v\n", name, err)
}

// secretText and pwnedText are the two payloads the /proc/<pid>/mem residual
// probe (victim/attacker) uses. Same length so a fixed-size buffer can hold
// either.
const secretText = "SIBLING-SECRET-DO-NOT-READ"

var pwnedText = mustPad("PWNED-VIA-PROCMEM-WRITE!", len(secretText))

// mustPad returns s padded with '!' to exactly n bytes, or truncated to it.
// Used only for the two fixed-width probe payloads above; panics on a length
// bug in this file, never on probe input.
func mustPad(s string, n int) string {
	for len(s) < n {
		s += "!"
	}
	return s[:n]
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "victim":
			victim(os.Args[2:])
			return
		case "attacker":
			attacker(os.Args[2:])
			return
		}
	}
	selfProbe()
}

// victim allocates a buffer holding secretText, prints its own pid and the
// buffer's address, then waits for a "victim-done" file to appear in the
// current directory (written by the attacker once it has finished) before
// printing the buffer back out as VICTIM-FINAL — so the test can tell,
// without any special access of its own, whether the attacker's write
// actually landed.
//
// With the first argument "--ptracer-any", it first calls
// prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) — the non-root way a process
// waives Yama's ptrace_scope=1 descendant check for itself, i.e. how a
// ptrace_scope=1 host (this one) is made to behave like the ptrace_scope=0
// host issue #47 is about. ptrace_scope=0 is not a hardened edge case for
// snug: it is the common state inside a container, which key feature 3 says
// snug must work from.
func victim(args []string) {
	if len(args) > 0 && args[0] == "--ptracer-any" {
		if err := unix.Prctl(unix.PR_SET_PTRACER, uintptr(unix.PR_SET_PTRACER_ANY), 0, 0, 0); err != nil {
			fmt.Println("VICTIM-PTRACER-ANY-FAILED=" + err.Error())
			return
		}
	}

	// make+copy, not a string-literal conversion — see selfProbe's comment on
	// process_vm_writev's target buffer for why: a []byte built straight from
	// a string constant can be backed by the binary's read-only rodata, and a
	// write into it then faults for a reason that has nothing to do with the
	// sandbox.
	secret := make([]byte, len(secretText))
	copy(secret, secretText)

	fmt.Printf("VICTIM-PID=%d\n", os.Getpid())
	fmt.Printf("VICTIM-ADDR=%d\n", uintptr(unsafe.Pointer(&secret[0])))

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat("victim-done"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Printed unconditionally, timeout or not: a victim that waited out the
	// full deadline should still show whatever its buffer holds, since a
	// missing "victim-done" file is itself something the test wants to see
	// rather than have this process hide by exiting silently.
	fmt.Printf("VICTIM-FINAL=%s\n", string(secret))
}

// attacker takes the victim's pid and buffer address (as printed by victim,
// above) and tries two independent routes into it: /proc/<pid>/mem, an
// ordinary open+pread/pwrite gated by Yama rather than any syscall a filter
// can name, and process_vm_readv/writev, which issue #23 denies outright and
// unconditionally — the filter runs at syscall entry, before the kernel ever
// reaches Yama's PR_SET_PTRACER check, so this half must read EPERM whether
// or not the victim opted in.
func attacker(args []string) {
	// The in-suite caller always supplies both (pidfd_test.go builds the
	// command line from victim's own printed output), so this cannot fire
	// today — but the package doc above presents victim/attacker as
	// hand-runnable, and an index panic is a worse diagnostic than the
	// ATTACKER-BAD-PID/-ADDR lines two lines down already know how to print
	// for a value that parses badly. A missing one is the same story.
	if len(args) < 2 {
		fmt.Println("ATTACKER-USAGE=attacker <pid> <addr>")
		return
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Println("ATTACKER-BAD-PID")
		return
	}
	addr, err := strconv.ParseUint(args[1], 10, 64)
	if err != nil {
		fmt.Println("ATTACKER-BAD-ADDR")
		return
	}

	// /proc/<pid>/mem: the issue #47 residual. open(2) is ordinary DAC plus
	// Yama's PTRACE_MODE_ATTACH check (ptrace_scope) — no syscall here for a
	// classic-BPF filter to single out.
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, openErr := os.OpenFile(memPath, os.O_RDWR, 0)
	report("PROCMEM_OPEN", openErr)
	if openErr == nil {
		defer f.Close()

		buf := make([]byte, len(secretText))
		n, err := f.ReadAt(buf, int64(addr))
		if err != nil {
			report("PROCMEM_READ", err)
		} else {
			fmt.Printf("PROCMEM_READ=OK content=%q n=%d\n", string(buf[:n]), n)
		}

		payload := make([]byte, len(pwnedText))
		copy(payload, pwnedText)
		n2, err := f.WriteAt(payload, int64(addr))
		if err != nil {
			report("PROCMEM_WRITE", err)
		} else {
			fmt.Printf("PROCMEM_WRITE=OK bytes=%d\n", n2)
		}
	}

	// process_vm_readv/writev, sibling to sibling. Denied unconditionally by
	// issue #23's fix — this must be EPERM in every run this binary makes,
	// with or without --ptracer-any, which is the point: the syscall route is
	// closed regardless of what Yama would have allowed, while the procfs
	// route above is not.
	dst := make([]byte, len(secretText))
	localRead := []unix.Iovec{{Base: &dst[0], Len: uint64(len(dst))}}
	remoteRead := []unix.RemoteIovec{{Base: uintptr(addr), Len: len(secretText)}}
	_, err = unix.ProcessVMReadv(pid, localRead, remoteRead, 0)
	report("VMREAD_SIBLING", err)

	wpayload := make([]byte, len(pwnedText))
	copy(wpayload, pwnedText)
	localWrite := []unix.Iovec{{Base: &wpayload[0], Len: uint64(len(wpayload))}}
	remoteWrite := []unix.RemoteIovec{{Base: uintptr(addr), Len: len(secretText)}}
	_, err = unix.ProcessVMWritev(pid, localWrite, remoteWrite, 0)
	report("VMWRITE_SIBLING", err)
}

// selfProbe is the original issue #23 regression probe: every syscall below
// is aimed at the calling process's OWN pid/fd/memory. See the package doc
// for why.
func selfProbe() {
	pid := os.Getpid()

	// POSITIVE CONTROL: pidfd_open on SELF must succeed whether or not the
	// filter is installed. Issue #23 deliberately leaves it allowed — it hands
	// out a handle, not a descriptor, and Phase 2's attach path wants it. This
	// line proves the family is reachable at all and that the filter (once
	// installed) is selective rather than the syscall being unavailable on this
	// host/kernel.
	pidfd, err := unix.PidfdOpen(pid, 0)
	report("pidfd_open", err)
	if err != nil {
		fmt.Println("pidfd_getfd=SKIPPED-no-pidfd")
	} else {
		defer unix.Close(pidfd)

		// pidfd_getfd on SELF's own stdin (fd 0). task == current, so
		// ptrace_may_access is never consulted — this is the SELF case the
		// audit measured succeeding today and denied only once
		// unix.SYS_PIDFD_GETFD is in deniedSyscalls.
		stolen, err := unix.PidfdGetfd(pidfd, 0, 0)
		report("pidfd_getfd", err)
		if err == nil {
			unix.Close(stolen)
		}
	}

	// process_vm_readv on SELF's own memory, through the syscall path (not a
	// plain Go memory access) — reads a buffer this same process owns.
	secret := []byte("VMREAD-MARKER-OK")
	dst := make([]byte, len(secret))
	localRead := []unix.Iovec{{Base: &dst[0], Len: uint64(len(dst))}}
	remoteRead := []unix.RemoteIovec{{Base: uintptr(unsafe.Pointer(&secret[0])), Len: len(secret)}}
	n, err := unix.ProcessVMReadv(pid, localRead, remoteRead, 0)
	report("process_vm_readv", err)
	if err == nil && n == len(secret) && string(dst) == string(secret) {
		fmt.Println("process_vm_readv_effect=CONFIRMED")
	}

	// process_vm_writev on SELF's own memory. The audit measured this as the
	// worse half sibling-to-sibling — a payload did not merely READ another's
	// memory, it REWROTE it. This is the same call aimed at the caller's own
	// buffer, so the effect is unambiguous: `target` starts as all-A and must
	// read back as the payload string if (and only if) the write went through.
	payload := []byte("PWNED-BY-SIBLING!!")
	// make+copy, not a string-literal conversion: converting a string constant
	// straight to []byte can leave the compiler free to back it with the
	// binary's read-only rodata (nothing in ordinary Go code ever assigns
	// through it), and the kernel then faults writing into it — a compiler
	// artifact indistinguishable from the syscall being refused. A fresh
	// make() is unambiguously a mutable heap allocation.
	target := make([]byte, len(payload))
	copy(target, "AAAAAAAAAAAAAAAAAA")
	localWrite := []unix.Iovec{{Base: &payload[0], Len: uint64(len(payload))}}
	remoteWrite := []unix.RemoteIovec{{Base: uintptr(unsafe.Pointer(&target[0])), Len: len(target)}}
	n2, err := unix.ProcessVMWritev(pid, localWrite, remoteWrite, 0)
	report("process_vm_writev", err)
	if err == nil && n2 == len(payload) && string(target) == string(payload) {
		fmt.Println("process_vm_writev_effect=CONFIRMED")
	}

	// POSITIVE CONTROL: requested is not the same as active
	// (TestSeccompIsActuallyInstalled's whole point) — fold the kernel's own
	// view into this same probe run so it sits beside the syscalls it gates.
	if f, err := os.Open("/proc/self/status"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "Seccomp:") {
				fmt.Printf("seccomp_status=%s\n", strings.TrimSpace(strings.TrimPrefix(line, "Seccomp:")))
			}
		}
		f.Close()
	}
}
