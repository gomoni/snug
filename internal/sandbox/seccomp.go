// Package sandbox turns a resolved policy into a running process: it builds the
// seccomp filter, stages file descriptors, execs bwrap, and propagates the exit
// code. Everything here touches the OS. The decisions were all made in
// internal/policy, which does not.
package sandbox

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// The seccomp filter is DEFENCE IN DEPTH, not the boundary. The boundary is the
// namespace set: if that fails this filter does not save you, and if this filter
// is unavailable the sandbox is still a sandbox. That is why it is the one
// subsystem allowed to degrade with a warning instead of refusing to run.
//
// It is a denylist, which is the weaker of the two shapes. An allowlist would be
// stronger and would also break arbitrary programs the moment libc reaches for a
// syscall nobody predicted — a bad trade for a tool whose job is running other
// people's build systems.

// classic BPF opcodes (linux/filter.h)
const (
	bpfLdWAbs = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJsetK  = 0x45 // BPF_JMP | BPF_JSET | BPF_K
	bpfRetK   = 0x06 // BPF_RET | BPF_K
)

const (
	seccompRetAllow = 0x7fff0000
	seccompRetErrno = 0x00050000 // | (errno & 0xffff)
	retEPERM        = seccompRetErrno | uint32(unix.EPERM)
	retENOSYS       = seccompRetErrno | uint32(unix.ENOSYS)
)

// Offsets into struct seccomp_data: nr, arch, instruction_pointer, args[6].
// args are 64-bit; on little-endian the low word sits at the base offset, which
// is the half we compare.
const (
	offNR   = 0
	offArch = 4
	offArg0 = 16
	offArg1 = 24
)

// audit arch values (linux/audit.h)
const (
	auditArchX86_64  = 0xC000003E
	auditArchAArch64 = 0xC00000B7
)

func nativeAuditArch() (uint32, bool) {
	switch runtime.GOARCH {
	case "amd64":
		return auditArchX86_64, true
	case "arm64":
		return auditArchAArch64, true
	default:
		return 0, false
	}
}

// deniedSyscalls are refused with EPERM. Each is an escape or introspection
// primitive a build system has no business calling:
//
//	ptrace           attach to and rewrite another process in the sandbox
//	bpf              load kernel programs
//	userfaultfd      a standard primitive for winning kernel races
//	perf_event_open  broad kernel introspection, historically a rich CVE seam
//	add_key/keyctl/request_key
//	                 the kernel keyring, which is NOT namespaced by the user
//	                 namespace and therefore reaches outside the sandbox
var deniedSyscalls = []int{
	unix.SYS_PTRACE,
	unix.SYS_BPF,
	unix.SYS_USERFAULTFD,
	unix.SYS_PERF_EVENT_OPEN,
	unix.SYS_ADD_KEY,
	unix.SYS_KEYCTL,
	unix.SYS_REQUEST_KEY,
}

// clone3 is denied with ENOSYS, and the errno is the entire point.
//
// It must be denied outright rather than by flag, because classic BPF cannot
// dereference the struct clone_args pointer to see CLONE_NEWUSER. The redteam
// agent confirmed that gap is not theoretical: with unshare(CLONE_NEWUSER)
// correctly denied, clone3(CLONE_NEWUSER) still succeeded and created a nested
// user namespace.
//
// But EPERM breaks the world. glibc's pthread_create uses clone3 and falls back
// to clone() ONLY on ENOSYS — an EPERM propagates as a hard failure. With EPERM
// here, `curl https://example.com` returned 000 inside the sandbox while
// `getent hosts example.com` resolved fine: curl uses a threaded resolver, the
// thread could not be created, and the failure surfaced as a DNS timeout that
// looked for all the world like a networking bug. Roughly an hour went into
// chasing pasta before the cause turned out to be the seccomp filter.
//
// ENOSYS is what a kernel without clone3 returns, so every caller already has a
// tested path for it. The CLONE_NEWUSER guard on clone() then does the real work.
var denyENOSYS = []int{
	unix.SYS_CLONE3,
}

const (
	tiocsti      = 0x5412
	cloneNewUser = 0x10000000

	// __X32_SYSCALL_BIT: set on every syscall number issued through the x32 ABI.
	x32SyscallBit = 0x40000000
)

// asm is a tiny label-resolving assembler. Classic BPF jumps are forward-only
// 8-bit offsets, so the two return instructions live at the end and everything
// branches forward to them.
type asm struct {
	code   []insn
	labels map[string]int
}

type insn struct {
	op     uint16
	jt, jf string // label name; "" means fall through
	k      uint32
}

func newAsm() *asm { return &asm{labels: map[string]int{}} }

func (a *asm) emit(op uint16, jt, jf string, k uint32) {
	a.code = append(a.code, insn{op, jt, jf, k})
}

// mark records that `name` refers to the position the next emitted instruction
// will occupy.
func (a *asm) mark(name string) { a.labels[name] = len(a.code) }

func (a *asm) assemble() ([]byte, error) {
	var buf bytes.Buffer
	for i, in := range a.code {
		jt, err := a.offset(in.jt, i)
		if err != nil {
			return nil, err
		}
		jf, err := a.offset(in.jf, i)
		if err != nil {
			return nil, err
		}
		binary.Write(&buf, binary.NativeEndian, in.op)
		buf.WriteByte(jt)
		buf.WriteByte(jf)
		binary.Write(&buf, binary.NativeEndian, in.k)
	}
	return buf.Bytes(), nil
}

func (a *asm) offset(name string, from int) (uint8, error) {
	if name == "" {
		return 0, nil
	}
	to, ok := a.labels[name]
	if !ok {
		return 0, fmt.Errorf("seccomp: undefined label %q", name)
	}
	d := to - from - 1
	if d < 0 || d > 255 {
		// A program that outgrows an 8-bit forward jump must be restructured,
		// never silently truncated into a filter that means something else.
		return 0, fmt.Errorf("seccomp: jump to %q out of range (%d)", name, d)
	}
	return uint8(d), nil
}

// BuildFilter assembles the seccomp program for this architecture. ok is false
// on an architecture we have no syscall table for — better to say so than to
// emit a filter whose numbers mean something else entirely.
func BuildFilter() (prog []byte, ok bool, err error) {
	arch, supported := nativeAuditArch()
	if !supported {
		return nil, false, nil
	}

	a := newAsm()

	// Guard on architecture first. x86_64 numbers applied to i386 numbers would
	// deny the wrong calls, which is worse than denying none.
	//
	// KNOWN GAP, documented rather than silently patched: a non-native audit
	// arch falls through to ALLOW, so the x86_64 i386-compat path bypasses this
	// filter entirely. Closing it means denying the compat arch outright, which
	// breaks 32-bit binaries. Seccomp here is defence in depth on top of the
	// namespace boundary, so the trade has been taken deliberately.
	a.emit(bpfLdWAbs, "", "", offArch)
	a.emit(bpfJeqK, "", "allow", arch)

	// On x86_64 the x32 ABI shares the audit arch and marks its syscalls with
	// __X32_SYSCALL_BIT (0x40000000), so an x32 caller's numbers would miss
	// every comparison below. Deny the whole ABI: x32 is near-extinct, needs
	// kernel support most distributions disable, and letting it through would
	// silently reopen everything this filter denies. Spotted by the redteam
	// agent while confirming the clone3 gap.
	if arch == auditArchX86_64 {
		a.emit(bpfLdWAbs, "", "", offNR)
		a.emit(bpfJsetK, "deny", "", x32SyscallBit)
	}

	a.emit(bpfLdWAbs, "", "", offNR)
	for _, nr := range deniedSyscalls {
		a.emit(bpfJeqK, "deny", "", uint32(nr))
	}
	for _, nr := range denyENOSYS {
		a.emit(bpfJeqK, "nosys", "", uint32(nr))
	}

	// ioctl(_, TIOCSTI, _) pushes characters into the controlling terminal's
	// input queue — the sandbox typing commands at the shell that launched it.
	// snug also asks bwrap for --new-session on kernels where TIOCSTI still
	// exists, so this is the second of two locks on one door.
	a.emit(bpfJeqK, "", "afterIoctl", unix.SYS_IOCTL)
	a.emit(bpfLdWAbs, "", "", offArg1)
	a.emit(bpfJeqK, "deny", "", tiocsti)
	a.emit(bpfLdWAbs, "", "", offNR) // restore nr for the comparisons below
	a.mark("afterIoctl")

	// A fresh user namespace inside the sandbox is the standard first move of a
	// namespace escape and nothing a build needs. Cost, stated plainly: with
	// this on you cannot run snug inside snug, nor rootless podman.
	for _, nr := range []int{unix.SYS_UNSHARE, unix.SYS_CLONE} {
		after := fmt.Sprintf("after%d", nr)
		a.emit(bpfJeqK, "", after, uint32(nr))
		a.emit(bpfLdWAbs, "", "", offArg0)
		a.emit(bpfJsetK, "deny", "", cloneNewUser)
		a.emit(bpfLdWAbs, "", "", offNR)
		a.mark(after)
	}

	a.mark("allow")
	a.emit(bpfRetK, "", "", seccompRetAllow)
	a.mark("deny")
	a.emit(bpfRetK, "", "", retEPERM)
	a.mark("nosys")
	a.emit(bpfRetK, "", "", retENOSYS)

	raw, err := a.assemble()
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

// FilterFD writes the program to an anonymous memfd for bwrap's --seccomp.
// A memfd rather than a temp file: nothing lands on disk, so there is no path
// for another process to read or swap it between write and use.
func FilterFD() (*os.File, error) {
	prog, ok, err := BuildFilter()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("no syscall table for GOARCH=%s", runtime.GOARCH)
	}
	return memfd("snug-seccomp", prog)
}

// memfd stages bytes in an anonymous file and rewinds it, ready to be handed to
// a child as a numbered fd.
func memfd(name string, data []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
