// Package sandbox turns a resolved policy into a running process: it builds the
// seccomp filter, stages file descriptors, execs bwrap, and propagates the exit
// code. Everything here touches the OS. The decisions were all made in
// internal/policy, which does not.
package sandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

	// SECCOMP_RET_KILL_PROCESS: SIGSYS the whole thread group. Used for one
	// case only — a syscall arriving under an audit arch this program has no
	// numbers for (issue #529). EPERM is deliberately NOT used there: the
	// numbers are unknown, so every EPERM would be a guess wearing the
	// costume of a rule, and a foreign-arch process would limp on with each
	// call failing, which reads like a broken program rather than a refusal.
	//
	// The value looks like the LEAST severe of the actions and is the most.
	// linux/seccomp.h: "The upper 16-bits are ordered from least permissive
	// values to most, AS A SIGNED VALUE (so 0x8000000 is negative). The
	// ordering ensures that a min_t() over composed return values always
	// selects the least permissive choice." So 0x80000000 is negative, and
	// when filters are composed — the engine's payload runs under this one
	// and whatever else is installed — this one wins over another filter's
	// ALLOW (0x7fff0000). An unsigned comparison would give the opposite
	// answer, which is why the constant is worth a paragraph.
	seccompRetKillProcess = 0x80000000
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

// CompatArchName names the SECOND syscall table a kernel for this GOARCH also
// serves — the 32-bit compat ABI — or reports false where there is none this
// filter would ever meet. It is exported for internal/cli's --dry-run SECCOMP
// block, which must disclose that a binary built for that arch is killed
// rather than run (issue #529).
//
// Derived here rather than spelled out again in internal/cli, for the reason
// DeniedSyscallNames exists: the arch rule in BuildFilter is unconditional, so
// a `runtime.GOARCH == "amd64"` test beside the RENDERER is a second opinion
// about what the FILTER does, and it was wrong for arm64 the moment it was
// written — aarch32 is killed there and the screen said nothing.
func CompatArchName() (string, bool) {
	switch runtime.GOARCH {
	case "amd64":
		return "i386", true
	case "arm64":
		// True whether or not this kernel was built with CONFIG_COMPAT: with
		// it, aarch32 syscalls arrive under AUDIT_ARCH_ARM and are killed;
		// without it the binary does not run at all. Either way "a 32-bit
		// binary does not run here" is the sentence to print.
		return "aarch32", true
	}
	return "", false
}

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
//	pidfd_getfd      steals a DUPLICATE of another process's open file
//	                 description by pidfd + index — not just a path reopen: it
//	                 reaches connected sockets, pipes, memfds, deleted and
//	                 O_TMPFILE files, and fds whose inode DAC would refuse a
//	                 fresh open. Read that as what pidfd_getfd REACHES, not as
//	                 what only it reaches — procfs reopens most of that list
//	                 too; see the residual paragraph below. pidfd_open (a handle,
//	                 no descriptors) stays allowed — Phase 2's attach path wants
//	                 it, and the stage's control channel has an independent lock
//	                 against it anyway (SUPERVISOR-DESIGN.md §3.3: the stage is
//	                 not in the payload's pid namespace, so there is no pid to
//	                 name). See issue #23: on this host (yama ptrace_scope=1) the
//	                 syscall is ALREADY refused sibling-to-sibling by Yama, not
//	                 by anything here — this filter is the lock for the hosts
//	                 (containers, hardened-off Yama) where that sysctl is 0.
//	                 THIS DOES NOT MAKE CO-RESIDENT PAYLOADS SAFE FROM EACH
//	                 OTHER: /proc/<pid>/fd/N reopen (PTRACE_MODE_READ, which
//	                 Yama does not gate) still lets a sibling read another
//	                 payload's regular files today; that is issue #47, not
//	                 something seccomp can reach. NOT REDUNDANT with that
//	                 residual, but the residual is ONE object, not four
//	                 (issue #115): this comment used to name "a socket, a
//	                 pipe, a memfd, a deleted file" as things procfs cannot
//	                 reopen, and three of the four were wrong. Measured
//	                 sibling-to-sibling, same uid, ptrace_scope=1: a memfd, a
//	                 pipe, a deleted file and an O_TMPFILE file all reopen
//	                 through /proc/<pid>/fd/N with their contents intact,
//	                 because each has a backing inode and open(2) on the magic
//	                 link re-derives a working descriptor once
//	                 ptrace_may_access(PTRACE_MODE_READ_FSCREDS) passes —
//	                 which same-uid does, and which Yama does not gate at any
//	                 ptrace_scope, since it checks PTRACE_MODE_ATTACH only.
//	                 What survives is the CONNECTED SOCKET: sockfs has no open
//	                 method (sock_no_open), so the reopen is ENXIO for every
//	                 caller, root included, and pidfd_getfd is the only route
//	                 to it. That one object is what this denial buys, and it
//	                 is not nothing — SUPERVISOR-DESIGN.md's control-channel
//	                 argument rests on exactly it. Pinned by
//	                 TestKnownOpenResidualSiblingReopensAnythingButASocket.
//	process_vm_readv/process_vm_writev
//	                 read and write another process's memory directly —
//	                 ptrace's effect without calling ptrace(2). Measured
//	                 exploitable sibling-to-sibling with Yama waived: one
//	                 payload both read and overwrote another's memory with the
//	                 filter otherwise on. ptrace itself is already denied above;
//	                 this is its ptrace-free spelling and belongs in the same
//	                 gate. DOES NOT CLOSE SIBLING MEMORY ACCESS, and the comment
//	                 above this denial must never be read as though it does:
//	                 /proc/<pid>/mem is the identical effect — full read AND
//	                 write, i.e. code injection into a sibling — reached by
//	                 open(2) + pread/pwrite(2), none of which this filter can
//	                 single out (an fd, once open, is indistinguishable from any
//	                 other fd to a classic BPF program keyed on syscall number).
//	                 Red-teamed sibling-to-sibling with Yama's PR_SET_PTRACER_ANY
//	                 waived (the same ptrace_scope=0 container model the
//	                 process_vm_* finding used): PROCMEM_READ=OK,
//	                 PROCMEM_WRITE=OK, victim overwritten. This denial is a
//	                 syscall-level lock on a door that has a second, procfs-level
//	                 lock (Yama) and no third; see issue #47 and CLAUDE.md's
//	                 "Seccomp cannot be the whole answer" note. One more
//	                 consequence, INTENTIONAL rather than overlooked: the denial
//	                 is unconditional, so it also refuses a SELF-directed
//	                 process_vm_readv — which task == current lets succeed on
//	                 every host regardless of ptrace_scope, since
//	                 ptrace_may_access is never consulted for self. No shipped
//	                 tool was observed to need it, but a crash handler or
//	                 sanitizer probing "is this address readable" with a self
//	                 process_vm_readv would fail only inside snug. Accepted: a
//	                 flag-based carve-out for self would need to inspect args[0]
//	                 against getpid(), which classic BPF can do, but the callers
//	                 that would benefit are not known to exist and the extra
//	                 branch is one more thing to get right in a security filter
//	                 for a benefit nobody has asked for.
var deniedSyscalls = []int{
	unix.SYS_PTRACE,
	unix.SYS_BPF,
	unix.SYS_USERFAULTFD,
	unix.SYS_PERF_EVENT_OPEN,
	unix.SYS_ADD_KEY,
	unix.SYS_KEYCTL,
	unix.SYS_REQUEST_KEY,
	unix.SYS_PIDFD_GETFD,
	unix.SYS_PROCESS_VM_READV,
	unix.SYS_PROCESS_VM_WRITEV,
}

// deniedSyscallName names every entry in deniedSyscalls, keyed on the same
// constants — not a second list of numbers, so there is exactly one place
// that says "these ints mean this". It exists for DeniedSyscallNames below,
// which is how internal/cli's --dry-run SECCOMP row gets its list: that row used
// to type the names out a second time by hand, and it drifted the same
// session it was written, silently disclosing one residual while omitting a
// worse one two comments away. A hand-typed copy is the same hazard
// CLAUDE.md already names for a count in prose; this is its list-of-names
// shape.
var deniedSyscallName = map[int]string{
	unix.SYS_PTRACE:            "ptrace",
	unix.SYS_BPF:               "bpf",
	unix.SYS_USERFAULTFD:       "userfaultfd",
	unix.SYS_PERF_EVENT_OPEN:   "perf_event_open",
	unix.SYS_ADD_KEY:           "add_key",
	unix.SYS_KEYCTL:            "keyctl",
	unix.SYS_REQUEST_KEY:       "request_key",
	unix.SYS_PIDFD_GETFD:       "pidfd_getfd",
	unix.SYS_PROCESS_VM_READV:  "process_vm_readv",
	unix.SYS_PROCESS_VM_WRITEV: "process_vm_writev",
}

// DeniedSyscallNames renders deniedSyscalls as names, in emission order, for
// a caller outside this package (internal/cli's --dry-run SECCOMP row). It PANICS
// on an entry with no name in deniedSyscallName, rather than silently
// rendering a bare number or dropping it: the whole point of deriving this
// list instead of typing it twice is that a syscall added to deniedSyscalls
// and forgotten here fails loudly — at test time, since any dry-run golden
// test exercises this — instead of shipping a --dry-run screen that quietly
// stopped matching the filter it describes.
func DeniedSyscallNames() []string {
	names := make([]string, len(deniedSyscalls))
	for i, nr := range deniedSyscalls {
		name, ok := deniedSyscallName[nr]
		if !ok {
			panic(fmt.Sprintf("sandbox: syscall number %d is in deniedSyscalls with no name in "+
				"deniedSyscallName — add one before this ships, or the --dry-run SECCOMP row "+
				"silently stops matching the filter", nr))
		}
		names[i] = name
	}
	return names
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
	// A non-native audit arch is KILLED, not allowed (issue #529). Every
	// comparison below is a number in the NATIVE table, so a syscall arriving
	// under any other arch matches none of them: falling through to ALLOW
	// meant the x86_64 i386-compat ABI bypassed this filter entirely, and a
	// 32-bit binary — which any payload can build or download — ran with
	// ptrace, bpf, keyctl, process_vm_writev and clone(CLONE_NEWUSER)
	// unfiltered. The same holds for aarch32 under arm64.
	//
	// The cost, stated: a 32-bit binary does not run inside the sandbox at
	// all. That is the whole of it, it is not silent (SIGSYS, and --dry-run's
	// SECCOMP block says so), and it is liftable the day a per-arch table
	// exists — the filter would then compare the compat numbers instead of
	// refusing them. --no-seccomp already lifts it for a payload that needs a
	// 32-bit binary today.
	a.emit(bpfLdWAbs, "", "", offArch)
	a.emit(bpfJeqK, "", "foreignarch", arch)

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
	a.mark("foreignarch")
	a.emit(bpfRetK, "", "", seccompRetKillProcess)

	raw, err := a.assemble()
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

// FilterDigest is the identity `snug attach` compares against: the run's
// state file records this over the program bytes it actually installed, and
// attach refuses to join unless ITS OWN BuildFilter() produces the identical
// digest (internal/attach's caller does this, in internal/cli/attach.go).
//
// Rebuilding and hashing rather than carrying the program bytes in the state
// file is the point, not an incidental choice: the bytes are authored by
// deniedSyscalls and BuildFilter, in code, and a file that carried them would
// be a second author of the filter — the same "trust the wire" shape this
// project already refused once for Bwrap/Argv travelling on a channel.
// Rebuilding also cannot fail open: if BuildFilter is missing, broken, or on
// an architecture with no syscall table, attach has no filter to install and
// says so rather than joining unfiltered.
func FilterDigest(prog []byte) string {
	sum := sha256.Sum256(prog)
	return "sha256:" + hex.EncodeToString(sum[:])
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
