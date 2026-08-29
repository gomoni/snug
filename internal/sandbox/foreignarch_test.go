package sandbox

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// AUDIT_ARCH_I386 (linux/audit.h). This is the audit arch a 32-bit binary's
// syscalls carry on an x86_64 kernel, and it is the whole of issue #529: it is
// not a hypothetical architecture, it is the one every x86_64 host already
// runs a second syscall table for.
const auditArchI386 = 0x40000003

// AUDIT_ARCH_ARM, the aarch32 compat arch under an arm64 kernel — the same
// shape as i386 under x86_64.
const auditArchARM = 0x40000028

// seccompData is the kernel's struct seccomp_data as the filter sees it: the
// syscall number, the audit arch, the instruction pointer and six 64-bit
// arguments, packed little-endian-native at the offsets seccomp.go names.
type seccompData struct {
	nr   uint32
	arch uint32
	args [6]uint64
}

func (d seccompData) word(off uint32) uint32 {
	switch {
	case off == offNR:
		return d.nr
	case off == offArch:
		return d.arch
	case off >= 16 && off < 64 && (off-16)%8 == 0:
		// args[] are 64-bit; the filter compares the low word, which on a
		// little-endian host sits at the base offset. Every offset seccomp.go
		// loads from an argument (offArg0, offArg1) is such a base.
		return uint32(d.args[(off-16)/8])
	}
	panic("seccomp_data offset the filter should never load")
}

// runFilter is a classic-BPF interpreter over exactly the opcodes BuildFilter
// emits. It exists because every other test in this package reads the program
// as a byte pattern — "is there a JSET against this constant" — and a byte
// pattern cannot answer the question issue #529 actually asks, which is what
// the KERNEL does with a syscall the program has no comparison for. A pattern
// assertion passed on the vulnerable code too: the fall-through to ALLOW was
// spelled by the ABSENCE of an instruction, and there is no byte to grep for
// an instruction that is not there.
//
// It returns the RET_K value the program terminates with, and fails the test
// rather than guessing if it meets an opcode BuildFilter does not emit — a
// silently-ignored instruction would let this interpreter disagree with the
// kernel in the safe-looking direction.
func runFilter(t *testing.T, prog []byte, d seccompData) uint32 {
	t.Helper()
	n := len(prog) / 8
	acc := uint32(0)
	for pc := 0; pc < n; pc++ {
		op := binary.NativeEndian.Uint16(prog[pc*8 : pc*8+2])
		jt := int(prog[pc*8+2])
		jf := int(prog[pc*8+3])
		k := binary.NativeEndian.Uint32(prog[pc*8+4 : pc*8+8])
		switch op {
		case bpfLdWAbs:
			acc = d.word(k)
		case bpfJeqK:
			if acc == k {
				pc += jt
			} else {
				pc += jf
			}
		case bpfJsetK:
			if acc&k != 0 {
				pc += jt
			} else {
				pc += jf
			}
		case bpfRetK:
			return k
		default:
			t.Fatalf("instruction %d has opcode %#x, which this interpreter does not "+
				"model — BuildFilter emitted something new and every verdict below "+
				"is now a guess", pc, op)
		}
	}
	t.Fatal("filter ran off the end without a RET; the kernel would reject this program")
	return 0
}

// REGRESSION for issue #529, confirmed by the redteam agent and stated in
// snug's own source before it was fixed: the filter guarded on architecture
// first and a NON-NATIVE audit arch fell through to ALLOW, so a 32-bit (i386
// compat) binary on x86_64 ran with ptrace, bpf, keyctl, process_vm_writev and
// clone(CLONE_NEWUSER) unfiltered. Building or downloading a 32-bit binary is
// not a privileged act, so the bypass cost a payload nothing.
//
// The syscall numbers below are deliberately NOT the native ones: under a
// foreign arch the number means something else entirely, which is exactly why
// the answer must not depend on it. Every one of them must be killed.
func TestAForeignAuditArchIsKilledAndNeverAllowed(t *testing.T) {
	prog, ok, err := BuildFilter()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Skip("no syscall table for this GOARCH")
	}
	native, _ := nativeAuditArch()

	for _, arch := range []uint32{auditArchI386, auditArchARM, auditArchX86_64, auditArchAArch64, 0, 0xffffffff} {
		if arch == native {
			continue
		}
		for _, nr := range []uint32{0, 1, 26, 101, 190, uint32(unix.SYS_PTRACE), 0xffffffff} {
			got := runFilter(t, prog, seccompData{nr: nr, arch: arch})
			if got != seccompRetKillProcess {
				t.Errorf("arch %#x nr %d returns %#x, want RET_KILL_PROCESS (%#x): a syscall "+
					"under an arch this program has no numbers for matches no comparison "+
					"in it, so anything but a kill is unfiltered",
					arch, nr, got, seccompRetKillProcess)
			}
		}
	}
}

// The other half of the same rule, because a filter that kills everything
// would also pass the test above: under the NATIVE arch the program must still
// allow an ordinary syscall and still deny the ones it names.
func TestTheNativeArchStillAllowsAndStillDenies(t *testing.T) {
	prog, ok, err := BuildFilter()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Skip("no syscall table for this GOARCH")
	}
	arch, _ := nativeAuditArch()

	if got := runFilter(t, prog, seccompData{nr: unix.SYS_READ, arch: arch}); got != seccompRetAllow {
		t.Errorf("read(2) returns %#x, want RET_ALLOW (%#x)", got, seccompRetAllow)
	}
	for _, nr := range deniedSyscalls {
		if got := runFilter(t, prog, seccompData{nr: uint32(nr), arch: arch}); got != retEPERM {
			t.Errorf("syscall %d returns %#x, want EPERM (%#x)", nr, got, retEPERM)
		}
	}
	for _, nr := range denyENOSYS {
		if got := runFilter(t, prog, seccompData{nr: uint32(nr), arch: arch}); got != retENOSYS {
			t.Errorf("syscall %d returns %#x, want ENOSYS (%#x)", nr, got, retENOSYS)
		}
	}
	// ioctl(_, TIOCSTI, _) is denied on its second argument; an ioctl with any
	// other request is not. Both directions, because the arch rule above sits
	// upstream of this comparison and a mistake there would show here first.
	tiocstiCall := seccompData{nr: unix.SYS_IOCTL, arch: arch}
	tiocstiCall.args[1] = tiocsti
	if got := runFilter(t, prog, tiocstiCall); got != retEPERM {
		t.Errorf("ioctl(_, TIOCSTI, _) returns %#x, want EPERM (%#x)", got, retEPERM)
	}
	otherIoctl := seccompData{nr: unix.SYS_IOCTL, arch: arch}
	otherIoctl.args[1] = 0x5401 // TCGETS
	if got := runFilter(t, prog, otherIoctl); got != seccompRetAllow {
		t.Errorf("ioctl(_, TCGETS, _) returns %#x, want RET_ALLOW (%#x)", got, seccompRetAllow)
	}
	// clone/unshare are denied on CLONE_NEWUSER in arg0 and allowed without it.
	for _, nr := range []int{unix.SYS_UNSHARE, unix.SYS_CLONE} {
		withUser := seccompData{nr: uint32(nr), arch: arch}
		withUser.args[0] = cloneNewUser
		if got := runFilter(t, prog, withUser); got != retEPERM {
			t.Errorf("syscall %d with CLONE_NEWUSER returns %#x, want EPERM (%#x)", nr, got, retEPERM)
		}
		plain := seccompData{nr: uint32(nr), arch: arch}
		plain.args[0] = 0x00000100 // CLONE_VM, nothing this filter judges
		if got := runFilter(t, prog, plain); got != seccompRetAllow {
			t.Errorf("syscall %d without CLONE_NEWUSER returns %#x, want RET_ALLOW (%#x)",
				nr, got, seccompRetAllow)
		}
	}
}

// x32 shares x86_64's audit arch and sets bit 30 on every syscall number, so it
// is NOT reached by the arch rule above — it is the one bypass that survives a
// correct arch guard, and it is denied by its own JSET. Asserted through the
// interpreter rather than by pattern, so the two rules are shown not to shadow
// each other.
func TestX32IsDeniedUnderTheNativeArch(t *testing.T) {
	prog, ok, err := BuildFilter()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Skip("no syscall table for this GOARCH")
	}
	arch, _ := nativeAuditArch()
	if arch != auditArchX86_64 {
		t.Skip("x32 only exists on x86_64")
	}
	if got := runFilter(t, prog, seccompData{nr: x32SyscallBit | unix.SYS_READ, arch: arch}); got != retEPERM {
		t.Errorf("x32 read(2) returns %#x, want EPERM (%#x)", got, retEPERM)
	}
}
