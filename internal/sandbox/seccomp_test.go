package sandbox

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// A sock_filter is 8 bytes. A program that is not a whole number of them is not
// a program, and the kernel would reject it — but late, and confusingly.
func TestFilterIsWellFormed(t *testing.T) {
	prog, ok, err := BuildFilter()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Skip("no syscall table for this GOARCH")
	}
	if len(prog) == 0 || len(prog)%8 != 0 {
		t.Fatalf("program is %d bytes, want a non-zero multiple of 8", len(prog))
	}
}

// Every jump must land inside the program. An out-of-range offset is how a
// filter silently comes to mean something other than what it reads like.
func TestAllJumpsLandInsideTheProgram(t *testing.T) {
	prog, ok, _ := BuildFilter()
	if !ok {
		t.Skip("no syscall table for this GOARCH")
	}
	n := len(prog) / 8
	for i := range n {
		op := binary.NativeEndian.Uint16(prog[i*8 : i*8+2])
		// Only BPF_JMP-class instructions use jt/jf. On a load or a return
		// those bytes are unused padding, so reading them as offsets would
		// flag the final RET as an out-of-range jump.
		if op&0x07 != 0x05 {
			continue
		}
		for _, j := range []byte{prog[i*8+2], prog[i*8+3]} {
			if dest := i + 1 + int(j); dest >= n {
				t.Errorf("instruction %d jumps to %d, past the end (%d)", i, dest, n)
			}
		}
	}
}

// The last two instructions are the return values everything branches to. If
// the allow/deny pair ever stopped being reachable the filter would still
// assemble and would deny nothing.
func TestProgramEndsWithAllowThenDeny(t *testing.T) {
	prog, ok, _ := BuildFilter()
	if !ok {
		t.Skip("no syscall table for this GOARCH")
	}
	n := len(prog) / 8
	readK := func(i int) uint32 {
		return binary.NativeEndian.Uint32(prog[i*8+4 : i*8+8])
	}
	readOp := func(i int) uint16 {
		return binary.NativeEndian.Uint16(prog[i*8 : i*8+2])
	}
	// Three returns, in emission order: allow, deny(EPERM), nosys(ENOSYS).
	// Everything branches forward to one of them.
	for i, want := range map[int]uint32{n - 3: seccompRetAllow, n - 2: retEPERM, n - 1: retENOSYS} {
		if readOp(i) != bpfRetK || readK(i) != want {
			t.Errorf("instruction %d is not RET(%#x)", i, want)
		}
	}
}

// The denylist is the security content of this package. Losing an entry would
// be silent, so assert each one is compared against somewhere in the program.
func TestEveryDeniedSyscallAppears(t *testing.T) {
	prog, ok, _ := BuildFilter()
	if !ok {
		t.Skip("no syscall table for this GOARCH")
	}
	seen := map[uint32]bool{}
	for i := range len(prog) / 8 {
		if binary.NativeEndian.Uint16(prog[i*8:i*8+2]) == bpfJeqK {
			seen[binary.NativeEndian.Uint32(prog[i*8+4:i*8+8])] = true
		}
	}
	for _, nr := range deniedSyscalls {
		if !seen[uint32(nr)] {
			t.Errorf("syscall %d is in deniedSyscalls but never compared in the program", nr)
		}
	}
	for _, extra := range []uint32{unix.SYS_IOCTL, unix.SYS_UNSHARE, unix.SYS_CLONE, tiocsti} {
		if !seen[extra] {
			t.Errorf("expected a comparison against %d (ioctl/unshare/clone/TIOCSTI handling)", extra)
		}
	}
}

// REGRESSION, confirmed exploitable by the redteam agent: with
// unshare(CLONE_NEWUSER) correctly denied, clone3(CLONE_NEWUSER) still
// succeeded and created a nested user namespace, because classic BPF cannot
// dereference the struct clone_args pointer to see the flag. The only fix
// available to a classic filter is to deny the syscall outright.
func TestClone3IsDeniedOutright(t *testing.T) {
	found := false
	for _, nr := range denyENOSYS {
		if nr == unix.SYS_CLONE3 {
			found = true
		}
	}
	if !found {
		t.Fatal("clone3 is not denied; a flag-based rule cannot see its arguments, " +
			"so CLONE_NEWUSER via clone3 would be unfiltered")
	}
	for _, nr := range deniedSyscalls {
		if nr == unix.SYS_CLONE3 {
			t.Fatal("clone3 is denied with EPERM. It must be ENOSYS: glibc's pthread_create " +
				"falls back to clone() only on ENOSYS, and EPERM breaks every threaded " +
				"program — curl's resolver among them.")
		}
	}
}

// On x86_64 the x32 ABI shares the audit arch but sets bit 30 on every syscall
// number, so an x32 caller would miss every comparison in the program and be
// allowed through. Assert the guard exists.
func TestX32AbiIsDenied(t *testing.T) {
	if _, ok := nativeAuditArch(); !ok {
		t.Skip("no syscall table for this GOARCH")
	}
	arch, _ := nativeAuditArch()
	if arch != auditArchX86_64 {
		t.Skip("x32 only exists on x86_64")
	}
	prog, _, _ := BuildFilter()
	for i := range len(prog) / 8 {
		op := binary.NativeEndian.Uint16(prog[i*8 : i*8+2])
		k := binary.NativeEndian.Uint32(prog[i*8+4 : i*8+8])
		if op == bpfJsetK && k == x32SyscallBit {
			return
		}
	}
	t.Fatal("no JSET against __X32_SYSCALL_BIT; x32 syscalls would bypass every rule")
}

// Out-of-range jumps must be an error, never a truncated offset that points
// somewhere plausible.
func TestAssemblerRejectsUnreachableLabel(t *testing.T) {
	a := newAsm()
	for range 300 {
		a.emit(bpfJeqK, "far", "", 0)
	}
	a.mark("far")
	a.emit(bpfRetK, "", "", seccompRetAllow)

	if _, err := a.assemble(); err == nil {
		t.Fatal("expected an out-of-range jump error")
	}
}

func TestAssemblerRejectsUndefinedLabel(t *testing.T) {
	a := newAsm()
	a.emit(bpfJeqK, "nowhere", "", 0)
	if _, err := a.assemble(); err == nil {
		t.Fatal("expected an undefined-label error")
	}
}
