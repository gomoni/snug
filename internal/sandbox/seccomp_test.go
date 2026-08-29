package sandbox

import (
	"encoding/binary"
	"strings"
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

// The last instructions are the return values everything branches to. If the
// allow/deny pair ever stopped being reachable the filter would still assemble
// and would deny nothing.
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
	// Four returns, in emission order: allow, deny(EPERM), nosys(ENOSYS),
	// foreignarch(KILL_PROCESS). Everything branches forward to one of them.
	for i, want := range map[int]uint32{
		n - 4: seccompRetAllow,
		n - 3: retEPERM,
		n - 2: retENOSYS,
		n - 1: seccompRetKillProcess,
	} {
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

// TestDeniedSyscallNamesMatchesDeniedSyscalls is the happy path for
// DeniedSyscallNames (internal/cli's --dry-run SECCOMP row is derived from it,
// rather than a hand-typed second list — see its doc comment for the drift
// that motivated deriving it): same length, same order, and every name
// actually traces back to the syscall number at the same position via
// deniedSyscallName, rather than the two lists merely happening to agree on
// length.
func TestDeniedSyscallNamesMatchesDeniedSyscalls(t *testing.T) {
	names := DeniedSyscallNames()
	if len(names) != len(deniedSyscalls) {
		t.Fatalf("DeniedSyscallNames returned %d names for %d denied syscalls",
			len(names), len(deniedSyscalls))
	}
	for i, nr := range deniedSyscalls {
		want, ok := deniedSyscallName[nr]
		if !ok {
			t.Fatalf("PRECONDITION: syscall %d has no entry in deniedSyscallName — "+
				"TestDeniedSyscallNamesPanicsOnAnUnnamedSyscall below is what should be "+
				"catching this, not this test failing on the real list", nr)
		}
		if names[i] != want {
			t.Errorf("names[%d] = %q, want %q (syscall %d)", i, names[i], want, nr)
		}
	}
}

// TestDeniedSyscallNamesPanicsOnAnUnnamedSyscall is the reachability check
// for the panic DeniedSyscallNames' doc comment promises: "add one before
// this ships, or the --dry-run SECCOMP row silently stops matching the
// filter". A guard that has never fired is a guard nobody has verified
// actually fires — CLAUDE.md's own warning about tests that cannot fail,
// applied to a panic instead of an assertion. There is no public way to add
// an unnamed entry (deniedSyscalls and deniedSyscallName are both unexported
// package state), so this injects one directly and restores it afterward.
func TestDeniedSyscallNamesPanicsOnAnUnnamedSyscall(t *testing.T) {
	orig := deniedSyscalls
	t.Cleanup(func() { deniedSyscalls = orig })

	const unnamed = -999999 // not a real syscall number; guaranteed absent from deniedSyscallName
	if _, ok := deniedSyscallName[unnamed]; ok {
		t.Fatal("PRECONDITION: the sentinel syscall number collides with a real entry")
	}
	deniedSyscalls = append(append([]int{}, orig...), unnamed)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("DeniedSyscallNames did not panic on a syscall number with no name — " +
				"the --dry-run SECCOMP row could now silently render an incomplete list, " +
				"exactly the drift this panic exists to make impossible")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "no name") {
			t.Errorf("panic value is %v, want it to say the syscall has no name — a maintainer "+
				"reading this panic needs to know what to fix", r)
		}
	}()
	DeniedSyscallNames()
}

// TestBuildFilterReturnsAnErrorWhenTheJumpRangeOverflows is the fault
// injection describeSeccomp's BROKEN row (internal/cli/dryrun.go) depends on.
// TestAssemblerRejectsUnreachableLabel above proves the underlying asm TYPE
// rejects an out-of-range jump; it does not prove BuildFilter itself — the
// function that actually assembles the shipped filter, and the one
// internal/cli's --dry-run and sandbox.Run both call — can ever be the thing
// that trips it. asm.offset's doc comment says the failure is reachable "once
// a future denial list makes the JEQ chain long enough": that is a claim
// about what happens when deniedSyscalls grows, so the fault has to be
// injected AT that list, in this same package, to mean anything. There is no
// public knob for it (deniedSyscalls is unexported on purpose — nothing
// outside this package should be able to change what is denied), so this
// reaches into the package var directly and restores it unconditionally.
//
// A full describeSeccomp/--dry-run BROKEN-row golden is NOT attempted here:
// it would need a seam in internal/cli for swapping out sandbox.BuildFilter,
// which is a production-code change outside what this test file should be
// deciding on its own, and BROKEN's on-screen text is `err.Error()` rendered
// verbatim with no branching of its own — this test is what proves that
// string is meaningful ("out of range") rather than a placeholder.
func TestBuildFilterReturnsAnErrorWhenTheJumpRangeOverflows(t *testing.T) {
	if _, ok := nativeAuditArch(); !ok {
		t.Skip("no syscall table for this GOARCH")
	}

	orig := deniedSyscalls
	t.Cleanup(func() { deniedSyscalls = orig })

	// Only the COUNT matters, not the values: each entry contributes one
	// BPF_JMP|BPF_JEQ instruction between the architecture guard (near the
	// start of the program) and the "deny" label (near the end), and the
	// 8-bit forward-jump limit is 255 instructions. 300 fake, out-of-range
	// syscall numbers is comfortably past that for the FIRST of them, which is
	// the one whose jump distance is largest.
	inflated := append([]int{}, orig...)
	for i := range 300 {
		inflated = append(inflated, 1_000_000+i)
	}
	deniedSyscalls = inflated

	prog, ok, err := BuildFilter()
	if err == nil {
		t.Fatalf("BuildFilter did not fail with %d denied syscalls — either the jump-range "+
			"limit moved, or this many entries no longer overflows it. Either way that is "+
			"worth knowing about deliberately, rather than discovering it as a silent gap in "+
			"describeSeccomp's BROKEN-branch reasoning", len(inflated))
	}
	if ok {
		t.Error("BuildFilter reported ok=true alongside a non-nil error — describeSeccomp " +
			"branches on err first specifically because ok=false,err=nil (unsupported GOARCH) " +
			"and ok=false,err!=nil (assembly bug) are supposed to be mutually exclusive")
	}
	if prog != nil {
		t.Error("BuildFilter returned a non-nil program alongside an error")
	}
	if !strings.Contains(err.Error(), "out of range") {
		t.Errorf("BuildFilter's error is %q, want it to mention the jump being out of range — "+
			"this string is what describeSeccomp's BROKEN row prints verbatim on the one "+
			"screen a human has to trust snug from", err.Error())
	}
}
