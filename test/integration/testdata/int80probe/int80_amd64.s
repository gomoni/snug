#include "textflag.h"

// func int80(nr, a1, a2, a3 uintptr) uintptr
//
// NOSPLIT because there is no stack growth to do and nothing here calls back
// into Go. The i386 entry point takes its arguments in AX/BX/CX/DX and returns
// -errno in AX, which is a different convention from the x86_64 SYSCALL
// instruction — using the i386 one is what makes the kernel serve this from
// the compat table and report AUDIT_ARCH_I386 to seccomp.
TEXT ·int80(SB), NOSPLIT, $0-40
	MOVQ nr+0(FP), AX
	MOVQ a1+8(FP), BX
	MOVQ a2+16(FP), CX
	MOVQ a3+24(FP), DX
	INT  $0x80
	MOVQ AX, ret+32(FP)
	RET
