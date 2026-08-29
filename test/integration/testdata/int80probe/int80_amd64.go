package main

const int80Supported = true

// int80 issues `int $0x80` with the i386 argument registers loaded. Declared
// here, implemented in int80_amd64.s: Go has no inline assembly, and this
// instruction is the entire point of the program.
func int80(nr, a1, a2, a3 uintptr) uintptr
