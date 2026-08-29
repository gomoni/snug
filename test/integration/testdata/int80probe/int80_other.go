//go:build !amd64

package main

// `int $0x80` is an x86 instruction. On every other architecture this program
// still BUILDS — so `go vet` and a cross-compile stay honest — and reports
// that it has nothing to measure, rather than the package failing to build and
// the test that uses it reading as an infrastructure problem.
const int80Supported = false

func int80(nr, a1, a2, a3 uintptr) uintptr { panic("int 0x80 is x86-only") }
