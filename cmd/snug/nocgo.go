//go:build cgo

package main

// snug is CGO_ENABLED=0 only (.claude/design/NOCGO.md), and this file is what
// makes that a rule rather than a Makefile default: it is compiled ONLY into a
// cgo build, and it does not compile. `go build`, `go install` and a
// distribution's own build all fail here, not just `make`.
//
// The binary is a runtime dependency of itself twice over: the stage re-execs
// /proc/self/exe, and the http door and login bridge bind this same image into
// the sandbox as /snug/lib/snug/wrapper, where no profile has to grant a libc or
// a loader for it to run. A dynamic snug would fail there with ENOENT on the
// interpreter.
var _ = snugMustBeBuiltWithCGO_ENABLED_0
