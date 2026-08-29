//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// REGRESSION (issue #529), found by the redteam agent and stated in snug's own
// source before it was fixed: BuildFilter guarded on the audit arch first and a
// NON-NATIVE arch fell through to ALLOW. Every comparison in the program is a
// number from the native syscall table, so a syscall arriving under any other
// arch matched none of them — and on x86_64 the i386 compat ABI is not exotic,
// it is a second syscall table the kernel already runs. A payload that wanted
// the filter gone only had to be 32 bits.
//
// # Why this is an INTEGRATION test and not only a unit test
//
// internal/sandbox/foreignarch_test.go interprets the BPF program and asserts
// the verdict for a foreign arch is RET_KILL_PROCESS. That test's weakness is
// that it is snug's own interpreter grading snug's own program: if the
// interpreter models an opcode the way BuildFilter meant it rather than the way
// the kernel implements it, both halves agree and both are wrong. This test
// hands the program to the KERNEL and reads what happens to a real 32-bit
// process.
//
// # What the three runs are
//
//  1. the 386 build under the filter — must be KILLED, exit 159 (128+31,
//     SIGSYS), with no output at all: the write(2) that would print the
//     probe's first line is itself the syscall that dies.
//  2. the 386 build under --no-seccomp — must RUN, and its two errnos are the
//     KERNEL's (EINVAL from unshare, 0 from the no-op ptrace). This is the
//     control that proves it is THE FILTER doing the killing above, and not
//     something else about a 32-bit binary in this sandbox. It is also,
//     exactly, what the bug looked like: this output is what run 1 produced
//     before the fix.
//  3. the native build under the filter — must RUN and report EPERM for both
//     calls. The positive control: the filter is selective, not a filter that
//     kills everything, and it is installed in these runs at all.
//
// Run 3's EPERM against run 2's EINVAL is the whole argument. Same source, same
// host, same sandbox; the errno says which side of the boundary answered.
const (
	// SIGSYS is what SECCOMP_RET_KILL_PROCESS raises; bash reports a killed
	// child as 128+signal and, being the last command, exits with it.
	killedBySIGSYS = 128 + 31

	// EPERM and EINVAL as the probe prints them: syscall.Errno rendered with
	// %d. Numbers rather than names because the probe must not depend on a
	// package whose 386 build might name them differently.
	eperm  = 1
	einval = 22
)

// buildArch32Probe builds testdata/arch32probe for one GOARCH, the way
// buildMarkerBin builds its own binary: statically, into a fresh directory,
// lazily — only the tests in this file pay for it, and only on a host that
// reaches them.
//
// CGO_ENABLED=0 is not a preference here, it is what makes the 386 build
// possible at all: a cgo build for 386 needs a 32-bit toolchain and 32-bit
// libc headers, which no CI image in this project has. Go's own cross-compile
// needs neither.
func buildArch32Probe(t *testing.T, goarch string) string {
	t.Helper()
	return buildProbeForArch(t, "arch32probe", goarch)
}

// buildProbeForArch builds one testdata package for one GOARCH.
func buildProbeForArch(t *testing.T, pkg, goarch string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), pkg+"-"+goarch)
	cmd := exec.Command("go", "build", "-o", bin, "./test/integration/testdata/"+pkg)
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOARCH="+goarch, "GOOS=linux")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("building testdata/%s for GOARCH=%s: %v: %s", pkg, goarch, err, out.String())
	}
	return bin
}

// stageArch32Probe copies a built probe into the target directory, for the
// reason stagePidfdProbe gives: the sandbox sees only what a grant covers, and
// the build lands in a scratch directory outside every grant.
func stageArch32Probe(t *testing.T, proj, bin, name string) {
	t.Helper()
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("reading the built arch32probe: %v", err)
	}
	if err := os.WriteFile(filepath.Join(proj, name), data, 0o755); err != nil {
		t.Fatalf("staging %s into the target: %v", name, err)
	}
}

// requireCompatArch skips on an architecture with no 32-bit compat ABI to
// speak of. The rule in BuildFilter is architecture-independent — anything
// that is not the native audit arch is killed — but the only compat arch this
// suite can produce a binary for with the Go toolchain alone is 386 under
// amd64.
//
// skipOrFail rather than t.Skip, so SNUG_REQUIRE_SANDBOX=1 on an amd64 runner
// cannot turn this into a silent pass; on a genuinely different GOARCH it is a
// real skip.
func requireCompatArch(t *testing.T) {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skipf("no 32-bit compat binary this suite can build for GOARCH=%s", runtime.GOARCH)
	}
}

// probeErrno pulls one "name=N" line out of a probe's output as an integer,
// failing with the whole output rather than letting a missing line read as 0 —
// which is the value that means "the call SUCCEEDED", i.e. the exact result
// this test exists to refuse.
func probeErrno(t *testing.T, out, name string) int {
	t.Helper()
	fields := parseProbeFields(out)
	v, ok := fields[name]
	if !ok {
		t.Fatalf("the probe printed no %q line, so nothing can be concluded from this "+
			"run — an absent line is not errno 0:\n%s", name, out)
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		t.Fatalf("%s=%q is not a number:\n%s", name, v, out)
	}
	return n
}

func TestA32BitBinaryIsKilledRatherThanRunUnfiltered(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requireCompatArch(t)

	bin32 := buildArch32Probe(t, "386")
	proj, _ := target(t)
	stageArch32Probe(t, proj, bin32, "probe32")

	r := run(t, nil, proj, "./probe32")
	if !r.ran {
		t.Fatalf("the payload never started, so this run measures nothing:\n%s", r.out)
	}
	if r.code != killedBySIGSYS {
		t.Errorf("the 32-bit probe exited %d, want %d (SIGSYS from "+
			"SECCOMP_RET_KILL_PROCESS). Anything else means its syscalls reached the "+
			"kernel under the i386 audit arch, which matches no rule in the filter — "+
			"i.e. unfiltered:\n%s", r.code, killedBySIGSYS, r.out)
	}
	if strings.Contains(r.out, "start=") {
		t.Errorf("the 32-bit probe printed its first line, so it survived at least one "+
			"write(2). The kill must land on the process's first syscall:\n%s", r.out)
	}
}

// The control for the test above: --no-seccomp must let the same binary run,
// which is what proves the filter is what killed it. Its errnos are also the
// bug's own fingerprint — EINVAL and 0 are the kernel's answers, and they are
// what the FILTERED run produced before this fix.
func TestA32BitBinaryRunsWithoutTheFilterAndItsErrnosAreTheKernels(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requireCompatArch(t)

	bin32 := buildArch32Probe(t, "386")
	proj, _ := target(t)
	stageArch32Probe(t, proj, bin32, "probe32")

	r := run(t, []string{"--no-seccomp"}, proj, "./probe32").mustRun(t)
	if r.code != 0 {
		t.Fatalf("the 32-bit probe exited %d under --no-seccomp; it must run:\n%s", r.code, r.out)
	}
	if got := probeErrno(t, r.out, "unshare_errno"); got != einval {
		t.Errorf("unshare_errno=%d, want %d (EINVAL, the KERNEL's answer). If this is %d "+
			"then something other than snug's filter is denying it and the comparison "+
			"with the filtered run below is not measuring the filter:\n%s",
			got, einval, eperm, r.out)
	}
	if got := probeErrno(t, r.out, "ptrace_errno"); got != 0 {
		t.Errorf("ptrace_errno=%d, want 0 (the call reached the kernel):\n%s", got, r.out)
	}
}

// The other control: on the NATIVE arch the filter is installed, selective and
// answering — EPERM for both calls, from the same source, in the same sandbox
// shape. Without this a filter that killed every process would pass the first
// test.
func TestTheNativeArchProbeIsDeniedByTheFilterNotTheKernel(t *testing.T) {
	budget(t)
	requireSandbox(t)

	bin := buildArch32Probe(t, runtime.GOARCH)
	proj, _ := target(t)
	stageArch32Probe(t, proj, bin, "probe")

	r := run(t, nil, proj, "./probe").mustRun(t)
	if r.code != 0 {
		t.Fatalf("the native probe exited %d; it must run to completion under the "+
			"filter:\n%s", r.code, r.out)
	}
	for _, name := range []string{"unshare_errno", "ptrace_errno"} {
		if got := probeErrno(t, r.out, name); got != eperm {
			t.Errorf("%s=%d, want %d (EPERM, the FILTER's answer). The native arch is the "+
				"one the filter's numbers are for; if this call is not denied here, the "+
				"32-bit test above proves nothing about a filter that works:\n%s",
				name, got, eperm, r.out)
		}
	}
}

// REGRESSION for the same defect in its strongest form, found by the redteam
// round on this change: `int $0x80` from an ORDINARY 64-bit binary. The kernel
// serves that entry point from the i386 syscall table and reports
// AUDIT_ARCH_I386 to seccomp, so the bypass never needed a 32-bit toolchain, a
// 32-bit libc or a 32-bit ELF — two bytes of machine code in a native program
// reach a table this filter has no numbers for.
//
// The test above would pass a filter that only refused 32-bit ELFs. This one
// would not, which is why both are here.
//
// Measured on the parent commit, filter ON, with a freestanding C build of the
// same idea: the i386 `unshare(CLONE_NEWUSER)` returned 0 — a user namespace
// created from inside the sandbox, through a filter that denies exactly that
// call on the native arch.
func TestInt80FromANativeBinaryIsKilled(t *testing.T) {
	budget(t)
	requireSandbox(t)
	if runtime.GOARCH != "amd64" {
		t.Skipf("int $0x80 is x86-only; GOARCH=%s", runtime.GOARCH)
	}

	bin := buildProbeForArch(t, "int80probe", runtime.GOARCH)
	proj, _ := target(t)
	stageArch32Probe(t, proj, bin, "int80probe")

	r := run(t, nil, proj, "./int80probe")
	if !r.ran {
		t.Fatalf("the payload never started, so this run measures nothing:\n%s", r.out)
	}
	if !strings.Contains(r.out, "start=OK") {
		t.Fatalf("the probe printed no start line — it died before reaching the int $0x80, "+
			"so this run does not measure that instruction:\n%s", r.out)
	}
	if r.code != killedBySIGSYS {
		t.Errorf("the int $0x80 probe exited %d, want %d (SIGSYS). A native binary reached "+
			"the i386 syscall table, which this filter has no numbers for:\n%s",
			r.code, killedBySIGSYS, r.out)
	}
	if strings.Contains(r.out, "survived=OK") {
		t.Errorf("the probe survived its int $0x80:\n%s", r.out)
	}
}

// The control for the test above, and the shape of the bug itself: without the
// filter the same instruction reaches the kernel and comes back with the
// KERNEL's errno. -1 would be EPERM, which is what snug's filter returns for a
// denied NATIVE call — seeing that here would mean something other than the
// arch rule was doing the work above.
func TestInt80ReachesTheKernelWithoutTheFilter(t *testing.T) {
	budget(t)
	requireSandbox(t)
	if runtime.GOARCH != "amd64" {
		t.Skipf("int $0x80 is x86-only; GOARCH=%s", runtime.GOARCH)
	}

	bin := buildProbeForArch(t, "int80probe", runtime.GOARCH)
	proj, _ := target(t)
	stageArch32Probe(t, proj, bin, "int80probe")

	r := run(t, []string{"--no-seccomp"}, proj, "./int80probe").mustRun(t)
	if r.code != 0 {
		t.Fatalf("the probe exited %d under --no-seccomp; it must run:\n%s", r.code, r.out)
	}
	if !strings.Contains(r.out, "survived=OK") {
		t.Fatalf("the probe did not survive its int $0x80 under --no-seccomp, so the kill "+
			"above cannot be attributed to the filter:\n%s", r.out)
	}
	if got := probeErrno(t, r.out, "int80_unshare_ret"); got == -1 {
		t.Errorf("int80_unshare_ret=-1, i.e. EPERM — that is the FILTER's answer, and the "+
			"filter is off in this run:\n%s", r.out)
	}
}
