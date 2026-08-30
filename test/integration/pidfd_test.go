//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// REGRESSION (issue #23): before this commit, pidfd_getfd, process_vm_readv
// and process_vm_writev were absent from deniedSyscalls, and were measured —
// sibling to sibling, inside one sandbox, on this host — stealing an open
// file description, reading another payload's memory, and REWRITING it,
// respectively. All three are now denied with EPERM in
// internal/sandbox/seccomp.go; pidfd_open stays allowed.
//
// # Why the SELF case, not the sibling case
//
// A sibling-to-sibling test cannot be the assertion here. On any host with
// kernel.yama.ptrace_scope=1 — this host, and every CI image that has not
// gone out of its way to turn it off — the sibling call already returns
// EPERM whether or not snug's filter is installed at all: Yama gets there
// first. A test built on that case would pass identically on a completely
// unfiltered sandbox, which is exactly the "a test that cannot fail" shape
// CLAUDE.md keeps a scar from (the pasta.avx2 comm-string check that could
// never observe `after > before`).
//
// pidfd_getfd and process_vm_readv/writev all skip ptrace_may_access
// entirely when the target task IS the caller (task == current), so calling
// each of them against ONE'S OWN pid/fd/memory succeeds on an unfiltered
// kernel and fails, specifically with EPERM, only once snug's seccomp filter
// is what is doing the denying. That is the case every test below uses. See
// test/integration/testdata/pidfdprobe/main.go for the probe itself — none of
// these three syscalls is shell-reachable, so it is a small compiled Go
// binary (built once in TestMain, the same way snugBin is), run inside the
// sandbox in place of a bash script.
//
// # What each test asserts, and why it is more than "it failed"
//
//   - the EXACT errno, EPERM, not merely a non-zero exit. EPERM was chosen
//     over ENOSYS deliberately: the kernel already returns EPERM for this
//     whole family on every ptrace_scope=1 distro (the well-trodden path
//     every caller already copes with), and ENOSYS while pidfd_open still
//     succeeds would describe a kernel that cannot exist — pidfd_open landed
//     in 5.3, pidfd_getfd in 5.6, so a kernel new enough for one and too old
//     for the other is not a real kernel. If a future edit changes the
//     errno, these tests fail and point back at this reasoning rather than
//     just going red.
//   - pidfd_open on self still SUCCEEDS in the same run — the positive
//     control that the filter is selective (denying three specific calls),
//     not that the whole pidfd family or this kernel/host is unavailable.
//   - /proc/self/status reports Seccomp: 2 in the same run — the positive
//     control that a filter is installed AT ALL, per
//     TestSeccompIsActuallyInstalled's reasoning: requested is not the same
//     as active.
//   - under --no-seccomp, the SAME call SUCCEEDS — the control that proves
//     THE FILTER, and not something else about the sandbox or this probe, is
//     what produces the denial above.

// pidfdProbeRun is one execution of the pidfdprobe binary inside a sandbox,
// with its "name=RESULT" lines parsed out.
type pidfdProbeRun struct {
	sandboxRun
	fields map[string]string
}

// stagePidfdProbe copies the once-built pidfdprobe binary into a fresh
// project directory. It has to be a copy under the target: bwrap only shows
// the sandbox what a granted mount covers, and the compiled binary lives in
// TestMain's own scratch directory, well outside every grant.
func stagePidfdProbe(t *testing.T, proj string) {
	t.Helper()
	data, err := os.ReadFile(pidfdProbeBin)
	if err != nil {
		t.Fatalf("reading the once-built pidfdprobe binary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(proj, "pidfdprobe"), data, 0o755); err != nil {
		t.Fatalf("staging pidfdprobe into the target: %v", err)
	}
}

// parseProbeFields pulls every "name=RESULT" line out of a probe's output.
// Shared by every runner in this file so a "name=RESULT" line means the same
// thing everywhere in it.
func parseProbeFields(out string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		name, result, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[name] = result
	}
	return fields
}

// runPidfdProbe stages and runs the probe, with extra snug flags (e.g.
// --no-seccomp) passed straight through, and fails the test unless the
// payload actually ran — mustRun's job, but applied here too since a probe
// that never started would make every field below read as "absent" and every
// assertion drawn from that would be vacuous.
func runPidfdProbe(t *testing.T, args ...string) pidfdProbeRun {
	t.Helper()
	proj, _ := target(t)
	stagePidfdProbe(t, proj)
	r := run(t, args, proj, "./pidfdprobe").mustRun(t)
	return pidfdProbeRun{sandboxRun: r, fields: parseProbeFields(r.out)}
}

// requireProbeField fails the test, naming the missing key and the full
// output, rather than letting a later comparison silently see "" and produce
// a confusing failure message about the wrong thing.
func requireProbeField(t *testing.T, r pidfdProbeRun, name string) string {
	t.Helper()
	v, ok := r.fields[name]
	if !ok {
		t.Fatalf("pidfdprobe never printed a %q line, so nothing below can be "+
			"asserted about it:\n%s", name, r.out)
	}
	return v
}

// requireFilterIsSelectiveAndInstalled applies the two positive controls
// every test in this file needs, on the FILTERED run: pidfd_open must still
// succeed (the filter denies three specific calls, not the whole pidfd
// family or the kernel's support for it), and the kernel's own
// /proc/self/status must report Seccomp: 2 (requested is not the same as
// active — TestSeccompIsActuallyInstalled's reasoning, applied to this
// probe's own run rather than borrowed from a different one).
func requireFilterIsSelectiveAndInstalled(t *testing.T, r pidfdProbeRun) {
	t.Helper()
	if got := requireProbeField(t, r, "pidfd_open"); got != "OK" {
		t.Fatalf("pidfd_open=%s: it must still succeed under the filter — the fix is "+
			"scoped to pidfd_getfd/process_vm_readv/process_vm_writev and pidfd_open "+
			"stays allowed because a handle with no way to become a descriptor buys "+
			"an attacker nothing. If this failed, everything below "+
			"is not measuring what it claims to:\n%s", got, r.out)
	}
	if got := requireProbeField(t, r, "seccomp_status"); got != "2" {
		t.Fatalf("seccomp_status=%s, want 2 (filter installed and active) — requested is "+
			"not the same as active:\n%s", got, r.out)
	}
}

// TestPidfdGetfdSelfIsDeniedByFilter is the named regression for the defect
// issue #23 reports: pidfd_getfd against ONE'S OWN pidfd (task == current,
// so Yama is never consulted) must now fail with EPERM, specifically,
// because unix.SYS_PIDFD_GETFD is in deniedSyscalls.
func TestPidfdGetfdSelfIsDeniedByFilter(t *testing.T) {
	budget(t)
	requireSandbox(t)

	filtered := runPidfdProbe(t)
	requireFilterIsSelectiveAndInstalled(t, filtered)

	if got := requireProbeField(t, filtered, "pidfd_getfd"); got != "operation not permitted" {
		t.Errorf("pidfd_getfd=%s, want \"operation not permitted\" (EPERM). EPERM is not "+
			"an arbitrary choice: it is the errno every ptrace_scope=1 host already "+
			"returns for this syscall, so every caller has a tested path for it, and "+
			"ENOSYS would describe a kernel that cannot exist (pidfd_open, which just "+
			"succeeded above, arrived a kernel release after pidfd_getfd's floor). If "+
			"this changed, re-read internal/sandbox/seccomp.go's deniedSyscalls comment "+
			"before changing the errno here to match:\n%s", got, filtered.out)
	}

	// CONTROL: with the filter off, the SAME self-directed call succeeds — the
	// evidence that the denial above is attributable to snug's seccomp filter
	// and not to this kernel, this probe, or ordinary process permissions
	// refusing pidfd_getfd on its own account.
	unfiltered := runPidfdProbe(t, "--no-seccomp")
	if got := requireProbeField(t, unfiltered, "pidfd_getfd"); got != "OK" {
		t.Errorf("--no-seccomp: pidfd_getfd=%s, want OK. If the self-case does not "+
			"succeed with the filter off, the EPERM above is not proven to come from "+
			"the filter at all:\n%s", got, unfiltered.out)
	}
}

// TestProcessVmReadvSelfIsDeniedByFilter is the named regression for the
// memory-read half of the same family: process_vm_readv against one's own
// pid must now fail with EPERM. The audit measured this exploitable sibling
// to sibling (VMREAD-MARKER-OK) before the fix; this is the SELF-case
// mechanisation — see the file doc comment for why sibling cannot be used.
func TestProcessVmReadvSelfIsDeniedByFilter(t *testing.T) {
	budget(t)
	requireSandbox(t)

	filtered := runPidfdProbe(t)
	requireFilterIsSelectiveAndInstalled(t, filtered)

	if got := requireProbeField(t, filtered, "process_vm_readv"); got != "operation not permitted" {
		t.Errorf("process_vm_readv=%s, want \"operation not permitted\" (EPERM), the same "+
			"errno chosen for the rest of this family and for the same reason (see "+
			"internal/sandbox/seccomp.go's deniedSyscalls comment):\n%s", got, filtered.out)
	}
	if filtered.fields["process_vm_readv_effect"] == "CONFIRMED" {
		t.Errorf("process_vm_readv reported an error but its effect line says the read "+
			"landed anyway — the probe's own error handling is not to be trusted here:\n%s",
			filtered.out)
	}

	// CONTROL: filter off, self-directed read succeeds and actually reads the
	// probe's own in-process buffer through the syscall path — process_vm_readv
	// is exercised for real, not merely invoked and ignored.
	unfiltered := runPidfdProbe(t, "--no-seccomp")
	if got := requireProbeField(t, unfiltered, "process_vm_readv"); got != "OK" {
		t.Errorf("--no-seccomp: process_vm_readv=%s, want OK:\n%s", got, unfiltered.out)
	}
	if unfiltered.fields["process_vm_readv_effect"] != "CONFIRMED" {
		t.Errorf("--no-seccomp: process_vm_readv succeeded but did not actually transfer "+
			"the expected bytes — the probe's technique itself may be broken, which would "+
			"make the filtered EPERM above unattributable to the filter:\n%s", unfiltered.out)
	}
}

// TestProcessVmWritevSelfIsDeniedByFilter is the named regression for the
// worse half of the pair: the audit measured a sibling not merely READING
// another payload's memory but REWRITING it (PWNED-BY-SIBLING). This is the
// SELF-case mechanisation of the same call.
func TestProcessVmWritevSelfIsDeniedByFilter(t *testing.T) {
	budget(t)
	requireSandbox(t)

	filtered := runPidfdProbe(t)
	requireFilterIsSelectiveAndInstalled(t, filtered)

	if got := requireProbeField(t, filtered, "process_vm_writev"); got != "operation not permitted" {
		t.Errorf("process_vm_writev=%s, want \"operation not permitted\" (EPERM):\n%s",
			got, filtered.out)
	}
	if filtered.fields["process_vm_writev_effect"] == "CONFIRMED" {
		t.Errorf("process_vm_writev reported an error but its effect line says the write "+
			"landed anyway — a memory write that happens despite a reported EPERM would "+
			"be a far worse finding than this test name suggests:\n%s", filtered.out)
	}

	// CONTROL: filter off, self-directed write succeeds and actually overwrites
	// the probe's own target buffer through the syscall path.
	unfiltered := runPidfdProbe(t, "--no-seccomp")
	if got := requireProbeField(t, unfiltered, "process_vm_writev"); got != "OK" {
		t.Errorf("--no-seccomp: process_vm_writev=%s, want OK:\n%s", got, unfiltered.out)
	}
	if unfiltered.fields["process_vm_writev_effect"] != "CONFIRMED" {
		t.Errorf("--no-seccomp: process_vm_writev succeeded but did not actually overwrite "+
			"the target buffer — the probe's technique itself may be broken, which would "+
			"make the filtered EPERM above unattributable to the filter:\n%s", unfiltered.out)
	}
}

// ── the /proc/<pid>/mem residual (issue #47) ────────────────────────────────
//
// Everything below this line is NOT a regression test for a fix. It asserts
// the OPPOSITE: that a known channel is deliberately, structurally, and
// currently STILL OPEN, so that the day somebody reads the three tests above,
// sees "pidfd_getfd and process_vm_readv/writev are denied", and concludes
// "co-resident payloads are isolated from each other", this test is what
// tells them they are wrong — the same correction issue #47 itself had to
// make about its own first draft.
//
// # What is open, and why seccomp cannot reach it
//
// /proc/<pid>/mem is an ordinary file. Opening it is open(2); reading and
// writing through it are pread(2)/pwrite(2) at an arbitrary offset — the
// offset IS the target address. None of that is a syscall #23's filter (or
// any classic-BPF filter) can single out without refusing ordinary file I/O
// outright: the filter can inspect a syscall NUMBER and a handful of integer
// arguments, never a path string, so "deny pread on this one magic path" is
// not an expressible rule. What gates /proc/<pid>/mem is Yama's
// PTRACE_MODE_ATTACH check on OPEN — the same check pidfd_getfd and
// process_vm_readv/writev used to rely on before #23 put a second,
// syscall-level lock beside it. This residual is what is left when that
// second lock does not apply, because there was never a syscall here for it
// to name.
//
// # Why the victim OPTS IN when Yama is enforcing, and why that is not a
// weaker test
//
// Yama's ptrace_scope=1 (this host, and most CI images) refuses the ATTACH
// check for anything but a ptracer's own descendant. Two siblings inside one
// sandbox are not descendants of each other, so the raw sibling case is
// refused — which is exactly the CONTROL this test runs when Yama is
// enforcing, and exactly why it is not the interesting case there.
// prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) is the standard, non-root,
// well-documented way a process waives that check for itself; it is how a
// ptrace_scope=1 host is made to demonstrate what a ptrace_scope=0 host does
// for every pair, unprompted.
//
// # Why this test does NOT skip on a ptrace_scope=0 host
//
// ptrace_scope=0 is not an exotic edge case for snug to shrug off — it is the
// common default INSIDE A CONTAINER, which is exactly where key feature 3
// says snug must work. `skipOrFail`'s usual shape (fail under
// SNUG_REQUIRE_SANDBOX, skip otherwise) would be actively wrong here: on a
// ptrace_scope=0 CI host the residual is MORE open than on this one, not
// less, so refusing to look would be backwards — the host where the finding
// is easiest to observe is the one this test would be declining to run on.
// So there is a branch instead of a skip: with Yama enforcing, run the
// opt-in/control pair described above; without it (ptrace_scope=0, or Yama
// not compiled into the kernel at all), assert the SAME residual with the
// opt-in step already removed, because on such a host there is nothing to
// opt out of and no refusal to use as a control — every sibling already has
// full read+write of another's /proc/<pid>/mem with no prctl call at all.
// Every host this test could run on takes one branch or the other; neither is
// a skip.
//
// # The two processes have to be REAL siblings in ONE sandbox
//
// This cannot be the SELF-case trick the three tests above use:
// PTRACE_MODE_ATTACH is never consulted for task == current in the first
// place (there is nothing to attach to), so a self-only probe cannot exercise
// Yama's check at all. victim and attacker (test/integration/testdata/
// pidfdprobe/main.go) are launched as two separate processes from the SAME
// snug invocation, coordinating through plain files in the shared target
// directory: victim publishes its pid and a buffer address, waits for a
// "victim-done" file, then reads its own buffer back so the test can see —
// independently of anything the attacker claims — whether the write actually
// landed.
func TestKnownOpenResidualSiblingReadWritesProcPidMem(t *testing.T) {
	budget(t)
	requireSandbox(t)

	yamaPresent, scope := hostPtraceScope(t)
	if yamaPresent && scope > 0 {
		testProcMemResidualUnderYama(t)
		return
	}
	testProcMemResidualWithNoYamaGate(t, yamaPresent, scope)
}

// hostPtraceScope reads the HOST kernel's ptrace_scope sysctl directly,
// rather than through a payload. Yama is a global, non-namespaced LSM knob —
// nothing about a mount or user namespace changes the value a process sees —
// so this is not a proxy for the real thing, it IS the real thing, read from
// wherever is simplest.
//
// present is false when Yama is not compiled into this kernel at all (the
// sysctl file does not exist). That behaves exactly like ptrace_scope=0 for
// this test's purposes: either way, there is no ATTACH check to waive.
func hostPtraceScope(t *testing.T) (present bool, scope int) {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		if os.IsNotExist(err) {
			return false, 0
		}
		t.Fatalf("reading /proc/sys/kernel/yama/ptrace_scope: %v", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("unparseable /proc/sys/kernel/yama/ptrace_scope %q: %v", string(b), err)
	}
	return true, n
}

// testProcMemResidualUnderYama is the branch for a host where Yama is
// actually enforcing (ptrace_scope>0) — this host, and most developer
// machines and CI images. See the package-level comment above for the full
// reasoning; this is the opt-in/control PAIR.
func testProcMemResidualUnderYama(t *testing.T) {
	t.Helper()

	// THE FINDING. Victim has opted in with PR_SET_PTRACER_ANY.
	positive := runProcMemProbe(t, true)

	// Assertion 1: the syscall route stays closed. #23's filter denies
	// process_vm_readv/writev at syscall entry, before the kernel reaches
	// Yama's check at all, so this must be EPERM regardless of the opt-in —
	// the contrast with assertion 2 IS the point of this test.
	if got := requireProbeField(t, positive, "VMREAD_SIBLING"); got != "operation not permitted" {
		t.Errorf("VMREAD_SIBLING=%s, want \"operation not permitted\" (EPERM) even with the "+
			"victim opted in — the syscall route must stay closed no matter what Yama would "+
			"allow, or this test is no longer showing a CONTRAST between the two routes:\n%s",
			got, positive.out)
	}
	if got := requireProbeField(t, positive, "VMWRITE_SIBLING"); got != "operation not permitted" {
		t.Errorf("VMWRITE_SIBLING=%s, want \"operation not permitted\" (EPERM):\n%s",
			got, positive.out)
	}

	// Assertion 2: THE RESIDUAL. /proc/<pid>/mem gives a sibling full read AND
	// write of the victim's memory. This is expected to SUCCEED — that is the
	// whole point of this test, and a future change that makes it fail here is
	// worth celebrating, but only if it is READ as "issue #47 got closed" and
	// this test gets deleted or rewritten to match, not silently tolerated as
	// flake.
	if got := requireProbeField(t, positive, "PROCMEM_OPEN"); got != "OK" {
		t.Fatalf("PROCMEM_OPEN=%s, want OK — the victim opted in via PR_SET_PTRACER_ANY "+
			"specifically so this would succeed; if it did not, the opt-in itself may be "+
			"broken and the CONTROL below would not mean what it claims to:\n%s",
			got, positive.out)
	}
	if got := requireProbeField(t, positive, "PROCMEM_READ"); !strings.HasPrefix(got, "OK") {
		t.Errorf("PROCMEM_READ=%s, want it to succeed (this is the KNOWN OPEN residual, "+
			"issue #47 — not a claim that it should be closed by this commit):\n%s",
			got, positive.out)
	}
	if got := requireProbeField(t, positive, "PROCMEM_WRITE"); !strings.HasPrefix(got, "OK") {
		t.Errorf("PROCMEM_WRITE=%s, want it to succeed:\n%s", got, positive.out)
	}
	// The victim's OWN readback, independent of anything the attacker
	// reported, is what makes this more than the attacker's word for it.
	if !strings.Contains(positive.out, "VICTIM-FINAL=PWNED-VIA-PROCMEM-WRITE") {
		t.Errorf("the attacker reported a successful write but the victim's own buffer, "+
			"read back independently in the SAME process, does not show it — this probe's "+
			"technique may be broken rather than the residual being real:\n%s", positive.out)
	}

	// Assertion 3: CONTROL. Same attempt, victim did NOT opt in. This has to
	// refuse, or assertion 2 proves nothing: without this half, "succeeds"
	// above would be equally true of a host where Yama's ptrace_scope check
	// is a dead letter for every pair — the "test that cannot fail" shape
	// from the OPPOSITE direction of the one the three tests above guard
	// against (there, a sibling call that is EPERM either way; here, a
	// sibling call that would SUCCEED either way).
	control := runProcMemProbe(t, false)
	if got := requireProbeField(t, control, "PROCMEM_OPEN"); got != "permission denied" {
		t.Fatalf("control: PROCMEM_OPEN=%s, want \"permission denied\" (EACCES) — without "+
			"this refusal, the SUCCEED case above is not shown to depend on the opt-in at "+
			"all, and this test would not be exercising Yama's real check:\n%s",
			got, control.out)
	}
	if !strings.Contains(control.out, "VICTIM-FINAL=SIBLING-SECRET-DO-NOT-READ") {
		t.Errorf("control: the victim's buffer changed even though the attacker's open was "+
			"refused — something wrote to it that this test did not account for:\n%s",
			control.out)
	}
}

// testProcMemResidualWithNoYamaGate is the branch for a host with NO
// ptrace_scope enforcement — ptrace_scope=0, or Yama not compiled into this
// kernel at all. This is not a lesser check: it is the same residual with the
// gate already removed, which is the common state INSIDE A CONTAINER (key
// feature 3). There is nothing to opt into and no refusal to use as a
// control, so there is one run, and the read+write succeeding with NO
// PR_SET_PTRACER call is itself the finding.
func testProcMemResidualWithNoYamaGate(t *testing.T, yamaPresent bool, scope int) {
	t.Helper()

	got := runProcMemProbe(t, false)

	// The syscall route stays closed regardless of Yama — worth showing
	// precisely on a host where Yama itself is not doing anything, since it
	// is the clearest demonstration that #23's filter is an independent lock
	// and not merely redundant with Yama's check.
	if fld := requireProbeField(t, got, "VMREAD_SIBLING"); fld != "operation not permitted" {
		t.Errorf("VMREAD_SIBLING=%s, want \"operation not permitted\" (EPERM):\n%s", fld, got.out)
	}
	if fld := requireProbeField(t, got, "VMWRITE_SIBLING"); fld != "operation not permitted" {
		t.Errorf("VMWRITE_SIBLING=%s, want \"operation not permitted\" (EPERM):\n%s", fld, got.out)
	}

	if fld := requireProbeField(t, got, "PROCMEM_OPEN"); fld != "OK" {
		t.Fatalf("PROCMEM_OPEN=%s, want OK — this host reports ptrace_scope=%d "+
			"(yama present=%v), so nothing should be refusing the open at all; a "+
			"refusal here means either Yama is enforcing after all (this branch chose "+
			"wrong) or something else is gating /proc/<pid>/mem:\n%s",
			fld, scope, yamaPresent, got.out)
	}
	if fld := requireProbeField(t, got, "PROCMEM_READ"); !strings.HasPrefix(fld, "OK") {
		t.Errorf("PROCMEM_READ=%s, want it to succeed (KNOWN OPEN residual, issue #47):\n%s",
			fld, got.out)
	}
	if fld := requireProbeField(t, got, "PROCMEM_WRITE"); !strings.HasPrefix(fld, "OK") {
		t.Errorf("PROCMEM_WRITE=%s, want it to succeed:\n%s", fld, got.out)
	}
	if !strings.Contains(got.out, "VICTIM-FINAL=PWNED-VIA-PROCMEM-WRITE") {
		t.Errorf("the attacker reported a successful write but the victim's own buffer, "+
			"read back independently, does not show it:\n%s", got.out)
	}
}

// procMemScript is the in-sandbox choreography for the two-process residual
// probe: start the victim in the background, poll (inside the sandbox — there
// is no host-side process to signal readiness to here, unlike the rest of
// this suite's listener tests) until it has published its pid and buffer
// address, run the attacker against them, release the victim by creating
// "victim-done", and print everything both sides said. %s is "--ptracer-any"
// or empty.
const procMemScript = `
./pidfdprobe victim %s > victim.out 2>&1 &
VPID=$!
for i in $(seq 1 250); do grep -q '^VICTIM-ADDR=' victim.out 2>/dev/null && break; sleep 0.02; done
PID=$(grep '^VICTIM-PID=' victim.out | cut -d= -f2)
ADDR=$(grep '^VICTIM-ADDR=' victim.out | cut -d= -f2)
./pidfdprobe attacker "$PID" "$ADDR"
touch victim-done
wait "$VPID"
cat victim.out
`

// runProcMemProbe runs the victim/attacker pair inside one sandbox and
// returns both sides' combined output, parsed the same way runPidfdProbe's
// is.
func runProcMemProbe(t *testing.T, ptracerAny bool) pidfdProbeRun {
	t.Helper()
	proj, _ := target(t)
	stagePidfdProbe(t, proj)

	arg := ""
	if ptracerAny {
		arg = "--ptracer-any"
	}
	r := run(t, nil, proj, fmt.Sprintf(procMemScript, arg)).mustRun(t)
	return pidfdProbeRun{sandboxRun: r, fields: parseProbeFields(r.out)}
}

// ── issue #115: the pidfd_getfd denial buys the SOCKET, not four objects ────
//
// This test, like the /proc/<pid>/mem one above, is not a regression test for
// a fix. It pins a MEASUREMENT that a comment had got wrong in the reassuring
// direction. seccomp.go used to justify denying pidfd_getfd by saying procfs
// could not reopen "a socket, a pipe, a memfd, a deleted file" — so the
// denial was the only route to any of them. Three of the four are false:
// /proc/<pid>/fd/N reopens a sibling's memfd, pipe, deleted file and
// O_TMPFILE file, contents included, through nothing but openat(2) and
// read(2).
//
// The socket is the one that holds, and it holds for a structural reason
// rather than a permission check: sockfs installs sock_no_open, so open(2) on
// the magic link returns ENXIO for every caller, root included. That single
// object is the whole residual value of the denial, and it is what
// SUPERVISOR-DESIGN.md's control-channel argument rests on — which is why the
// assertion below is exact (ENXIO, not "some error"): if a future kernel ever
// gives sockfs an open method, that argument loses its footing and this test
// is where the news should arrive.
//
// Direction of each assertion, since they do not all run the same way:
//
//   - control (a plain, still-linked regular file) MUST reopen. Without it,
//     every refusal below could be a broken thief rather than a closed door.
//   - memfd, pipe, deleted, tmpfile MUST reopen, with their own marker bytes.
//     These are expected successes — issue #47's reach made concrete. A day
//     when they start failing is a day the kernel changed, and the right
//     response is to re-read #47 and #115, not to "fix" this test.
//   - socket MUST fail, with ENXIO exactly.
//
// No Yama branch, unlike TestKnownOpenResidualSiblingReadWritesProcPidMem:
// opening /proc/<pid>/fd/N needs ptrace_may_access(PTRACE_MODE_READ_FSCREDS)
// and yama_ptrace_access_check gates PTRACE_MODE_ATTACH only, so
// ptrace_scope does not apply at any value. That asymmetry is the point of
// the finding: this reach survives on exactly the hardened hosts where the
// syscall-shaped descriptor theft does not.
func TestKnownOpenResidualSiblingReopensAnythingButASocket(t *testing.T) {
	budget(t)
	requireSandbox(t)

	r := runFdReopenProbe(t)

	// POSITIVE CONTROL first: if this one is not reopenable the thief never
	// worked, and the socket's refusal below would be indistinguishable from
	// a typo in a path.
	if got := requireProbeField(t, r, "REOPEN_control_OPEN"); got != "OK" {
		t.Fatalf("REOPEN_control_OPEN=%s, want OK — a plain, still-linked regular file "+
			"held by a sibling must be reopenable through /proc/<pid>/fd/N. It is not, so "+
			"the thief is broken and nothing else this test reports means anything:\n%s",
			got, r.out)
	}
	if got := requireProbeField(t, r, "REOPEN_control_READ"); !strings.Contains(got, "REOPEN-MARKER-115-control") {
		t.Fatalf("REOPEN_control_READ=%s, want the control's own marker bytes:\n%s", got, r.out)
	}

	// THE FINDING. Each of these was named in the old comment as something
	// only pidfd_getfd could reach.
	for _, kind := range []string{"memfd", "pipe", "deleted", "tmpfile"} {
		// O_TMPFILE needs filesystem support; the holder says so explicitly
		// rather than reporting a refusal it never measured.
		if kind == "tmpfile" && strings.Contains(r.out, "HOLDER-SKIPPED=tmpfile") {
			t.Logf("tmpfile not measured on this filesystem (holder said so); "+
				"the other three carry the finding:\n%s", r.out)
			continue
		}
		if got := requireProbeField(t, r, "REOPEN_"+kind+"_OPEN"); got != "OK" {
			t.Errorf("REOPEN_%s_OPEN=%s, want OK. This test asserts a KNOWN OPEN reach "+
				"(issues #47, #115), not a closed one: a %s held by a sibling IS "+
				"reopenable through /proc/<pid>/fd/N on the kernels measured. If this "+
				"now refuses, the kernel changed — go and correct seccomp.go, "+
				"CLAUDE.md and INDEX.md, which all currently say it does:\n%s",
				kind, got, kind, r.out)
			continue
		}
		want := "REOPEN-MARKER-115-" + kind
		if got := requireProbeField(t, r, "REOPEN_"+kind+"_READ"); !strings.Contains(got, want) {
			t.Errorf("REOPEN_%s_READ=%s, want it to contain %q — the open succeeded, so a "+
				"missing or wrong marker means the reopened descriptor is not the object "+
				"the holder published, and this probe is measuring the wrong thing:\n%s",
				kind, got, want, r.out)
		}
	}

	// THE RESIDUAL, and the only part of the old four-object claim that
	// survived. Exact errno: ENXIO is sockfs having no open method, not a
	// permission decision, and the distinction is what makes it durable.
	if got := requireProbeField(t, r, "REOPEN_socket_OPEN"); got != "no such device or address" {
		t.Errorf("REOPEN_socket_OPEN=%s, want \"no such device or address\" (ENXIO). The "+
			"socket is the ENTIRE residual value of denying pidfd_getfd, and "+
			"SUPERVISOR-DESIGN.md's control-channel argument rests on it. If this is now "+
			"OK, a sibling can reopen a connected socket through procfs and that argument "+
			"needs rewriting, not this assertion:\n%s", got, r.out)
	}
	// The link still RESOLVES even though the open refuses — enumeration was
	// never gated, only the reopen. Asserted so nobody reads the ENXIO above
	// as "procfs hides sockets from a sibling", which it does not.
	if got := requireProbeField(t, r, "REOPEN_socket_LINK"); !strings.HasPrefix(got, "OK") {
		t.Errorf("REOPEN_socket_LINK=%s, want OK: /proc/<pid>/fd LISTS and readlinks a "+
			"sibling's socket fine — it is only open(2) that refuses. A failure here "+
			"means something gated the enumeration too, which would be a different "+
			"(and better) world than the one #47 describes:\n%s", got, r.out)
	}
}

// fdReopenScript is the in-sandbox choreography for the fdholder/fdthief
// pair. Same shape as procMemScript: start the holder, poll until it says it
// is ready, build the thief's argument list out of the holder's own published
// "HOLDER-FD-<kind>=<n>" lines rather than assuming fd numbers, run the
// thief, release the holder, print both sides.
const fdReopenScript = `
./pidfdprobe fdholder > holder.out 2>&1 &
HPID=$!
for i in $(seq 1 250); do grep -q '^HOLDER-READY=' holder.out 2>/dev/null && break; sleep 0.02; done
PID=$(grep '^HOLDER-PID=' holder.out | cut -d= -f2)
SPECS=$(sed -n 's/^HOLDER-FD-\([a-z]*\)=\([0-9]*\)$/\1=\2/p' holder.out | tr '\n' ' ')
./pidfdprobe fdthief "$PID" $SPECS
touch fdholder-done
wait "$HPID"
cat holder.out
`

// runFdReopenProbe runs the fdholder/fdthief pair inside one sandbox and
// returns both sides' combined output, parsed the same way runProcMemProbe's
// is.
func runFdReopenProbe(t *testing.T) pidfdProbeRun {
	t.Helper()
	proj, _ := target(t)
	stagePidfdProbe(t, proj)

	r := run(t, nil, proj, fdReopenScript).mustRun(t)
	return pidfdProbeRun{sandboxRun: r, fields: parseProbeFields(r.out)}
}
