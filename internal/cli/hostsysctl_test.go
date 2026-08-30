package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSysctlHost turns a knob->value map into the reader readHostSysctls
// takes. A knob absent from the map is UNREADABLE, which is the state a
// kernel without Yama or without BPF is really in — not zero.
func fakeSysctlHost(values map[string]string) func(string) (string, error) {
	return func(path string) (string, error) {
		for _, s := range inheritedSysctls {
			if s.path() == path {
				v, ok := values[s.knob]
				if !ok {
					// fs.ErrNotExist, not a lookalike: the report and the
					// fix distinguish "this kernel does not have the knob"
					// from "the knob is there and would not read", and a
					// fixture that fakes absence with a bare error tests
					// neither arm.
					return "", fmt.Errorf("open %s: %w", path, fs.ErrNotExist)
				}
				return v + "\n", nil
			}
		}
		return "", fmt.Errorf("test asked for %s, which is not in the table", path)
	}
}

// allSet is a host that satisfies every row, written from the table so a row
// added later cannot leave this fixture silently short.
func allSet() map[string]string {
	m := map[string]string{}
	for _, s := range inheritedSysctls {
		m[s.knob] = fmt.Sprint(s.want)
	}
	return m
}

// The classification IS the feature: weak, satisfied, stricter than asked,
// unreadable and unparseable are five different answers and the report and
// the fix command act differently on each.
func TestAnInheritedSysctlIsClassifiedByValueAndByReadability(t *testing.T) {
	const knob = "kernel.kptr_restrict"
	row := inheritedSysctl(knob)
	if row.want != 1 {
		t.Fatalf("this test is written against want=1 for %s, got %d", knob, row.want)
	}

	for _, tc := range []struct {
		name       string
		value      string
		present    bool
		wantOK     bool
		wantReadab bool
	}{
		{name: "below want is weak", value: "0", present: true, wantReadab: true},
		{name: "exactly want is satisfied", value: "1", present: true, wantOK: true, wantReadab: true},
		// The one a naive equality check gets wrong, and getting it wrong
		// would make `snug fix sysctl -w` LOWER a hardened host's knob.
		{name: "stricter than want is satisfied", value: "2", present: true, wantOK: true, wantReadab: true},
		{name: "absent is unreadable, not weak", present: false},
		{name: "unparseable is unreadable, not weak", value: "yes please", present: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := allSet()
			if tc.present {
				values[knob] = tc.value
			} else {
				delete(values, knob)
			}
			var got sysctlReading
			for _, r := range readHostSysctls(fakeSysctlHost(values)) {
				if r.sysctl.knob == knob {
					got = r
				}
			}
			if got.ok() != tc.wantOK {
				t.Errorf("ok() = %v, want %v (value %q present=%v)", got.ok(), tc.wantOK, tc.value, tc.present)
			}
			if got.readable() != tc.wantReadab {
				t.Errorf("readable() = %v, want %v", got.readable(), tc.wantReadab)
			}
		})
	}
}

// A weak knob is only disclosed if the report NAMES it, with the number it
// has and the number it needs. "some hardening is missing" sends a reader to
// a search engine; the knob, the value and the want are the whole fix.
func TestTheDoctorReportNamesTheWeakKnobItsValueAndWhatItCosts(t *testing.T) {
	values := allSet()
	values["kernel.dmesg_restrict"] = "0"
	out := captureStdout(t, func() {
		reportHostSysctls(readHostSysctls(fakeSysctlHost(values)))
	})

	for _, want := range []string{
		"kernel.dmesg_restrict = 0",
		"want 1 or stricter",
		"kernel ring buffer",
		"snug fix sysctl",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report never said %q:\n%s", want, out)
		}
	}
	// The negative: the four rows that ARE set must not be dressed up as
	// problems, or the one that matters is lost in the noise.
	if strings.Contains(out, "kernel.kptr_restrict = 1, want") {
		t.Errorf("a satisfied knob was reported as weak:\n%s", out)
	}
}

// An absent knob is not a weak one. Reporting "kernel.yama.ptrace_scope = 0"
// on a kernel with no Yama names a sysctl the machine will refuse to set,
// and `snug fix sysctl -w` would then write a drop-in that fails on every
// boot.
func TestAnAbsentKnobIsReportedAsAbsentAndIsNeverFixed(t *testing.T) {
	values := allSet()
	delete(values, "kernel.yama.ptrace_scope")
	readings := readHostSysctls(fakeSysctlHost(values))

	out := captureStdout(t, func() { reportHostSysctls(readings) })
	if !strings.Contains(out, "kernel.yama.ptrace_scope — this kernel does not have it") {
		t.Errorf("an absent knob was not reported as absent:\n%s", out)
	}
	if strings.Contains(out, "kernel.yama.ptrace_scope = 0") {
		t.Errorf("an absent knob was reported as a value of 0:\n%s", out)
	}
	for _, l := range sysctlWeakLines(readings) {
		if strings.Contains(l, "ptrace_scope") {
			t.Errorf("`snug fix sysctl` would apply %q for a knob this kernel does not have", l)
		}
	}
	for _, l := range sysctlDropInLines(readings) {
		if strings.Contains(l, "ptrace_scope") {
			t.Errorf("the drop-in would carry %q — a sysctl.d line for a knob this kernel does "+
				"not have fails on every boot", l)
		}
	}

	// And the headline must not claim the host failed to SET something it
	// does not have. "already sets every knob" is the sentence this arm gets
	// wrong, and it is wrong in the reassuring direction.
	if strings.Contains(out, "does not set every kernel knob") {
		t.Errorf("a kernel that lacks the knob was reported as a host that failed to set it:\n%s", out)
	}
	if !strings.Contains(out, "have no usable value here") {
		t.Errorf("the no-usable-value headline never appeared:\n%s", out)
	}
}

// A host that satisfies everything gets one line and no advice: doctor is
// read by people looking for what is wrong.
func TestAFullySetHostGetsOneLineAndNoFixAdvice(t *testing.T) {
	out := captureStdout(t, func() {
		reportHostSysctls(readHostSysctls(fakeSysctlHost(allSet())))
	})
	if !strings.Contains(out, "✅") || strings.Contains(out, "snug fix sysctl") {
		t.Errorf("a fully-set host should get a tick and no advice:\n%s", out)
	}
}

// THE RULE THAT MAKES THIS COMMAND SAFE TO RUN: only the weak rows are
// written. A host stricter than snug asks for must not be walked back to
// snug's minimum by the very file that claims to harden it.
func TestFixSysctlNeverWritesALineForAKnobThatIsAlreadyAtLeastAsStrict(t *testing.T) {
	values := allSet()
	values["kernel.kptr_restrict"] = "2"               // stricter than want=1
	values["kernel.perf_event_paranoid"] = "0"         // weak
	delete(values, "kernel.unprivileged_bpf_disabled") // absent

	lines := sysctlWeakLines(readHostSysctls(fakeSysctlHost(values)))
	want := []string{"kernel.perf_event_paranoid = 2"}
	if len(lines) != len(want) || lines[0] != want[0] {
		t.Fatalf("lines = %q, want %q", lines, want)
	}

	body := sysctlDropInBody(lines)
	if !strings.Contains(body, "kernel.perf_event_paranoid = 2") {
		t.Errorf("the drop-in does not carry the setting:\n%s", body)
	}
	if strings.Contains(body, "kptr_restrict") {
		t.Errorf("the drop-in would lower this host's kptr_restrict from 2 to 1:\n%s", body)
	}
}

// A fully-set host has nothing to APPLY. It still has a file to persist —
// see TestTheDropInIsWrittenEvenWhenTheRunningKernelNeedsNothing below, which
// is the half this assertion used to be read as covering.
func TestFixSysctlHasNothingToApplyOnAHostThatIsAlreadySet(t *testing.T) {
	if lines := sysctlWeakLines(readHostSysctls(fakeSysctlHost(allSet()))); len(lines) != 0 {
		t.Errorf("a fully-set host produced %q to apply, want nothing at all", lines)
	}
}

// The ticket's own requirement: doctor and container preflight P6 must not
// disagree about the ptrace_scope threshold. They cannot, because P6 takes
// the row — this drives P6's decision at every value the kernel defines and
// asserts the split falls exactly where the row says.
func TestContainerPreflightP6RefusesExactlyWhereTheReportedRowSaysItShould(t *testing.T) {
	row := inheritedSysctl("kernel.yama.ptrace_scope")
	for _, value := range []string{"0", "1", "2", "3"} {
		err := judgePtraceScope(row, value+"\n", nil)
		refused := err != nil
		wantRefused := value < fmt.Sprint(row.want)
		if refused != wantRefused {
			t.Errorf("ptrace_scope=%s: refused=%v, want %v (row wants %d)", value, refused, wantRefused, row.want)
		}
		if refused && !strings.Contains(err.Error(), row.knob) {
			t.Errorf("the refusal at %s does not name %s: %v", value, row.knob, err)
		}
	}
	// Absent Yama behaves like 0 — the kernel enforces nothing beyond the
	// same-uid rule, so assuming it is enforcing is the one answer P6 must
	// never give.
	if err := judgePtraceScope(row, "", errors.New("no such file or directory")); err == nil {
		t.Error("P6 accepted a host with no Yama at all")
	}
}

// inheritedSysctl panics rather than returning a zero row: a zero row has
// want=0, which every value satisfies, so a renamed knob would turn P6's
// refusal off and doctor's row green in the same silent step.
func TestAskingForAKnobThatIsNotInTheTablePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("inheritedSysctl returned instead of panicking on an unknown knob")
		}
	}()
	_ = inheritedSysctl("kernel.no_such_knob")
}

// captureSplitStreams keeps the two streams APART, which captureStdout
// deliberately does not: the property here is that a redirect of stdout
// alone yields a valid sysctl.d file, and a helper that interleaved them
// could not tell a corrupted file from a clean one.
func captureSplitStreams(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	outF, err := os.CreateTemp(t.TempDir(), "out-")
	if err != nil {
		t.Fatal(err)
	}
	errF, err := os.CreateTemp(t.TempDir(), "err-")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = outF, errF
	f()
	os.Stdout, os.Stderr = origOut, origErr
	outF.Close()
	errF.Close()

	o, err := os.ReadFile(outF.Name())
	if err != nil {
		t.Fatal(err)
	}
	e, err := os.ReadFile(errF.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(o), string(e)
}

// ── the drop-in is a function of the TABLE, not of this boot ────────────────
//
// Every test below is a redteam finding made permanent. The shape they share:
// `snug doctor` reads the RUNNING kernel and the drop-in governs the NEXT
// BOOT, and every defect in this family came from answering the second
// question with the first one's data.

// F1a. A drop-in derived from the weak rows alone DELETES hardening it wrote
// itself. Measured: a five-line 00-snug.conf on a host where a developer had
// loosened one knob at runtime (`sysctl -w kernel.perf_event_paranoid=-1` to
// profile something) was truncated to that one line — four persistent
// settings gone, exit 0, and doctor answering ✅ for all five because the
// runtime was fine.
func TestTheDropInCarriesEveryReadableRowAndNotOnlyTheWeakOnes(t *testing.T) {
	values := allSet()
	values["kernel.perf_event_paranoid"] = "-1"
	readings := readHostSysctls(fakeSysctlHost(values))

	if weak := sysctlWeakLines(readings); len(weak) != 1 {
		t.Fatalf("this fixture is meant to have exactly one weak knob, got %q", weak)
	}
	lines := sysctlDropInLines(readings)
	if len(lines) != len(inheritedSysctls) {
		t.Fatalf("the drop-in carries %d line(s) for a host with %d readable knobs: %q\n"+
			"a file with fewer lines than the last one DELETES the settings it is missing",
			len(lines), len(inheritedSysctls), lines)
	}
}

// F1/F3. The drop-in is a FLOOR. A host running stricter than snug asks for
// must never be lowered by the file snug wrote to harden it — and the value
// that would lower it is exactly the one `want` alone produces.
func TestTheDropInNeverPersistsAValueBelowWhatTheKernelIsAlreadyRunning(t *testing.T) {
	values := allSet()
	values["kernel.kptr_restrict"] = "2" // stricter than want=1
	lines := sysctlDropInLines(readHostSysctls(fakeSysctlHost(values)))

	found := false
	for _, l := range lines {
		if strings.HasPrefix(l, "kernel.kptr_restrict ") {
			found = true
			if l != "kernel.kptr_restrict = 2" {
				t.Errorf("the drop-in says %q on a host running 2 — the next boot would be WEAKER "+
					"than the host was before the fix", l)
			}
		}
	}
	if !found {
		t.Error("the drop-in carries no kptr_restrict line at all")
	}
}

// F1b. `-w` has two independent jobs. Measured: once the runtime was strict,
// -w said "nothing to do" and exited 0 with the drop-in DELETED — an image
// rebuild, an ansible run, a package upgrade — so the persistence could never
// be restored until a reboot made the knobs weak again. `snug fix` names that
// exact failure mode for the sibling noun and this one had it with no
// recovery.
func TestTheDropInIsWrittenEvenWhenTheRunningKernelNeedsNothing(t *testing.T) {
	dir := t.TempDir()
	dropIn := filepath.Join(dir, "00-snug.conf")
	readings := readHostSysctls(fakeSysctlHost(allSet()))
	body := sysctlDropInBody(sysctlDropInLines(readings))

	applied := 0
	code := captureCode(t, func() int {
		return applySysctlFix(readings, body, 0, "", dropIn, func(string, int) error {
			applied++
			return nil
		})
	})
	if code != 0 {
		t.Errorf("exit %d on a host that needed only its drop-in restored", code)
	}
	if applied != 0 {
		t.Errorf("%d knob(s) were written to the running kernel, which needed none", applied)
	}
	got, err := os.ReadFile(dropIn)
	if err != nil {
		t.Fatalf("the drop-in was not restored: %v", err)
	}
	if string(got) != body {
		t.Errorf("the drop-in holds %q, want %q", got, body)
	}
}

// The same call twice must not rewrite a file that is already correct — the
// "already current" arm exists so a distrobox init_hook calling this on every
// start is not a write on every start.
func TestASecondRunLeavesACurrentDropInAlone(t *testing.T) {
	dir := t.TempDir()
	dropIn := filepath.Join(dir, "00-snug.conf")
	readings := readHostSysctls(fakeSysctlHost(allSet()))
	body := sysctlDropInBody(sysctlDropInLines(readings))

	captureCode(t, func() int {
		return applySysctlFix(readings, body, 0, "", dropIn, func(string, int) error { return nil })
	})
	first, err := os.Stat(dropIn)
	if err != nil {
		t.Fatal(err)
	}
	_, stderr := captureSplitStreams(t, func() {
		applySysctlFix(readings, body, 0, "", dropIn, func(string, int) error { return nil })
	})
	if !strings.Contains(stderr, "already current") {
		t.Errorf("the second run did not report the drop-in as already current:\n%s", stderr)
	}
	second, err := os.Stat(dropIn)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ModTime().Equal(second.ModTime()) {
		t.Error("a correct drop-in was rewritten by a second run")
	}
}

// F2. `snug fix sysctl > 00-snug.conf` is documented as doing what it looks
// like. Printing nothing when the running kernel is fine made that
// instruction TRUNCATE the drop-in to zero bytes — measured, 148 bytes before
// and 0 after, exit 0. Stdout is the complete file, always.
func TestThePreviewPrintsTheWholeFileEvenWhenNothingIsWeak(t *testing.T) {
	readings := readHostSysctls(fakeSysctlHost(allSet()))
	body := sysctlDropInBody(sysctlDropInLines(readings))

	stdout, stderr := captureSplitStreams(t, func() {
		printSysctlFixPreview(readings, sysctlWeakLines(readings), body)
	})
	if stdout != body {
		t.Errorf("stdout is not the file -w would write.\n got: %q\nwant: %q", stdout, body)
	}
	if stdout == "" {
		t.Error("redirecting this into the drop-in would empty it")
	}
	if !strings.Contains(stderr, "nothing was changed") {
		t.Errorf("stderr never said the host was left alone:\n%s", stderr)
	}
}

// And on a weak host the two streams still divide the same way: the file on
// stdout, the reason each knob is weak on stderr.
func TestThePreviewKeepsTheCostOnStderrAndTheFileOnStdout(t *testing.T) {
	values := allSet()
	values["kernel.kptr_restrict"] = "0"
	readings := readHostSysctls(fakeSysctlHost(values))
	body := sysctlDropInBody(sysctlDropInLines(readings))

	stdout, stderr := captureSplitStreams(t, func() {
		printSysctlFixPreview(readings, sysctlWeakLines(readings), body)
	})
	if stdout != body {
		t.Errorf("stdout = %q, want the whole file %q", stdout, body)
	}
	if strings.Contains(stdout, "snug:") {
		t.Errorf("commentary reached stdout, so the redirect writes an invalid file:\n%s", stdout)
	}
	if !strings.Contains(stderr, "KASLR") {
		t.Errorf("stderr does not say what kptr_restrict=0 costs:\n%s", stderr)
	}
}

// F5. Inside a container there is, by snug's own refusal, nothing that can be
// done — which is the definition of nothing to do, and `snug fix` states in
// capitals that nothing to do exits 0 because distrobox-init runs hooks under
// `set -o errexit`. Measured at 69 before this: a hook that aborted box
// startup with a message about sysctls.
func TestTheContainerArmExitsZeroBecauseAnInitHookRunsUnderErrexit(t *testing.T) {
	dir := t.TempDir()
	readings := readHostSysctls(fakeSysctlHost(map[string]string{}))
	body := sysctlDropInBody(sysctlDropInLines(readings))

	var code int
	_, stderr := captureSplitStreams(t, func() {
		code = applySysctlFix(readings, body, 0, "running inside a container (distrobox/podman)",
			filepath.Join(dir, "00-snug.conf"), func(string, int) error {
				t.Error("a knob was written to the running kernel from inside a container")
				return nil
			})
	})
	if code != 0 {
		t.Errorf("exit %d — an init_hook under `set -o errexit` stops the box coming up", code)
	}
	if !strings.Contains(stderr, "on the host instead") {
		t.Errorf("the refusal does not name where to run it:\n%s", stderr)
	}
}

// The non-root arm keeps its nonzero status, and the difference is not
// arbitrary: asking to write and being unable to is a failure to do what was
// asked, where the container arm is a correct refusal to do anything.
func TestWritingWithoutRootIsAFailureAndSaysHowToRetry(t *testing.T) {
	readings := readHostSysctls(fakeSysctlHost(allSet()))
	var code int
	_, stderr := captureSplitStreams(t, func() {
		code = applySysctlFix(readings, "", 1000, "", filepath.Join(t.TempDir(), "x.conf"),
			func(string, int) error { return nil })
	})
	if code == 0 {
		t.Error("-w as a non-root user reported success")
	}
	if !strings.Contains(stderr, "sudo snug fix sysctl -w") {
		t.Errorf("the refusal does not name the fix:\n%s", stderr)
	}
}

// F4 and its symlink sibling. -w runs as ROOT, so anything at the drop-in
// path that is a second name for another file must be REFUSED rather than
// written through. O_NOFOLLOW alone stopped the symlink and a hard link
// walked straight past it, overwriting the victim under the user's sudo.
func TestTheDropInIsNeverWrittenThroughASecondNameForAnotherFile(t *testing.T) {
	const untouched = "PRECIOUS-HOST-FILE\n"

	for _, tc := range []struct {
		name string
		link func(t *testing.T, victim, at string)
		want string
	}{
		{name: "symlink", want: "will not write through one", link: func(t *testing.T, victim, at string) {
			if err := os.Symlink(victim, at); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hard link", want: "hard link", link: func(t *testing.T, victim, at string) {
			if err := os.Link(victim, at); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			victim := filepath.Join(dir, "victim.conf")
			if err := os.WriteFile(victim, []byte(untouched), 0o644); err != nil {
				t.Fatal(err)
			}
			at := filepath.Join(dir, "00-snug.conf")
			tc.link(t, victim, at)

			err := writeDropIn(at, "kernel.kptr_restrict = 1\n")
			if err == nil {
				t.Fatal("writeDropIn wrote through it instead of refusing")
			}
			// CLAUDE.md: errors name the fix. The bare O_NOFOLLOW error was
			// `too many levels of symbolic links`, which reads as a symlink
			// loop rather than as snug declining to follow one.
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not say what it refused: %v", err)
			}
			if got, _ := os.ReadFile(victim); string(got) != untouched {
				t.Errorf("the other name's file was rewritten: %q", got)
			}
		})
	}
}

// The ordinary path still works, and leaves no temporary behind — or the
// refusals above would prove nothing and the directory would fill with them.
func TestTheDropInIsWrittenAtomicallyAndLeavesNoTemporary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "00-snug.conf")
	const body = "kernel.kptr_restrict = 1\n"
	if err := writeDropIn(path, body); err != nil {
		t.Fatalf("writeDropIn refused an ordinary path: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != body {
		t.Errorf("the drop-in holds %q", b)
	}
	// And again over the file it just wrote: an existing regular file with
	// one link is the ordinary case, not something to refuse.
	if err := writeDropIn(path, body+"kernel.dmesg_restrict = 1\n"); err != nil {
		t.Fatalf("writeDropIn refused to replace its own file: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "00-snug.conf" {
			t.Errorf("left %s behind in the drop-in directory", e.Name())
		}
	}
}

// The three not-a-value states are three different sentences, because they
// send a reader to three different places. A redteam round found all three
// printed as the single word "not readable".
func TestTheThreeWaysAKnobHasNoValueAreToldApart(t *testing.T) {
	for _, tc := range []struct {
		name  string
		read  func(string) (string, error)
		want  string
		never string
	}{
		{name: "absent", want: "this kernel does not have it", never: "= 0",
			read: func(path string) (string, error) {
				return "", fmt.Errorf("open %s: %w", path, fs.ErrNotExist)
			}},
		{name: "unreadable", want: "could not be read", never: "does not have it",
			read: func(string) (string, error) { return "", errors.New("permission denied") }},
		{name: "not a number", want: `holds "garbage", which is not a number`, never: "could not be read",
			read: func(string) (string, error) { return "garbage\n", nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() { reportHostSysctls(readHostSysctls(tc.read)) })
			if !strings.Contains(out, tc.want) {
				t.Errorf("the report never said %q:\n%s", tc.want, out)
			}
			if strings.Contains(out, tc.never) {
				t.Errorf("the report said %q, which belongs to a different state:\n%s", tc.never, out)
			}
		})
	}
}

// captureCode is captureStdout for a function that returns an exit status:
// the screen is swallowed, the status is what the caller asserts on.
func captureCode(t *testing.T, f func() int) int {
	t.Helper()
	var code int
	captureStdout(t, func() { code = f() })
	return code
}
