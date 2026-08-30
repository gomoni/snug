package cli

import (
	"errors"
	"fmt"
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
					return "", errors.New("no such file or directory")
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
func TestAnAbsentKnobIsReportedAsUnreadableAndIsNeverFixed(t *testing.T) {
	values := allSet()
	delete(values, "kernel.yama.ptrace_scope")
	readings := readHostSysctls(fakeSysctlHost(values))

	out := captureStdout(t, func() { reportHostSysctls(readings) })
	if !strings.Contains(out, "kernel.yama.ptrace_scope — not readable") {
		t.Errorf("an absent knob was not reported as unreadable:\n%s", out)
	}
	if strings.Contains(out, "kernel.yama.ptrace_scope = 0") {
		t.Errorf("an absent knob was reported as a value of 0:\n%s", out)
	}
	for _, l := range sysctlFixLines(readings) {
		if strings.Contains(l, "ptrace_scope") {
			t.Errorf("`snug fix sysctl` would write %q for a knob this kernel does not have", l)
		}
	}

	// And the headline must not claim the host failed to SET something it
	// does not have. "already sets every knob" is the sentence this arm gets
	// wrong, and it is wrong in the reassuring direction.
	if strings.Contains(out, "does not set every kernel knob") {
		t.Errorf("a kernel that lacks the knob was reported as a host that failed to set it:\n%s", out)
	}
	if !strings.Contains(out, "could not be read here") {
		t.Errorf("the unreadable-only headline never appeared:\n%s", out)
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

	lines := sysctlFixLines(readHostSysctls(fakeSysctlHost(values)))
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

// Nothing to do prints nothing, which is the contract that makes this
// callable from a distrobox init_hook under `set -o errexit`.
func TestFixSysctlHasNothingToSayAboutAHostThatIsAlreadySet(t *testing.T) {
	if lines := sysctlFixLines(readHostSysctls(fakeSysctlHost(allSet()))); len(lines) != 0 {
		t.Errorf("a fully-set host produced %q, want nothing at all", lines)
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

// `snug fix sysctl > /etc/sysctl.d/99-snug.conf` must produce a file the
// kernel will read, so stdout carries the settings and NOTHING else. This is
// `snug fix subuid`'s contract, and it is the one a stray Println breaks
// without any test noticing.
func TestFixSysctlPutsOnlyTheSettingsOnStdout(t *testing.T) {
	values := allSet()
	values["kernel.kptr_restrict"] = "0"
	values["kernel.dmesg_restrict"] = "0"
	readings := readHostSysctls(fakeSysctlHost(values))

	stdout, stderr := captureSplitStreams(t, func() {
		if code := printSysctlFixPreview(readings, sysctlFixLines(readings)); code != 0 {
			t.Errorf("the preview exited %d; it changes nothing and must always exit 0", code)
		}
	})

	want := "kernel.kptr_restrict = 1\nkernel.dmesg_restrict = 1\n"
	if stdout != want {
		t.Errorf("stdout = %q, want exactly %q", stdout, want)
	}
	if !strings.Contains(stderr, "nothing was changed") {
		t.Errorf("stderr never said the host was left alone:\n%s", stderr)
	}
	// The cost of each weak knob belongs on stderr, next to the line that
	// would fix it — a number with no consequence attached is advice nobody
	// can weigh.
	if !strings.Contains(stderr, "KASLR") {
		t.Errorf("stderr does not say what kptr_restrict=0 costs:\n%s", stderr)
	}
}

// -w runs as ROOT, so a symlink at the drop-in path must be REFUSED rather
// than followed and rewritten. os.WriteFile would follow it. /etc/sysctl.d
// is root-owned so planting one is not an unprivileged step, and that is
// exactly the argument this refusal exists to stop being made file by file
// (appendLine states the same for /etc/subuid).
func TestTheSysctlDropInIsNotWrittenThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("do not touch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "99-snug.conf")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	if err := writeDropIn(link, "kernel.kptr_restrict = 1\n"); err == nil {
		t.Error("writeDropIn followed a symlink instead of refusing it")
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "do not touch\n" {
		t.Errorf("the symlink target was rewritten: %q", got)
	}

	// And the ordinary path still works, or the refusal above proves nothing.
	plain := filepath.Join(dir, "plain.conf")
	if err := writeDropIn(plain, "kernel.kptr_restrict = 1\n"); err != nil {
		t.Fatalf("writeDropIn refused an ordinary path: %v", err)
	}
	if b, _ := os.ReadFile(plain); string(b) != "kernel.kptr_restrict = 1\n" {
		t.Errorf("the drop-in content is %q", b)
	}
}
