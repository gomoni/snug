package cli

import (
	"errors"
	"strings"
	"testing"
)

// TestReportGetentIsSilentWhenFound pins the ONLY-WHEN-MISSING shape: a
// present getent must print NOTHING, not even a ✅ line, because it is true of
// every glibc host and this section reports what is wrong rather than
// inventorying everything present.
func TestReportGetentIsSilentWhenFound(t *testing.T) {
	out := captureStdout(t, func() {
		if !reportGetent(func() (string, error) { return "/usr/bin/getent", nil }) {
			t.Error("reportGetent returned false for a lookup that succeeded")
		}
	})
	if out != "" {
		t.Errorf("reportGetent printed something for a FOUND getent, want silence:\n%q", out)
	}
}

// TestReportGetentMissingNamesTheFix pins the shape a missing getent must
// print: it must say every run refuses, and it must name a package for both
// glibc hosts and a musl/embedded one — the two paragraphs README.md's
// "Requirements" section repeats for a human who never runs `snug doctor` at
// all, so the two must not drift.
func TestReportGetentMissingNamesTheFix(t *testing.T) {
	out := captureStdout(t, func() {
		if reportGetent(func() (string, error) { return "", errors.New("exec: \"getent\": executable file not found in $PATH") }) {
			t.Error("reportGetent returned true for a lookup that failed")
		}
	})
	for _, want := range []string{"getent", "every run will refuse", "glibc", "libc-bin", "glibc-common", "musl"} {
		if !strings.Contains(out, want) {
			t.Errorf("reportGetent's report does not carry %q:\n%s", want, out)
		}
	}
}
