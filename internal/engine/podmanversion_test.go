package engine

import (
	"strings"
	"testing"
)

// The parser is deliberately tested in the HOSTLESS lane (no build tag, no
// engine, no privileges): the version gate's whole job is to fail a run whose
// engine is not one snug supports, and a gate whose own parsing is only
// exercised on a host that happens to have podman is the shape it exists to
// refuse.
func TestParsePodmanVersionReadsWhatPodmanActuallyPrints(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want PodmanVersion
	}{
		// MEASURED on the development host, podman-6.0.2-1.1.x86_64 on
		// openSUSE Tumbleweed: `podman --version` prints exactly this.
		{"the development host", "podman version 6.0.2", PodmanVersion{6, 0, 2}},
		{"trailing newline from Output()", "podman version 6.0.2\n", PodmanVersion{6, 0, 2}},
		// A distribution suffix names a BUILD, not a capability, so it is
		// dropped rather than refused — refusing it would fail a host that is
		// in the supported set.
		{"a distribution suffix", "podman version 6.0.2-rhel", PodmanVersion{6, 0, 2}},
		{"an upstream dev build", "podman version 6.1.0-dev", PodmanVersion{6, 1, 0}},
		{"something after the version", "podman version 6.0.2 (extra)", PodmanVersion{6, 0, 2}},
		{"the retired bundle's engine", "podman version 5.8.4", PodmanVersion{5, 8, 4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePodmanVersion(tc.line)
			if err != nil {
				t.Fatalf("ParsePodmanVersion(%q) = error %v, want %v", tc.line, err, tc.want)
			}
			if got != tc.want {
				t.Fatalf("ParsePodmanVersion(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}

// The negative, and it is the half that matters: a line this parser cannot
// identify must be an ERROR, never a zero value that some caller renders as
// "unknown" and lets through. UnsupportedPodmanReason turning a parse failure
// into a refusal reason is what makes that structural.
func TestParsePodmanVersionRefusesWhatItCannotIdentify(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
	}{
		{"empty, which is what a failed exec leaves behind", ""},
		{"another engine answering --version", "docker version 27.3.1"},
		{"no version at all", "podman"},
		{"two components", "podman version 6.0"},
		{"four components", "podman version 6.0.2.1"},
		{"not a number", "podman version 6.x.2"},
		{"a negative component", "podman version 6.-1.2"},
		// The prefix check is what tells a podman from anything else that
		// prints a bare number, so a bare number is not enough.
		{"a bare version with no prefix", "6.0.2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParsePodmanVersion(tc.line); err == nil {
				t.Fatalf("ParsePodmanVersion(%q) = %v, nil — want an error", tc.line, got)
			}
			if UnsupportedPodmanReason(tc.line) == "" {
				t.Fatalf("UnsupportedPodmanReason(%q) = \"\" — an unidentifiable engine must be a refusal reason, not a pass", tc.line)
			}
		})
	}
}

// The set itself. 6.x is IN; the retired bundle's 5.x and a future 7.x are
// OUT, and 7.x being out is the point of the upper bound — a new major that
// changes the API the container proxy filters must go red on its first run
// rather than pass against filters nobody re-measured.
func TestSupportedPodmanSetIsSixDotX(t *testing.T) {
	for _, tc := range []struct {
		line string
		want bool
	}{
		{"podman version 6.0.0", true},
		{"podman version 6.0.2", true},
		{"podman version 6.99.99", true},
		{"podman version 5.8.4", false},
		{"podman version 4.9.4", false}, // Ubuntu 24.04's podman
		{"podman version 7.0.0", false},
	} {
		v, err := ParsePodmanVersion(tc.line)
		if err != nil {
			t.Fatalf("ParsePodmanVersion(%q): %v", tc.line, err)
		}
		if got := v.Supported(); got != tc.want {
			t.Errorf("PodmanVersion(%s).Supported() = %v, want %v", v, got, tc.want)
		}
		if reason := UnsupportedPodmanReason(tc.line); (reason == "") != tc.want {
			t.Errorf("UnsupportedPodmanReason(%q) = %q, want empty=%v", tc.line, reason, tc.want)
		}
	}
}

// A refusal names the version it read AND the set it is not in. "Errors name
// the fix" is a project rule, and the fix here is either "run the supported
// engine" or "widen the constant" — neither is actionable from a message that
// only says no.
func TestTheRefusalReasonNamesBothTheVersionAndTheSet(t *testing.T) {
	const line = "podman version 4.9.4"
	reason := UnsupportedPodmanReason(line)
	for _, want := range []string{"4.9.4", SupportedPodmanSet} {
		if !strings.Contains(reason, want) {
			t.Errorf("UnsupportedPodmanReason(%q) = %q, does not name %q", line, reason, want)
		}
	}
}
