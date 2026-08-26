package engine

import (
	"fmt"
	"strconv"
	"strings"
)

// The supported container-engine set, and the ONE place it is written.
//
// snug does not ship an engine. The pinned engine bundle was retired
// (issue #384) and cannot come back, so the engine version FLOATS with
// whatever distribution the host installs — which makes "which podman" a
// property of the environment and "which podman we support" a claim only the
// source tree can hold.
//
// The set is 6.x. That is not a preference for a number: every test result
// this repository has about the engine tier was measured against podman 6.0.2
// (the development host) and CI runs an openSUSE Tumbleweed container, which
// is the same major. 5.x is deliberately OUT — the retired bundle was 5.8.4
// and the one baseline taken against it carried two failures nobody diagnosed,
// so claiming support would be claiming a measurement that was never made.
//
// A podman 7 therefore fails CI on the first run rather than passing quietly
// against an API the container proxy's filters were never checked against.
// Widening the set is a deliberate edit here plus the run that justifies it.
const (
	SupportedPodmanMajor = 6
	// SupportedPodmanSet renders the set for a human, and every message that
	// reports a version outside it quotes this rather than re-spelling the
	// bound. Two spellings of one constant is how the bound drifts.
	SupportedPodmanSet = "podman 6.x"
)

// PodmanVersion is the numeric prefix of a `podman --version` line. Only the
// three components are kept: a distribution suffix ("-rhel", "-dev") names a
// build, not a capability, and nothing here decides on one.
type PodmanVersion struct {
	Major int
	Minor int
	Patch int
}

func (v PodmanVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Supported reports whether v is in the set SupportedPodmanSet names.
func (v PodmanVersion) Supported() bool {
	return v.Major == SupportedPodmanMajor
}

// ParsePodmanVersion reads the version out of `podman --version`'s single
// line, whose shape is "podman version 6.0.2" (measured: podman-6.0.2-1.1 on
// openSUSE Tumbleweed).
//
// It is deliberately strict about the PREFIX and loose about the tail. The
// prefix is what tells a podman from something else answering --version, so a
// line that does not start "podman version " is an error rather than a
// best-effort number: a caller that fell back to "unknown" would be the silent
// downgrade this whole file exists to prevent. The tail is loose because a
// distribution's own suffix ("6.0.2-rhel") is not a version snug reasons
// about, and refusing it would fail a host that is in the supported set.
func ParsePodmanVersion(line string) (PodmanVersion, error) {
	const prefix = "podman version "
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), prefix)
	if !ok {
		return PodmanVersion{}, fmt.Errorf("not a podman version line (want %q, got %q)", prefix+"X.Y.Z", strings.TrimSpace(line))
	}
	// The tail after the third component is dropped whole: "6.0.2-rhel",
	// "6.1.0-dev" and "6.0.2 (extra)" all name a 6.x engine.
	rest, _, _ = strings.Cut(rest, " ")
	rest, _, _ = strings.Cut(rest, "-")
	fields := strings.Split(rest, ".")
	if len(fields) != 3 {
		return PodmanVersion{}, fmt.Errorf("podman version %q is not three dot-separated components", rest)
	}
	var v PodmanVersion
	for i, dst := range []*int{&v.Major, &v.Minor, &v.Patch} {
		n, err := strconv.Atoi(fields[i])
		if err != nil || n < 0 {
			return PodmanVersion{}, fmt.Errorf("podman version %q: component %d (%q) is not a number", rest, i+1, fields[i])
		}
		*dst = n
	}
	return v, nil
}

// UnsupportedPodmanReason returns "" when line names an engine in the
// supported set, and otherwise a sentence naming the version it read, the set
// it is not in, and — for an unparseable line — what it actually saw.
//
// One function for both the parse failure and the out-of-set case on purpose.
// A caller has the same decision to make either way (warn on a developer host,
// fail in CI) and splitting them invites a caller to handle one and not the
// other, which is how "we tested an engine nobody identified" gets a green
// run.
func UnsupportedPodmanReason(line string) string {
	v, err := ParsePodmanVersion(line)
	if err != nil {
		return fmt.Sprintf("could not tell which engine this is: %v — snug is developed and tested against %s", err, SupportedPodmanSet)
	}
	if !v.Supported() {
		return fmt.Sprintf("podman %s is outside %s, the only set snug is developed and tested against", v, SupportedPodmanSet)
	}
	return ""
}
