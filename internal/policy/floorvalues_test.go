package policy

import (
	"strings"
	"testing"
)

// TestProfileFloorValuesAreRefused: git = "off", podman = "off" and
// network = "isolated" are the floor of a max-joined key. Written in a profile
// they can have no effect, so the parser refuses them and the message names the
// line to delete.
func TestProfileFloorValuesAreRefused(t *testing.T) {
	for _, tc := range []struct {
		key, value string
		parse      func(string) error
	}{
		{"git", "off", func(s string) error { _, err := ParseGitMode(s); return err }},
		{"podman", "off", func(s string) error { _, err := ParsePodmanMode(s); return err }},
		{"network", "isolated", func(s string) error { _, err := ParseNetMode(s); return err }},
	} {
		want := tc.key + ` = "` + tc.value + `" changes nothing: "` + tc.value +
			`" is the default and a profile can only add. Remove the line.`
		err := tc.parse(tc.value)
		if err == nil {
			t.Errorf("%s = %q parsed; the floor has no effect and must be refused", tc.key, tc.value)
			continue
		}
		if err.Error() != want {
			t.Errorf("%s floor refusal = %q; want %q", tc.key, err, want)
		}

		reg := testRegistry()
		p := &Profile{Name: "writes-floor"}
		switch tc.key {
		case "git":
			p.Git = tc.value
		case "podman":
			p.Podman = tc.value
		case "network":
			p.Network = tc.value
		}
		reg["writes-floor"] = p
		_, rerr := Resolve(reg, []ProfileName{"@sys", "@target-rw", "writes-floor"}, testCtx(), newFakeEnv())
		if rerr == nil || !strings.Contains(rerr.Error(), "writes-floor") || !strings.Contains(rerr.Error(), want) {
			t.Errorf("Resolve with %s = %q: err = %v; want one naming the profile and %q", tc.key, tc.value, rerr, want)
		}
	}
}

// TestAbsentModeKeyIsTheFloor: an empty key is not a value the parser refuses
// or the join raises; Resolve lands on the floor word String() spells.
func TestAbsentModeKeyIsTheFloor(t *testing.T) {
	if m, err := ParseGitMode(""); err != nil || m != GitOff {
		t.Errorf(`ParseGitMode("") = %v, %v; want the floor`, m, err)
	}
	if m, err := ParsePodmanMode(""); err != nil || m != PodmanOff {
		t.Errorf(`ParsePodmanMode("") = %v, %v; want the floor`, m, err)
	}
	reg := testRegistry()
	reg["silent"] = &Profile{Name: "silent"}
	p, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "silent"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.Git != GitOff || p.Podman != PodmanOff || p.Net.Mode != NetIsolated {
		t.Errorf("absent keys resolved to git=%v podman=%v network=%v; want the floors", p.Git, p.Podman, p.Net.Mode)
	}
	if p.Git.String() != "off" || p.Podman.String() != "off" || p.Net.Mode.String() != "isolated" {
		t.Error("the floor words stopped being spelled by String()")
	}
}
