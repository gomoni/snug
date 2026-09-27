package profile

import (
	"strconv"
	"strings"
	"testing"
)

// #627 F1: an unknown `podman`, `git` or `network` value parsed, so `snug
// profile show` exited 0 and rendered `podman  sockets` with the "starts a
// container engine" row, while every run selecting it refused (exit 77). The
// screen that decides whether to select a profile must refuse what a run
// refuses — the same shape TestUnknownAgentModeIsRefusedAtParseTime holds for
// identity.ssh.agent.
func TestUnknownFeatureModeIsRefusedAtParseTime(t *testing.T) {
	for _, tc := range []struct{ key, value, accepted string }{
		{"podman", "sockets", "off, socket or build"},
		{"podman", "Socket", "off, socket or build"},
		{"git", "extracted", "extract or off"},
		{"network", "host", "isolated or egress"},
		{"network", "egress ", "isolated or egress"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			_, err := parse([]byte("[profile.x]\n"+tc.key+" = "+strconv.Quote(tc.value)+"\n"), "mine.toml", true)
			if err == nil {
				t.Fatalf("%s = %q parsed; `snug profile show` would render a profile no run can use",
					tc.key, tc.value)
			}
			for _, want := range []string{"mine.toml", `"x"`, strconv.Quote(tc.value), tc.accepted} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not say %s: %v", want, err)
				}
			}
		})
	}

	// POSITIVE CONTROL: every accepted spelling parses, the no-ops included,
	// and so does leaving each key out. Without it the test above passes on a
	// parse that refuses every value.
	for _, body := range []string{
		"", `podman = "off"`, `podman = "socket"`, `podman = "build"`,
		`git = "off"`, `git = "extract"`, `network = "isolated"`, `network = "egress"`,
	} {
		if _, err := parse([]byte("[profile.x]\n"+body+"\n"), "mine.toml", true); err != nil {
			t.Errorf("accepted spelling %q refused: %v", body, err)
		}
	}
}
