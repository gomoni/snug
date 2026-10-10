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

	// login is a list; one unknown element refuses the whole key, and so does
	// a value spelled as a mode rather than a provider.
	for _, body := range []string{
		`login = ["claude-login"]`, `login = ["x"]`, `login = ["Claude"]`, `login = ["claude", "x"]`,
	} {
		t.Run(body, func(t *testing.T) {
			_, err := parse([]byte("[profile.x]\n"+body+"\n"), "mine.toml", true)
			if err == nil {
				t.Fatalf("%s parsed; `snug profile show` would render a profile no run can use", body)
			}
			for _, want := range []string{"mine.toml", `"x"`, "unknown login provider", "(want claude)"} {
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
		`login = []`, `login = ["claude"]`, `login = ["claude", "claude"]`,
	} {
		if _, err := parse([]byte("[profile.x]\n"+body+"\n"), "mine.toml", true); err != nil {
			t.Errorf("accepted spelling %q refused: %v", body, err)
		}
	}
}

// The bridge is spelled `login = ["claude"]` and nothing else: `browser` is
// not a key, so a profile still carrying it is refused by strict decoding
// rather than read as the bridge being on or off.
func TestBrowserKeyIsNotAKey(t *testing.T) {
	for _, body := range []string{`browser = "claude-login"`, `browser = "off"`} {
		if _, err := parse([]byte("[profile.x]\n"+body+"\n"), "mine.toml", true); err == nil ||
			!strings.Contains(err.Error(), "unknown key") {
			t.Errorf("%s: want an unknown-key refusal, got %v", body, err)
		}
	}
}
