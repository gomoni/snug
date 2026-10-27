package profile

import (
	"strconv"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// #627 F1: an unknown `podman` or `network` value parsed, so `snug
// profile show` exited 0 and rendered `podman  sockets` with the "starts a
// container engine" row, while every run selecting it refused (exit 77). The
// screen that decides whether to select a profile must refuse what a run
// refuses — the same shape TestUnknownAgentModeIsRefusedAtParseTime holds for
// identity.ssh.agent.
func TestUnknownFeatureModeIsRefusedAtParseTime(t *testing.T) {
	for _, tc := range []struct{ key, value, accepted string }{
		{"podman", "sockets", "socket or build"},
		{"podman", "Socket", "socket or build"},
		{"network", "host", "egress"},
		{"network", "egress ", "egress"},
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

	// POSITIVE CONTROL: every accepted spelling parses, and so does leaving
	// each key out. Without it the test above passes on a parse that refuses
	// every value. The floors are refused and graded by
	// policy.TestProfileFloorValuesAreRefused.
	for _, body := range []string{
		"", `podman = "socket"`, `podman = "build"`, `network = "egress"`,
		`login.claude = "sandbox"`, `login.claude = "host"`, `login = { claude = "host" }`,
	} {
		if _, err := parse([]byte("[profile.x]\n"+body+"\n"), "mine.toml", true); err != nil {
			t.Errorf("accepted spelling %q refused: %v", body, err)
		}
	}
}

// The bridge is spelled `login.claude` and nothing else: `browser` is not a
// key, so a profile still carrying it is refused by strict decoding rather
// than read as the bridge being on or off.
func TestBrowserKeyIsNotAKey(t *testing.T) {
	for _, body := range []string{`browser = "claude-login"`, `browser = "off"`} {
		if _, err := parse([]byte("[profile.x]\n"+body+"\n"), "mine.toml", true); err == nil ||
			!strings.Contains(err.Error(), "unknown key") {
			t.Errorf("%s: want an unknown-key refusal, got %v", body, err)
		}
	}
}

// TestGitKeyAndGitProfileAreGoneRegression651 holds #651: `git` is not a
// profile key, so a profile file still carrying it is refused by strict
// decoding like any other unknown key, and no `@git` profile exists to select.
func TestGitKeyAndGitProfileAreGoneRegression651(t *testing.T) {
	for _, body := range []string{`git = "extract"`, `git = "off"`} {
		if _, err := parse([]byte("[profile.x]\n"+body+"\n"), "mine.toml", true); err == nil ||
			!strings.Contains(err.Error(), "unknown key") {
			t.Errorf("%s: want an unknown-key refusal, got %v", body, err)
		}
	}

	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []policy.ProfileName{"@git", "git", "@git-ro"} {
		if _, ok := reg[name]; ok {
			t.Errorf("builtin %q exists", name)
		}
	}
	err = policy.UnknownProfile(reg, "@git")
	if err == nil || !strings.Contains(err.Error(), `unknown profile "@git"`) {
		t.Errorf("selecting @git: want the plain unknown-profile error, got %v", err)
	}
	if _, rerr := policy.Resolve(reg, []policy.ProfileName{"@git"}, policy.Context{}, nil); rerr == nil ||
		!strings.Contains(rerr.Error(), "unknown profile") {
		t.Errorf("Resolve of @git: want an unknown-profile refusal, got %v", rerr)
	}
}
