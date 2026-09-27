//go:build integration

package integration

import (
	"strings"
	"testing"
)

// TestConditionalEnvThroughTheRealBinary is issue #621 end to end. A name snug
// writes only when a feature is on is a profile's to write in every other
// selection — and the value must reach the payload under the profile's own
// verb — while a selection that turns the feature on refuses it, on --dry-run
// and on a run alike, because the verdict is Resolve's and both paths call it.
//
// The LISTEN_PID arm is the #621 red team's F1: the staged door script exports
// it, so a profile's value rendered on --dry-run while the payload got its own
// pid. Only the real binary exercises the profile loader, the builtins and
// Resolve together, which is why this lives here and not beside the unit tests.
func TestConditionalEnvThroughTheRealBinary(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	env := writeProfile(t, "[profile.dh]\n"+
		"[profile.dh.environ.set]\n"+
		"DOCKER_HOST = \"unix:///run/nowhere.sock\"\n"+
		"[profile.door]\n"+
		"listen_names = [\"web\"]\n"+
		"[profile.door.environ.set]\n"+
		"LISTEN_PID = \"1\"\n")

	// Feature off: the profile's value reaches the payload.
	out, code := cli(t, env, "-p", "dh", proj, "--", "/usr/bin/env")
	if code != 0 {
		t.Fatalf("snug -p dh exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "SNUG=1") {
		t.Fatalf("control: SNUG=1 absent, the payload did not run inside snug:\n%s", out)
	}
	if !strings.Contains(out, "DOCKER_HOST=unix:///run/nowhere.sock\n") {
		t.Errorf("a profile's DOCKER_HOST did not reach the payload with no podman selected:\n%s", out)
	}

	// Feature on: refused, on both paths, naming both claimants.
	for _, dry := range []bool{true, false} {
		args := []string{"-p", "dh", "-p", "@podman-socket", proj, "--", "/usr/bin/true"}
		if dry {
			args = append([]string{"--dry-run"}, args...)
		}
		out, code := cli(t, env, args...)
		if code == 0 {
			t.Errorf("dry=%v: DOCKER_HOST beside @podman-socket was admitted:\n%s", dry, out)
			continue
		}
		for _, want := range []string{"DOCKER_HOST has two authors", "dh (environ.set)", "@podman-socket sets podman"} {
			if !strings.Contains(out, want) {
				t.Errorf("dry=%v: refusal does not say %q:\n%s", dry, want, out)
			}
		}
	}

	out, code = cli(t, env, "--dry-run", "-p", "door", proj, "--", "/usr/bin/true")
	if code == 0 || !strings.Contains(out, "LISTEN_PID has two authors") {
		t.Errorf("LISTEN_PID beside listen_names was not refused (exit %d):\n%s", code, out)
	}
}
