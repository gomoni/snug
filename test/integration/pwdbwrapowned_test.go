//go:build integration

package integration

import (
	"strings"
	"testing"
)

// TestAProfilePWDNeverReachesTheScreen is the end-to-end regression for
// bwrapOwnedEnv (internal/policy/env.go): bwrap sets PWD to its working
// directory AFTER applying every --setenv, with or without --chdir, so a
// profile's line on PWD can never reach the payload. Before the fix such a
// profile resolved cleanly and --dry-run rendered a PWD row the payload never
// got — the "no silent downgrade" invariant, one screen over: a human reading
// that screen would believe a value the sandbox does not carry.
//
// It would catch: bwrapOwnedEnv losing PWD, or the resolve-time check that
// reads it being removed or bypassed.
func TestAProfilePWDNeverReachesTheScreen(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	toml := "[profile.pwder]\n" +
		"[profile.pwder.environ.set]\n" +
		"PWD = \"/somewhere-bwrap-does-not-control\"\n"
	env := writeProfile(t, toml)

	out, code := cli(t, env, "-p", "pwder", proj, "--", "/usr/bin/env")
	if code != exitPolicyCode {
		t.Fatalf("snug -p pwder exited %d, want %d (policy refusal):\n%s", code, exitPolicyCode, out)
	}
	for _, want := range []string{"pwder", "PWD", "bwrap"} {
		if !strings.Contains(out, want) {
			t.Errorf("refusal does not name %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "SNUG=1") {
		t.Errorf("the payload ran despite the refused PWD line:\n%s", out)
	}
}
