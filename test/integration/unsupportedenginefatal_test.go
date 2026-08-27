//go:build integration

package integration

import "testing"

// TestUnsupportedEngineIsFatalInCI pins issue #458's decision, which is a
// maintainer ruling rather than anything derivable from the code: a CI lane
// that resolves a podman outside the supported set FAILS instead of warning
// and then skipping its engine coverage under a message naming a different
// condition.
//
// It is a table over the trigger set because the SET is the claim. The
// pre-#458 code had one trigger, SNUG_REQUIRE_ENGINE, set by exactly one of
// the two CI jobs that resolve an engine — so the `real sandbox behaviour` job
// logged UNSUPPORTED and went green with 27 tests skipped.
func TestUnsupportedEngineIsFatalInCI(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		requireEng, ci, requireSbox string
		wantFatal                   bool
	}{
		{"a developer host: nothing set", "", "", "", false},
		{"a developer running the sandbox suite", "", "", "1", false},
		{"the engine job", "1", "", "", true},
		{"the sandbox matrix job", "", "true", "1", true},
		{"the engine job as it actually runs in CI", "1", "true", "1", true},

		// THE REGRESSION. $CI alone fatal'd the `hostless` lane, which
		// deliberately leaves SNUG_REQUIRE_SANDBOX unset (ci.yml) — 8 tests
		// failed there for an engine that lane never claimed to exercise.
		{"the hostless lane: CI, but it promises no sandbox", "", "true", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SNUG_REQUIRE_ENGINE", tc.requireEng)
			t.Setenv("CI", tc.ci)
			t.Setenv("SNUG_REQUIRE_SANDBOX", tc.requireSbox)
			why := unsupportedEngineIsFatal()
			if (why != "") != tc.wantFatal {
				t.Fatalf("unsupportedEngineIsFatal() = %q, want fatal=%v", why, tc.wantFatal)
			}
			// The message is the half a reader acts on: it must name WHICH
			// trigger fired, or turning it off is guesswork.
			if tc.wantFatal && why == "" {
				t.Error("fatal with no reason named")
			}
		})
	}
}
