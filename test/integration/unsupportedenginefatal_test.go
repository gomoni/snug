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
		name       string
		requireEng string
		ci         string
		wantFatal  bool
	}{
		{"a developer host: neither set", "", "", false},
		{"the engine job", "1", "", true},
		{"any CI lane", "", "true", true},
		{"both, as the engine job in CI actually runs", "1", "true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SNUG_REQUIRE_ENGINE", tc.requireEng)
			t.Setenv("CI", tc.ci)
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
