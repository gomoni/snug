//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExpandedSeparatorNeverReachesThePayload is the end-to-end regression for
// the redteam finding fixed by checkExpandedElement (internal/policy/envresolve.go):
// a merge/prepend element written as `{target_parent}/bin` passes every
// TEXT-level check clean (the ':' is not in the profile's own spelling), and
// only appears once {target_parent} expands against a real target whose
// parent directory is itself named with a ':'. Before the fix this reached
// the real bwrap argv as a single --setenv value that a PATH-splitting
// consumer reads as two elements, the second one relative and resolved
// against the sandbox's own working directory — the target.
//
// It would catch: the check being removed, bypassed, or narrowed to the
// profile's raw text (which is exactly the shape that shipped first and
// missed this).
func TestExpandedSeparatorNeverReachesThePayload(t *testing.T) {
	budget(t)
	requireSandbox(t)

	root := t.TempDir()
	// FIXTURE GUARD: if the temp root itself carried a ':' the test would be
	// measuring an accident of the harness, not the one directory this test
	// deliberately names with one.
	if strings.Contains(root, ":") {
		t.Fatalf("t.TempDir() %q contains ':'; the fixture cannot isolate the one "+
			"colon this test is about", root)
	}

	// root/pp:q/proj — the PARENT directory carries the ':', not the root and
	// not a sibling, so the ancestor grant below stays colon-free while
	// {target_parent} does not.
	parent := filepath.Join(root, "pp:q")
	proj := filepath.Join(parent, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	toml := "[profile.leaky]\n" +
		"ro = [\"" + root + "\"]\n" +
		"[profile.leaky.environ.merge]\n" +
		"PATH = [\"{target_parent}/bin\"]\n"
	env := writeProfile(t, toml)

	// No @target-rw: {target} itself sits under the colon-bearing directory,
	// and splitSpec's own host:guest split — unrelated to this check, and
	// triggered on the EXPANDED spec — would refuse it before this rule is
	// ever reached. Granting the colon-free root directly, as "leaky" does
	// above, is what isolates the one behaviour under test.
	out, code := cli(t, env, "--no-defaults", "-p", "@sys", "-p", "@home", "-p", "leaky",
		proj, "--", "/usr/bin/env")
	if code != exitPolicyCode {
		t.Fatalf("snug exited %d, want %d (policy refusal):\n%s", code, exitPolicyCode, out)
	}
	for _, want := range []string{"leaky", "{target_parent}/bin", "pp:q/bin"} {
		if !strings.Contains(out, want) {
			t.Errorf("refusal does not name %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "SNUG=1") {
		t.Errorf("the payload ran despite the refused element — a list element carrying "+
			"the separator reached the sandbox instead of being caught at resolve time:\n%s", out)
	}
}
