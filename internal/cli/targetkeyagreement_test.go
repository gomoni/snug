package cli

import (
	"testing"

	"github.com/gomoni/snug/internal/targetkey"
)

// TestTargetLockAgreesWithTargetkey is targetKeyPrefix's half of the narrower
// assertion internal/targetkey's doc comment names as
// the fallback to an AST sweep for a second sha256.Sum256 over a
// target-shaped string — see internal/engine's identical test
// (TestEngineKeyAgreesWithTargetkey) for why the sweep itself was dropped:
// this module already has an unrelated sha256.Sum256 (internal/sandbox's
// FilterDigest, hashing a seccomp program, not a target), and a name-only
// AST match cannot tell the two apart without a type checker. Each consumer
// instead asserts its own output IS targetkey.Hash applied to the same
// string.
func TestTargetLockAgreesWithTargetkey(t *testing.T) {
	target := "/proj/agreement-check"
	want := targetkey.Hash(target)

	if got := targetKeyPrefix(target); got != "target-"+want {
		t.Errorf("targetKeyPrefix(%q) = %q, want \"target-\"+targetkey.Hash(target) = %q",
			target, got, "target-"+want)
	}
}
