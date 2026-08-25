package engine

import (
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/targetkey"
)

// TestEngineKeyAgreesWithTargetkey is the narrower assertion internal/targetkey's
// own doc comment names as the fallback to an AST sweep: an AST sweep for a
// second sha256.Sum256 over a "target-shaped" string cannot actually tell a
// target hash apart from an unrelated one without a type checker, and this
// module already has one — internal/sandbox's FilterDigest hashes a seccomp
// BPF program, not a target, and a name-only sweep flags it as a stray. So
// instead of a sweep, each of targetkey's three consumers asserts its own
// output IS targetkey.Hash applied to the same string, byte for byte. A
// consumer that quietly reintroduced its own sha256.Sum256 (or its own
// truncation of one) fails here directly, on the one property that matters:
// agreement with the shared function, not merely "some hash was called
// somewhere in this file".
func TestEngineKeyAgreesWithTargetkey(t *testing.T) {
	pol := &policy.Policy{Target: "/proj/agreement-check"}
	want := targetkey.Hash(pol.Target)

	if got := engineKey(pol); got != want {
		t.Errorf("engineKey(%q) = %q, want targetkey.Hash(target) = %q — engineKey must not run "+
			"its own hash or its own truncation of one", pol.Target, got, want)
	}
	if got := KeyForTarget(pol.Target); got != want {
		t.Errorf("KeyForTarget(%q) = %q, want targetkey.Hash(target) = %q", pol.Target, got, want)
	}
}
