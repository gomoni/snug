package targetkey

// targetkey_test.go is issue #349's own assertion: Hash's output carries its
// algorithm as a label, not just a bare digest. The three consumer packages
// each hold a narrower "my output IS Hash(target)" agreement test (see this
// package's doc comment); none of them assert the SHAPE of Hash's own return
// value, so a regression that dropped the label back to a bare digest would
// pass every one of them unchanged.

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"testing"
)

var hashShape = regexp.MustCompile(`^sha256_[0-9a-f]{64}$`)

// TestHashCarriesItsAlgorithmLabel is the shape assertion: "sha256_" followed
// by exactly 64 lowercase hex characters, and nothing else — this is what
// lets a reader, or another package's regexp (internal/engine's
// storeKeyPattern), tell a Hash output apart from an unlabelled digest on
// sight rather than by convention.
func TestHashCarriesItsAlgorithmLabel(t *testing.T) {
	for _, target := range []string{
		"/proj/one",
		"/proj/two/three",
		"",
		"/proj/has spaces/and-dashes_and.dots",
	} {
		got := Hash(target)
		if !hashShape.MatchString(got) {
			t.Errorf("Hash(%q) = %q, does not match %s", target, got, hashShape.String())
		}
	}
}

// TestHashIsTheLabelledDigest is the POSITIVE half of the shape check: a
// test that only matched the regexp above would equally pass a Hash that
// returned "sha256_" followed by 64 hex characters of GARBAGE — this proves
// the 64 hex characters are actually sha256 of the target, not merely
// hex-shaped.
func TestHashIsTheLabelledDigest(t *testing.T) {
	target := "/proj/agreement-check"
	sum := sha256.Sum256([]byte(target))
	want := "sha256_" + hex.EncodeToString(sum[:])
	if got := Hash(target); got != want {
		t.Errorf("Hash(%q) = %q, want %q", target, got, want)
	}
}

// TestHashIsDeterministicAndTargetSpecific is the pair of properties every
// consumer relies on without re-checking: the SAME target always yields the
// SAME key (so a second run finds what the first one wrote), and two
// DIFFERENT targets never collide in practice (so two unrelated projects
// never share a lock, a store, or a tmp directory).
func TestHashIsDeterministicAndTargetSpecific(t *testing.T) {
	a1 := Hash("/proj/a")
	a2 := Hash("/proj/a")
	b := Hash("/proj/b")
	if a1 != a2 {
		t.Errorf("Hash is not deterministic: Hash(%q) = %q the first time, %q the second", "/proj/a", a1, a2)
	}
	if a1 == b {
		t.Errorf("two different targets produced the same key %q", a1)
	}
}
