package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gomoni/snug/internal/targetkey"
)

// TestTargetLockAndTmpDirAgreeWithTargetkey is targetLockName/hostTmpDirPath's
// half of the narrower assertion internal/targetkey's doc comment names as
// the fallback to an AST sweep for a second sha256.Sum256 over a
// target-shaped string — see internal/engine's identical test
// (TestEngineKeyAgreesWithTargetkey) for why the sweep itself was dropped:
// this module already has an unrelated sha256.Sum256 (internal/sandbox's
// FilterDigest, hashing a seccomp program, not a target), and a name-only
// AST match cannot tell the two apart without a type checker. Each consumer
// instead asserts its own output IS targetkey.Hash applied to the same
// string.
func TestTargetLockAndTmpDirAgreeWithTargetkey(t *testing.T) {
	target := "/proj/agreement-check"
	want := targetkey.Hash(target)

	if got := targetKeyPrefix(target); got != "target-"+want {
		t.Errorf("targetKeyPrefix(%q) = %q, want \"target-\"+targetkey.Hash(target) = %q",
			target, got, "target-"+want)
	}

	wantTmp := filepath.Join(os.TempDir(), fmt.Sprintf("snug-%d-%s", os.Getuid(), want))
	if got := hostTmpDirPath(target); got != wantTmp {
		t.Errorf("hostTmpDirPath(%q) = %q, want %q — it must use targetkey.Hash's full digest, "+
			"not a truncation of its own", target, got, wantTmp)
	}
}
