package cli

// Issue #613: every fmt.Errorf in targetLive interpolated its `real` argument
// (a target directory's realpath, taken verbatim from a breadcrumb or from
// `filepath.EvalSymlinks`) raw, unlike this same value's sibling call sites in
// this file (label, describeLeftover), which route it through visibleValue.
// A directory named with a forging rune reached the composed error unescaped.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetLiveEscapesAForgingRuneInTheTargetPath(t *testing.T) {
	snugDir := useTargetLockBase(t)
	base := t.TempDir()
	const forged = "FORGED-TARGET-LIVE-LINE"
	evilName := "proj-\n          reclaimed  " + forged + "\x1b[2K"
	target := filepath.Join(base, evilName)
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}

	// Fixture: create the lock directory (lockTarget's own doing), then take
	// away read access to it so the very next targetLive call fails inside
	// vdir.OpenExistingSubdir instead of reporting "not live".
	unlock, err := lockTarget(target)
	if err != nil {
		t.Fatalf("fixture: could not take the target lock: %v", err)
	}
	unlock()
	if err := os.Chmod(snugDir, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(snugDir, 0o700)

	_, _, err = targetLive(real, liveProbeOnly)
	if err == nil {
		t.Fatal("targetLive did not fail with its lock directory made unreadable — fixture is broken")
	}
	msg := err.Error()
	if !strings.Contains(msg, forged) {
		t.Fatalf("the fixture's forged text never reached the error at all, so this test measures "+
			"nothing: %v", err)
	}
	if i := strings.IndexFunc(msg, func(r rune) bool { return r != '\n' && isForgingRune(r) }); i >= 0 {
		t.Errorf("targetLive's error printed a raw control character (%q) from the target path it "+
			"was given:\n%s", []rune(msg[i:])[0], strings.ReplaceAll(msg, "\x1b", "<ESC>"))
	}
	if !strings.Contains(msg, `\n`) {
		t.Errorf("the escaped form of the newline never reached the error: %v", err)
	}
}
