package cli

// Issue #613: `snug doctor`'s "profile set will not load" block printed
// profile.BadFile's Path and Err fields with a bare %s/%v, unlike
// refuseBadFiles/reportBadFiles two files over, which route both through
// VisibleText/badFileErrorLines specifically because a profiles.d filename
// is host text a hostile $XDG_CONFIG_HOME (invariant 3) can plant with a
// forging rune — a byte a filename may legally carry that a TOML file's own
// CONTENT may not (go-toml's lexer refuses a raw control byte inside a
// string), which is why this fixture forges the FILENAME rather than the
// file's contents.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorEscapesAForgingRuneInABadProfileFilePath(t *testing.T) {
	dir := t.TempDir()
	profilesDir := filepath.Join(dir, "snug", "profiles.d")
	if err := os.MkdirAll(profilesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const forged = "FORGED-DOCTOR-BADFILE-PATH"
	name := "evil-\n          reclaimed  " + forged + "\x1b[2K.toml"
	// Content need not carry anything forged: an ordinary parse error is
	// enough to put this file's Path (not its Err) in front of doctor's print.
	if err := os.WriteFile(filepath.Join(profilesDir, name), []byte("not valid toml =====\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)

	out := captureStdout(t, func() { doctor(nil) })
	if !strings.Contains(out, forged) {
		t.Fatalf("the fixture's forged filename never reached stdout at all, so this test "+
			"measures nothing:\n%s", out)
	}
	if r, ok := rawForgingRune(out); ok {
		t.Errorf("doctor printed a raw control character (%q) from a profiles.d file's own "+
			"name:\n%s", r, strings.ReplaceAll(out, "\x1b", "<ESC>"))
	}
	if !strings.Contains(out, `\n`) {
		t.Errorf("the escaped form of the newline never reached stdout:\n%s", out)
	}
}
