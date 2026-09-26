package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// THE CAVEAT THAT KEEPS §4.6(b) FROM BEING A SILENT DOWNGRADE.
//
// Once a diagnostic command continues past a file it could not parse, a name
// defined in that file comes back as "unknown profile" — which is a lie. snug
// does not know whether it exists, and the difference between "you typed it
// wrong" and "the file defining it is broken" is the whole of what the user
// needs in order to act.
func TestUnknownProfileNamesTheFileThatDidNotLoad(t *testing.T) {
	reg := profile.Registry{}
	bad := []profile.BadFile{{
		Path: "/home/u/.config/snug/profiles.d/mine.toml",
		Err:  fmt.Errorf("unknown key"),
	}}

	err := unknownProfile(reg, "work", bad)
	if err == nil {
		t.Fatal("a name nothing defines must still be an error")
	}
	for _, want := range []string{"work", "mine.toml", "did not load"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	// CONTROL: with nothing skipped, the message is the resolver's own and gains
	// no speculation. An unconditional footnote would train people to ignore it.
	clean := unknownProfile(reg, "work", nil)
	if clean.Error() != policy.UnknownProfile(reg, "work").Error() {
		t.Errorf("with no skipped files the message must be unchanged, got %q", clean)
	}
}

// The fatal half names every file and points at a command that still works.
// "snug is broken" with nowhere to go is how a user ends up deleting their
// config directory.
func TestRefusingToRunNamesEveryFileAndAWayForward(t *testing.T) {
	bad := []profile.BadFile{
		{Path: "/etc/snug/profiles.d/a.toml", Err: fmt.Errorf("unknown key")},
		{Path: "/home/u/.config/snug/profiles.d/b.toml", Err: fmt.Errorf("bad name")},
	}
	err := refuseBadFiles(bad)
	if err == nil {
		t.Fatal("running a sandbox must be refused while a profile file does not parse")
	}
	for _, want := range []string{"a.toml", "b.toml", "unknown key", "bad name", "snug profile list"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	// CONTROL: nothing wrong, nothing refused.
	if err := refuseBadFiles(nil); err != nil {
		t.Errorf("a clean load was refused: %v", err)
	}
}

// Issue #613: badFileErrorLines is the one place a profiles.d parser error —
// go-toml's, not snug's, and per this file's own doc comment attacker-
// influenceable via a hostile $XDG_CONFIG_HOME (invariant 3) — reaches a
// screen. refuseBadFiles and reportBadFiles both already routed it (and
// f.Path) through VisibleText; doctor's own "profile set will not load"
// block was the one caller composing both fields with a bare %s/%v instead,
// found by this issue's audit and fixed to use the same two calls.
func TestBadFileEscapesAForgingRuneInThePathAndTheError(t *testing.T) {
	const forgedPath = "FORGED-BADFILE-PATH"
	const forgedErr = "FORGED-BADFILE-ERR"
	bad := []profile.BadFile{{
		Path: "/home/u/.config/snug/profiles.d/\n          reclaimed  " + forgedPath + "\x1b[2K.toml",
		Err:  fmt.Errorf("bad line\n          reclaimed  " + forgedErr + "\x1b[2K"),
	}}

	check := func(name, screen string) {
		t.Helper()
		for _, forged := range []string{forgedPath, forgedErr} {
			if !strings.Contains(screen, forged) {
				t.Fatalf("%s: the fixture's forged text (%q) never reached the screen at all, so "+
					"this test measures nothing:\n%s", name, forged, screen)
			}
		}
		if r, ok := rawForgingRune(screen); ok {
			t.Errorf("%s printed a raw control character (%q) from a profiles.d file's own path "+
				"or parse error:\n%s", name, r, strings.ReplaceAll(screen, "\x1b", "<ESC>"))
		}
		if !strings.Contains(screen, `\n`) {
			t.Errorf("%s: the escaped form of the newline never reached the screen: %s", name, screen)
		}
	}

	if err := refuseBadFiles(bad); err == nil {
		t.Fatal("refuseBadFiles accepted a non-empty bad list")
	} else {
		check("refuseBadFiles", err.Error())
	}

	check("reportBadFiles", captureStderr(t, func() { reportBadFiles(bad) }))
}
