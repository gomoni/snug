package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// THE CAVEAT THAT KEEPS §4.6(b) FROM BEING A SILENT DOWNGRADE.
//
// Once a command continues past a file it could not parse, a name defined in
// that file must not come back as a bare "unknown profile" — snug either knows
// the file defines it, or cannot say, and the difference between "you typed it
// wrong" and "the file defining it is broken" is the whole of what the user
// needs in order to act.
func TestUnknownProfileNamesTheFileThatDidNotLoad(t *testing.T) {
	reg := profile.Registry{}

	// Names unrecoverable (not TOML): snug cannot say.
	syntax := []profile.BadFile{{
		Path: "/home/u/.config/snug/profiles.d/mine.toml",
		Err:  fmt.Errorf("expected newline"),
	}}
	err := unknownProfile(reg, "work", syntax)
	for _, want := range []string{"work", "mine.toml", "cannot say"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	// Names recovered and this is one: the file and its error, which is the fix.
	defines := []profile.BadFile{{
		Path:       "/etc/snug/profiles.d/10-future.toml",
		Err:        fmt.Errorf("unknown key net_hosts"),
		Defines:    []policy.ProfileName{"work"},
		NamesKnown: true,
	}}
	err = unknownProfile(reg, "work", defines)
	for _, want := range []string{`"work" is defined in`, "10-future.toml", "unknown key net_hosts"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	// CONTROL: names recovered and this is not one, or nothing skipped — the
	// resolver's own message, no speculation. An unconditional footnote would
	// train people to ignore it.
	want := policy.UnknownProfile(reg, "other").Error()
	if got := unknownProfile(reg, "other", defines).Error(); got != want {
		t.Errorf("a bad file known not to define the name changed the message: %q", got)
	}
	if got := unknownProfile(reg, "other", nil).Error(); got != want {
		t.Errorf("with no skipped files the message must be unchanged, got %q", got)
	}
}

// #624: a bad file refuses the runs that REACH it, not every run. Reaching is
// the include closure: a selected profile whose include names a profile from
// the bad file refuses exactly as selecting that profile does.
func TestABadFileRefusesOnlyTheSelectionThatReachesIt(t *testing.T) {
	reg := profile.Registry{
		"@sys": {Name: "@sys"},
		"mine": {Name: "mine", Include: []policy.ProfileName{"future"}},
	}
	bad := []profile.BadFile{{
		Path:       "/etc/snug/profiles.d/10-future.toml",
		Err:        fmt.Errorf("unknown key net_hosts"),
		Defines:    []policy.ProfileName{"future"},
		NamesKnown: true,
	}}

	if err := refuseBadSelection(reg, []policy.ProfileName{"@sys"}, bad); err != nil {
		t.Errorf("a selection that never reaches the bad file was refused: %v", err)
	}
	for _, sel := range [][]policy.ProfileName{{"future"}, {"@sys", "mine"}} {
		err := refuseBadSelection(reg, sel, bad)
		if err == nil {
			t.Errorf("selection %v reaches a profile from a file that did not load and ran", sel)
			continue
		}
		if !strings.Contains(err.Error(), "10-future.toml") {
			t.Errorf("selection %v: refusal does not name the file: %v", sel, err)
		}
	}

	// A file whose names are unrecoverable cannot be ruled out for a name the
	// registry lacks, and cannot be ruled IN for one it holds.
	syntax := []profile.BadFile{{Path: "/etc/snug/profiles.d/broken.toml", Err: fmt.Errorf("x")}}
	if err := refuseBadSelection(reg, []policy.ProfileName{"@sys"}, syntax); err != nil {
		t.Errorf("a loaded selection was refused over a syntax-broken sibling: %v", err)
	}
	if err := refuseBadSelection(reg, []policy.ProfileName{"work"}, syntax); err == nil ||
		!strings.Contains(err.Error(), "cannot say") {
		t.Errorf("an unknown name beside a syntax-broken file must say snug cannot tell, got %v", err)
	}

	// CONTROL: nothing wrong, nothing refused.
	if err := refuseBadSelection(reg, []policy.ProfileName{"nosuch"}, nil); err != nil {
		t.Errorf("with no bad files the walk must leave unknown names to Resolve: %v", err)
	}
}

// The run that goes ahead still names the file, on every run and not only
// under -v: its owner has a profile no run can select.
func TestARunPastABadFileNamesItUnconditionally(t *testing.T) {
	bad := []profile.BadFile{{Path: "/etc/snug/profiles.d/b.toml", Err: fmt.Errorf("bad name")}}
	got := captureStderr(t, func() { noteBadFiles(newNotes(os.Stderr, false), bad) })
	for _, want := range []string{"b.toml", "bad name", "did not load"} {
		if !strings.Contains(got, want) {
			t.Errorf("note %q does not mention %q", got, want)
		}
	}
}

// Issue #613: badFileErrorLines is the one place a profiles.d parser error —
// go-toml's, not snug's, and per this file's own doc comment attacker-
// influenceable via a hostile $XDG_CONFIG_HOME (invariant 3) — reaches a
// screen. unknownProfile, noteBadFiles and reportBadFiles route it (and
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

	defined := []profile.BadFile{{Path: bad[0].Path, Err: bad[0].Err,
		Defines: []policy.ProfileName{"work"}, NamesKnown: true}}
	check("unknownProfile", unknownProfile(profile.Registry{}, "work", defined).Error())
	check("noteBadFiles", captureStderr(t, func() { noteBadFiles(newNotes(os.Stderr, false), bad) }))

	check("reportBadFiles", captureStderr(t, func() { reportBadFiles(bad) }))
}
