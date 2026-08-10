package main

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
