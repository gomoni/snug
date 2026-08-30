package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestNotesGatingByKind is the whole of issue #541's behaviour change, and it
// is a NEGATIVE test in the sense CLAUDE.md means: what this pins is that four
// of five startup notes STOP reaching a quiet run's stderr, and that the fifth
// does not.
func TestNotesGatingByKind(t *testing.T) {
	tests := []struct {
		name       string
		verbose    bool
		wantEscape bool
		wantAside  bool
	}{
		{name: "quiet run: the escape note, and nothing else", verbose: false, wantEscape: true, wantAside: false},
		{name: "-v: everything", verbose: true, wantEscape: true, wantAside: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			n := newNotes(&buf, tt.verbose)
			n.escape("A SANDBOX ESCAPE\n")
			n.aside("an ergonomic footnote\n")

			got := buf.String()
			if strings.Contains(got, "A SANDBOX ESCAPE") != tt.wantEscape {
				t.Errorf("escape note present = %v, want %v; stderr was %q",
					!tt.wantEscape, tt.wantEscape, got)
			}
			if strings.Contains(got, "an ergonomic footnote") != tt.wantAside {
				t.Errorf("aside present = %v, want %v; stderr was %q",
					!tt.wantAside, tt.wantAside, got)
			}
			// Collected either way: --dry-run and --explain render the whole
			// set regardless of -v, so a note that is merely SUPPRESSED must
			// still have been recorded.
			if len(n.all()) != 2 {
				t.Errorf("collected %d notes, want 2 — suppressing a note must not discard it", len(n.all()))
			}
		})
	}
}

// TestNotesLiveNilPrintsNothing pins the --dry-run/--explain arm: those two
// screens render the collected set themselves, and a note also landing on
// stderr while a pager holds the terminal is the wall of text moved rather
// than fixed.
func TestNotesLiveNilPrintsNothing(t *testing.T) {
	n := newNotes(nil, true)
	n.escape("A SANDBOX ESCAPE\n")
	n.aside("an ergonomic footnote\n")
	if len(n.all()) != 2 {
		t.Fatalf("collected %d notes, want 2", len(n.all()))
	}
	var screen bytes.Buffer
	n.render(&screen)
	for _, want := range []string{"A SANDBOX ESCAPE", "an ergonomic footnote"} {
		if !strings.Contains(screen.String(), want) {
			t.Errorf("render() dropped %q:\n%s", want, screen.String())
		}
	}
}

// TestNotesRenderEmptyIsSilent: "NOTES (none)" would teach a reader that the
// block is usually empty, and the block's whole value is that its presence
// means something.
func TestNotesRenderEmptyIsSilent(t *testing.T) {
	var screen bytes.Buffer
	newNotes(nil, false).render(&screen)
	if screen.Len() != 0 {
		t.Errorf("a run with no notes rendered %q, want nothing", screen.String())
	}
}

// TestNotesNilReceiverIsSafe. Every test that stages Claude files or starts
// containers passes nil rather than building a collector, and a nil-hostile
// method here would turn "this test does not care about notes" into a panic.
func TestNotesNilReceiverIsSafe(t *testing.T) {
	var n *notes
	n.escape("x\n")
	n.aside("y\n")
	if n.isVerbose() {
		t.Error("a nil collector reported verbose")
	}
	if len(n.all()) != 0 {
		t.Error("a nil collector collected something")
	}
	var buf bytes.Buffer
	n.render(&buf)
	if buf.Len() != 0 {
		t.Errorf("a nil collector rendered %q", buf.String())
	}
}

// TestHTTPDoorNoteIsAnEscape is the one that must never be relaxed by a later
// tidy-up. announceHTTPDoors is the only producer of noteEscape, and the
// argument for it is in that function's own doc comment: the same warning is
// written into a CLAUDE.md living in a writable project tree that snug's
// threat model assumes a hostile payload may edit, so stderr is the only copy
// that can be trusted. Route it through aside and the sentence "THAT IS A
// SANDBOX ESCAPE" reaches only the people who typed -v.
func TestHTTPDoorNoteIsAnEscape(t *testing.T) {
	var buf bytes.Buffer
	n := newNotes(&buf, false) // NOT verbose: that is the point
	announceHTTPDoors(n, []httpDoor{{Name: "web"}})

	got := buf.String()
	if !strings.Contains(got, "THAT IS A SANDBOX ESCAPE") {
		t.Fatalf("the http-door escape sentence did not reach a quiet run's stderr:\n%s", got)
	}
	if !strings.Contains(got, `http door "web" is declared`) {
		t.Errorf("the door's name did not reach stderr:\n%s", got)
	}
	if len(n.all()) != 1 {
		t.Errorf("announceHTTPDoors produced %d notes, want 1 — a door block split across "+
			"several notes lets -v or the NOTES block break the paragraph", len(n.all()))
	}
	if n.all()[0].kind != noteEscape {
		t.Error("the http-door note is not noteEscape, so a quiet run would not print it")
	}
}

// TestNoDoorSaysNothing: the escape note costs an ordinary run nothing,
// because a door exists only where a profile named one in listen_names.
func TestNoDoorSaysNothing(t *testing.T) {
	var buf bytes.Buffer
	n := newNotes(&buf, false)
	announceHTTPDoors(n, nil)
	if buf.Len() != 0 {
		t.Errorf("a selection with no declared door printed %q", buf.String())
	}
	if len(n.all()) != 0 {
		t.Errorf("a selection with no declared door recorded %d notes", len(n.all()))
	}
}
