package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// --dry-run STATES WHAT WILL BE EXECUTED, and argv[0] is the one element of
// both argv blocks that is not what will be executed (issue #332).
//
// The measurement behind the note under test: snug starts bwrap and pasta the
// same way — exec.LookPath(<bare name>) at run time, then exec.Command with
// LookPath's ANSWER, which makes the real argv[0] an absolute path chosen from
// the HOST user's $PATH after this artifact was written. The bare word both
// renderers print is therefore not a resolution, and until this the document
// said nothing to stop a reader taking it for one. `pasta.argv[0]` in
// particular got the literal string by copying jsonBwrap.Argv[0]'s comment,
// which argues about golden fixtures being host-independent — a true argument
// about a different question.
//
// The fix is one producer (execResolution, reportExec) with two printers, the
// arrangement grantMark/envGrantVerdict already uses. These tests grade that
// arrangement by EXECUTION, because the AST sweep in factproducersweep_test.go
// structurally cannot: its producer predicate is "package-level func taking a
// *policy.Policy", and execResolution takes a name. Giving it a parameter it
// does not read, purely to be swept, would be a lie told to a test.
func TestBothRenderersStateTheSameArgv0Resolution(t *testing.T) {
	sel := []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@net"}

	human := squashSpace(jsonGoldenHumanScreen(t, sel))
	doc := jsonGoldenReport(t, sel, false)

	var parsed struct {
		Bwrap struct {
			Argv          []string `json:"argv"`
			Argv0Resolved bool     `json:"argv0_resolved"`
			Argv0Note     string   `json:"argv0_note"`
		} `json:"bwrap"`
		Pasta *struct {
			Argv          []string `json:"argv"`
			Argv0Resolved bool     `json:"argv0_resolved"`
			Argv0Note     string   `json:"argv0_note"`
		} `json:"pasta"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("the machine format did not parse: %v", err)
	}
	// POSITIVE CONTROL for the pasta half: this selection carries @net, so a
	// nil pasta block means the fixture stopped exercising the block every
	// assertion below is about, and the pasta half would pass vacuously.
	if parsed.Pasta == nil {
		t.Fatalf("the document carries no pasta block for %v, so this test asserts nothing "+
			"about the helper whose argv[0] issue #332 was about", sel)
	}

	for _, tc := range []struct {
		name      string
		argv      []string
		resolved  bool
		note      string
		humanArgv string
	}{
		{"bwrap", parsed.Bwrap.Argv, parsed.Bwrap.Argv0Resolved, parsed.Bwrap.Argv0Note, "bwrap --unshare-user"},
		{"pasta", parsed.Pasta.Argv, parsed.Pasta.Argv0Resolved, parsed.Pasta.Argv0Note, "pasta --config-net"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := execResolution(tc.name)

			// 1. the word, in both renderers, from the producer. A key named
			// `argv` whose index 0 is a flag is not runnable at all, which is
			// what this half fixed; a key whose index 0 is an ABSOLUTE PATH
			// would be host-dependent in a committed golden.
			switch {
			case len(tc.argv) == 0:
				t.Fatalf("%s.argv is empty", tc.name)
			case tc.argv[0] != want.Argv0:
				t.Errorf("%s.argv[0] = %q, the producer says %q", tc.name, tc.argv[0], want.Argv0)
			case strings.HasPrefix(tc.argv[0], "/"):
				t.Errorf("%s.argv[0] = %q is an absolute path. A resolved path here is a "+
					"per-developer value in a committed fixture (#301, #320) AND a claim snug "+
					"cannot keep: the resolution that matters happens on the next run.",
					tc.name, tc.argv[0])
			}
			if !strings.Contains(human, tc.humanArgv) {
				t.Errorf("the human screen does not print %q, so it is not printing the same "+
					"argv[0] the document does", tc.humanArgv)
			}

			// 2. the fact, as something a gate can branch on.
			if tc.resolved {
				t.Errorf("%s.argv0_resolved is true, and snug resolves that name at run time "+
					"(TestTheArgv0NoteIsTrueOfHowSnugStartsTheHelper measures it). A consumer "+
					"reading this branches the wrong way.", tc.name)
			}

			// 3. THE ASSERTION: one sentence, both renderers, byte-identical
			// modulo the screen's wrapping. Two renderers each writing their
			// own English is how #332's seven producers drifted in the first
			// place.
			if tc.note != want.Note {
				t.Errorf("%s.argv0_note is not the producer's sentence.\n got: %s\nwant: %s",
					tc.name, tc.note, want.Note)
			}
			if !strings.Contains(human, squashSpace(want.Note)) {
				t.Errorf("the human screen does not carry the %s argv[0] note. The JSON says\n"+
					"  %s\nand the screen is\n%s", tc.name, want.Note, jsonGoldenHumanScreen(t, sel))
			}
		})
	}
}

// TestTheArgv0NoteIsTrueOfHowSnugStartsTheHelper is what keeps the sentence
// from going stale. Everything above compares two renderers against each
// other, and two renderers agreeing on a false statement is exactly the shape
// #332 found: the note claims snug calls exec.LookPath at run time and execs
// LookPath's answer, so the claim is checked against the code that starts each
// helper.
//
// Read as a source sweep (test/guard/sourcesweep_test.go's shape), not as a
// unit test: if snug ever starts execing a path it resolved earlier — or one a
// profile named — the note must change with it, and this is the failure that
// says so.
func TestTheArgv0NoteIsTrueOfHowSnugStartsTheHelper(t *testing.T) {
	for _, tc := range []struct{ helper, file string }{
		{"bwrap", filepath.Join("..", "sandbox", "exec.go")},
		{"pasta", filepath.Join("..", "sandbox", "netns.go")},
	} {
		b, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("reading %s: %v", tc.file, err)
		}
		src := string(b)
		lookPath := `exec.LookPath("` + tc.helper + `")`
		if !strings.Contains(src, lookPath) {
			t.Errorf("%s does not contain %s, and the argv[0] note in execResolution says snug "+
				"resolves %q that way at run time. Either the helper is started differently "+
				"now — in which case the note is a false statement on the trust artifact — or "+
				"the start moved to another file and this sweep is reading the wrong one.",
				tc.file, lookPath, tc.helper)
		}
		// exec.Command(<the LookPath result>, ...) is the half that makes the
		// executed argv[0] an absolute path rather than the bare word: os/exec
		// sets Args[0] to the string it is handed. A change to
		// exec.Command("<name>", ...) would make the printed word correct and
		// the note wrong in the other direction.
		if !strings.Contains(src, "exec.Command("+tc.helper+",") {
			t.Errorf("%s does not hand the LookPath result to exec.Command; the note claims "+
				"the executed argv[0] is the absolute path that search returned", tc.file)
		}
	}
	// POSITIVE CONTROL: both loops above are "the file contains X", which a
	// wrong path, an empty file or a typo answers with the same failure a real
	// regression would. A string that IS in the file grades the reader.
	b, err := os.ReadFile(filepath.Join("..", "sandbox", "netns.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "func startPasta(") {
		t.Fatal("internal/sandbox/netns.go does not contain func startPasta( — this sweep is " +
			"reading a file that is not the one it thinks, and every assertion above is " +
			"failing or passing for the wrong reason")
	}
}

// squashSpace collapses runs of whitespace, so a sentence the human screen
// wraps across lines can be compared with the one the document carries whole.
// It is the wrapping that differs between the two renderers and nothing else —
// wrapWords splits on Fields and rejoins with single spaces.
func squashSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
