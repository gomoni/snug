package cli

import (
	"testing"
	"unicode/utf8"

	"github.com/gomoni/snug/internal/policy"
)

// TestEveryInterpretedMarkFitsTheScreen is §9 test 3 (issues #169/#170): every
// row in policy.InterpretedPaths, rendered through every shape it can take —
// the guest-side mark (template A or B), the host-side mark (template C) —
// must wrap through wrapMark to at most 3 lines, none exceeding screenWidth.
// The geometry constants (markIndent, markWrapPad, screenWidth) live in this
// package, which is why the test does too, alongside
// TestNoDryRunEnvironmentLineIsWiderThanEightyColumns and
// TestWrapMarkNeverSplitsAToken (envrowgeometry_test.go), the equivalent
// checks for the environment notes' marks.
//
// Budget, not measurement: policy.InterpretedPath.Keys is kept to <=60 runes
// specifically so this holds (interpretedpaths.go's own doc comment on the
// field), and TestEveryInterpretedRowIsWellFormed (internal/policy) is the
// test that enforces that budget on the DATA. This test enforces the same
// promise on the RENDERED OUTPUT, which is the one a human actually reads.
func TestEveryInterpretedMarkFitsTheScreen(t *testing.T) {
	checked := 0
	for _, row := range policy.InterpretedPaths {
		for _, side := range []policy.InterpretedSide{policy.SideGuest, policy.SideHost} {
			hit := policy.InterpretedHit{Row: row, Side: side, Match: policy.MatchExact}
			for _, mark := range policy.InterpretedMarks([]policy.InterpretedHit{hit}) {
				checked++
				lines := wrapMark(mark)
				if len(lines) == 0 {
					t.Errorf("row %q side %v produced an empty mark", row.Path, side)
					continue
				}
				if len(lines) > 3 {
					t.Errorf("row %q side %v wraps to %d lines, over the 3-line budget: %q",
						row.Path, side, len(lines), mark)
				}
				for _, l := range lines {
					if n := utf8.RuneCountInString(l); n > screenWidth {
						t.Errorf("row %q side %v produced a line %d runes wide (screenWidth=%d): %q",
							row.Path, side, n, screenWidth, l)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no marks were checked at all; this test measures nothing")
	}

	// Template D, the ancestor collapse, is dynamic — its length depends on
	// how many rows fold together — so it cannot be checked per row the way
	// A/B/C are above. Covered against every ancestor grant wide enough to
	// matter: /etc (17 rows) and, since redteam finding F4 removed "/" from
	// BroadHostTrees, "/" itself — now the widest real case there is,
	// collapsing all 52 catalogued rows (system AND home) into one line.
	for _, grant := range []string{"/etc", "/"} {
		ancestorMarks := policy.InterpretedMarks(policy.ClassifyInterpretedPath(grant, "/home/u"))
		if len(ancestorMarks) == 0 {
			t.Fatalf("control: %q produced no ancestor mark at all, so the D-template check below "+
				"measures nothing", grant)
		}
		for _, mark := range ancestorMarks {
			lines := wrapMark(mark)
			if len(lines) > 3 {
				t.Errorf("the %q ancestor collapse wraps to %d lines, over the 3-line budget: %q",
					grant, len(lines), mark)
			}
			for _, l := range lines {
				if n := utf8.RuneCountInString(l); n > screenWidth {
					t.Errorf("the %q ancestor collapse produced a line %d runes wide (screenWidth=%d): %q",
						grant, n, screenWidth, l)
				}
			}
		}
	}
}
