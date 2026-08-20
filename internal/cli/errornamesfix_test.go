package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// ── "errors name the fix" is a rule with no mechanism (issue #180) ──────────
//
// CLAUDE.md's working agreement says a bad message in an odd environment costs
// an hour, and names these two files' subject matter as exactly that: a per-uid
// runtime directory that must resolve from the uid alone, and a lock whose whole
// job is refusing a second sandbox on one target. Measured before this test
// existed: 24 fmt.Errorf sites across the two files, 6 naming a fix and 18 bare
// wraps of the form `context: %w`.
//
// A bare wrap is not a bug — it is the DEFAULT, which is the problem. Nothing
// ever noticed the eighteen, and nothing would notice the nineteenth. So the
// rule gets a mechanism: every fmt.Errorf in these two files must either say
// something beyond the wrap, or be listed as exempt with a reason.
//
// WHAT THIS CAN AND CANNOT CHECK, stated because a fuzzy assertion that reads as
// a strong one is worse than none. It cannot tell whether a named fix is the
// RIGHT fix — only a human reading the message can, and this change turned up an
// instance of exactly that: the brief for #180 proposed making the target-lock
// flock error say "another sandbox holds this, use snug attach", which would have
// been WRONG, because EWOULDBLOCK is caught one branch earlier and already
// returns targetBusyError with that advice. What this checks is that a message
// says more than what failed — the floor, not the ceiling.
//
// Deliberately scoped to these two files. Widening it to the package would
// either need a large exempt list assembled without reading each site, or would
// pass on a threshold low enough to prove nothing.

// errorFixFiles maps each swept file to the minimum number of fmt.Errorf sites
// it must still contain. PER FILE rather than a single total, found by mutation:
// with one global floor, deleting targetlock.go from this list changed nothing,
// because runtimedir.go's nineteen sites cleared it on their own.
//
// The floors are well below the measured counts (19 and 5) so an ordinary
// refactor does not trip them, while a file that stops yielding errors — renamed,
// gutted, or its calls no longer spelled fmt.Errorf — does.
//
// WHAT IT STILL CANNOT CATCH, said out loud rather than left implied: deleting an
// entry from THIS MAP. A test cannot police edits to its own input list, and
// pretending otherwise with a hardcoded expected length would just move the same
// edit one line down. The mutation was run and it survives; the per-file floor is
// what turns the version that matters — a file quietly stopping being covered
// while still existing — into a failure.
var errorFixFiles = map[string]int{"runtimedir.go": 12, "targetlock.go": 3}

// A message clears the bar if it carries a clause beyond the "what failed" head.
// The dash is snug's own idiom for that clause across every screen it prints;
// the other markers catch the messages that lead with the explanation instead.
var fixMarkers = []string{
	" - ", " — ",
	"refusing", "refuses", "check that", "check free space",
	"see ", "report it", "cannot run here",
}

// exemptErrors lists messages that legitimately say only what failed, keyed by a
// distinctive fragment. Each needs a reason, and "it is only a wrap" is not one.
var exemptErrors = map[string]string{}

func TestErrorsInTheOddEnvironmentPathsNameTheFix(t *testing.T) {
	fset := token.NewFileSet()
	counts := map[string]int{}

	for name, floor := range errorFixFiles {
		_ = floor
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Errorf" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "fmt" {
				return true
			}
			if len(call.Args) == 0 {
				return true
			}
			msg := concatString(call.Args[0])
			if msg == "" {
				return true
			}
			counts[name]++

			for frag, why := range exemptErrors {
				if strings.Contains(msg, frag) {
					if why == "" {
						t.Errorf("%s: the exemption for %q has no reason", name, frag)
					}
					return true
				}
			}
			for _, marker := range fixMarkers {
				if strings.Contains(msg, marker) {
					return true
				}
			}
			t.Errorf("%s:%d: this error says only what failed:\n\t%q\n"+
				"CLAUDE.md's working agreement: errors name the fix, because snug runs in odd "+
				"environments and a bad message there costs an hour — and this file IS one of "+
				"the odd-environment paths (issue #180). Say what snug was attempting and what "+
				"the reader can do about it, or add it to exemptErrors with the reason. Do NOT "+
				"invent a remedy you have not checked: a wrong fix is worse than none.",
				name, fset.Position(call.Pos()).Line, msg)
			return true
		})
	}

	// A sweep that matched nothing would pass forever.
	for name, floor := range errorFixFiles {
		if counts[name] < floor {
			t.Fatalf("only %d fmt.Errorf sites were found in %s (floor %d) — the sweep is no "+
				"longer finding them there and cannot fail for the right reason",
				counts[name], name, floor)
		}
	}
}

// concatString flattens `"a " + "b"`, which is how a long message is written.
func concatString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return ""
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return ""
		}
		return s
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return ""
		}
		return concatString(v.X) + concatString(v.Y)
	}
	return ""
}
