package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"testing"
)

// ── issue #224: the design index listed a path variable that was never built ──
//
// `{target_ancestor:N}` appeared in the design index twice for the whole life
// of the project, alongside the variables that exist. It was never
// implemented. A profile writing `ro = ["{target_ancestor:2}"]` gets that
// literal string as a path.
//
// This is the "documented but not implemented" shape CLAUDE.md names as
// recurring, and it is the same list that records `--seccomp` being passed,
// accepted and never installed. The file's own advice is the fix: when a comment
// says "requires X", grep for X before believing it.
//
// Deleting the mentions would have closed the ticket and left nothing to
// stop the next one. So the book and the code are checked against each other:
// TestBookListsExactlyThePathVariablesResolveBuilds requires the variables
// docs/src/filesystem.md lists to be exactly the ones `Resolve` builds.
//
// WHAT THIS DELIBERATELY DOES NOT DO: assert that no document MENTIONS an
// unbuilt variable — a reader who finds no trace of `{target_ancestor:N}`
// anywhere will design it twice. What must not happen is it being listed as
// though it were live. So the check is on the ADVERTISED LIST, and prose
// about a variable that does not exist is fine as long as it says so.

// resolvePathVars reads the keys of the `vars` map literal in Resolve. Parsed
// rather than duplicated, because a hand-copied list here would be the same
// defect this test exists to catch, one file over.
func resolvePathVars(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "resolve.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing resolve.go: %v", err)
	}
	var got []string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		mt, ok := lit.Type.(*ast.MapType)
		if !ok {
			return true
		}
		if k, ok := mt.Key.(*ast.Ident); !ok || k.Name != "string" {
			return true
		}
		if v, ok := mt.Value.(*ast.Ident); !ok || v.Name != "string" {
			return true
		}
		// The vars map is the only map[string]string literal in Resolve whose
		// keys are all bare path-variable names; require a known one to be
		// present so an unrelated literal cannot be mistaken for it.
		var keys []string
		for _, e := range lit.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			bl, ok := kv.Key.(*ast.BasicLit)
			if !ok || bl.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(bl.Value)
			if err != nil {
				return true
			}
			keys = append(keys, s)
		}
		for _, k := range keys {
			if k == "target" {
				got = keys
				return false
			}
		}
		return true
	})
	if len(got) == 0 {
		t.Fatal("could not find Resolve's path-variable map in resolve.go — the shape it is " +
			"parsed by changed, so this test is grading nothing")
	}
	sort.Strings(got)
	return got
}
