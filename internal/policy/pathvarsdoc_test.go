package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ── issue #224: INDEX.md listed a path variable that was never built ────────
//
// `{target_ancestor:N}` appeared in INDEX.md twice — in §2's resolution
// algorithm and in §12's summary — alongside the variables that exist, for the
// whole life of the project. It was never implemented. A profile writing
// `ro = ["{target_ancestor:2}"]` gets that literal string as a path.
//
// This is the "documented but not implemented" shape CLAUDE.md names as
// recurring, and it is the same list that records `--seccomp` being passed,
// accepted and never installed. The file's own advice is the fix: when a comment
// says "requires X", grep for X before believing it.
//
// Deleting the two mentions would have closed the ticket and left nothing to
// stop the next one. So the doc and the code are now checked against each other:
// the variables INDEX.md advertises must be exactly the ones `Resolve` builds.
//
// WHAT THIS DELIBERATELY DOES NOT DO: assert that the doc never MENTIONS an
// unbuilt variable. #224's own resolution keeps `{target_ancestor:N}` in the
// file on purpose — it is the natural home for a `@parent-ro` variant, which is
// what #179 wants, and a reader who finds no trace of it will design it twice.
// What must not happen is it being listed as though it were live. So the check
// is on the ADVERTISED LIST, and prose about a variable that does not exist is
// fine as long as it says so.

var pathVarLine = regexp.MustCompile(`(?m)^- Path variables: (.*)$`)

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

func TestINDEXAdvertisesExactlyThePathVariablesResolveBuilds(t *testing.T) {
	built := resolvePathVars(t)

	index := filepath.Join("..", "..", ".claude", "design", "INDEX.md")
	body, err := os.ReadFile(index)
	if err != nil {
		t.Fatalf("cannot read %s: %v", index, err)
	}
	m := pathVarLine.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no \"- Path variables:\" line in %s. It is the list this test grades; if it "+
			"was renamed, update pathVarLine rather than deleting the check", index)
	}
	// Everything in `backticks` on that line, minus the tilde, which is a
	// spelling rather than a named variable.
	advertised := map[string]bool{}
	for _, q := range regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(string(m[1]), -1) {
		name := strings.Trim(q[1], "{}")
		if name == "~" {
			continue
		}
		advertised[name] = true
	}

	for _, b := range built {
		if !advertised[b] {
			t.Errorf("Resolve builds {%s} and INDEX.md's path-variable list does not advertise "+
				"it. A profile author reading the design doc would not know it exists", b)
		}
	}
	for a := range advertised {
		found := false
		for _, b := range built {
			if a == b {
				found = true
			}
		}
		if !found {
			t.Errorf("INDEX.md advertises {%s} as a live path variable and Resolve does not "+
				"build it. This is issue #224 happening again: `{target_ancestor:N}` was listed "+
				"here for the life of the project and never existed, so a profile writing it "+
				"got the literal string as a path. Either build it, or move it out of the "+
				"advertised list and say it was never built", a)
		}
	}
}
