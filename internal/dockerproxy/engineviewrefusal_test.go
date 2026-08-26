package dockerproxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// refusalLiteral is one string a user can be shown, with where it was written.
type refusalLiteral struct {
	file string
	line int
	text string
}

// collectRefusalLiterals returns every string literal in the named files,
// WITH `+` concatenations joined into the one string a user actually reads.
//
// The joining is the whole reason this helper exists rather than a second copy
// of TestNoRefusalTextOverclaimsWhatTheFilterDoes' per-literal walk. Two of the
// three defects the sweep below was written for straddled a line break —
// `"... in a cgroup outside this " + "sandbox's own"` and `"... which is
// outside this " + "sandbox"` — so a per-literal scan reads neither phrase and
// reports the file clean. Every refusal in this package is written as a
// concatenation, because gofmt-width forces it, which makes the joined form the
// only form worth scanning.
//
// STRING LITERALS only, via the parser: a comment quoting a falsified clause is
// documentation, not a claim made to a user, and the corrections this test
// guards deliberately quote the phrases they replaced.
func collectRefusalLiterals(t *testing.T, files ...string) []refusalLiteral {
	t.Helper()
	var out []refusalLiteral
	for _, name := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.BinaryExpr:
				if e.Op != token.ADD {
					return true
				}
				parts, ok := flattenStringAdd(e)
				if !ok {
					return true
				}
				out = append(out, refusalLiteral{name, fset.Position(e.Pos()).Line, parts})
				return false // the operands are already in `parts`
			case *ast.BasicLit:
				if e.Kind != token.STRING {
					return true
				}
				out = append(out, refusalLiteral{name, fset.Position(e.Pos()).Line, litValue(e)})
			}
			return true
		})
	}
	return out
}

// flattenStringAdd joins an `a + b + c` chain of string literals. Reports false
// for any chain carrying a non-literal operand: a format argument or a variable
// is not text this test can read, and guessing at it would produce a string
// nobody is ever shown.
func flattenStringAdd(e *ast.BinaryExpr) (string, bool) {
	var walk func(ast.Expr) (string, bool)
	walk = func(x ast.Expr) (string, bool) {
		switch v := x.(type) {
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return "", false
			}
			return litValue(v), true
		case *ast.BinaryExpr:
			if v.Op != token.ADD {
				return "", false
			}
			l, ok := walk(v.X)
			if !ok {
				return "", false
			}
			r, ok := walk(v.Y)
			if !ok {
				return "", false
			}
			return l + r, true
		}
		return "", false
	}
	return walk(e)
}

// litValue unquotes a string literal, tolerating either quoting style.
func litValue(bl *ast.BasicLit) string {
	s := bl.Value
	if len(s) >= 2 && (s[0] == '"' || s[0] == '`') {
		s = s[1 : len(s)-1]
	}
	return strings.ReplaceAll(s, `\"`, `"`)
}

// proxyRefusalFiles are the four files that decide something and say so. Named
// rather than globbed: a glob would pull in _test.go files, whose fixtures
// legitimately contain the phrases below.
var proxyRefusalFiles = []string{"proxy.go", "create.go", "build.go", "toplevel.go"}

// TestNoRefusalTextPlacesTheEngineOutsideTheSandbox is issue #372's regression,
// and it guards the CLASS across every refusal string this package writes
// rather than the one clause that was found.
//
// THE DEFECT. The archive refusal told a user the endpoint "is serviced by the
// ENGINE, outside the sandbox, as the host uid, so it is not bounded by this
// sandbox's mount grants the way `exec` is". Half of that is true — the engine
// does service it — and the operative half became false at Tier C (issue #125):
// internal/stage/inengine.go step 4 builds the engine's mount namespace by
// joining the SANDBOX's and adding this run's grafts, so the engine is bounded
// by the sandbox's mount grants, just by a wider set than the container rootfs
// that bounds `exec`. A reader acting on the old sentence looks for a host-tree
// escape that is not there and misses the store that is.
//
// Two siblings of the same shape were live when this was written, both found by
// the concatenation-aware scan above and neither by any existing sweep:
// build.go's `cgroupparent` refusal still said "a cgroup outside this sandbox's
// own" after the create-side twin had been corrected to name the engine's own
// cgroup namespace, and checkNSOptions told a client that Host:true on
// pid/ipc/uts/cgroup "asks for the HOST's namespace, which is outside this
// sandbox" when the engine clones all four for itself
// (internal/stage/enginefork.go).
//
// WHY IT IS A PHRASE BLOCKLIST. Same reasoning as its two siblings in
// refusalreason_test.go, which cover the refusalReason and namespaceModeReason
// MAPS: the point is to catch a stale MODEL, not to freeze prose. This one
// covers the literals instead, which is where all three defects above lived —
// none of them is a map entry.
func TestNoRefusalTextPlacesTheEngineOutsideTheSandbox(t *testing.T) {
	// Each phrase puts the engine, or something it resolves, on the far side of
	// a boundary Tier C removed.
	stale := []string{
		"outside the sandbox",
		"outside this sandbox",
		"not bounded by this sandbox's mount grants",
		"the host's pid namespace",
		"a copy of the host tree",
	}

	lits := collectRefusalLiterals(t, proxyRefusalFiles...)
	for _, l := range lits {
		lower := strings.ToLower(l.text)
		for _, phrase := range stale {
			if strings.Contains(lower, strings.ToLower(phrase)) {
				t.Errorf("%s:%d writes refusal text containing %q, which places the engine "+
					"outside the sandbox it now derives its view FROM (issue #125 Tier C, "+
					"issue #372).\nWrite what the engine's reach actually is — the sandbox's "+
					"own tree plus this run's grafts — the way refusalReason's ContainerIDFile "+
					"entry does.\ntext: %s", l.file, l.line, phrase, l.text)
			}
		}
	}

	// POSITIVE CONTROL. Without it the sweep passes when the files fail to
	// parse, when they are renamed out from under it, and when the collector
	// returns nothing — each of which reads as "no stale model found".
	if len(lits) < 200 {
		t.Fatalf("collected only %d refusal strings from %v; the sweep above proves nothing",
			len(lits), proxyRefusalFiles)
	}

	// POSITIVE CONTROL for the JOINING, which is the property that makes this
	// test find what the per-literal sweep cannot. The archive refusal is one
	// `+` chain spanning seven source lines: if concatenations were not joined,
	// no single collected string would hold both its first and its last clause.
	joined := false
	for _, l := range lits {
		if strings.Contains(l.text, "the container archive endpoint") &&
			strings.Contains(l.text, "tar -x") {
			joined = true
		}
	}
	if !joined {
		t.Error("no collected string holds both ends of the archive refusal, so `+` chains " +
			"are not being joined and the two sibling defects this test was written for " +
			"would both read as clean")
	}

	// POSITIVE CONTROL, per phrase: every entry must be caught by a sentence
	// shaped like the defect it guards, so a phrase that matches nothing cannot
	// masquerade as coverage. The first three are the defects as they were
	// actually written.
	poisoned := []string{
		"it is serviced by the ENGINE, outside the sandbox, as the host uid, so it is not " +
			"bounded by this sandbox's mount grants the way `exec` is",
		"it places the build in a cgroup outside this sandbox's own",
		"asks for the HOST's pid namespace, which is outside this sandbox",
		"pid 1 there is the engine, whose mount namespace is a copy of the host tree",
	}
	for _, phrase := range stale {
		caught := false
		for _, sentence := range poisoned {
			if strings.Contains(strings.ToLower(sentence), strings.ToLower(phrase)) {
				caught = true
				break
			}
		}
		if !caught {
			t.Errorf("no poisoned control sentence contains %q, so adding it to the stale "+
				"list proves nothing — it would match no real defect either", phrase)
		}
	}
}
