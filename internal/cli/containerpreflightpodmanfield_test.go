package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// findPodmanFieldReaders parses src (named filename, only for parser
// diagnostics) and returns the source text of the enclosing line of every
// `pf.Podman` SELECTOR EXPRESSION it finds — an AST walk, not a text grep, so
// a prose mention of "pf.Podman" in a doc comment (container.go's own comment
// introducing issue #405's call site says the literal words "pf.Podman is a
// single field") can never appear here: go/ast never visits a comment as a
// node, so ast.Inspect walking *ast.SelectorExpr sees only real reads.
func findPodmanFieldReaders(t testing.TB, filename string, src []byte) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", filename, err)
	}
	lines := strings.Split(string(src), "\n")
	var hits []string
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Podman" {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != "pf" {
			return true
		}
		pos := fset.Position(sel.Pos())
		if pos.Line-1 < len(lines) {
			hits = append(hits, strings.TrimSpace(lines[pos.Line-1]))
		} else {
			hits = append(hits, "<position out of range>")
		}
		return true
	})
	return hits
}

// TestContainerPreflightPodmanFieldHasExactlyTwoReaders is issue #405's
// ruling that both sources of an engine binary — $SNUG_PODMAN and the PATH
// lookup — land in the ONE field containerPreflight.Podman, so gating the
// FIELD (pol.CheckEngineBinary(pf.Podman), container.go) covers every source
// by construction. That claim is only true for as long as there really are
// exactly the two readers this test names; a THIRD reader added later — one
// that uses pf.Podman before the gate runs, or in a code path the gate never
// reaches — would silently defeat the ruling's whole argument.
//
// Swept: every non-test .go file in this package (container.go is the only
// one today, but nothing stops a future patch threading pf into a helper
// elsewhere). Read via go/parser + ast.Inspect rather than a text regex —
// see findPodmanFieldReaders's own doc comment for why that matters here
// specifically: a regex over raw source would also match this test's own
// doc comment, and container.go's own comment introducing the #405 call
// site, both of which say "pf.Podman" in prose.
func TestContainerPreflightPodmanFieldHasExactlyTwoReaders(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	// visited: the standard positive control that the walk actually reached
	// the one file either reader could live in today. Without it, an empty
	// `hits` slice below could mean "no readers exist" OR "the walk never
	// looked" — the same failure mode #291 part 1b named for a directory
	// walk, here at file-list granularity.
	visited := map[string]bool{}
	var hits []string
	hitFiles := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		visited[e.Name()] = true
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range findPodmanFieldReaders(t, e.Name(), src) {
			hits = append(hits, e.Name()+": "+h)
			hitFiles[e.Name()] = true
		}
	}
	if !visited["container.go"] {
		t.Fatal("the sweep never visited container.go — an empty result below would mean " +
			"nothing about whether a reader exists")
	}

	want := []string{
		"pol.CheckEngineBinary(pf.Podman)",
		"eng.Spec(pol, pf.Podman, nil, pf.CgroupsDisabled, sig)",
	}
	if len(hits) != len(want) {
		t.Fatalf("expected exactly %d readers of containerPreflight.Podman (both sources land "+
			"in this one field, and issue #405's ruling is that gating the field covers the "+
			"set — a THIRD reader would need its own gate, or it bypasses this one), found %d: %v",
			len(want), len(hits), hits)
	}
	for _, w := range want {
		found := false
		for _, h := range hits {
			if strings.Contains(h, w) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected reader %q not found among: %v", w, hits)
		}
	}
	if len(hitFiles) != 1 || !hitFiles["container.go"] {
		t.Errorf("expected both readers to live in container.go, found in: %v", hitFiles)
	}

	// POSITIVE CONTROL: a synthetic THIRD reader, written as a string
	// literal rather than planted anywhere real, proving
	// findPodmanFieldReaders can actually see a NEW one — otherwise the
	// exact-count assertion above could be passing because the walk is
	// blind, not because there really are only two.
	synthetic := []byte("package cli\n\nfunc synthetic(pf containerPreflight) string {\n\treturn pf.Podman\n}\n")
	got := findPodmanFieldReaders(t, "synthetic.go", synthetic)
	if len(got) != 1 {
		t.Fatalf("control: findPodmanFieldReaders found %d reader(s) in a fixture with exactly "+
			"one synthetic third reader (want 1) — the sweep above cannot be trusted to catch "+
			"a real one either: %v", len(got), got)
	}
}
