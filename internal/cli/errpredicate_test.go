package cli

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nonUnwrappingPredicates are the pre-errors os helpers. Each one inspects the
// CONCRETE error value and does not unwrap, so it answers false for the same
// error once anything has wrapped it with %w.
var nonUnwrappingPredicates = map[string]string{
	"IsNotExist":   "errors.Is(err, fs.ErrNotExist)",
	"IsExist":      "errors.Is(err, fs.ErrExist)",
	"IsPermission": "errors.Is(err, fs.ErrPermission)",
}

// TestNoProductionCodeUsesANonUnwrappingErrorPredicate asserts the SET rather
// than the site that issue #124 was found at.
//
// The bug was one line: discoverLiveRuns asked `os.IsNotExist(err)` about an
// error vdir.OpenExistingSubdir had wrapped with %w, so "snug has never run on
// this host" — the zero case — surfaced to the user as a raw path error.
//
// Fixing that one line would have been fixing the instance. The DEFECT is that
// `os.IsNotExist` and its two siblings are silently wrong in the presence of a
// wrap, and whether a given error arrives wrapped is decided elsewhere — in
// internal/policy's case, by an INJECTED function this package does not
// control. There is no compiler error, no vet diagnostic and no test failure;
// the only symptom is a wrong answer. That is the same shape as the rules
// CLAUDE.md already records: when you fix a predicate, name every sink it can
// reach and assert the set.
//
// Scanning the AST rather than grepping, deliberately. A grep matches this
// test's own explanatory comments, and it would have to be written to exclude
// them — which is how a sweep ends up "verified" by a pattern that could never
// match anything (the `grep -rn 'a|b'` without -E lesson).
func TestNoProductionCodeUsesANonUnwrappingErrorPredicate(t *testing.T) {
	roots := []string{"..", filepath.Join("..", "..", "cmd")}

	var scanned int
	var hits []string
	for _, root := range roots {
		n, found := scanForOSPredicates(t, root)
		scanned += n
		hits = append(hits, found...)
	}

	// PRECONDITION: the walk actually read the tree. A scanner that found no
	// files would report no hits and look like proof.
	if scanned < 20 {
		t.Fatalf("PRECONDITION: only %d production .go files were scanned under %v — the walk is "+
			"not reaching the tree, so a clean result below means nothing", scanned, roots)
	}

	for _, h := range hits {
		t.Errorf("%s — this predicate does not unwrap, so it silently answers false once the "+
			"error has been through a %%w. That is issue #124. Use %s instead.",
			h, nonUnwrappingPredicates[strings.SplitN(h, " os.", 2)[1]])
	}
}

// TestTheNonUnwrappingPredicateScannerCanFail is the positive control for the
// test above, and it is not a formality: "no production file calls
// os.IsNotExist" is exactly what a detector that recognises nothing reports.
// This feeds the detector a file that plainly does call it.
func TestTheNonUnwrappingPredicateScannerCanFail(t *testing.T) {
	dir := t.TempDir()
	planted := filepath.Join(dir, "planted.go")
	src := "package planted\n\nimport \"os\"\n\nfunc f(err error) bool { return os.IsNotExist(err) }\n"
	if err := os.WriteFile(planted, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	n, hits := scanForOSPredicates(t, dir)
	if n != 1 {
		t.Fatalf("the scanner read %d files in a directory holding exactly one", n)
	}
	if len(hits) != 1 {
		t.Fatalf("the scanner did not flag a file that literally calls os.IsNotExist — every "+
			"assertion in TestNoProductionCodeUsesANonUnwrappingErrorPredicate is therefore "+
			"vacuous. Got %v", hits)
	}

	// And it must not flag a MENTION: the production tree carries several
	// comments naming os.IsNotExist to explain why it is not used.
	commented := filepath.Join(t.TempDir(), "commented.go")
	if err := os.WriteFile(commented,
		[]byte("package c\n\n// os.IsNotExist does not unwrap; see issue #124.\nfunc g() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, hits := scanForOSPredicates(t, filepath.Dir(commented)); len(hits) != 0 {
		t.Errorf("the scanner flagged a COMMENT mentioning os.IsNotExist: %v. It would then be "+
			"unfixable without deleting the explanation of why the predicate is wrong", hits)
	}
}

// scanForOSPredicates parses every non-test .go file under root and reports
// how many it read and which ones CALL one of nonUnwrappingPredicates on the
// `os` package.
func scanForOSPredicates(t *testing.T, root string) (scanned int, hits []string) {
	t.Helper()
	fset := token.NewFileSet()

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// testdata holds deliberately odd fixtures and is not production.
			if info.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		scanned++
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "os" {
				return true
			}
			if _, bad := nonUnwrappingPredicates[sel.Sel.Name]; bad {
				hits = append(hits, fmt.Sprintf("%s calls os.%s", fset.Position(call.Pos()), sel.Sel.Name))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return scanned, hits
}
