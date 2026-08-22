package guard

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ── the source sweeps must survive `go test ./...` ──────────────────────────
//
// Several packages assert properties over this module's own source by walking
// it. `go test ./...` runs packages CONCURRENTLY, so any such walk reads a tree
// that other packages' tests are writing in, and two things follow.
//
//	Nothing may write a temporary directory under the module root. A fixture
//	there appears and vanishes mid-walk, and a leftover is committable by a
//	routine `git add -A` — internal/cli's dry-run fixture was found under
//	internal/cli/ and had to be removed from a worktree before a commit
//	(issue #350).
//
//	A walk must survive one anyway. The rule above constrains code that
//	exists; the next test to write under the module root reintroduces the race,
//	and a walk that fails on another package's cleanup reports the defect in
//	the WRONG package. `internal/policy` failing because `internal/cli` removed
//	a directory is a message that sends someone to the walkers for an
//	afternoon.
//
// Both are checked here rather than in any one of the sweeping packages,
// because the property is about the module and not about any of them.
//
// Tolerance cannot empty a sweep: every walk it covers has a floor of its own —
// "found ZERO writes", "want exactly one", an expected file set, or a list of
// directories the walk must have visited — so a sweep that silently stopped
// reading source fails on that floor rather than passing quietly.

// vanishTolerance is what a walk must contain: the errors.Is check against
// fs.ErrNotExist that turns another package's cleanup into a skipped entry.
const vanishTolerance = "fs.ErrNotExist"

// moduleRoot finds the directory holding go.mod by walking UP, never by
// counting ".." segments — a hardcoded subroot is how a sweep came to walk a
// subdirectory of the module and miss cmd/snug entirely (issue #291).
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's working directory")
		}
		dir = parent
	}
}

// testFiles hands every _test.go file in the module to fn. It is itself a
// module-root walk, so it obeys the rule it checks — and it is its own first
// customer, which is the only way this file is not exempt from its own claim.
func testFiles(t *testing.T, fn func(rel string, f *ast.File, fset *token.FileSet)) int {
	t.Helper()
	root := moduleRoot(t)
	n := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			if errors.Is(rerr, fs.ErrNotExist) {
				return nil
			}
			return rerr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, src, 0)
		if perr != nil {
			return perr
		}
		n++
		fn(filepath.ToSlash(rel), f, fset)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestEverySourceSweepToleratesAVanishedEntry is the ratchet on the walks.
//
// The walks it covers are the ones rooted at THIS MODULE's source, detected by
// the root expression rather than by a list of files: a call to a helper whose
// name ends in "Root", or a filepath.Join beginning with "..". A walk of a
// directory the test created itself is not covered — nothing else writes there,
// and two such walks exist precisely to prove a directory stayed empty.
func TestEverySourceSweepToleratesAVanishedEntry(t *testing.T) {
	type site struct {
		file    string
		line    int
		root    string
		missing []string
	}
	var covered, intolerant []site

	n := testFiles(t, func(rel string, f *ast.File, fset *token.FileSet) {
		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !isSelector(call.Fun, "filepath", "WalkDir") || len(call.Args) != 2 {
				return true
			}
			rootExpr := types.ExprString(call.Args[0])
			if !rootsAtModuleSource(call.Args[0]) {
				return true
			}
			s := site{file: rel, line: fset.Position(call.Pos()).Line, root: rootExpr}
			covered = append(covered, s)
			if missing := untolerated(call.Args[1]); len(missing) > 0 {
				s.missing = missing
				intolerant = append(intolerant, s)
			}
			return true
		})
	})

	// POSITIVE CONTROLS. Without the first, a broken walk reports no test files
	// and passes; without the second, a broken detector reports no sweeps and
	// passes. Both read as proof.
	if n == 0 {
		t.Fatal("no _test.go file was parsed, so this check measures nothing")
	}
	if len(covered) == 0 {
		t.Fatalf("no module-source walk was detected across %d test files, so this check "+
			"measures nothing. Either the detector's notion of a module root is wrong, or "+
			"the sweeps moved.", n)
	}

	for _, s := range intolerant {
		t.Errorf("%s:%d walks the module source (%s) and does not check %v against %s.\n"+
			"       `go test ./...` runs packages concurrently, so this walk reads a tree other\n"+
			"       packages' tests are writing in. An entry that vanished between its parent's\n"+
			"       ReadDir and the callback is not a source file: skip it. Failing instead makes\n"+
			"       THIS package fail for what ANOTHER one did (issue #350). Every error that can\n"+
			"       be a vanished entry needs its own check — the walk's, and every os.ReadFile's.",
			s.file, s.line, s.root, s.missing, vanishTolerance)
	}
}

// TestNoTestWritesATemporaryDirectoryUnderTheModuleRoot is the ratchet on the
// writers, and it is the half that removes the race rather than surviving it.
//
// It keys on the ARGUMENT: os.MkdirTemp's first parameter is the parent, and ""
// means os.TempDir(). A non-empty RELATIVE literal — "." above all — puts the
// directory inside the package being tested, which is inside the module root.
//
// Residual, stated: a parent computed at run time escapes this, because a
// static check cannot read it. internal/cli's testTree is exactly that shape —
// it picks from $SNUG_TEST_FIXTURE_ROOT, $HOME and $XDG_CACHE_HOME — and what
// covers it is the walk tolerance above plus the .gitignore entry, not this.
func TestNoTestWritesATemporaryDirectoryUnderTheModuleRoot(t *testing.T) {
	var bad []string
	seen := 0

	n := testFiles(t, func(rel string, f *ast.File, fset *token.FileSet) {
		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !isSelector(call.Fun, "os", "MkdirTemp") || len(call.Args) == 0 {
				return true
			}
			seen++
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true // a computed parent; see the doc comment
			}
			parent := strings.Trim(lit.Value, `"`+"`")
			if parent == "" || filepath.IsAbs(parent) {
				return true
			}
			bad = append(bad, fmt.Sprintf("%s:%d os.MkdirTemp(%s, …)",
				rel, fset.Position(call.Pos()).Line, lit.Value))
			return true
		})
	})

	if n == 0 {
		t.Fatal("no _test.go file was parsed, so this check measures nothing")
	}
	// POSITIVE CONTROL on the detector: os.MkdirTemp is used in this module, so
	// finding none of it means the selector match is broken.
	if seen == 0 {
		t.Fatal("no os.MkdirTemp call was found in any test, so this check measures nothing")
	}

	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("%s creates a temporary directory inside the checkout.\n"+
			"       It then appears and vanishes under the module root while other packages'\n"+
			"       source sweeps walk it, and a leftover — t.Cleanup does not survive a panic,\n"+
			"       a -timeout kill or an interrupt — is committable by a routine `git add -A`\n"+
			"       (issue #350). Use \"\" for os.TempDir(), or a root outside the checkout.", b)
	}
}

// TestSweepDetectorsSeeEverySpelling is the control on both detectors, on
// source this test authors.
func TestSweepDetectorsSeeEverySpelling(t *testing.T) {
	t.Run("a module-source root is recognised however it is spelled", func(t *testing.T) {
		for _, src := range []string{
			`package p
func f(t *testing.T) { filepath.WalkDir(moduleRoot(t), fn) }`,
			`package p
func f() { root := filepath.Join("..", ".."); filepath.WalkDir(root, fn) }`,
			`package p
func f() { filepath.WalkDir(filepath.Join("..", "..", "internal"), fn) }`,
			`package p
func f(t *testing.T) { r := repoRoot(t); filepath.WalkDir(r, fn) }`,
		} {
			if !hasModuleSourceWalk(t, src) {
				t.Errorf("not recognised as a module-source walk:\n%s", src)
			}
		}
	})

	t.Run("a self-owned root is not", func(t *testing.T) {
		for _, src := range []string{
			`package p
func f(t *testing.T) { filepath.WalkDir(t.TempDir(), fn) }`,
			`package p
func f(dir string) { filepath.WalkDir(dir, fn) }`,
			`package p
func f() { filepath.WalkDir("/proc", fn) }`,
		} {
			if hasModuleSourceWalk(t, src) {
				t.Errorf("wrongly recognised as a module-source walk:\n%s", src)
			}
		}
	})

	t.Run("the tolerance is found in the callback and not merely in the file", func(t *testing.T) {
		with := `package p
func f(t *testing.T) {
	filepath.WalkDir(moduleRoot(t), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		return nil
	})
}`
		without := `package p
// fs.ErrNotExist is mentioned in this comment and nowhere that runs.
func f(t *testing.T) {
	filepath.WalkDir(moduleRoot(t), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return nil
	})
}`
		if !callbackTolerates(t, with) {
			t.Error("the tolerance in the callback was not seen")
		}
		if callbackTolerates(t, without) {
			t.Error("a mention in a COMMENT was accepted as tolerance; the check must read the " +
				"callback's code, or a walk is excused by prose")
		}
	})
}

// ── detectors ───────────────────────────────────────────────────────────────

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

// rootsAtModuleSource reports whether a walk root names this module's own
// source: a helper whose name ends in "Root", or a filepath.Join starting at
// "..". Either way the tree is one other packages write in.
func rootsAtModuleSource(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.CallExpr:
		if id, ok := v.Fun.(*ast.Ident); ok && strings.HasSuffix(id.Name, "Root") {
			return true
		}
		if isSelector(v.Fun, "filepath", "Join") && len(v.Args) > 0 {
			if lit, ok := v.Args[0].(*ast.BasicLit); ok && strings.Trim(lit.Value, `"`) == ".." {
				return true
			}
		}
	case *ast.Ident:
		// `root := <module source>` earlier in the function. Resolved through
		// the identifier's own declaration, which go/ast records.
		if v.Obj == nil {
			return false
		}
		if as, ok := v.Obj.Decl.(*ast.AssignStmt); ok {
			for _, rhs := range as.Rhs {
				if rootsAtModuleSource(rhs) {
					return true
				}
			}
		}
	}
	return false
}

// untolerated names the error variables in a walk callback that can be a
// vanished entry and are NOT checked against fs.ErrNotExist: the walk's own
// third parameter, and the result of any os.ReadFile inside it. Empty means the
// callback is tolerant.
//
// PER VARIABLE, and that is the whole of the check. Two earlier drafts were
// both green against a mutation that removed the tolerance:
//
//   - strings.Contains(types.ExprString(callback), "fs.ErrNotExist") — go/types
//     .ExprString elides a function literal's BODY, so it found nothing and
//     reported every correct walk as intolerant.
//   - "the callback mentions fs.ErrNotExist somewhere" — a callback that
//     tolerates only its os.ReadFile passed while its WALK error still failed
//     the run, which is the actual defect issue #350 describes.
//
// Reading the AST also means a mention in a COMMENT cannot excuse a walk, since
// ast.Inspect does not visit comments.
func untolerated(callback ast.Expr) []string {
	lit, ok := callback.(*ast.FuncLit)
	if !ok {
		// A named function passed as the callback. Not a shape this module
		// uses, and following it would mean resolving across files; report it
		// so it cannot pass silently.
		return []string{"a callback this check cannot read (" + types.ExprString(callback) + ")"}
	}

	// The walk's own error, and every os.ReadFile error inside the callback.
	var want []string
	if ps := lit.Type.Params; ps != nil && len(ps.List) > 0 {
		last := ps.List[len(ps.List)-1]
		for _, n := range last.Names {
			if n.Name != "_" {
				want = append(want, n.Name)
			}
		}
	}
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok || !isSelector(call.Fun, "os", "ReadFile") || len(as.Lhs) != 2 {
			return true
		}
		if id, ok := as.Lhs[1].(*ast.Ident); ok && id.Name != "_" {
			want = append(want, id.Name)
		}
		return true
	})

	checked := map[string]bool{}
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isSelector(call.Fun, "errors", "Is") || len(call.Args) != 2 {
			return true
		}
		if !isSelector(call.Args[1], "fs", "ErrNotExist") {
			return true
		}
		if id, ok := call.Args[0].(*ast.Ident); ok {
			checked[id.Name] = true
		}
		return true
	})

	var missing []string
	for _, v := range want {
		if !checked[v] {
			missing = append(missing, v)
		}
	}
	sort.Strings(missing)
	return missing
}

func hasModuleSourceWalk(t *testing.T, src string) bool {
	t.Helper()
	found := false
	forEachWalk(t, src, func(call *ast.CallExpr) {
		if rootsAtModuleSource(call.Args[0]) {
			found = true
		}
	})
	return found
}

func callbackTolerates(t *testing.T, src string) bool {
	t.Helper()
	ok := false
	forEachWalk(t, src, func(call *ast.CallExpr) {
		if len(untolerated(call.Args[1])) == 0 {
			ok = true
		}
	})
	return ok
}

func forEachWalk(t *testing.T, src string, fn func(*ast.CallExpr)) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("the fixture does not parse, so this control measures nothing: %v", err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok && isSelector(call.Fun, "filepath", "WalkDir") && len(call.Args) == 2 {
			fn(call)
		}
		return true
	})
}
