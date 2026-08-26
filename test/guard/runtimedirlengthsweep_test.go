package guard

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// ── no test/integration XDG_RUNTIME_DIR is built from t.TempDir() ───────────
//
// AF_UNIX's sun_path is 108 bytes including the NUL, so 107 is the usable
// limit. The container proxy's socket lands at
// "<XDG_RUNTIME_DIR>/snug/run-<pid>/podman.sock" — 22 bytes plus the pid's
// own digits — so the length of $XDG_RUNTIME_DIR itself is the whole of what
// a test controls. t.TempDir() names its directory after the calling test,
// truncated to 64 chars, on top of a 1-10 digit os.MkdirTemp random suffix:
//
//	total ≈ 5 + min(len(name),64) + R + 1 + nDigits + 22 + pidDigits
//
// At R=10, a 4-digit per-call index and a 7-digit pid, this reaches 110 on
// this suite's longest test name (65 characters,
// TestEngineBinaryNamedThroughASymlinkInsideAWritableGrantIsRefused) — over
// the 107-byte limit.
//
// attachEnv (attach_test.go) is now the suite default: every $XDG_RUNTIME_DIR
// it hands out is rooted at os.MkdirTemp("", …) instead, which is 5 bytes plus
// a fixed prefix plus the same 1-10 digit suffix — test-name-agnostic, so no
// test can grow into this failure by being renamed. This sweep is the ratchet
// that keeps the property true: with attachEnv fixed, "no XDG_RUNTIME_DIR
// built from t.TempDir()" is a purely static, AST-checkable claim, and a rule
// enforced by an exception list is what rots (attachEnv's own doc comment) —
// there is deliberately no allow-list of "test names known to be short
// enough" here.

// isTempDirCall reports whether e is a call to some receiver's TempDir method
// — <anything>.TempDir(), not just t.TempDir(), so a subtest's own *testing.T
// still matches under a different local name.
func isTempDirCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == "TempDir"
}

// resolvesToTempDir reports whether e is a t.TempDir() call, or an identifier
// whose declaration is (through any number of hops) one — "dir := t.TempDir();
// … + dir" is exactly as much a violation as the inline form.
func resolvesToTempDir(e ast.Expr) bool {
	if isTempDirCall(e) {
		return true
	}
	id, ok := e.(*ast.Ident)
	if !ok || id.Obj == nil {
		return false
	}
	as, ok := id.Obj.Decl.(*ast.AssignStmt)
	if !ok {
		return false
	}
	for _, rhs := range as.Rhs {
		if resolvesToTempDir(rhs) {
			return true
		}
	}
	return false
}

// runtimeDirEnvShape reports whether e is built with a literal
// "XDG_RUNTIME_DIR=" prefix — a "+"-concatenation or an fmt.Sprintf format
// string — and, if so, whether any of the remaining pieces resolves to
// t.TempDir(). The first return is the walk's own positive control (an
// "XDG_RUNTIME_DIR=" entry was actually found to check); the second is the
// violation.
func runtimeDirEnvShape(e ast.Expr) (isRuntimeDirEntry, fromTempDir bool) {
	if call, ok := e.(*ast.CallExpr); ok && isSelector(call.Fun, "fmt", "Sprintf") && len(call.Args) >= 1 {
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || !strings.HasPrefix(unquoteLit(lit), "XDG_RUNTIME_DIR=") {
			return false, false
		}
		for _, a := range call.Args[1:] {
			if resolvesToTempDir(a) {
				return true, true
			}
		}
		return true, false
	}

	leaves := flattenAdd(e)
	first, ok := leaves[0].(*ast.BasicLit)
	if !ok || first.Kind != token.STRING || !strings.HasPrefix(unquoteLit(first), "XDG_RUNTIME_DIR=") {
		return false, false
	}
	for _, leaf := range leaves[1:] {
		if resolvesToTempDir(leaf) {
			return true, true
		}
	}
	return true, false
}

// TestIntegrationXDGRuntimeDirIsNeverBuiltFromTempDir is the sweep, over
// test/integration only — attachEnv's own package.
func TestIntegrationXDGRuntimeDirIsNeverBuiltFromTempDir(t *testing.T) {
	type site struct {
		file string
		line int
	}
	var checked, bad []site

	n := testFiles(t, func(rel string, f *ast.File, fset *token.FileSet) {
		if !strings.HasPrefix(rel, "test/integration/") {
			return
		}
		ast.Inspect(f, func(node ast.Node) bool {
			e, ok := node.(ast.Expr)
			if !ok {
				return true
			}
			isEntry, fromTempDir := runtimeDirEnvShape(e)
			if !isEntry {
				return true
			}
			s := site{file: rel, line: fset.Position(e.Pos()).Line}
			checked = append(checked, s)
			if fromTempDir {
				bad = append(bad, s)
			}
			// Matched at the OUTERMOST node of this concatenation/Sprintf;
			// its own operands would otherwise be visited again as their own
			// (partial, and therefore wrong) chains.
			return false
		})
	})

	if n == 0 {
		t.Fatal("no _test.go file was parsed, so this check measures nothing")
	}
	// POSITIVE CONTROL: test/integration is known to build "XDG_RUNTIME_DIR="
	// entries (attachEnv, containerEngineEnv, shortRuntimeDir and their
	// callers). Finding none means the shape detector broke, not that the
	// suite stopped setting the variable.
	if len(checked) == 0 {
		t.Fatal("no \"XDG_RUNTIME_DIR=\" environment entry was found under test/integration, so " +
			"this check measures nothing")
	}

	for _, s := range bad {
		t.Errorf("%s:%d builds $XDG_RUNTIME_DIR from t.TempDir(). t.TempDir() names its directory "+
			"after the calling test (truncated to 64 chars) — on this suite's longer test names "+
			"that pushes the container proxy's socket path past AF_UNIX's 108-byte sun_path (see "+
			"this file's own doc comment for the measurement). Use attachEnv, containerEngineEnv or "+
			"shortRuntimeDir instead.", s.file, s.line)
	}
}

// TestRuntimeDirEnvShapeSeesEverySpelling is the control on the shape
// detector: it must be ABLE to flag a violation, or the sweep above passing
// proves nothing.
func TestRuntimeDirEnvShapeSeesEverySpelling(t *testing.T) {
	t.Run("flagged", func(t *testing.T) {
		for _, src := range []string{
			`"XDG_RUNTIME_DIR=" + t.TempDir()`,
			`fmt.Sprintf("XDG_RUNTIME_DIR=%s", t.TempDir())`,
		} {
			e := mustParseExpr(t, src)
			isEntry, fromTempDir := runtimeDirEnvShape(e)
			if !isEntry || !fromTempDir {
				t.Errorf("%s: got (isEntry=%v, fromTempDir=%v), want (true, true)", src, isEntry, fromTempDir)
			}
		}
	})

	t.Run("not flagged", func(t *testing.T) {
		for _, src := range []string{
			`"XDG_RUNTIME_DIR=" + shortRuntimeDir(t)`,
			`"HOME=" + t.TempDir()`,
			`"XDG_RUNTIME_DIR=/fixed/path"`,
		} {
			e := mustParseExpr(t, src)
			if _, fromTempDir := runtimeDirEnvShape(e); fromTempDir {
				t.Errorf("%s: wrongly flagged as built from t.TempDir()", src)
			}
		}
	})
}
