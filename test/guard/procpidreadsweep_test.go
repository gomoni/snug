package guard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"testing"
)

// ── /proc/<pid>/{cmdline,environ,stat} reads must wait for the kernel ───────
//
// The kernel populates mm->arg_start only after close-on-exec fires, later in
// the exec path than os/exec.Cmd.Start returns — so /proc/<pid>/cmdline reads
// back ZERO bytes for a real window right after Start: 2965 of 3000 reads
// taken immediately after Start were empty (issue #317). An assertion of the
// form "the cmdline does NOT contain X", read in that window, passes for the
// wrong reason: there was nothing to contain X in the first place.
//
// waitCmdline (internal/engine/engine_test.go) is the fix — poll until the
// file is non-empty, THEN look at it — and it is applied in internal/engine
// ONLY. This sweep is the ratchet on that package's own tests: every raw
// read of /proc/<pid>/{cmdline,environ,stat} there must be either
// waitCmdline's own read or occur in a function that has already called
// waitCmdline.
//
// SCOPE, decided and stated here rather than left implicit: this sweep does
// NOT cover the seven test/integration and one internal/cli sites #317 also
// measured (enginec3_test.go, orphan_test.go, stage_test.go,
// containerengine_test.go, orphansweep_test.go x2). The reason is STRUCTURAL,
// not a claim about timing: each of those reads sits inside a MATCHER over a
// process tree — a findDescendant predicate, or a loop testing each pid — so
// an empty cmdline makes the predicate return false and the search poll
// again. Empty is "not this pid yet", never "asserted and passed". Verified
// at enginec3_test.go's findDescendant predicate; the vacuous-pass shape this
// sweep closes needs the read to feed an ASSERTION, which is the
// internal/engine pattern. A host-wide /proc sweep is the different question
// #317 itself leaves open.
const waitHelperName = "waitCmdline"

// procPidPathKind reports which of cmdline/environ/stat a /proc/<pid>/…
// argument to os.ReadFile names, and false for anything else — a literal
// "/proc/self/…" included, since self is always populated and is not the
// race this sweep is about.
//
// Two shapes are read: a string built by "+"-concatenation around a
// non-literal segment ("/proc/" + strconv.Itoa(pid) + "/cmdline"), and
// fmt.Sprintf with a %d/%s/%v verb in the pid's place. Both are reduced to
// the same shape check: literal fragments joined with a NUL placeholder for
// every non-literal piece, matched against ^/proc/\x00+/(cmdline|environ
// |stat)$ — a fully literal path (no placeholder at all, "/proc/self/…"
// among them) does not match, because there is no pid variable to race.
func procPidPathKind(arg ast.Expr) (string, bool) {
	if call, ok := arg.(*ast.CallExpr); ok && isSelector(call.Fun, "fmt", "Sprintf") && len(call.Args) >= 1 {
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return "", false
		}
		s := unquoteLit(lit)
		s = strings.NewReplacer("%d", "\x00", "%s", "\x00", "%v", "\x00").Replace(s)
		return matchProcShape(s)
	}

	var sb strings.Builder
	for _, leaf := range flattenAdd(arg) {
		if lit, ok := leaf.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			sb.WriteString(unquoteLit(lit))
		} else {
			sb.WriteByte(0)
		}
	}
	return matchProcShape(sb.String())
}

// procShapeRE's \x00 is a literal NUL byte in the pattern (Go interprets it
// in the source string before regexp ever sees it) standing in for any
// non-literal path segment — never a byte a real /proc path can contain.
var procShapeRE = regexp.MustCompile("^/proc/\x00+/(cmdline|environ|stat)$")

func matchProcShape(shape string) (string, bool) {
	m := procShapeRE.FindStringSubmatch(shape)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// flattenAdd walks a chain of "+"-concatenated expressions left to right and
// returns its leaves in source order, so ("/proc/" + a + "/cmdline") becomes
// three leaves rather than one opaque BinaryExpr.
func flattenAdd(e ast.Expr) []ast.Expr {
	if b, ok := e.(*ast.BinaryExpr); ok && b.Op == token.ADD {
		return append(flattenAdd(b.X), flattenAdd(b.Y)...)
	}
	return []ast.Expr{e}
}

func unquoteLit(lit *ast.BasicLit) string {
	return strings.Trim(lit.Value, "`\"")
}

// TestEngineProcPidReadsWaitForAPopulatedCmdline is the sweep. It fails if
// any test file under internal/engine reads /proc/<pid>/{cmdline,environ,
// stat} directly without a prior call to waitCmdline in the same function —
// the shape that let #317's zero-bytes window pass a negative assertion
// vacuously.
func TestEngineProcPidReadsWaitForAPopulatedCmdline(t *testing.T) {
	type site struct {
		file string
		line int
		kind string
	}
	var checked, bad []site

	n := testFiles(t, func(rel string, f *ast.File, fset *token.FileSet) {
		if !strings.HasPrefix(rel, "internal/engine/") {
			return
		}
		ast.Inspect(f, func(node ast.Node) bool {
			fn, ok := node.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			waited := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == waitHelperName {
					waited = true
					return true
				}
				if !isSelector(call.Fun, "os", "ReadFile") || len(call.Args) != 1 {
					return true
				}
				kind, ok := procPidPathKind(call.Args[0])
				if !ok {
					return true
				}
				s := site{file: rel, line: fset.Position(call.Pos()).Line, kind: kind}
				checked = append(checked, s)
				if fn.Name.Name == waitHelperName {
					return true // this IS the wait-for-populated helper's own read
				}
				if !waited {
					bad = append(bad, s)
				}
				return true
			})
			// A FuncDecl's own body was fully walked above; do not also let
			// the outer Inspect descend into it again as a plain node.
			return false
		})
	})

	if n == 0 {
		t.Fatal("no _test.go file was parsed, so this check measures nothing")
	}
	// POSITIVE CONTROL: internal/engine's tests are known (waitCmdline itself,
	// and marker) to read /proc/<pid>/cmdline. Finding none means the shape
	// detector broke, not that the package stopped reading /proc.
	if len(checked) == 0 {
		t.Fatal("no /proc/<pid>/{cmdline,environ,stat} read was found under internal/engine, so " +
			"this check measures nothing — either procPidPathKind's notion of the shape is wrong, " +
			"or the reads moved")
	}

	for _, s := range bad {
		t.Errorf("%s:%d reads /proc/<pid>/%s directly, with no call to %s earlier in the same "+
			"function. The kernel does not populate this file until after close-on-exec, so a read "+
			"taken right after Start can come back empty and any \"does not contain\" assertion over "+
			"it would pass vacuously (issue #317).", s.file, s.line, s.kind, waitHelperName)
	}
}

// TestProcPidPathKindSeesEverySpelling is the control on the shape detector.
func TestProcPidPathKindSeesEverySpelling(t *testing.T) {
	t.Run("recognised", func(t *testing.T) {
		for _, tc := range []struct{ src, kind string }{
			{`"/proc/" + strconv.Itoa(pid) + "/cmdline"`, "cmdline"},
			{`"/proc/" + strconv.Itoa(pid) + "/environ"`, "environ"},
			{`"/proc/" + strconv.Itoa(pid) + "/stat"`, "stat"},
			{`fmt.Sprintf("/proc/%d/cmdline", pid)`, "cmdline"},
			{`"/proc/" + ent.Name() + "/cmdline"`, "cmdline"},
		} {
			kind, ok := procPidPathKind(mustParseExpr(t, tc.src))
			if !ok || kind != tc.kind {
				t.Errorf("%s: got (%q, %v), want (%q, true)", tc.src, kind, ok, tc.kind)
			}
		}
	})

	t.Run("not recognised", func(t *testing.T) {
		for _, src := range []string{
			`"/proc/self/cmdline"`,                   // populated at every read; not the race
			`"/proc/" + strconv.Itoa(pid) + "/comm"`, // not one of the three files
			`fmt.Sprintf("/proc/%d/comm", pid)`,
			`path`,
		} {
			if kind, ok := procPidPathKind(mustParseExpr(t, src)); ok {
				t.Errorf("%s: wrongly recognised as %q", src, kind)
			}
		}
	})
}

func mustParseExpr(t *testing.T, src string) ast.Expr {
	t.Helper()
	e, err := parser.ParseExpr(src)
	if err != nil {
		t.Fatalf("fixture %q does not parse, so this control measures nothing: %v", src, err)
	}
	return e
}
