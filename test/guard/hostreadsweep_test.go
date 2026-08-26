package guard

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gomoni/snug/test/modroot"
)

// ── raw host reads outside internal/hostread ─────────────────────────────────
//
// internal/hostread is snug's one discipline for reading a file it does not
// own: bounded, non-blocking, refusing anything that is not a regular file. A
// plain os.ReadFile/os.Open/os.OpenFile trusts the node to be an ordinary
// file that returns promptly — `rm key.pub && mkfifo key.pub` (issue #337)
// turns it into an open(2) that never returns.
//
// /proc and /dev are the exempt class, not a convenience: they are kernel
// pseudo-files, not nodes an attacker who controls a host path can
// substitute a FIFO or a symlink to /dev/zero for. A call site names one by
// its ARGUMENT — a literal, a "+"-concatenation or fmt.Sprintf built around
// one, or os.DevNull — and the sweep reads that argument, never a comment
// claiming it.
//
// Anything else needs a justification: a comment containing the literal
// marker text hostreadExemptMarker, on the flagged line or the one directly
// above it. A mention anywhere else in the file does not count — the mistake
// untolerated's own doc comment (sourcesweep_test.go) records for the same
// shape of check: "a mention in a COMMENT cannot excuse a walk" unless the
// AST places that comment where the check looks.
const hostreadExemptMarker = "HOSTREAD-EXEMPT"

// nonTestGoFiles hands every non-test .go file in the module to fn, skipping
// internal/hostread (the discipline itself) and test/integration/testdata
// (standalone probe programs, not snug — they are exec'd as separate
// binaries by the integration suite, not part of this module's own reads).
// Comments are retained (parser.ParseComments) because hasExemptMarker below
// needs them; testFiles' walk (sourcesweep_test.go) does not carry them.
func nonTestGoFiles(t *testing.T, fn func(rel string, f *ast.File, fset *token.FileSet)) int {
	t.Helper()
	root, err := modroot.Find()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "internal/hostread/") || strings.HasPrefix(rel, "test/integration/testdata/") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			if errors.Is(rerr, fs.ErrNotExist) {
				return nil
			}
			return rerr
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, src, parser.ParseComments)
		if perr != nil {
			return perr
		}
		n++
		fn(rel, f, fset)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// namesProcOrDev reports whether arg is a literal, a "+"-concatenation or an
// fmt.Sprintf format string that names a path under /proc or /dev, or the
// os.DevNull constant. Anything else — including a bare variable, even one
// that always happens to hold a /proc or /dev path at run time — is not
// statically a /proc or /dev literal and needs the justification arm
// instead: this check reads the argument, not the data-flow into it.
func namesProcOrDev(arg ast.Expr) bool {
	if isSelector(arg, "os", "DevNull") {
		return true
	}
	if call, ok := arg.(*ast.CallExpr); ok && isSelector(call.Fun, "fmt", "Sprintf") && len(call.Args) >= 1 {
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return false
		}
		s := unquoteLit(lit)
		return strings.HasPrefix(s, "/proc") || strings.HasPrefix(s, "/dev")
	}
	leaves := flattenAdd(arg)
	lit, ok := leaves[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	s := unquoteLit(lit)
	return strings.HasPrefix(s, "/proc") || strings.HasPrefix(s, "/dev")
}

// hasExemptMarker reports whether some comment group in f ends on line or on
// line-1 and contains hostreadExemptMarker — read from the AST's own comment
// list, positioned by the file set, never by scanning the raw source text.
func hasExemptMarker(f *ast.File, fset *token.FileSet, line int) bool {
	for _, cg := range f.Comments {
		end := fset.Position(cg.End()).Line
		if (end == line || end == line-1) && strings.Contains(cg.Text(), hostreadExemptMarker) {
			return true
		}
	}
	return false
}

// TestRawHostReadsOutsideHostreadNameProcDevOrAreJustified is the sweep. Every
// os.ReadFile/os.Open/os.OpenFile call site outside internal/hostread and
// outside test/integration/testdata must either name a /proc or /dev path in
// its own argument, or carry hostreadExemptMarker.
func TestRawHostReadsOutsideHostreadNameProcDevOrAreJustified(t *testing.T) {
	type site struct {
		file string
		line int
		call string
	}
	var checked, bad []site

	n := nonTestGoFiles(t, func(rel string, f *ast.File, fset *token.FileSet) {
		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			var fname string
			switch {
			case isSelector(call.Fun, "os", "ReadFile"):
				fname = "os.ReadFile"
			case isSelector(call.Fun, "os", "Open"):
				fname = "os.Open"
			case isSelector(call.Fun, "os", "OpenFile"):
				fname = "os.OpenFile"
			default:
				return true
			}
			if len(call.Args) == 0 {
				return true
			}
			line := fset.Position(call.Pos()).Line
			s := site{file: rel, line: line, call: fname}
			checked = append(checked, s)
			if namesProcOrDev(call.Args[0]) {
				return true
			}
			if hasExemptMarker(f, fset, line) {
				return true
			}
			bad = append(bad, s)
			return true
		})
	})

	if n == 0 {
		t.Fatal("no non-test .go file was parsed, so this check measures nothing")
	}
	// POSITIVE CONTROL: internal/stage and internal/cli are known to read
	// /proc directly (they built and drive the sandbox). Finding none means
	// the call-site detector broke, not that this module stopped reading
	// files.
	if len(checked) == 0 {
		t.Fatal("no os.ReadFile/os.Open/os.OpenFile call was found outside internal/hostread, so " +
			"this check measures nothing")
	}

	sort.Slice(bad, func(i, j int) bool {
		if bad[i].file != bad[j].file {
			return bad[i].file < bad[j].file
		}
		return bad[i].line < bad[j].line
	})
	for _, s := range bad {
		t.Errorf("%s:%d calls %s outside internal/hostread on an argument that does not name a "+
			"/proc or /dev path, and carries no %q comment. Either route it through "+
			"internal/hostread (issue #337: a FIFO at that path turns this into an open(2) that "+
			"never returns), or justify it with a comment carrying %q on this line or the one "+
			"above.", s.file, s.line, s.call, hostreadExemptMarker, hostreadExemptMarker)
	}
}

// TestNamesProcOrDevSeesEverySpelling is the control on the shape detector.
func TestNamesProcOrDevSeesEverySpelling(t *testing.T) {
	t.Run("recognised", func(t *testing.T) {
		for _, src := range []string{
			`"/proc/self/status"`,
			`"/dev/net/tun"`,
			`os.DevNull`,
			`"/proc/" + strconv.Itoa(pid) + "/cmdline"`,
			`fmt.Sprintf("/proc/%d/stat", pid)`,
			`fmt.Sprintf("/dev/pts/%d", n)`,
		} {
			if !namesProcOrDev(mustParseExpr(t, src)) {
				t.Errorf("%s: not recognised as a /proc or /dev path", src)
			}
		}
	})

	t.Run("not recognised", func(t *testing.T) {
		for _, src := range []string{
			`"/etc/resolv.conf"`,
			`path`,
			`resolved`,
			`ptsPath(n)`,
		} {
			if namesProcOrDev(mustParseExpr(t, src)) {
				t.Errorf("%s: wrongly recognised as a /proc or /dev path", src)
			}
		}
	})
}
