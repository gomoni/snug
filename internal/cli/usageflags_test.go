package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestUsageListsEveryFlagParseArgsAccepts reads parseArgs's source for every
// flag spelling it compares an argument with, and requires each in writeUsage.
// TestUsageListsEveryReservedWord holds the subcommands; this holds the flags,
// which have no table to range over, so the switch itself is the list. A flag
// parseArgs accepts and the help never names is a flag nobody can find
// without reading the source.
func TestUsageListsEveryFlagParseArgsAccepts(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "parseArgs" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("main.go has no parseArgs: this test reads its switch for the flag spellings")
	}

	var flags []string
	ast.Inspect(body, func(n ast.Node) bool {
		var lit *ast.BasicLit
		switch e := n.(type) {
		case *ast.BinaryExpr:
			if e.Op == token.EQL {
				lit, _ = e.Y.(*ast.BasicLit)
			}
		case *ast.CallExpr:
			if sel, ok := e.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "HasPrefix" && len(e.Args) == 2 {
				lit, _ = e.Args[1].(*ast.BasicLit)
			}
		}
		if lit == nil || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		// "-" is the unknown-flag catch-all, not a flag.
		if err != nil || !strings.HasPrefix(s, "-") || s == "-" {
			return true
		}
		flags = append(flags, strings.TrimSuffix(s, "="))
		return true
	})
	slices.Sort(flags)
	flags = slices.Compact(flags)
	if len(flags) < 10 {
		t.Fatalf("found only %d flag spellings in parseArgs (%v): the source scan no longer matches how it compares arguments",
			len(flags), flags)
	}

	var help strings.Builder
	writeUsage(&help)
	for _, f := range flags {
		// A whole word, so "-p" is not found inside "--profile".
		named := regexp.MustCompile(`(^|[\s\[])` + regexp.QuoteMeta(f) + `($|[\s,\]])`)
		if !named.MatchString(help.String()) {
			t.Errorf("parseArgs accepts %q and usage() never names it: `snug help` omits a flag", f)
		}
	}
}
