package guard

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// ── host account data only through internal/getent ───────────────────────────
//
// internal/getent is snug's one entrypoint for host account data, so snug
// answers "who is this uid" the way glibc NSS does — files, sssd, LDAP,
// systemd userdb — and never two ways at once. cgo-free os/user parses
// /etc/passwd and /etc/group as text: on an sssd host it knows no name for the
// uid while getent does, and a second source is how one command names an
// account the other cannot find.
//
// Two shapes are swept in non-test code: an import of "os/user", and a
// "getent" literal handed to exec.Command, exec.CommandContext or
// exec.LookPath anywhere but internal/getent. Test files may still call
// user.Current() for a fixture uid; they are not snug.
func TestHostAccountDataOnlyThroughGetent(t *testing.T) {
	var bad []string
	n := nonTestGoFiles(t, func(rel string, f *ast.File, fset *token.FileSet) {
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "os/user" {
				bad = append(bad, rel+": imports os/user; use internal/getent")
			}
		}
		if strings.HasPrefix(rel, "internal/getent/") {
			return
		}
		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if !isSelector(call.Fun, "exec", "Command") && !isSelector(call.Fun, "exec", "CommandContext") &&
				!isSelector(call.Fun, "exec", "LookPath") {
				return true
			}
			for _, arg := range call.Args {
				lit, ok := arg.(*ast.BasicLit)
				if ok && lit.Kind == token.STRING && unquoteLit(lit) == "getent" {
					bad = append(bad, fset.Position(call.Pos()).String()+": runs getent outside internal/getent")
				}
			}
			return true
		})
	})
	if n == 0 {
		t.Fatal("swept no files; the walk is broken, not the tree clean")
	}
	for _, b := range bad {
		t.Error(b)
	}
}
