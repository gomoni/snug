package guard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// ── the retired x-access-token fallback must not come back (#454) ───────────
//
// stageGhConfig (internal/cli/identity.go) used to fall back to the literal
// user "x-access-token" whenever a profile named gh.host with no gh.user,
// staging the token of whatever account the host's gh happened to be logged
// into under a name the profile never wrote. #454 deletes the fallback and
// Resolve now refuses identity.gh.host with no identity.gh.user outright
// (refuseUnpinnedGhAccount, internal/policy/resolve.go), so the string has no
// legitimate reason to appear as a STRING LITERAL in non-test Go again.
//
// The phrase stays legal in PROSE: the comment explaining why the fallback is
// gone (internal/cli/identity.go, internal/policy/resolve.go) and the
// red-team regression recording what it let happen (test/integration's own
// identity test, a _test.go file nonTestGoFiles already excludes). ast.Inspect
// does not re-walk a *ast.File's Comments — go/ast's own Walk skips them,
// since they were already visited through the Doc/Comment fields of the
// declarations that carry them — so a scan restricted to *ast.BasicLit STRING
// nodes sees exactly the code, never the prose describing the code.
const retiredGhFallback = "x-access-token"

func TestNoProductionGoReferencesXAccessToken(t *testing.T) {
	n := nonTestGoFiles(t, func(rel string, f *ast.File, fset *token.FileSet) {
		ast.Inspect(f, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if strings.Contains(unquoteLit(lit), retiredGhFallback) {
				t.Errorf("%s:%d: string literal %s reintroduces the retired gh fallback %q; "+
					"stageGhConfig must stage only the account identity.gh.user names",
					rel, fset.Position(lit.Pos()).Line, lit.Value, retiredGhFallback)
			}
			return true
		})
	})
	if n == 0 {
		t.Fatal("nonTestGoFiles walked zero files; the sweep below never ran against anything")
	}
}

// TestNoProductionGoReferencesXAccessTokenDetectsAPlantedLiteral is the
// positive control: it proves the matcher above CAN fail, against a synthetic
// file that plants the retired literal, rather than relying on the sweep
// having never fired against today's tree as evidence it works.
func TestNoProductionGoReferencesXAccessTokenDetectsAPlantedLiteral(t *testing.T) {
	const src = `package fixture

const guest = "x-access-token"
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(f, func(node ast.Node) bool {
		lit, ok := node.(*ast.BasicLit)
		if ok && lit.Kind == token.STRING && strings.Contains(unquoteLit(lit), retiredGhFallback) {
			found = true
		}
		return true
	})
	if !found {
		t.Fatal("the matcher used by TestNoProductionGoReferencesXAccessToken did not flag a " +
			"planted literal; the sweep above could not have failed on a real regression either")
	}
}
