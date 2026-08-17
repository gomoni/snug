package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// ── the drop-reason set, checked the same way ownedenv_test.go checks
// policy.SnugOwnedEnv ────────────────────────────────────────────────────────
//
// describeEnvironment (dryrun.go) renders p.Env[name].Dropped grouped by
// reason, over a FIXED slice — never map order, so the rendering does not vary
// run to run — with a comment saying "EVERY reason must be listed here. ...
// Adding a reason to policy.EnvDropReason means adding it here."
//
// A comment saying that is not a guard, it is a request. This is the same
// copy-with-no-link-back shape CLAUDE.md's environment-handling note and this
// very session have hit more than once: DropReplaceable was ADDED to
// policy.EnvDropReason (env.go) for exactly the live hole this review round
// closed, and the fixed slice in dryrun.go had to be updated by hand to keep
// listing it. Nothing except a human remembering the note enforces that a
// FIFTH reason gets the same treatment. A dropped element whose reason is
// missing from the slice is not merely mis-labelled — describeEnvironment's
// loop `if len(vals) == 0 { continue }` for a reason with no matches, so an
// unlisted reason's elements are simply never grouped into ANY line and
// vanish from the screen entirely: the exact "1 of 3 kept" failure §2.8 exists
// to prevent, reintroduced one enum value at a time.
//
// go/parser is stdlib, so this costs no dependency and internal/policy stays
// pure — the same reasoning ownedenv_test.go gives for using it.

func TestDryRunListsEveryEnvDropReason(t *testing.T) {
	declared := collectEnvDropReasonConsts(t, filepath.Join("..", "..", "internal", "policy", "env.go"))
	rendered := collectDryRunDropReasonSlice(t, "dryrun.go")

	declaredSet := map[string]bool{}
	for _, n := range declared {
		declaredSet[n] = true
	}
	renderedSet := map[string]bool{}
	for _, n := range rendered {
		renderedSet[n] = true
	}

	for n := range declaredSet {
		if !renderedSet[n] {
			t.Errorf("policy.EnvDropReason declares %s, but dryrun.go's describeEnvironment does "+
				"not list it in the fixed slice it iterates — a Dropped element with this reason "+
				"is grouped under NO line and never appears on --dry-run's screen at all", n)
		}
	}
	for n := range renderedSet {
		if !declaredSet[n] {
			t.Errorf("dryrun.go lists %s in the drop-reason slice, but policy.EnvDropReason does "+
				"not declare it any more — a stale entry that can never match anything", n)
		}
	}

	// POSITIVE CONTROL: a broken parse that silently found nothing on both
	// sides would pass the set-equality check above vacuously. Name the
	// reason this very review round added, so a parse that stopped seeing
	// EITHER file fails loudly instead of green.
	if !declaredSet["DropReplaceable"] {
		t.Fatal("the AST pass over env.go did not see DropReplaceable; it is parsing the wrong " +
			"file or matching the wrong shape of const block")
	}
	if !renderedSet["DropReplaceable"] {
		t.Fatal("the AST pass over dryrun.go did not see DropReplaceable; it is parsing the wrong " +
			"file or matching the wrong shape of composite literal")
	}
}

// collectEnvDropReasonConsts reads every constant name declared in the SAME
// const(...) block as `DropNoGrant EnvDropReason = iota` in env.go — the
// canonical source of what reasons exist. It does not merely grep for the
// TYPE name, because EnvVerb (the same file) is also a uint8 iota block and a
// looser match would silently start comparing the wrong enum.
func collectEnvDropReasonConsts(t *testing.T, path string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	var names []string
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		// Is this the EnvDropReason block? Only the FIRST spec in the block
		// carries an explicit Type (`= iota`); every following spec in an iota
		// group repeats the same type implicitly. So the block qualifies if any
		// one spec in it names the type explicitly.
		isDropReasonBlock := false
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || vs.Type == nil {
				continue
			}
			id, ok := vs.Type.(*ast.Ident)
			if ok && id.Name == "EnvDropReason" {
				isDropReasonBlock = true
			}
		}
		if !isDropReasonBlock {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, n := range vs.Names {
				if n.Name != "_" {
					names = append(names, n.Name)
				}
			}
		}
	}
	return names
}

// collectDryRunDropReasonSlice reads the identifiers inside the
// `[]policy.EnvDropReason{...}` composite literal describeEnvironment ranges
// over.
func collectDryRunDropReasonSlice(t *testing.T, path string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	var names []string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		arr, ok := lit.Type.(*ast.ArrayType)
		if !ok {
			return true
		}
		sel, ok := arr.Elt.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "EnvDropReason" {
			return true
		}
		xIdent, ok := sel.X.(*ast.Ident)
		if !ok || xIdent.Name != "policy" {
			return true
		}
		for _, elt := range lit.Elts {
			es, ok := elt.(*ast.SelectorExpr)
			if !ok {
				t.Fatalf("%s: []policy.EnvDropReason{...} element is not a policy.Xxx selector "+
					"(%T) — write the reason as a literal so this AST pass can check it", path, elt)
			}
			names = append(names, es.Sel.Name)
		}
		return true
	})
	if len(names) == 0 {
		t.Fatalf("%s: no []policy.EnvDropReason{...} composite literal found — the AST pass is "+
			"looking at the wrong shape, or describeEnvironment stopped iterating a fixed slice", path)
	}
	return names
}
