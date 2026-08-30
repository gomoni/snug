package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestRunReadsNoDryRunFlagDirectly is the guard on config.startsNothing, and
// it exists because the failure it prevents is invisible one line at a time.
//
// run has eight places that must not touch the host when the human only asked
// for a screen: the target lock, the host tmp directory, the git probe, the
// runtime directory, the identity proxy, the container engine, the http door
// sockets and the resolver warning. Every one of them used to read cfg.dryRun.
// Adding --explain (issue #541) meant every one of them had to learn about a
// SECOND flag, and a guard that learns about one flag and not the other is not
// a cosmetic bug — it is a screen whose first line says "nothing was started"
// while a socket it opened sits on the host. Issue #21 is what that looked
// like the first time, for --dry-run alone.
//
// So the rule is structural rather than reviewed: inside run, the question is
// spelled cfg.startsNothing() and never cfg.dryRun. A ninth guard written
// tomorrow either uses the predicate or fails here.
//
// OUTSIDE run, cfg.dryRun is still the right question and this sweep does not
// touch it — parseArgs sets it, checkFlagCombination refuses pairs of it, and
// refuseVerbatim asks whether THIS run owes a JSON document. Those are about
// the flag, not about whether the host gets touched.
//
// cfg.explain IS allowed inside run, and the asymmetry is deliberate rather
// than an exemption granted to make the sweep pass. The hazard is a guard
// written as `!cfg.dryRun`, because that is the spelling every one of the
// eight had before --explain existed and the spelling a reader copies from the
// line above. There is no matching hazard for cfg.explain: run consults it in
// exactly one place, to choose which of the two renderers to call, which is a
// question about the flag and not about the host.
func TestRunReadsNoDryRunFlagDirectly(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing main.go: %v", err)
	}

	var runFn *ast.FuncDecl
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name.Name == "run" {
			runFn = fn
		}
	}
	if runFn == nil {
		t.Fatal("no func run in main.go — this test has lost its subject and would " +
			"otherwise pass by finding nothing")
	}

	// POSITIVE CONTROL: the predicate is actually used in here. Without this,
	// a run that stopped consulting either flag — or a parse that gave back an
	// empty body — would pass by finding nothing to complain about.
	uses := 0
	ast.Inspect(runFn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != "cfg" {
			return true
		}
		switch sel.Sel.Name {
		case "dryRun":
			t.Errorf("%s: run reads cfg.dryRun directly. Inside run the question is never "+
				"\"which flag was given\" but \"does this run touch the host\", and that is "+
				"cfg.startsNothing() — a guard that knows about one flag and not the other "+
				"is a screen that says nothing was started while holding a socket",
				fset.Position(sel.Pos()))
		case "startsNothing":
			uses++
		}
		return true
	})

	if uses < 5 {
		t.Fatalf("this sweep found cfg.startsNothing() only %d time(s) in run, which is too "+
			"few for the guards that exist — it is measuring nothing", uses)
	}
}
