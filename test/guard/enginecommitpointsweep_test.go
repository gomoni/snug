package guard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// ── a test that drives the host engine must reach the run-count floor ───────
//
// SNUG_ENGINE_FLOOR (Makefile) is snug's inert-test detector: it counts the
// DISTINCT test names that logged "snug-engine-ran:", and fails a run that
// lost engine coverage. A test that skips BEFORE its markEngineRan call is
// therefore invisible to it — the floor cannot notice it going inert, because
// it was never a member. Issue #458 is one instance
// (TestTheEngineCarriesItsOwnSignaturePolicy, which has never executed in any
// measured environment); a sweep of the suite found two more in the same file,
// covering issue #142's and issue #307's regressions.
//
// SCOPE, decided rather than left implicit: DIRECT callers of runPodman
// (imageprovenance_test.go), which drive podman on the HOST outside every
// namespace and therefore mark by hand. Every other engine test reaches the
// marker through requireRealEngine or startEngineRun, which mark internally
// past their own skip decision — those cannot have the defect, and asserting
// over them would mean modelling call transitivity to say nothing new.
// gate_test.go sets $SNUG_PODMAN to a FAKE podman and correctly never marks;
// it does not call runPodman, so it is out of scope by the same rule rather
// than by an exemption.
//
// WHAT IS ASSERTED, and what is NOT. Presence of the call, and that no
// t.Skip appears LEXICALLY AFTER it — a skip past the commit point means the
// floor counted a test that then asserted nothing, which is the same defect
// facing the other way. Lexical position is a proxy for execution order and
// is named as one: an early `return` or a helper that skips on the test's
// behalf is not visible here. What enforces the real ordering is
// requireRealEngine's own structure for every other test, and review for
// these four.
const engineMarkFunc = "markEngineRan"

// engineCommitPointExempt names tests that drive the host engine and are
// KNOWN not to mark, with the reason. It is not a list of things to get
// round to: TestEngineCommitPointExemptionsAreStillNeeded fails when an
// entry starts marking, so a stale row cannot survive the fix that made it
// stale.
var engineCommitPointExempt = map[string]string{
	// EMPTY, and that is the point rather than an oversight: every test that
	// drives the host engine through runPodman reaches the floor today. An
	// entry here is a test claiming no engine coverage, and
	// TestEngineCommitPointExemptionsAreStillNeeded fails when one starts
	// marking, so a row cannot outlive the fix that made it stale.
}

// engineTestMarks reports, for one *ast.FuncDecl, whether it calls
// runPodman, the position of its markEngineRan call (0 if absent), and the
// position of the LAST t.Skip-family call.
func engineTestMarks(fn *ast.FuncDecl) (drivesEngine bool, markPos, lastSkipPos token.Pos) {
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			switch f.Name {
			case "runPodman":
				drivesEngine = true
			case engineMarkFunc:
				if markPos == token.NoPos {
					markPos = f.Pos()
				}
			}
		case *ast.SelectorExpr:
			// t.Skip / t.Skipf / t.SkipNow. The receiver is not checked
			// beyond being an identifier: nothing else in this suite owns
			// these three names, and a subtest's own variable is as much a
			// skip as the outer t is.
			if _, ok := f.X.(*ast.Ident); ok && strings.HasPrefix(f.Sel.Name, "Skip") {
				if f.Sel.Pos() > lastSkipPos {
					lastSkipPos = f.Sel.Pos()
				}
			}
		}
		return true
	})
	return drivesEngine, markPos, lastSkipPos
}

// TestEveryHostEngineTestReachesTheRunCountFloor is the sweep.
func TestEveryHostEngineTestReachesTheRunCountFloor(t *testing.T) {
	var drivers []string

	n := testFiles(t, func(rel string, f *ast.File, fset *token.FileSet) {
		if !strings.HasPrefix(rel, "test/integration/") {
			return
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			drivesEngine, markPos, lastSkipPos := engineTestMarks(fn)
			if !drivesEngine {
				continue
			}
			drivers = append(drivers, fn.Name.Name)
			if reason, exempt := engineCommitPointExempt[fn.Name.Name]; exempt {
				if markPos != token.NoPos {
					continue // the reverse control below owns this case
				}
				t.Logf("%s:%d: %s is exempt — %s", rel, fset.Position(fn.Pos()).Line, fn.Name.Name, reason)
				continue
			}
			if markPos == token.NoPos {
				t.Errorf("%s:%d: %s drives the host engine through runPodman and never calls %s, "+
					"so SNUG_ENGINE_FLOOR does not count it and cannot notice it going inert "+
					"(issue #458). Add the commit point immediately past the test's own control "+
					"skip, as TestTheEngineReadsItsOwnRegistriesConf does.",
					rel, fset.Position(fn.Pos()).Line, fn.Name.Name, engineMarkFunc)
				continue
			}
			if lastSkipPos > markPos {
				t.Errorf("%s:%d: %s calls %s at line %d and then skips at line %d, so the floor "+
					"counts a test that went on to assert nothing. The commit point belongs "+
					"AFTER every skip that can excuse the test.",
					rel, fset.Position(fn.Pos()).Line, fn.Name.Name, engineMarkFunc,
					fset.Position(markPos).Line, fset.Position(lastSkipPos).Line)
			}
		}
	})

	if n == 0 {
		t.Fatal("no _test.go file was parsed, so this check measures nothing")
	}
	// POSITIVE CONTROL: imageprovenance_test.go is known to drive podman on the
	// host through runPodman. Finding no caller means the detector broke, not
	// that the suite stopped driving the engine — which is exactly the
	// "green having measured nothing" shape this sweep exists to catch.
	if len(drivers) == 0 {
		t.Fatal("no test/integration test calls runPodman, so this check measures nothing: " +
			"either the helper was renamed or the host-engine tests are gone")
	}
}

// TestEngineCommitPointExemptionsAreStillNeeded is the reverse control: an
// exemption that has stopped being true must FAIL rather than sit there. A
// list of known gaps is otherwise a copy of tree state, stale from the moment
// somebody fixes one.
func TestEngineCommitPointExemptionsAreStillNeeded(t *testing.T) {
	seen := map[string]bool{}

	n := testFiles(t, func(rel string, f *ast.File, fset *token.FileSet) {
		if !strings.HasPrefix(rel, "test/integration/") {
			return
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			reason, exempt := engineCommitPointExempt[fn.Name.Name]
			if !exempt {
				continue
			}
			seen[fn.Name.Name] = true
			drivesEngine, markPos, _ := engineTestMarks(fn)
			if !drivesEngine {
				t.Errorf("%s:%d: %s is exempt from the run-count floor (%s) but no longer drives "+
					"the host engine through runPodman. Delete the exemption.",
					rel, fset.Position(fn.Pos()).Line, fn.Name.Name, reason)
			}
			if markPos != token.NoPos {
				t.Errorf("%s:%d: %s now calls %s at line %d, so its exemption (%s) is false. "+
					"Delete the exemption — the sweep covers this test now.",
					rel, fset.Position(fn.Pos()).Line, fn.Name.Name, engineMarkFunc,
					fset.Position(markPos).Line, reason)
			}
		}
	})

	if n == 0 {
		t.Fatal("no _test.go file was parsed, so this check measures nothing")
	}
	for name := range engineCommitPointExempt {
		if !seen[name] {
			t.Errorf("%s is exempt from the run-count floor but no such test exists in "+
				"test/integration. Delete the exemption.", name)
		}
	}
}

// TestEngineTestMarksSeesEachShape is the control on the detector: it must be
// ABLE to flag a missing or misplaced commit point, or the sweep above
// passing proves nothing.
func TestEngineTestMarksSeesEachShape(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		body                          string
		drives, marks, skipsAfterMark bool
	}{
		{
			name:   "control then commit point",
			body:   "control := runPodman(t, env)\nif control == \"\" {\nt.Skipf(\"no\")\n}\nmarkEngineRan(t, hostEngine(t))\n",
			drives: true, marks: true,
		},
		{
			name:   "drives the engine and never marks",
			body:   "got := runPodman(t, env)\nif got == \"\" {\nt.Skip(\"no\")\n}\n",
			drives: true,
		},
		{
			name:   "marks and then skips",
			body:   "markEngineRan(t, hostEngine(t))\ngot := runPodman(t, env)\nif got == \"\" {\nt.Skip(\"nothing to observe\")\n}\n",
			drives: true, marks: true, skipsAfterMark: true,
		},
		{
			name: "a fake podman is not a driver",
			body: "env := append(baseEnv(), \"SNUG_PODMAN=\"+fp)\n_ = env\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "package p\nfunc TestX(t *testing.T) {\n" + tc.body + "}\n"
			f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", src, 0)
			if err != nil {
				t.Fatalf("fixture does not parse, so this control measures nothing: %v", err)
			}
			fn := f.Decls[0].(*ast.FuncDecl)
			drives, markPos, lastSkipPos := engineTestMarks(fn)
			if drives != tc.drives {
				t.Errorf("drivesEngine = %v, want %v", drives, tc.drives)
			}
			if marks := markPos != token.NoPos; marks != tc.marks {
				t.Errorf("marks = %v, want %v", marks, tc.marks)
			}
			if after := markPos != token.NoPos && lastSkipPos > markPos; after != tc.skipsAfterMark {
				t.Errorf("skipsAfterMark = %v, want %v", after, tc.skipsAfterMark)
			}
		})
	}
}
