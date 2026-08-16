package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestEveryAnnotationCarriesItsMeasurementOrSaysItHasNone is the mechanical half
// of envNotes' header contract:
//
//	EVERY ENTRY CARRIES, IN THE COMMENT BESIDE IT, EITHER THE MEASUREMENT IT WAS
//	WRITTEN FROM OR THE WORDS "DOCUMENTED, NOT MEASURED ON THIS HOST" AND WHAT
//	WAS TRIED.
//
// REGRESSION (redteam host round 2, F4). That paragraph was written, was true of
// most rows, and was never checked. Measured over the rendered catalogue: 76 of
// 167 (name, verb) pairs — 41 distinct names — carried neither word. The
// distribution is what makes it a finding rather than an untidiness: CLASSPATH
// carried "(documented — no JVM on this host)" while JAVA_TOOL_OPTIONS,
// _JAVA_OPTIONS and JDK_JAVA_OPTIONS sat four lines above it with nothing at all,
// on the very host whose missing JVM the CLASSPATH row cited. One block labelled,
// the block above it not — the shape CLAUDE.md records twice ("fixed the
// ENVIRONMENT block and left the argv block four lines below it").
//
// WHY IT PARSES THE SOURCE RATHER THAN READING THE TABLE. The contract is about
// the COMMENT, and a comment is not reachable from a map at runtime. It is also
// where the second half of the contract has to live: "DOCUMENTED, NOT MEASURED"
// is only worth anything with "and what was TRIED" beside it, and that is three
// lines of transcript no rendered sentence should carry.
//
// A COMMENT COVERS EXACTLY ONE ENTRY — the next one — and that is the deliberate
// half of the design. The covering text for a row is what lies between the END of
// the previous row and the START of this one, so a block heading satisfies the
// first row under it and NOTHING ELSE. Without that, the sweep would have passed
// the case that motivated it: PROMPT_COMMAND sat under "Measured, bash 5.3.15,
// all four in one run", which was about PS0/PS2/PS3/PS4 and never about
// PROMPT_COMMAND. Under this rule it fails until someone measures it or says why
// they cannot, which is what the header asks for. The cost is a comment (or a
// "(measured, …)" in the sentence) per row; that is the price of the contract
// being a fact.
//
// WHAT IT STILL CANNOT CATCH, so the green tick is not read as more than it is:
// this is a check for the PRESENCE of a claim, never for its TRUTH. A row saying
// "measured" about something it did not measure passes here — which is why the
// table also carries TestTheFalsifiedAnnotationsStayFalsified, one named
// assertion per sentence that did not survive a re-measurement (PS3,
// MALLOC_TRACE, HOSTALIASES, LOCPATH), and why the rendered wording is pinned in
// testdata/annotations.txt for a human to read.
func TestEveryAnnotationCarriesItsMeasurementOrSaysItHasNone(t *testing.T) {
	src, err := os.ReadFile("envtypes.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "envtypes.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}

	notes := compositeLiteralFor(t, f, "envNotes")
	prefixes := compositeLiteralFor(t, f, "envNotePrefixes")

	type entry struct {
		label string
		node  ast.Expr
	}
	var entries []entry
	for _, elt := range notes.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			t.Fatalf("envNotes has an element that is not KEY: VALUE at %s", fset.Position(elt.Pos()))
		}
		name, err := strconv.Unquote(kv.Key.(*ast.BasicLit).Value)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry{"envNotes[" + name + "]", elt})
	}
	for _, elt := range prefixes.Elts {
		lit, ok := elt.(*ast.CompositeLit)
		if !ok || len(lit.Elts) == 0 {
			t.Fatalf("envNotePrefixes has an unexpected element at %s", fset.Position(elt.Pos()))
		}
		prefix, err := strconv.Unquote(lit.Elts[0].(*ast.BasicLit).Value)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry{"envNotePrefixes " + prefix, elt})
	}

	// The covering text for one entry is every comment between the end of the
	// PREVIOUS entry and the start of this one, plus the entry's own source. The
	// entry's own source counts because a sentence that says "(measured, git
	// 2.55.0)" is a stronger form of the same statement — it is on the screen a
	// human reads, not only in the file a maintainer reads.
	prevEnd := map[ast.Expr]token.Pos{}
	for _, lit := range []*ast.CompositeLit{notes, prefixes} {
		last := lit.Lbrace
		for _, elt := range lit.Elts {
			prevEnd[elt] = last
			last = elt.End()
		}
	}

	for _, e := range entries {
		var b strings.Builder
		for _, cg := range f.Comments {
			if cg.Pos() > prevEnd[e.node] && cg.End() < e.node.Pos() {
				b.WriteString(cg.Text())
				b.WriteString("\n")
			}
		}
		b.Write(src[fset.Position(e.node.Pos()).Offset:fset.Position(e.node.End()).Offset])

		switch measured, documented, tried := annotationProvenance(b.String()); {
		case !measured && !documented:
			t.Errorf("%s carries neither a measurement nor the words DOCUMENTED, NOT MEASURED "+
				"ON THIS HOST. envNotes' header promises one or the other beside every entry, "+
				"and the sentence in this row is on the screen a human reads to decide whether "+
				"to trust a sandbox. Measure it, or say what you tried and could not run", e.label)
		case !measured && !tried:
			t.Errorf("%s says it was not measured but does not say what was TRIED. That is the "+
				"half of the contract that keeps a row from being unmeasurable forever: the "+
				"next reader has to be able to tell whether it needs a different host, a "+
				"vendored tool, or a container", e.label)
		}
	}

	// POSITIVE CONTROL for the parse: if the literals stop being found, or the
	// element shape changes, every assertion above passes over an empty list.
	if len(entries) < 70 {
		t.Fatalf("only %d annotation entries were parsed out of envtypes.go (78 today); this "+
			"sweep is measuring almost nothing", len(entries))
	}
	// POSITIVE CONTROL for the RULE, driven through the same function the sweep
	// uses so the control cannot drift away from what was actually applied. A
	// sweep whose predicate is always true is this project's named failure mode.
	for _, probe := range []struct {
		text string
		want bool
	}{
		{"the JVM loads classes from here", false},
		{"documented, not measured on this host", false}, // says nothing about what was tried
		{"DOCUMENTED, NOT MEASURED ON THIS HOST. Tried: no JVM here", true},
		{"measured, git 2.55.0, with the control", true},
	} {
		measured, documented, tried := annotationProvenance(probe.text)
		accepted := (measured || documented) && (measured || tried)
		if accepted != probe.want {
			t.Errorf("the rule accepted=%v for %q, want %v — the sweep above is not the check "+
				"this test claims to be", accepted, probe.text, probe.want)
		}
	}
}

// annotationProvenance is the whole of the rule, in one place, so the sweep and
// its control cannot disagree about what "labelled" means.
// "NOT MEASURED" IS NOT A MEASUREMENT, and the first draft of this function read
// it as one — `strings.Contains(text, "measured")` is true of the exact phrase
// the contract offers as the ALTERNATIVE to a measurement, so every documented
// row would have satisfied the measured branch and the "what was tried" half
// would never have been asked for. Caught by the rule's own control, which is the
// whole reason a control that exercises the real function is worth writing.
func annotationProvenance(text string) (measured, documented, tried bool) {
	l := strings.ToLower(text)
	return strings.Contains(strings.ReplaceAll(l, "not measured", ""), "measured"),
		strings.Contains(l, "documented"),
		strings.Contains(l, "tried")
}

// compositeLiteralFor returns the composite literal assigned to a package-level
// var, so the sweep above names the table it means rather than the first literal
// in the file.
func compositeLiteralFor(t *testing.T, f *ast.File, name string) *ast.CompositeLit {
	t.Helper()
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || vs.Names[0].Name != name || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.CompositeLit)
			if !ok {
				t.Fatalf("%s is not a composite literal", name)
			}
			return lit
		}
	}
	t.Fatalf("no package-level var %s in envtypes.go — it was renamed or moved, and this "+
		"sweep silently stopped covering it", name)
	return nil
}
