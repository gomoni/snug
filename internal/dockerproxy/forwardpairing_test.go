package dockerproxy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestEveryForwardedClientPathIsJudgedInGuestSpace is issue #374's rule, one
// clause longer than #371's own: resolving a client path for forwarding and
// judging the name the engine will resolve are ONE operation, and a function
// doing the first without the second is judging a string the engine will not
// be asked for. build.go's checkSeccompProfile did exactly that until #371 —
// resolveForwardable ran, but CheckEngineForwardedPath did not, until the fix
// added it. This sweep is what keeps a THIRD such function from shipping the
// same way: every non-test function body in this package whose source
// contains a call to resolveForwardable must also contain a call to
// CheckEngineForwardedPath, in the SAME function body.
//
// Today that pairing binds exactly two functions — checkOne (create.go) and
// checkSeccompProfile (build.go) — and this test asserts BOTH are found, so
// it cannot pass by sweeping a tree that happens to contain neither call.
func TestEveryForwardedClientPathIsJudgedInGuestSpace(t *testing.T) {
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	type hit struct{ file, fn string }
	var found []hit   // every func whose body calls resolveForwardable(
	var missing []hit // ...and does NOT also call CheckEngineForwardedPath(

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, fn := range funcsCalling(t, f.Name(), string(src), "resolveForwardable(") {
			found = append(found, hit{f.Name(), fn})
		}
		for _, fn := range funcsCallingButMissing(t, f.Name(), string(src), "resolveForwardable(", "CheckEngineForwardedPath(") {
			missing = append(missing, hit{f.Name(), fn})
		}
	}

	// POSITIVE CONTROL: the sweep actually found something, and specifically
	// found BOTH of the two functions this pairing is known to bind today. A
	// sweep that silently matched nothing would pass this test for the wrong
	// reason (issue #243's shape: "did it run?" is not "did it run against
	// the right target?").
	want := map[hit]bool{
		{"create.go", "checkOne"}:           true,
		{"build.go", "checkSeccompProfile"}: true,
	}
	gotSet := map[hit]bool{}
	for _, h := range found {
		gotSet[h] = true
	}
	for w := range want {
		if !gotSet[w] {
			t.Errorf("expected %s's %s to call resolveForwardable( — it no longer does, or the "+
				"sweep's AST walk missed it; either way this inventory needs updating", w.file, w.fn)
		}
	}
	if len(found) < len(want) {
		t.Fatalf("the sweep found only %d function(s) calling resolveForwardable(, want at least %d — "+
			"it cannot be trusted to catch a missing pairing if it barely matches the KNOWN one",
			len(found), len(want))
	}

	if len(missing) != 0 {
		sort.Slice(missing, func(i, j int) bool {
			if missing[i].file != missing[j].file {
				return missing[i].file < missing[j].file
			}
			return missing[i].fn < missing[j].fn
		})
		var lines []string
		for _, h := range missing {
			lines = append(lines, h.file+": "+h.fn)
		}
		t.Errorf("the following function(s) resolve a client path with resolveForwardable( but never "+
			"judge it with CheckEngineForwardedPath( in the SAME body — resolving a client path for "+
			"forwarding and judging the name the engine will resolve are one operation (issue #374); "+
			"a function doing the first without the second is judging a string the engine will not be "+
			"asked for:\n  %s", strings.Join(lines, "\n  "))
	}
}

// TestForwardPairingSweepCanActuallyDetectAViolation is the sweep's own
// positive control: a synthetic function calling resolveForwardable( and
// never CheckEngineForwardedPath( must be reported by the same detection
// logic the real sweep above uses. Without this, a typo in either marker
// string would make TestEveryForwardedClientPathIsJudgedInGuestSpace pass by
// finding nothing to report, not by finding nothing wrong.
func TestForwardPairingSweepCanActuallyDetectAViolation(t *testing.T) {
	fixture := `package dockerproxy

func evil(p *Proxy, v string) (string, error) {
	real, err := resolveForwardable(v)
	if err != nil {
		return "", err
	}
	if err := p.pol.CheckEngineBindSource(real); err != nil {
		return "", err
	}
	return real, nil
}
`
	missing := funcsCallingButMissing(t, "fixture.go", fixture, "resolveForwardable(", "CheckEngineForwardedPath(")
	if len(missing) != 1 || missing[0] != "evil" {
		t.Fatalf("the sweep's detection logic did not catch a synthetic violation: got %v, want [evil] — "+
			"it would not catch a real one either", missing)
	}

	// And it must NOT report a function that pairs the two calls correctly —
	// or the real sweep above would be failing on its own two known-good
	// functions right now.
	paired := `package dockerproxy

func fine(p *Proxy, v string) (string, error) {
	real, err := resolveForwardable(v)
	if err != nil {
		return "", err
	}
	if err := p.pol.CheckEngineForwardedPath(real); err != nil {
		return "", err
	}
	return real, nil
}
`
	if got := funcsCallingButMissing(t, "fixture.go", paired, "resolveForwardable(", "CheckEngineForwardedPath("); len(got) != 0 {
		t.Fatalf("the sweep reported a correctly-paired function as a violation: %v", got)
	}
}

// funcsCalling returns the names of every top-level func or method declared in
// src whose body's source text contains marker.
func funcsCalling(t *testing.T, filename, src, marker string) []string {
	t.Helper()
	return walkFuncBodies(t, filename, src, func(body string) bool {
		return strings.Contains(body, marker)
	})
}

// funcsCallingButMissing returns the names of every top-level func or method
// declared in src whose body's source text contains `has` but not `missing`.
func funcsCallingButMissing(t *testing.T, filename, src, has, missing string) []string {
	t.Helper()
	return walkFuncBodies(t, filename, src, func(body string) bool {
		return strings.Contains(body, has) && !strings.Contains(body, missing)
	})
}

// walkFuncBodies parses src as a Go source file and returns the name of every
// top-level func or method whose BODY's exact source text (the '{' through the
// matching '}') satisfies pred. Using go/parser rather than the funcBody
// brace-counter this package already has (hostpathauthor_test.go) because that
// helper is built for one KNOWN signature at a time; this sweep needs to
// enumerate every function in a file without knowing their signatures in
// advance.
func walkFuncBodies(t *testing.T, filename, src string, pred func(body string) bool) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("%s does not parse: %v", filename, err)
	}
	var names []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		if start < 0 || end > len(src) || start > end {
			continue
		}
		body := src[start:end]
		if pred(body) {
			names = append(names, fn.Name.Name)
		}
	}
	return names
}
