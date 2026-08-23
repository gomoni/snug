package policy

import (
	"go/ast"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// ── the single-writer sweep for a field named TmpfsSizeBytes ────────────────
//
// This is the same device TestOnlyGraftWritesGrafts (graft_test.go) is for
// p.Grafts and TestAuthoredWritersAreTheThreeTheCommentsName
// (authoredwriters_test.go) is for Mount.Authored: a single-writer invariant
// asserted by finding every mutation module-wide via go/ast, not by trusting
// the doc comment that claims it (types.go's doc comment on Policy.TmpfsSizeBytes:
// "a FUTURE writer of a KindTmpfs mount... cannot ship an unbounded tmpfs by
// forgetting to set a per-mount size", which rests entirely on Resolve's
// Policy{} literal being the ONLY place that ever sets it).
//
// It reuses sweepModule, moduleRoot, requireWalked, forEachFunc, fieldSelector,
// unparen and writeSite from norestriction_test.go, and baseTypeName from
// authoredwriters_test.go, all in this package already — a fifth copy of the
// walk would be the catalogue shape invariant 2 rejects.
//
// UNLIKE those two sweeps, the field name TmpfsSizeBytes is shared by THREE
// distinct types, deliberately (their own doc comments say so):
//
//	policy.Context   the caller's raw preference (0 means "unset")
//	policy.Policy    Resolve's single source of truth — the one this
//	                 invariant is actually about
//	cli.Report       the --dry-run/JSON view, copied from p.TmpfsSizeBytes
//
// So a sweep keyed on the field name alone finds three sites, not one, and the
// point of this test is asserting WHICH three — exactly the Grafts sweep's
// "three writers, one of them a documented name collision" shape.

const tmpfsSizeBytesField = "TmpfsSizeBytes"

// tmpfsSizeBytesMutations reports every assignment, address-taken, and keyed
// composite literal field named TmpfsSizeBytes, with the struct type name
// where a composite literal made that determinable. It does not attempt
// unkeyed-literal detection (unlike authoredWritesInSource): every build site
// of Context, Policy and Report in this tree uses keyed literals, which is the
// module's own convention, and an unkeyed literal of any of the three would
// already fail to compile against a struct this wide without every field named.
func tmpfsSizeBytesMutations(file string, f *ast.File, fset *token.FileSet) []writeSite {
	var sites []writeSite
	forEachFunc(f, func(name string, root ast.Node) {
		add := func(pos token.Pos, how string) {
			sites = append(sites, writeSite{file: file, fn: name, how: how, line: fset.Position(pos).Line})
		}
		ast.Inspect(root, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range v.Lhs {
					if fieldSelector(lhs, tmpfsSizeBytesField) {
						add(lhs.Pos(), "assignment")
					}
				}
			case *ast.UnaryExpr:
				if v.Op == token.AND && fieldSelector(v.X, tmpfsSizeBytesField) {
					add(v.Pos(), "address taken")
				}
			case *ast.CompositeLit:
				typeName := baseTypeName(v.Type)
				for _, e := range v.Elts {
					kv, ok := e.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if id, ok := kv.Key.(*ast.Ident); ok && id.Name == tmpfsSizeBytesField {
						how := "keyed composite literal"
						if typeName != "" {
							how = "keyed composite literal in " + typeName
						}
						add(kv.Pos(), how)
					}
				}
			}
			return true
		})
	})
	return sites
}

// TestOnlyResolveSetsTmpfsSizeBytes sweeps the whole module for every write to
// a field named TmpfsSizeBytes and asserts the result is exactly the three
// documented sites, with the POLICY one — the one the security argument
// actually rests on — living inside Resolve and nowhere else.
func TestOnlyResolveSetsTmpfsSizeBytes(t *testing.T) {
	sites, dirs := sweepModule(t, tmpfsSizeBytesMutations)
	requireWalked(t, dirs)

	got := make([]string, 0, len(sites))
	for _, s := range sites {
		got = append(got, s.key())
	}
	sort.Strings(got)

	want := []string{
		// cli.Report's own copy, built in buildReport from the resolved p.
		"internal/cli/report.go buildReport (keyed composite literal in Report)",
		// policy.Context, built once in run() from the config-file/CLI setting.
		"internal/cli/main.go run (keyed composite literal in Context)",
		// policy.Policy — the ONE this invariant is about.
		"internal/policy/resolve.go Resolve (keyed composite literal in Policy)",
	}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("a field named TmpfsSizeBytes is written at:\n  %s\nwant exactly:\n  %s\n\n"+
			"Three types share this field name by design (see this file's own doc comment), so\n"+
			"finding three sites is expected. A site that is not one of the three above is either\n"+
			"a FOURTH type that has started sharing the name (add it here with a reason) or a\n"+
			"second writer of Policy.TmpfsSizeBytes — the single-writer invariant types.go's doc\n"+
			"comment claims, which is broken if so.",
			strings.Join(sitesLines(sites), "\n  "), strings.Join(want, "\n  "))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}

	// The assertion that actually matters: Policy.TmpfsSizeBytes — identified
	// by file, since Context and Report share the field name but live in
	// different files — is written inside Resolve, and Resolve alone.
	policySites := 0
	for _, s := range sites {
		if s.file != "internal/policy/resolve.go" {
			continue
		}
		policySites++
		if s.fn != "Resolve" {
			t.Errorf("internal/policy/resolve.go writes a field named TmpfsSizeBytes outside "+
				"Resolve, in %s — Resolve's own Policy{} literal is meant to be the only writer", s.fn)
		}
	}
	if policySites != 1 {
		t.Fatalf("resolve.go writes a field named TmpfsSizeBytes %d times, want exactly 1 — if "+
			"this sweep cannot see that one write, it cannot see a second one arriving either",
			policySites)
	}
}

// TestTmpfsSizeBytesMutationDetectorCatchesEverySpelling is the mandatory
// positive control on the detector itself, in
// TestAuthoredWriteDetectorCatchesEverySpelling's style: fixtures the detector
// must flag, so a future edit that narrows it fails here before the sweep
// above can quietly stop measuring anything.
func TestTmpfsSizeBytesMutationDetectorCatchesEverySpelling(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"plain assignment", `package p
type Policy struct{ TmpfsSizeBytes uint64 }
func f(p *Policy) { p.TmpfsSizeBytes = 5 }`, "assignment"},

		{"keyed composite literal", `package p
type Policy struct{ TmpfsSizeBytes uint64 }
func f() *Policy { return &Policy{TmpfsSizeBytes: 5} }`, "keyed composite literal in Policy"},

		{"keyed composite literal, qualified type", `package p
import "github.com/gomoni/snug/internal/policy"
func f() policy.Context { return policy.Context{TmpfsSizeBytes: 5} }`, "keyed composite literal in Context"},

		{"address of the field", `package p
type Policy struct{ TmpfsSizeBytes uint64 }
func f(p *Policy) *uint64 { return &p.TmpfsSizeBytes }`, "address taken"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectInSource(t, tmpfsSizeBytesMutations, tc.src)
			if len(got) == 0 {
				t.Fatalf("the detector does not flag this spelling, so a new writer written this "+
					"way would ship green:\n%s", tc.src)
			}
			if got[0].how != tc.want {
				t.Errorf("flagged as %q, want %q", got[0].how, tc.want)
			}
		})
	}

	// NEGATIVE control: a READ of the field must not be flagged.
	clean := `package p
type Policy struct{ TmpfsSizeBytes uint64 }
func f(p Policy) bool { return p.TmpfsSizeBytes > 0 }`
	if got := detectInSource(t, tmpfsSizeBytesMutations, clean); len(got) != 0 {
		t.Errorf("the detector flags a READ of the field as a write: %v", got)
	}
}
