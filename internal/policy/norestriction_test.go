package policy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ── the no-restriction invariant, swept for as a property ────────────────────
//
// CLAUDE.md invariant 1 has two halves. Visibility is monotone because the
// grant language cannot express subtraction, and access is monotone because
// nothing lowers one. TestPolicyHasNoRestrictionOperation (resolve_test.go)
// pins Access.Join's maximum for one path in one selection, which is a
// statement about Join and not about the module: a `Clamp`, an `Apply`, or a
// `func (p *Policy) Derive() *Policy` returning a copy with every AccessRW
// rewritten to AccessRO satisfies it (issue #271).
//
// A list of forbidden identifiers is not the answer. Invariant 2's own
// corollary rejects the catalogue shape, and `Clamp|Apply|Restrict|Derive` as a
// name list fails on the next demote, which will be called something else. What
// is swept for here is the EFFECT, which a demote cannot avoid having:
//
//	P1  Every assignment into an Access field has the form
//	        x.Access = x.Access.Join(e)
//	    The stored access is the join of what was stored with something else,
//	    so it cannot decrease. This is a property of the expression — a demote
//	    under any name either is not a Join of the previous value, or is not an
//	    assignment into Access at all.
//
//	P2  Every mutation of a mount collection happens in one of three named
//	    functions. That is what closes P1's "or is not an assignment at all":
//	    a demote that rebuilds mounts as fresh composite literals, or un-grants
//	    by deleting them, has to write a Mounts map to have any effect, and the
//	    set below names every place that does.
//
// P2 is load-bearing rather than belt-and-braces, and this is the measurement
// that says so: issue #271's own example — a Derive returning a copy of the
// mounts with every AccessRW rewritten to AccessRO — is reported by P2 ONLY.
// P1 shows nothing for it, because it assigns no Access field anywhere. Anyone
// who finds P1 sufficient and deletes P2 restores exactly the patch this file
// exists to catch. Both fixtures are below.
//
// Together they leave three ways in, and each is monotone or documented:
//
//	Policy.join     Access joins by max (resolve.go), which is P1's one site.
//	Policy.yieldTo  installs a base mount only at an unclaimed guest path, so
//	                it displaces nothing.
//	Policy.Replace  overwrites, access included. This is invariant 1's named
//	                exception — snug's own generated KindData mounts must win
//	                over a profile's bind at the same path. The exception is
//	                bounded by being countable, which is what P2 keeps true.
//
// Residual, stated rather than implied. The Access→bwrap-flag mapping
// (bwrap.go) demotes without touching the policy at all; the golden argv files
// pin it, and a change there is a golden diff. A Mounts map passed as a
// function ARGUMENT is aliased into a callee neither sweep follows —
// TestOnlyGraftWritesGrafts carries the same residual for p.Grafts. Neither
// sweep sees reflection or unsafe.

// accessField and mountsField are the two field names the sweeps key on.
// Matching by NAME needs no type checker, so this costs no dependency in a
// go.mod whose every entry runs with the authority of the thing building the
// sandbox — and for Mounts the name is the point rather than a compromise:
// Policy.SandboxView returns a View sharing the very map (envresolve.go), so a
// write through `v.Mounts[k]` is a write to p.Mounts and a type-directed sweep
// would have to know that.
const (
	accessField = "Access"
	mountsField = "Mounts"
)

// writeSite is one place the module writes one of the two fields. `how` names
// the spelling because "a fourth writer exists" and "a fourth writer exists AS
// A DELETE" send a reader to different lines.
type writeSite struct {
	file string // module-root-relative, forward slashes
	fn   string // enclosing function, receiver included
	how  string
	line int
}

func (s writeSite) String() string {
	return fmt.Sprintf("%s %s (%s, line %d)", s.file, s.fn, s.how, s.line)
}

// key is what the assertions compare. The LINE is deliberately not in it: a
// line moves whenever anything above it is edited, and a test that fails on an
// unrelated edit is a test people learn to update without reading. The line is
// still in the failure message.
func (s writeSite) key() string { return s.file + " " + s.fn + " (" + s.how + ")" }

// ── the walk ────────────────────────────────────────────────────────────────

// sweepModule parses every non-test .go file under the module root and returns
// what detect reports, plus the directories it visited. The directory list is
// the walk's own positive control: "three writers" is a statement about
// whatever subtree was actually walked, and hardcoding a walk root below the
// module is how a writer in cmd/snug shipped green once already (issue #291
// part 1b).
func sweepModule(t *testing.T, detect func(file string, f *ast.File, fset *token.FileSet) []writeSite) ([]writeSite, map[string]bool) {
	t.Helper()
	root := moduleRoot(t)

	var sites []writeSite
	dirs := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			// Dotted directories are skipped for a REASON: .claude/worktrees/
			// in the primary checkout holds complete copies of this tree on
			// other branches, and walking them would report another branch's
			// writers as this one's.
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
		dirs[filepath.ToSlash(filepath.Dir(rel))] = true

		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, rel, src, 0)
		if perr != nil {
			return perr
		}
		sites = append(sites, detect(rel, f, fset)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sortSites(sites)
	return sites, dirs
}

// detectInSource runs one detector over source text the caller authors, which
// is how the positive controls below drive the detectors without planting a
// demote in the tree.
func detectInSource(t *testing.T, detect func(string, *ast.File, *token.FileSet) []writeSite, src string) []writeSite {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("the fixture does not parse, so this control measures nothing: %v", err)
	}
	return detect("fixture.go", f, fset)
}

func sortSites(s []writeSite) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].file != s[j].file {
			return s[i].file < s[j].file
		}
		return s[i].line < s[j].line
	})
}

// forEachFunc calls fn for every function body in the file, and once for the
// file-scope declarations, with the enclosing name. A demote written as a
// package-level var initialiser is still a demote.
func forEachFunc(f *ast.File, fn func(name string, n ast.Node)) {
	for _, d := range f.Decls {
		switch v := d.(type) {
		case *ast.FuncDecl:
			if v.Body == nil {
				continue
			}
			fn(funcName(v), v.Body)
		default:
			fn("(file scope)", d)
		}
	}
}

func funcName(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return d.Name.Name
	}
	return "(" + types.ExprString(d.Recv.List[0].Type) + ")." + d.Name.Name
}

// fieldSelector reports whether e selects a field of the given name, and is
// what makes both detectors indifferent to the receiver's spelling: `p.Mounts`,
// `pol.Mounts`, `v.Mounts` and `q.Mounts` are all the same write.
func fieldSelector(e ast.Expr, name string) bool {
	sel, ok := unparen(e).(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == name
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// ── P1: every Access assignment is a join with the previous value ────────────

// accessWrites reports every write into a field named Access, classifying the
// one shape that cannot lower a value — `x.Access = x.Access.Join(e)` — as
// "join with the previous value" and everything else by its spelling.
//
// The comparison of the two Access expressions is TEXTUAL (go/types.ExprString
// renders syntax and type-checks nothing), so `old.Access = old.Access.Join(m.Access)`
// passes and `old.Access = m.Access.Join(x)` does not. That is the intended
// strictness: a join whose receiver is not the value being overwritten says
// nothing about whether the result is larger than what was there.
func accessWrites(file string, f *ast.File, fset *token.FileSet) []writeSite {
	var sites []writeSite
	forEachFunc(f, func(name string, root ast.Node) {
		add := func(pos token.Pos, how string) {
			sites = append(sites, writeSite{file: file, fn: name, how: how, line: fset.Position(pos).Line})
		}
		ast.Inspect(root, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range v.Lhs {
					if !fieldSelector(lhs, accessField) {
						continue
					}
					add(lhs.Pos(), classifyAccessAssign(v, i, lhs))
				}
			case *ast.IncDecStmt:
				// Access is a uint8, so `m.Access--` compiles and is a demote
				// that no `= AccessRO` pattern and no name list can see.
				if fieldSelector(v.X, accessField) {
					add(v.Pos(), "increment or decrement")
				}
			case *ast.UnaryExpr:
				// Taking the address hands the write to a callee.
				if v.Op == token.AND && fieldSelector(v.X, accessField) {
					add(v.Pos(), "address taken")
				}
			}
			return true
		})
	})
	return sites
}

func classifyAccessAssign(a *ast.AssignStmt, i int, lhs ast.Expr) string {
	if a.Tok != token.ASSIGN && a.Tok != token.DEFINE {
		return "compound assignment"
	}
	if len(a.Rhs) != len(a.Lhs) {
		// `m.Access, err = f()` — the value comes from a call whose result
		// this sweep cannot read.
		return "multi-value assignment"
	}
	call, ok := unparen(a.Rhs[i]).(*ast.CallExpr)
	if !ok {
		return "assignment of " + types.ExprString(a.Rhs[i])
	}
	sel, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Join" {
		return "assignment of " + types.ExprString(call.Fun) + "(...)"
	}
	if types.ExprString(sel.X) != types.ExprString(lhs) {
		return "Join whose receiver is " + types.ExprString(sel.X) + ", not " + types.ExprString(lhs)
	}
	return "join with the previous value"
}

const accessJoinHow = "join with the previous value"

// TestEveryAccessWriteIsAJoinWithThePreviousValue is P1.
func TestEveryAccessWriteIsAJoinWithThePreviousValue(t *testing.T) {
	sites, dirs := sweepModule(t, accessWrites)
	requireWalked(t, dirs)

	var joins, others []writeSite
	for _, s := range sites {
		if s.how == accessJoinHow {
			joins = append(joins, s)
		} else {
			others = append(others, s)
		}
	}

	// POSITIVE CONTROL on the sweep: Policy.join must trip it. Without this,
	// a detector that matched nothing at all would report zero demotes and
	// read as proof.
	want := "internal/policy/resolve.go (*Policy).join (" + accessJoinHow + ")"
	if len(joins) != 1 || joins[0].key() != want {
		t.Fatalf("the sweep found %v as the join(s) of an Access with its previous value, want\n"+
			"exactly %s. Policy.join is the whole of the monotonicity argument in code; if this\n"+
			"sweep cannot see it, it cannot see a demote either.", joins, want)
	}

	for _, s := range others {
		t.Errorf("%s writes an Access that is not the join of the previous value with anything.\n"+
			"       Access is a total order joined by max and nothing may lower one: CLAUDE.md\n"+
			"       invariant 1, and types.go's \"no Clamp, no Apply, no demote\". If this write\n"+
			"       cannot raise access — a fresh mount handed to Policy.join, say — construct\n"+
			"       the Mount with the field set rather than assigning to it afterwards.", s)
	}
}

// ── P2: the mount collections have three writers ────────────────────────────

// mountsMutations reports every mutation of a field named Mounts: the four map
// shapes, whole-field replacement, and the alias assignment through which a
// later write is invisible to all of them.
func mountsMutations(file string, f *ast.File, fset *token.FileSet) []writeSite {
	var sites []writeSite
	forEachFunc(f, func(name string, root ast.Node) {
		add := func(pos token.Pos, how string) {
			sites = append(sites, writeSite{file: file, fn: name, how: how, line: fset.Position(pos).Line})
		}
		ast.Inspect(root, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range v.Lhs {
					switch l := unparen(lhs).(type) {
					case *ast.IndexExpr:
						if fieldSelector(l.X, mountsField) {
							add(l.Pos(), "index assignment")
						}
					case *ast.SelectorExpr:
						if l.Sel != nil && l.Sel.Name == mountsField {
							add(l.Pos(), "whole-field assignment")
						}
					}
				}
				// `m := p.Mounts` aliases the map. The later `m[k] = v` is
				// invisible to every shape above — that is what aliasing
				// does — so what is flagged is the alias itself, and a human
				// looks at it. `for _, m := range p.Mounts` (a RangeStmt, not
				// an AssignStmt) and `m := p.Mounts[guest]` (an IndexExpr, a
				// one-entry copy) are ordinary reads and are not alias
				// assignments.
				for _, rhs := range v.Rhs {
					if fieldSelector(rhs, mountsField) {
						add(rhs.Pos(), "alias assignment")
					}
				}
			case *ast.UnaryExpr:
				if v.Op == token.AND && fieldSelector(v.X, mountsField) {
					add(v.Pos(), "address taken")
				}
			case *ast.CallExpr:
				callMutation(v, add)
			}
			return true
		})
	})
	return sites
}

// callMutation names the builtin and stdlib spellings that mutate a map in
// place, reporting through add so that a call matching none of them adds
// nothing.
func callMutation(c *ast.CallExpr, add func(token.Pos, string)) {
	if len(c.Args) == 0 || !fieldSelector(c.Args[0], mountsField) {
		return
	}
	switch fn := unparen(c.Fun).(type) {
	case *ast.Ident:
		switch fn.Name {
		case "delete":
			add(c.Pos(), "delete")
		case "clear":
			add(c.Pos(), "clear")
		}
	case *ast.SelectorExpr:
		// maps.Copy(p.Mounts, other) — Mounts as the DESTINATION. As the
		// source it is the second argument and a read, which is why only
		// Args[0] is tested.
		if fn.Sel != nil && (fn.Sel.Name == "Copy" || fn.Sel.Name == "Insert" || fn.Sel.Name == "DeleteFunc") {
			add(c.Pos(), "maps."+fn.Sel.Name)
		}
	}
}

// TestMountCollectionsHaveThreeWriters is P2.
//
// The expected set is a list of the sites that EXIST, not a list of names that
// are forbidden: anything new fails regardless of what it is called, which is
// the difference between this and the catalogue shape invariant 2 rejects.
func TestMountCollectionsHaveThreeWriters(t *testing.T) {
	sites, dirs := sweepModule(t, mountsMutations)
	requireWalked(t, dirs)

	// Policy.join writes the map TWICE — the fresh insert and the merged
	// entry — and both rows are kept rather than collapsed to a set, so a
	// third write landing in join is a failure rather than a no-op.
	//
	// The two internal/cli rows are the JSON document's own `Mounts`, a
	// []jsonMount rendering of the policy that shares nothing but the field
	// name. They are listed rather than filtered: a name-matched sweep that
	// hid its own name collisions would be hiding exactly what a reader has
	// to check, and filtering by package would make the sweep's scope a second
	// thing to keep in step with the walk. The failure message says which rows
	// are collisions, so whoever adds a seventh write is not left guessing.
	want := []string{
		"internal/cli/dryrunjson.go (*lossyEncoder).document (whole-field assignment)",
		"internal/cli/dryrunjson.go (*lossyEncoder).document (whole-field assignment)",
		"internal/policy/resolve.go (*Policy).join (index assignment)",
		"internal/policy/resolve.go (*Policy).join (index assignment)",
		"internal/policy/resolve.go (*Policy).yieldTo (index assignment)",
		"internal/policy/types.go (*Policy).Replace (index assignment)",
	}

	var got []string
	for _, s := range sites {
		got = append(got, s.key())
	}
	sort.Strings(got)
	sorted := append([]string(nil), want...)
	sort.Strings(sorted)

	if len(got) != len(sorted) {
		t.Fatalf("the mount collections are mutated at %d sites:\n  %s\nwant exactly %d:\n  %s\n\n"+
			"Three functions may write p.Mounts — Policy.join (max), Policy.yieldTo (unclaimed\n"+
			"paths only) and Policy.Replace (invariant 1's named exception, snug's own generated\n"+
			"mounts). A fourth is a fourth way for a resolved policy to say something other than\n"+
			"what the profiles granted: a rebuilt mount set is a demote whatever it is called,\n"+
			"and a delete is an un-grant. Add it to the argument above or do not add it.\n\n"+
			"The two (*lossyEncoder).document rows are a NAME COLLISION, not a fourth writer:\n"+
			"that Mounts is the --dry-run JSON document's own []jsonMount, a rendering of the\n"+
			"policy that shares nothing with p.Mounts but the field name. This sweep matches by\n"+
			"field name deliberately — Policy.SandboxView returns a View sharing the very map,\n"+
			"so a write through v.Mounts[k] IS a write to p.Mounts — and it lists its own\n"+
			"collisions rather than filtering them, because a sweep that hides them hides what\n"+
			"a reader has to check. If you edited that renderer, add or drop the row here.",
			len(got), strings.Join(sitesLines(sites), "\n  "), len(sorted), strings.Join(sorted, "\n  "))
	}
	for i := range got {
		if got[i] != sorted[i] {
			t.Errorf("mount-collection writer %q is not one of the three the model names:\n  %s",
				got[i], strings.Join(sorted, "\n  "))
		}
	}
}

func sitesLines(sites []writeSite) []string {
	out := make([]string, 0, len(sites))
	for _, s := range sites {
		out = append(out, s.String())
	}
	return out
}

// requireWalked is the walk's positive control, shared by both sweeps.
func requireWalked(t *testing.T, dirs map[string]bool) {
	t.Helper()
	for _, d := range []string{"internal/policy", "internal/cli", "internal/engine", "cmd/snug"} {
		if !dirs[d] {
			t.Fatalf("the sweep never visited %s, so it is not a module-wide check and a demote "+
				"there would ship green (issue #291 part 1b, verbatim). Visited %d directories.",
				d, len(dirs))
		}
	}
}

// ── positive controls ───────────────────────────────────────────────────────

// TestAccessWriteDetectorCatchesEveryDemoteSpelling is the mandatory positive
// control on P1, and it is why this file exists rather than a comment saying
// the invariant is enforced by review. Each fixture is source the detector
// must classify as something other than a join; if a future edit narrows the
// detector, this fails before the sweep can quietly stop measuring.
func TestAccessWriteDetectorCatchesEveryDemoteSpelling(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"the plain demote", `package p
func f(m *Mount) { m.Access = AccessRO }`, "assignment of AccessRO"},

		// The whole point of the property: a demote is not a name. None of the
		// three below contains AccessRO, AccessNone, Clamp, Apply, Restrict or
		// Derive anywhere.
		{"decrement", `package p
func f(m *Mount) { m.Access-- }`, "increment or decrement"},

		{"a helper that lowers", `package p
func f(m *Mount) { m.Access = tighten(m.Access) }`, "assignment of tighten(...)"},

		{"a Meet beside the Join", `package p
func f(m, o *Mount) { m.Access = m.Access.Meet(o.Access) }`, "assignment of m.Access.Meet(...)"},

		{"a Join of something else, discarding the previous value", `package p
func f(m, o *Mount) { m.Access = o.Access.Join(AccessNone) }`, "Join whose receiver is o.Access"},

		{"compound assignment", `package p
func f(m *Mount) { m.Access &= AccessRO }`, "compound assignment"},

		{"the value comes from a call this sweep cannot read", `package p
func f(m *Mount) { var err error; m.Access, err = clamp(); _ = err }`, "multi-value assignment"},

		{"address handed to a callee", `package p
func f(m *Mount) { lower(&m.Access) }`, "address taken"},

		{"a package-level initialiser", `package p
var x = func(m *Mount) { m.Access = AccessNone }`, "assignment of AccessNone"},

		// The receiver's spelling is not part of the property.
		{"an unfamiliar receiver name", `package p
func f(anything *Mount) { anything.Access = AccessRO }`, "assignment of AccessRO"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectInSource(t, accessWrites, tc.src)
			if len(got) == 0 {
				t.Fatalf("the detector reports nothing for this spelling, so a demote written "+
					"this way ships green:\n%s", tc.src)
			}
			if got[0].how == accessJoinHow {
				t.Fatalf("the detector classifies this as a join with the previous value:\n%s", tc.src)
			}
			if !strings.Contains(got[0].how, tc.want) {
				t.Errorf("classified as %q, want something containing %q", got[0].how, tc.want)
			}
		})
	}

	// NEGATIVE controls. A sweep that flagged a read would push the next
	// author towards a contorted spelling, and one that rejected join itself
	// would be unsatisfiable.
	for _, tc := range []struct{ name, src, want string }{
		{"the join Policy.join performs", `package p
func f(old, m Mount) Mount { old.Access = old.Access.Join(m.Access); return old }`, accessJoinHow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := detectInSource(t, accessWrites, tc.src)
			if len(got) != 1 || got[0].how != tc.want {
				t.Fatalf("classified as %v, want exactly one %q", got, tc.want)
			}
		})
	}

	clean := `package p
func f(m Mount, o Mount) bool {
	if m.Access == AccessRW { return true }
	x := m.Access
	_ = x.Join(o.Access)
	return m.Access > o.Access
}`
	if got := detectInSource(t, accessWrites, clean); len(got) != 0 {
		t.Errorf("the detector reports a READ of the field as a write: %v", got)
	}
}

// TestMountsMutationDetectorCatchesEveryDeriveSpelling is the positive control
// on P2. The first two fixtures are the `Derive` from issue #271 in the two
// shapes it can take, and the first is the one P1 cannot see: it lowers access
// without assigning to an Access field anywhere, by building fresh mounts.
func TestMountsMutationDetectorCatchesEveryDeriveSpelling(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"Derive rebuilding the mounts as fresh literals", `package p
func (p *Policy) Derive() *Policy {
	q := &Policy{Mounts: map[string]Mount{}}
	for g, m := range p.Mounts {
		q.Mounts[g] = Mount{Guest: m.Guest, Host: m.Host, Kind: m.Kind, Access: AccessRO, From: m.From}
	}
	return q
}`, "index assignment"},

		{"Derive replacing the map wholesale", `package p
func (p *Policy) Derive(m map[string]Mount) { p.Mounts = m }`, "whole-field assignment"},

		{"un-granting by delete", `package p
func (p *Policy) Prune(g string) { delete(p.Mounts, g) }`, "delete"},

		{"un-granting everything", `package p
func (p *Policy) Reset() { clear(p.Mounts) }`, "clear"},

		{"overwriting through maps.Copy", `package p
func (p *Policy) Load(other map[string]Mount) { maps.Copy(p.Mounts, other) }`, "maps.Copy"},

		{"aliasing the map so a later write is invisible", `package p
func (p *Policy) Sneak(g string, m Mount) { x := p.Mounts; x[g] = m }`, "alias assignment"},

		{"a write through the View that shares the map", `package p
func f(v View, g string, m Mount) { v.Mounts[g] = m }`, "index assignment"},

		{"address of the map handed to a callee", `package p
func f(p *Policy) { rebuild(&p.Mounts) }`, "address taken"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectInSource(t, mountsMutations, tc.src)
			if len(got) == 0 {
				t.Fatalf("the detector reports nothing for this spelling, so a mount-collection "+
					"writer written this way ships green:\n%s", tc.src)
			}
			var hows []string
			for _, s := range got {
				hows = append(hows, s.how)
			}
			if !strings.Contains(strings.Join(hows, ","), tc.want) {
				t.Errorf("reported %v, want one containing %q", hows, tc.want)
			}
		})
	}

	// NEGATIVE controls: the ordinary reads this module is full of. Each is a
	// real shape from internal/policy or internal/cli, and each is what a
	// naive pattern confuses with a write.
	clean := `package p
func f(p *Policy, guest string) int {
	for g := range p.Mounts { _ = g }
	for _, m := range p.Mounts { _ = m }
	m := p.Mounts[guest]
	_ = m
	if _, ok := p.Mounts[guest]; ok { return 1 }
	maps.Copy(dst, p.Mounts)
	return len(p.Mounts) + len(sortedGuests(p.Mounts))
}`
	if got := detectInSource(t, mountsMutations, clean); len(got) != 0 {
		t.Errorf("the detector reports one of these ordinary reads as a mutation: %v", got)
	}
}
