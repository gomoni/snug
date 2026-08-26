package policy

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gomoni/snug/test/modroot"
)

// authoredField is the field name both Mount and Graft declare and both
// exemptions key on. The sweep below is written against the NAME rather than
// against a resolved type: a write to `Authored` on any struct in this module
// is worth a human look, and matching by name needs no type checker and so no
// new dependency in a go.mod whose every entry runs with the authority of the
// thing building the sandbox.
const authoredField = "Authored"

// authoredBearingTypes are the types that declare the field. They matter for
// exactly one detection the field name cannot make on its own: an UNKEYED
// composite literal writes every field positionally without ever spelling one.
var authoredBearingTypes = map[string]bool{"Mount": true, "Graft": true}

// authoredSite is one place the module writes the field, with the spelling
// that found it — the spelling is in the failure message because "a fourth
// writer exists" and "a fourth writer exists AS A COMPOSITE LITERAL" send a
// reader to different lines.
type authoredSite struct {
	file string // module-root-relative, forward slashes
	line int
	how  string
}

func (s authoredSite) String() string { return fmt.Sprintf("%s:%d (%s)", s.file, s.line, s.how) }

// findAuthoredWrites parses every non-test .go file under root and returns
// every write to a field named Authored.
//
// It replaces a regexp (`\.Authored\s*=[^=]`) run over `internal/` only, which
// issue #291 measured green against THREE separate fourth writers: a composite
// literal `Mount{..., Authored: true}` (the way every other Mount in this tree
// is built, and the regexp never sees an `=` at all), an assignment in
// `cmd/snug/main.go` (outside the walk root), and `join` inheriting the field
// on merge (not a write, and handled by TestJoinDoesNotInheritAuthored below,
// not here).
//
// Four spellings are detected:
//
//	x.Authored = v          assignment, including compound and multi-value
//	Mount{Authored: v}      keyed composite literal, any type
//	Mount{a, b, ...}        UNKEYED composite literal of an Authored-bearing
//	                        type — writes the field positionally, naming
//	                        nothing. Elided element types inside a slice or
//	                        map literal are resolved through the parent.
//	&x.Authored             address taken, which is a write the callee makes
//
// What it does NOT catch, stated rather than implied: reflection, unsafe, a
// type alias of Mount or Graft declared elsewhere, and a plain struct COPY
// (`m2 := m1`) that carries an already-true field to a new guest path. The
// copy is the interesting residual and it is why TestJoinDoesNotInheritAuthored
// exists: propagation, not authorship, was issue #291's live finding.
func findAuthoredWrites(root string) ([]authoredSite, []string, error) {
	var sites []authoredSite
	var filesSeen []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		// A source sweep walks a tree other packages' tests are writing in. An entry
		// that vanished between its parent's ReadDir and this call is not a source
		// file and is not this sweep's business: skipping it keeps a failure in
		// THIS package from being caused by another one (issue #350).
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			// Dotted directories are skipped for a REASON, not for tidiness:
			// `.claude/worktrees/` in the primary checkout holds complete
			// copies of this tree on other branches, and walking them would
			// make this test report another branch's writers as this one's.
			// `vendor` would double-count the module's own files if it ever
			// appears.
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
		filesSeen = append(filesSeen, rel)

		src, rerr := os.ReadFile(path)
		// The file can vanish between the walk naming it and this read, for
		// the reason above.
		if errors.Is(rerr, fs.ErrNotExist) {
			return nil
		}
		if rerr != nil {
			return rerr
		}
		found, perr := authoredWritesInSource(rel, src)
		if perr != nil {
			return perr
		}
		sites = append(sites, found...)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].file != sites[j].file {
			return sites[i].file < sites[j].file
		}
		return sites[i].line < sites[j].line
	})
	sort.Strings(filesSeen)
	return sites, filesSeen, nil
}

// authoredWritesInSource is the detector proper, split out from the walk so
// the positive control below can drive it against source text it authors
// itself rather than against files it would have to create on disk.
func authoredWritesInSource(name string, src []byte) ([]authoredSite, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	var sites []authoredSite
	add := func(pos token.Pos, how string) {
		sites = append(sites, authoredSite{file: name, line: fset.Position(pos).Line, how: how})
	}

	// Elided element types: `[]Mount{{...}}` and `map[string]Mount{k: {...}}`
	// give the inner literal a nil Type, so the type is read off the parent.
	elidedType := map[*ast.CompositeLit]string{}
	var noteChildren func(cl *ast.CompositeLit)
	noteChildren = func(cl *ast.CompositeLit) {
		elem := elementTypeName(cl.Type)
		if elem == "" {
			if outer, ok := elidedType[cl]; ok {
				elem = outer
			}
		}
		for _, e := range cl.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				e = kv.Value
			}
			if child, ok := e.(*ast.CompositeLit); ok && child.Type == nil && elem != "" {
				elidedType[child] = elem
			}
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range v.Lhs {
				if isAuthoredSelector(lhs) {
					add(lhs.Pos(), "assignment")
				}
			}
		case *ast.UnaryExpr:
			if v.Op == token.AND && isAuthoredSelector(v.X) {
				add(v.Pos(), "address taken")
			}
		case *ast.CompositeLit:
			noteChildren(v)
			keyed := false
			for _, e := range v.Elts {
				kv, ok := e.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				keyed = true
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == authoredField {
					add(kv.Pos(), "keyed composite literal")
				}
			}
			if len(v.Elts) > 0 && !keyed {
				typeName := baseTypeName(v.Type)
				if typeName == "" {
					typeName = elidedType[v]
				}
				if authoredBearingTypes[typeName] {
					add(v.Pos(), "unkeyed composite literal of "+typeName)
				}
			}
		}
		return true
	})
	return sites, nil
}

func isAuthoredSelector(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == authoredField
}

// baseTypeName names the struct a composite literal builds, unwrapping the
// spellings that still build one: `&Mount{}`, `policy.Mount{}`, `*Mount`.
func baseTypeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		if v.Sel != nil {
			return v.Sel.Name
		}
	case *ast.StarExpr:
		return baseTypeName(v.X)
	case *ast.ParenExpr:
		return baseTypeName(v.X)
	}
	return ""
}

// elementTypeName names what a slice, array or map literal holds, which is
// what an elided inner literal's type is.
func elementTypeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.ArrayType:
		return baseTypeName(v.Elt)
	case *ast.MapType:
		return baseTypeName(v.Value)
	case *ast.StarExpr:
		return elementTypeName(v.X)
	case *ast.ParenExpr:
		return elementTypeName(v.X)
	}
	return ""
}

// TestAuthoredWriteDetectorCatchesEverySpelling is the mandatory positive
// control, and it is the whole reason this rewrite exists. The regexp it
// replaces could not fail on three of the shapes below, and NOTHING said so —
// the test passed, which reads as proof.
//
// Each fixture is source the detector must flag. If a future edit narrows the
// detector, this fails before the sweep can quietly stop measuring.
func TestAuthoredWriteDetectorCatchesEverySpelling(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string // substring of the reported spelling
	}{
		{"plain assignment", `package p
type Mount struct{ Authored bool }
func f(m *Mount) { m.Authored = true }`, "assignment"},

		{"assignment in a multi-value statement", `package p
type Mount struct{ Authored bool }
func f(m *Mount, b bool) { b, m.Authored = false, true }`, "assignment"},

		// Issue #291 part 1a, measured green under the regexp: there is no
		// ` = ` after `.Authored` anywhere in this text.
		{"keyed composite literal", `package p
type Mount struct{ Guest string; Authored bool }
func f() Mount { return Mount{Guest: "/x", Authored: true} }`, "keyed composite literal"},

		{"keyed composite literal, address-of form", `package p
type Mount struct{ Authored bool }
func f() *Mount { return &Mount{Authored: true} }`, "keyed composite literal"},

		{"keyed composite literal, elided in a slice", `package p
type Mount struct{ Authored bool }
func f() []Mount { return []Mount{{Authored: true}} }`, "keyed composite literal"},

		// The field is written and never named. A name-based sweep of any
		// kind — regexp or AST — misses this without the type check.
		{"unkeyed composite literal", `package p
type Mount struct{ Guest string; Authored bool }
func f() Mount { return Mount{"/x", true} }`, "unkeyed composite literal"},

		{"unkeyed composite literal, elided in a slice", `package p
type Mount struct{ Guest string; Authored bool }
func f() []Mount { return []Mount{{"/x", true}} }`, "unkeyed composite literal"},

		{"unkeyed composite literal, elided in a map", `package p
type Mount struct{ Guest string; Authored bool }
func f() map[string]Mount { return map[string]Mount{"a": {"/x", true}} }`, "unkeyed composite literal"},

		{"unkeyed composite literal, qualified type", `package p
import "github.com/gomoni/snug/internal/policy"
func f() policy.Mount { return policy.Mount{"/x", true} }`, "unkeyed composite literal"},

		{"address of the field", `package p
type Mount struct{ Authored bool }
func f(m *Mount) *bool { return &m.Authored }`, "address taken"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := authoredWritesInSource("fixture.go", []byte(tc.src))
			if err != nil {
				t.Fatalf("the fixture does not parse, so this control measures nothing: %v", err)
			}
			if len(got) == 0 {
				t.Fatalf("the detector does not flag this spelling, so a fourth Authored "+
					"writer written this way would ship green:\n%s", tc.src)
			}
			if !strings.Contains(got[0].how, tc.want) {
				t.Errorf("flagged as %q, want a %q", got[0].how, tc.want)
			}
		})
	}

	// NEGATIVE control for the detector itself: a comparison is not a write,
	// and a sweep that flagged one would push a reader towards the contorted
	// spelling authoredWriteRE's `[^=]` was there to avoid.
	clean := `package p
type Mount struct{ Authored bool }
func f(m Mount) bool { if m.Authored { return true }; return m.Authored == false }`
	got, err := authoredWritesInSource("clean.go", []byte(clean))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("the detector flags a READ of the field as a write: %v", got)
	}
}

// TestAuthoredWritersAreTheThreeTheCommentsName makes the "a profile cannot
// borrow the exemption" argument CHECKABLE instead of prose.
//
// Two rules rest on Mount.Authored: rejectMasking's RULE 3 (snug may replace
// what a profile exposed) and rejectEndpointSource (#219 — snug's own proxy
// sockets are sockets, deliberately). Both carried the same sentence — "set
// only by Policy.Replace, which nothing a profile can write reaches" — and it
// was false in both: there are THREE writers. The exemption survives, for a
// reason that has to be given per writer:
//
//	Policy.Replace   snug's own post-resolve writes; a profile cannot express one
//	Policy.Graft     writes p.Grafts, a different map neither rule reads
//	Policy.yieldTo   installs base mounts ONLY at an unclaimed guest, so a
//	                 profile's grant is left UNauthored and RULE 4 can name it
//
// A FOURTH site writes the field and is not a writer in that sense: join's
// meet (resolve.go) can only ever CLEAR it. It is listed below with the other
// three deliberately — the sweep's job is to make every write visible, and
// deciding which ones grant the exemption is the reader's, once.
//
// The same false sentence in two places is this project's most-repeated shape
// — a rule written once and applied to one of its halves — and prose cannot
// notice a fourth writer arriving. This test can: if one does, it fails here,
// pointing at the comments whose argument would then be incomplete rather than
// merely out of date.
func TestAuthoredWritersAreTheThreeTheCommentsName(t *testing.T) {
	root, err := modroot.Find()
	if err != nil {
		t.Fatal(err)
	}
	sites, filesSeen, err := findAuthoredWrites(root)
	if err != nil {
		t.Fatal(err)
	}

	// POSITIVE CONTROL on the WALK, not on the detector: issue #291 part 1b
	// was a writer in cmd/snug, outside the old walk root, and the old test
	// could not have said so. Assert the sweep really reaches code outside
	// internal/policy and outside internal/ altogether — otherwise "three
	// writers" is a statement about whatever subtree happened to be walked.
	seen := map[string]bool{}
	for _, f := range filesSeen {
		seen[filepath.Dir(f)] = true
	}
	for _, dir := range []string{"internal/policy", "internal/cli", "internal/engine", "cmd/snug"} {
		if !seen[dir] {
			t.Fatalf("the sweep never visited %s, so it is not a module-wide check and a "+
				"writer there would ship green (this is issue #291 part 1b, verbatim). "+
				"Visited %d files under %s.", dir, len(filesSeen), root)
		}
	}

	var files []string
	for _, s := range sites {
		files = append(files, s.file)
	}
	// The FILES rather than the line numbers: a line moves whenever anything
	// above it is edited, and a test that fails on an unrelated edit is a test
	// people learn to update without reading. resolve.go appears TWICE and the
	// duplicate is load-bearing — yieldTo SETS the field, join only ever
	// CLEARS it (the meet, issue #291 part 1c). Collapsing this to a set would
	// let a fourth SETTER land in resolve.go unnoticed.
	want := []string{
		"internal/policy/graft.go",   // Policy.Graft   — sets
		"internal/policy/resolve.go", // Policy.join    — meets (can only clear)
		"internal/policy/resolve.go", // Policy.yieldTo — sets
		"internal/policy/types.go",   // Policy.Replace — sets
	}
	if len(files) != len(want) {
		t.Fatalf("Authored is written at %v (%d sites), want exactly %v.\n"+
			"Two security rules — rejectMasking's RULE 3 and rejectEndpointSource — exempt an\n"+
			"Authored mount, and both justify it by naming who can set the field. A new writer\n"+
			"is a new way for a mount to become exempt, so it belongs in that argument or it\n"+
			"belongs nowhere. If the new site only ever CLEARS the field, say so where you add\n"+
			"it to this list — the exemption is what needs justifying, not the assignment.",
			sites, len(sites), want)
	}
	for i := range files {
		if files[i] != want[i] {
			t.Errorf("Authored is written in %s (%s); the writers the comments name are %v",
				files[i], sites[i].how, want)
		}
	}
}

// TestJoinDoesNotInheritAuthored is issue #291 part 1c, which is not a
// "writer" at all and is why enumerating writers was enumerating the wrong
// thing.
//
// MEASURED on main 022410b: `join` merges a profile's grant into the EXISTING
// entry at that guest path and keeps its fields, so a profile's `rw` grant
// landing on an authored mount produced `Authored=true Access=rw
// From=[(snug) hostile]` — a mount a profile contributed to, wearing snug's
// exemption from BOTH rejectMasking RULE 3 and rejectEndpointSource.
//
// Unreachable in the shipped path ONLY because Resolve folds profiles (step 3)
// before every Replace/yieldTo (step 3b/4). NOTHING asserted that ordering,
// so the property rested on statement order in one function — exactly the
// shape CLAUDE.md calls a rule written somewhere it can be forgotten.
//
// The fix is in join itself and it is a MEET, not a demotion of access:
// `old.Authored = old.Authored && m.Authored`. Authorship is a claim about
// PROVENANCE ("snug wrote this itself", types.go), so a mount any profile
// contributed to is not authored by definition, and the merge result says so.
// Commutative and idempotent like every other field join here, so Resolve's
// fixpoint properties are untouched; and it fails CLOSED — losing the
// exemption means Validate NAMES the profile rather than waving it through.
func TestJoinDoesNotInheritAuthored(t *testing.T) {
	const guest = "/snug/authored"

	// A profile grant, exactly as the fold builds one: never Authored.
	profileGrant := Mount{
		Guest: guest, Host: "/opt", Kind: KindBind,
		Access: AccessRW, From: []string{"hostile"},
	}

	t.Run("a profile grant merged into an authored mount drops the exemption", func(t *testing.T) {
		p := &Policy{Mounts: map[string]Mount{}}
		p.Replace(Mount{
			Guest: guest, Host: "/opt", Kind: KindBind,
			Access: AccessRO, From: []string{"(snug)"},
		})

		// POSITIVE CONTROL: the fixture really is authored before the join,
		// otherwise the assertion below passes on a mount that never carried
		// the exemption at all.
		if !p.Mounts[guest].Authored {
			t.Fatal("the fixture mount is not Authored before the join, so this test measures nothing")
		}

		if err := p.join(profileGrant); err != nil {
			t.Fatalf("join: %v", err)
		}
		got := p.Mounts[guest]

		// POSITIVE CONTROL: the merge really happened. Without this, a join
		// that silently discarded the profile's grant would satisfy every
		// assertion below while leaving the mount untouched.
		if got.Access != AccessRW {
			t.Fatalf("the profile's rw grant did not merge (Access=%v), so this test measures nothing", got.Access)
		}
		if len(got.From) != 2 {
			t.Fatalf("the profile is not recorded in the provenance %v, so the merge did not happen", got.From)
		}

		if got.Authored {
			t.Errorf("a mount a profile contributed to is still Authored (From=%v). It is exempt "+
				"from rejectMasking RULE 3 and from rejectEndpointSource, which is the loophole "+
				"issue #291 part 1c measured.", got.From)
		}
	})

	t.Run("snug's own repeated write keeps the exemption", func(t *testing.T) {
		// The other half, and the one that makes the first half a MEET rather
		// than an unconditional clear: two authored contributions to one guest
		// path stay authored. Without this, a fix that simply cleared the
		// field on every join would pass the subtest above by destroying the
		// exemption outright.
		p := &Policy{Mounts: map[string]Mount{}}
		snugs := Mount{
			Guest: guest, Host: "/opt", Kind: KindBind,
			Access: AccessRO, From: []string{"(snug)"}, Authored: true,
		}
		p.Mounts[guest] = snugs
		if err := p.join(snugs); err != nil {
			t.Fatalf("join: %v", err)
		}
		if !p.Mounts[guest].Authored {
			t.Error("two of snug's OWN contributions at one guest path lost the exemption; " +
				"the join is a meet over provenance, not an unconditional clear")
		}
	})

	t.Run("the ordering this no longer depends on", func(t *testing.T) {
		// Resolve folds profiles before Replace/yieldTo, which is what made
		// part 1c unreachable in the shipped path. That is still TRUE and
		// still worth stating — but it is now a second line of defence rather
		// than the only one. Drive the real resolver with a profile granting
		// a path snug also authors, and assert the resulting mount is not
		// exempt whichever way the two arrived.
		reg := testRegistry()
		reg["hostile"] = &Profile{Name: "hostile", RW: []string{"/opt:/tmp"}}
		p, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "hostile"}, testCtx(), newFakeEnv())
		if err != nil {
			t.Fatal(err)
		}
		m, ok := p.Mounts["/tmp"]
		if !ok {
			t.Fatal("/tmp is not in the policy, so this test measures nothing")
		}
		// /tmp is the one path yieldTo is MEANT to yield (@tmp-shared works
		// this way), so the profile's grant wins outright and must not be
		// wearing snug's exemption.
		if m.Authored {
			t.Errorf("/tmp came from the profile %v and is Authored", m.From)
		}
	})
}

// TestAuthoredIsNotSettableFromProfileText is the other half, and it is the
// one a reader actually cares about: whatever the writers are, no profile can
// reach them.
//
// Profile is the whole of what a TOML file can say. If none of its fields is
// named Authored — and no path from ParseProfile to a Mount copies one — then
// the exemption cannot be requested, only granted by snug's own code. This is
// asserted structurally rather than by reading the parser, because the parser
// is the thing that would change.
func TestAuthoredIsNotSettableFromProfileText(t *testing.T) {
	// A profile that tries every spelling a TOML author might reach for is
	// beside the point: the type has no such field, so this is a compile-time
	// property. What CAN drift is a future Mount built FROM profile text
	// carrying Authored through, so the check is on the resolved policy.
	reg := testRegistry()
	reg["binder"] = &Profile{Name: "binder", RO: []string{"/opt:/home/u/mounted"}}
	p, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "binder"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	m, ok := p.Mounts["/home/u/mounted"]
	if !ok {
		t.Fatal("the fixture profile's grant is not in the policy, so this test measured nothing")
	}
	if m.Authored {
		t.Error("a mount that came from PROFILE TEXT is Authored — it would be exempt from " +
			"rejectMasking's RULE 3 and from rejectEndpointSource, which is exactly the " +
			"loophole both comments claim is impossible")
	}
}
