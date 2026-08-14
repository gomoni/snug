package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"testing"
)

// ── Gap 1b (issue #51 follow-up) — no struct in any production package that
// imports internal/policy may reach a policy.Secret through an UNEXPORTED
// field, BY VALUE ────────────────────────────────────────────────────────
//
// secret_test.go's TestFmtLeaksASecretBehindAnUnexportedFieldKnownLimit is the
// MEASUREMENT: fmt's printValue only calls handleMethods — the code path that
// checks Formatter/Stringer, i.e. what makes Secret.Format ever run — when
// reflect.Value.CanInterface() is true, and that is false for anything reached
// through an unexported struct field. So a Mount, a Policy, or a bare Secret
// sitting behind an unexported field skips Secret's redaction entirely and
// prints the raw bytes. A POINTER field is the one safe shape (fmt prints a
// bare address without dereferencing) — measured in production at
// internal/dockerproxy/proxy.go:41's `pol *policy.Policy` — so the property
// worth defending structurally is "no unexported field reaches Secret BY
// VALUE", not "no unexported field reaches anything Secret-shaped at all".
//
// Why THIS test is a source scan rather than a reflect sweep like Gap 2's:
// reflect can only ask "does this Go VALUE, that I already constructed,
// leak" — it has no way to enumerate "every struct type declared in these
// packages", most of which nothing in a test binary ever instantiates. The
// property this test defends is about every struct DECLARATION, so it has to
// read declarations, not values. go/parser is stdlib and needs no new
// dependency, matching the sweeps already in this file's neighbours
// (ownedenv_test.go, envdropreason_test.go) — this one shares goFilesIn with
// ownedenv_test.go rather than redefining it.
//
// What this sweep can and cannot see, said plainly rather than left to be
// assumed: it tracks named struct types declared ANYWHERE in a swept file —
// package-level or nested inside a function body, since a function-local
// helper struct is exactly as capable of leaking as a package-level one and
// go/ast draws no distinction the sweep is allowed to ignore — plus every
// unnamed (inline/anonymous) struct type literal used as a field's type,
// resolved structurally rather than through the name table. It resolves
// plain identifiers within the package they were declared in, and resolves
// one level of package-qualified reference — `policy.X` written from another
// swept file — back into the policy package's own table. Anything else (a
// type from a package this sweep does not read the source of, a generic
// instantiation, a type alias defined with `=`) is out of scope and treated
// as NOT containing a Secret; a struct that smuggles a Secret in through one
// of those routes would not be caught here. That is the same shape of limit
// TestSnugOwnedEnvIsExactlyWhatSnugWrites already accepts for AuthorEnv calls
// with a computed name — the fix there was "refuse the computed name outright
// rather than pretend to check it", which is not available here since we are
// reading declarations that already exist; the honest statement is the
// paragraph above, not a silent gap.
//
// Swept directories: every production package under this module that
// imports internal/policy — internal/policy itself, cmd/snug,
// internal/sandbox, internal/dockerproxy, internal/profile and
// internal/stage (loadProductionStructTables) — not just the two the sweep
// started with. internal/dockerproxy/proxy.go:41's `pol *policy.Policy` is
// the one live cross-package holder today, and it is a pointer (measured
// safe); the point of sweeping the rest is to keep the NEXT one from being
// latent instead of caught, per "assert the set rather than the site" above.
// poc/nsd mentions policy.Policy only in a code comment and does not import
// the package, so it is correctly not swept.

// structTable maps package label ("policy", "cmd", "sandbox", ...) -> type
// name -> struct AST. One label per swept directory, all in one table,
// because e.g. a cmd/snug field can be typed `policy.Mount` and resolving
// that reference means looking the name up in the policy label's half of the
// table.
type structTable map[string]map[string]*ast.StructType

// collectStructTypes parses every production .go file in dir and records each
// `type X struct{...}` declaration under pkg in into — at package level AND
// nested inside a function body (see recordStructTypes).
func collectStructTypes(t *testing.T, dir, pkg string, into structTable) {
	t.Helper()
	if into[pkg] == nil {
		into[pkg] = map[string]*ast.StructType{}
	}
	for _, name := range goFilesIn(t, dir) {
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		recordStructTypes(f, pkg, into)
	}
}

// recordStructTypes walks the WHOLE file, not just f.Decls, so a
// `type X struct{...}` declared inside a function body is recorded exactly
// like one declared at package level. f.Decls alone misses it in both
// directions that matter: it can never be RESOLVED as a field's type (it is
// not in the table at all), and — the sharper miss — it is never examined as
// a CONTAINER either, so an unexported by-value Mount/Policy/Secret field on
// a function-local helper struct would be invisible to this sweep even
// though fmt leaks it exactly as it would leak a package-level struct.
// ast.Inspect finds it because a local `type` declaration is wrapped in an
// *ast.DeclStmt inside the function's body, and go/ast's own Walk descends
// into DeclStmt.Decl the same way it descends into a top-level *ast.GenDecl.
func recordStructTypes(f *ast.File, pkg string, into structTable) {
	ast.Inspect(f, func(n ast.Node) bool {
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			return true
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			into[pkg][ts.Name.Name] = st
		}
		return true
	})
}

// typeContainsSecretByValue answers: following expr's type declaration
// through this table, is there a value-typed path (no pointer indirection)
// that reaches policy.Secret? pkg is the package expr's identifiers should be
// resolved in. visited guards against a cycle (none is expected in this
// codebase, but an infinite recursion would be a worse failure mode than a
// false negative).
func typeContainsSecretByValue(expr ast.Expr, pkg string, tables structTable, visited map[string]bool) bool {
	switch e := expr.(type) {
	case *ast.StarExpr:
		// A pointer breaks the by-value chain and is the one shape fmt
		// prints safely (bare address) when reached through an unexported
		// field — see the header comment and
		// TestFmtLeaksASecretBehindAnUnexportedFieldKnownLimit's pointerHolder
		// control in internal/policy/secret_test.go.
		return false
	case *ast.Ident:
		if pkg == "policy" && e.Name == "Secret" {
			return true
		}
		key := pkg + "." + e.Name
		if visited[key] {
			return false
		}
		st, ok := tables[pkg][e.Name]
		if !ok {
			// A primitive (string, bool, uint8, ...) or a type this sweep
			// does not track (see the header comment's scope paragraph).
			return false
		}
		visited[key] = true
		for _, field := range st.Fields.List {
			// Every field is checked here, regardless of its OWN
			// exportedness: once the walk has already crossed one
			// unexported field to get here, flagRO applies to everything
			// reached afterwards — a further EXPORTED sub-field does not
			// regain safety. Only the outer sweep (below) restricts itself
			// to unexported entry points; this inner walk must not.
			if typeContainsSecretByValue(field.Type, pkg, tables, visited) {
				return true
			}
		}
		return false
	case *ast.SelectorExpr:
		if x, ok := e.X.(*ast.Ident); ok && x.Name == "policy" {
			return typeContainsSecretByValue(&ast.Ident{Name: e.Sel.Name}, "policy", tables, visited)
		}
		return false // a reference into a third package — out of scope, see header comment
	case *ast.ArrayType:
		return typeContainsSecretByValue(e.Elt, pkg, tables, visited)
	case *ast.MapType:
		return typeContainsSecretByValue(e.Value, pkg, tables, visited)
	case *ast.Ellipsis:
		return typeContainsSecretByValue(e.Elt, pkg, tables, visited)
	case *ast.StructType:
		// An anonymous (inline) struct type literal used directly as a
		// field's type — `staged struct{ m policy.Mount }` — never has a
		// name to look up in tables, so it must be walked structurally
		// instead of resolved. Falling through to the default case here
		// used to report this shape as clean while fmt leaks it exactly as
		// it leaks mountHolder in secret_test.go; see the header comment.
		for _, field := range e.Fields.List {
			if typeContainsSecretByValue(field.Type, pkg, tables, visited) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// fieldNames returns the declared name(s) of a struct field, or — for an
// embedded field, which has no Names — the single name Go promotes it under,
// which is what its exportedness is actually judged on.
func fieldNames(f *ast.Field) []string {
	if len(f.Names) == 0 {
		switch t := f.Type.(type) {
		case *ast.Ident:
			return []string{t.Name}
		case *ast.SelectorExpr:
			return []string{t.Sel.Name}
		case *ast.StarExpr:
			return fieldNames(&ast.Field{Type: t.X})
		default:
			return []string{"<anonymous>"}
		}
	}
	out := make([]string, 0, len(f.Names))
	for _, n := range f.Names {
		out = append(out, n.Name)
	}
	return out
}

type secretFieldViolation struct{ pkg, typeName, field string }

// sweepUnexportedByValueSecretFields is the actual predicate under test: for
// every struct type in tables, for every field that is unexported, does that
// field's OWN type reach policy.Secret by value?
func sweepUnexportedByValueSecretFields(tables structTable) []secretFieldViolation {
	var out []secretFieldViolation
	for pkg, types := range tables {
		names := make([]string, 0, len(types))
		for n := range types {
			names = append(names, n)
		}
		sort.Strings(names) // deterministic failure order
		for _, typeName := range names {
			st := types[typeName]
			for _, field := range st.Fields.List {
				for _, name := range fieldNames(field) {
					if ast.IsExported(name) {
						continue
					}
					if typeContainsSecretByValue(field.Type, pkg, tables, map[string]bool{}) {
						out = append(out, secretFieldViolation{pkg, typeName, name})
					}
				}
			}
		}
	}
	return out
}

// loadProductionStructTables sweeps every production package under this
// module that imports internal/policy, not only the two the sweep started
// with (internal/policy and cmd/snug). internal/sandbox iterates
// p.SortedMounts() and internal/dockerproxy holds a *policy.Policy — today's
// only cross-package holder, and a pointer, measured safe — so both were
// live gaps in the narrower sweep, and internal/profile and internal/stage
// are swept for the same reason nothing in either currently needs it: the
// property this test defends is about every DECLARATION, so it has to cover
// every place a declaration could appear, not only the places one has
// appeared so far. (poc/nsd is not swept: it names policy.Policy in a code
// comment only and does not import the package.)
func loadProductionStructTables(t *testing.T) structTable {
	t.Helper()
	tables := structTable{}
	collectStructTypes(t, filepath.Join("..", "..", "internal", "policy"), "policy", tables)
	collectStructTypes(t, ".", "cmd", tables)
	collectStructTypes(t, filepath.Join("..", "..", "internal", "sandbox"), "sandbox", tables)
	collectStructTypes(t, filepath.Join("..", "..", "internal", "dockerproxy"), "dockerproxy", tables)
	collectStructTypes(t, filepath.Join("..", "..", "internal", "profile"), "profile", tables)
	collectStructTypes(t, filepath.Join("..", "..", "internal", "stage"), "stage", tables)
	return tables
}

func TestNoUnexportedByValueFieldReachesASecret(t *testing.T) {
	tables := loadProductionStructTables(t)

	// The sweep is only as good as what it actually parsed.
	for label, want := range map[string]string{
		"policy":      "Mount",
		"cmd":         "",
		"sandbox":     "Options",
		"dockerproxy": "Proxy",
		"profile":     "rawProfile",
		"stage":       "Config",
	} {
		if len(tables[label]) == 0 {
			t.Fatalf("swept 0 struct types under the %q label; the sweep is reading the wrong directory", label)
		}
		if want == "" {
			continue
		}
		if _, ok := tables[label][want]; !ok {
			t.Fatalf("the %q struct was not found under the %q label — the parse is not seeing the file that declares it", want, label)
		}
	}
	if _, ok := tables["policy"]["Policy"]; !ok {
		t.Fatal(`internal/policy's Policy struct was not found — the parse is not seeing types.go`)
	}

	for _, v := range sweepUnexportedByValueSecretFields(tables) {
		t.Errorf("%s.%s has an unexported field %q whose type reaches policy.Secret BY VALUE.\n"+
			"fmt's printValue only calls Formatter/Stringer when reflect.Value.CanInterface() is "+
			"true, and that is false for anything read through an unexported field — Secret's "+
			"redaction is skipped entirely there, and fmt prints the raw bytes instead (measured "+
			"in internal/policy/secret_test.go's TestFmtLeaksASecretBehindAnUnexportedFieldKnownLimit).\n"+
			"A POINTER field is safe (fmt prints a bare address, measured at "+
			"internal/dockerproxy/proxy.go:41); a BY-VALUE field is not. Either hold %s by pointer, "+
			"or stop embedding a Mount/Policy/Secret by value behind an unexported field.",
			v.pkg, v.typeName, v.field, v.field)
	}
}

// TestPositiveControlUnexportedByValueHoldersTripTheSweep proves the sweep can
// actually fail. Without it, "no struct in any swept package has this shape"
// could be true because the sweep never really resolves a field's type, not
// because the shape does not exist — the same reasoning every other positive
// control in this codebase exists for.
//
// mountHolder and runByValue already live in internal/policy/secret_test.go
// (they are secret_test.go's OWN positive controls for the fmt-level leak),
// but this test's job is different: it has to prove the SOURCE SCAN sees
// them, and secret_test.go is a _test.go file this sweep deliberately does
// not read (see collectStructTypes / goFilesIn — production files only, so a
// test fixture cannot widen or narrow what counts as a violation). So this
// parses the exact two shapes named in the issue —
// `unexportedMountHolder{m Mount}` and `unexportedPolicyHolder{p Policy}` —
// from an in-memory source string and merges them into the SAME table the
// real sweep just built, which is what proves the check function itself,
// not a fixture built to please it, is what is being exercised.
func TestPositiveControlUnexportedByValueHoldersTripTheSweep(t *testing.T) {
	tables := loadProductionStructTables(t)

	const src = `package policy

type unexportedMountHolder struct {
	m Mount
}

type unexportedPolicyHolder struct {
	p Policy
}

// The negative control in the same source: a POINTER under an unexported
// field must NOT trip the sweep, or the "by value, not any reference"
// property this test defends is being enforced by a predicate that flags
// everything indiscriminately.
type unexportedPointerHolder struct {
	p *Policy
}
`
	f, err := parser.ParseFile(token.NewFileSet(), "control.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the control source: %v", err)
	}
	recordStructTypes(f, "policy", tables)

	violations := map[string]bool{}
	for _, v := range sweepUnexportedByValueSecretFields(tables) {
		violations[v.pkg+"."+v.typeName+"."+v.field] = true
	}

	for _, want := range []string{
		"policy.unexportedMountHolder.m",
		"policy.unexportedPolicyHolder.p",
	} {
		if !violations[want] {
			t.Errorf("the sweep did not flag %s — it cannot see the shape it exists to catch, "+
				"which means TestNoUnexportedByValueFieldReachesASecret's clean result on the "+
				"real trees is true for the wrong reason", want)
		}
	}

	if violations["policy.unexportedPointerHolder.p"] {
		t.Errorf("the sweep flagged unexportedPointerHolder.p, a POINTER field, as a violation — " +
			"the sweep is no longer distinguishing by-value from by-reference, and would now " +
			"reject internal/dockerproxy/proxy.go's own `pol *policy.Policy`, which is the " +
			"measured-safe shape this whole design relies on")
	}
}

// TestPositiveControlAnonymousInlineStructTripsTheSweep proves
// typeContainsSecretByValue's *ast.StructType case actually recurses into an
// unnamed struct type literal used directly as a field's type, rather than
// falling into the `default: return false` branch that used to swallow it.
// `staged struct{ m Mount }` has no name to look up in the table — it has to
// be walked structurally — and before the fix this shape was reported clean
// while fmt leaks it exactly as it leaks mountHolder in secret_test.go.
func TestPositiveControlAnonymousInlineStructTripsTheSweep(t *testing.T) {
	tables := loadProductionStructTables(t)

	const src = `package policy

type anonymousStagedHolder struct {
	staged struct{ m Mount }
}

// The negative control: an anonymous struct whose only path to Secret goes
// through a POINTER must not trip the sweep either — the by-value property
// applies just as much inside an inline struct type as inside a named one.
type anonymousPointerHolder struct {
	staged struct{ p *Policy }
}
`
	f, err := parser.ParseFile(token.NewFileSet(), "anon_control.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the control source: %v", err)
	}
	recordStructTypes(f, "policy", tables)

	violations := map[string]bool{}
	for _, v := range sweepUnexportedByValueSecretFields(tables) {
		violations[v.pkg+"."+v.typeName+"."+v.field] = true
	}

	if !violations["policy.anonymousStagedHolder.staged"] {
		t.Error("the sweep did not flag anonymousStagedHolder.staged — an anonymous inline struct " +
			"type reaching Secret by value through a nested field is invisible to the sweep, which " +
			"means the header comment's scope paragraph is claiming coverage this predicate does " +
			"not have")
	}
	if violations["policy.anonymousPointerHolder.staged"] {
		t.Error("the sweep flagged anonymousPointerHolder.staged, whose only path to Secret is a " +
			"POINTER, as a violation — the anonymous-struct case is not distinguishing by-value " +
			"from by-reference the way the named-struct case does")
	}
}

// TestPositiveControlFunctionLocalStructTripsTheSweep proves recordStructTypes
// finds a `type X struct{...}` declared inside a function body, not only one
// declared at package level. Before the fix, f.Decls never contained it, so
// it was invisible in BOTH directions: unresolvable as a field's type, and —
// the sharper miss — never examined as a CONTAINER, so an unexported by-value
// Mount field on a function-local helper struct was missed entirely rather
// than merely mis-resolved.
func TestPositiveControlFunctionLocalStructTripsTheSweep(t *testing.T) {
	tables := loadProductionStructTables(t)

	const src = `package policy

func helper() {
	type localMountHolder struct {
		m Mount
	}
	_ = localMountHolder{}
}
`
	f, err := parser.ParseFile(token.NewFileSet(), "local_control.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the control source: %v", err)
	}
	recordStructTypes(f, "policy", tables)

	if _, ok := tables["policy"]["localMountHolder"]; !ok {
		t.Fatal("recordStructTypes did not record localMountHolder at all — a function-local " +
			"`type` declaration is invisible to the sweep, so it is never examined as a container " +
			"even before asking whether it can be resolved as a field's type")
	}

	violations := map[string]bool{}
	for _, v := range sweepUnexportedByValueSecretFields(tables) {
		violations[v.pkg+"."+v.typeName+"."+v.field] = true
	}

	if !violations["policy.localMountHolder.m"] {
		t.Error("the sweep did not flag localMountHolder.m — a function-local struct with an " +
			"unexported by-value Mount field is invisible to the sweep, exactly as invisible as it " +
			"is to fmt's own redaction, which does not care where the struct was declared")
	}
}
