package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ── Issue #67 — policy.NewProfileName is the ONLY door ───────────────────────
//
// policy.ProfileName is a defined type over `string`, so a value of type
// `string` is NOT assignable to it: Go's assignability rule requires one of the
// two types to be unnamed, and `string` is predeclared and named. The
// consequence is the whole reason the type is worth its churn — **the only way
// runtime data becomes a ProfileName is an explicit `ProfileName(x)`
// conversion**, and a conversion is a syntactic shape a sweep can find.
//
// So this file asserts the property over the PACKAGE SET rather than over the
// call sites someone remembered: outside the constructor's own file, no
// production .go file in this module writes that conversion. Then
// `NewProfileName` stops being something a caller must remember to call and
// becomes something a caller cannot avoid — which is the difference between a
// grammar that holds and a grammar that held last time anyone looked.
//
// # What is deliberately NOT a violation, and why each is safe
//
//   - An untyped string CONSTANT in a ProfileName context —
//     `[]policy.ProfileName{"@sys"}`, `reg["@sys"]`, `Name: "root"`. Go converts
//     these at compile time with no conversion node, and they are safe BY
//     CONSTRUCTION: a constant cannot carry runtime data. profile.BuiltinDefaults
//     is exactly this shape. (They are not thereby guaranteed GRAMMATICAL —
//     internal/profile's TestEveryBuiltinNamePassesTheNameGrammar is what checks
//     that, over the built registry rather than over the source.)
//   - `string(name)` — the SAFE direction, out of the type. NameStrings and
//     JoinNames exist so most of those live in one file too, but a stray one
//     leaks nothing.
//   - `map[policy.ProfileName]*policy.Profile(reg)` — a conversion of a named
//     MAP type to its underlying type. Its operand is already keyed by
//     ProfileName, so no name is constructed; the Fun of that call is an
//     *ast.MapType, not the type's own identifier, so the predicate below does
//     not match it. `[]ProfileName(someStringSlice)` is not expressible at all:
//     Go refuses a slice conversion whose element types differ.
//
// # What this sweep genuinely cannot see
//
// Reflection. A decoder writing into a ProfileName-typed struct field never
// calls the constructor and never writes a conversion —
// TestNoDecodedStructFieldIsAProfileName below is the second half that closes
// it. And `unsafe`, which this module does not use.
//
// A _test.go file is exempt, deliberately and by the same reasoning
// unexportedsecretfield_test.go uses for its own scan: a fixture must be able
// to build a name the grammar refuses in order to prove a RENDERER is still
// safe (see namegrammar_test.go's ESC-bearing registry keys). Making that
// impossible would delete the tests that prove the sinks hold. What matters is
// that the bypass is impossible in code that ships.

// conversionExemptFile is the one production file allowed to write the
// conversion: policy.NewProfileName's own, which is where the grammar is
// applied. Exempting the FILE and not the whole policy package is deliberate —
// internal/policy has twenty-odd other files, and "the constructor's package"
// would let any of them build a name without the grammar.
const conversionExemptFile = "internal/policy/profilename.go"

// productionGoFiles is every non-test .go file in the module, relative to the
// module root, sorted.
//
// A WALK rather than a hand-written list of packages, for the reason
// unexportedsecretfield_test.go's own header gives and CLAUDE.md restates about
// the writable-surface count: a list is a copy of state held somewhere else and
// drifts silently the moment a package is added. A new package is covered the
// day it exists.
func productionGoFiles(t *testing.T) (root string, files []string) {
	t.Helper()
	root = filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", "testdata", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
	sort.Strings(files)
	return root, files
}

// profileNameConversions returns the line numbers at which f converts something
// to policy.ProfileName. Both spellings: the bare `ProfileName(x)` an
// internal/policy file would write, and the qualified `policy.ProfileName(x)`
// every other package writes.
//
// A conversion is an *ast.CallExpr with exactly one argument whose Fun is the
// type's identifier. Nothing in this module declares a FUNCTION by that name,
// so there is no ambiguity to resolve; if one is ever added, this sweep will
// flag it, which is the correct direction to be wrong in.
func profileNameConversions(fset *token.FileSet, f *ast.File) []int {
	var lines []int
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			if fun.Name == "ProfileName" {
				lines = append(lines, fset.Position(call.Pos()).Line)
			}
		case *ast.SelectorExpr:
			x, ok := fun.X.(*ast.Ident)
			if ok && x.Name == "policy" && fun.Sel.Name == "ProfileName" {
				lines = append(lines, fset.Position(call.Pos()).Line)
			}
		}
		return true
	})
	return lines
}

func TestOnlyTheConstructorConvertsToAProfileName(t *testing.T) {
	root, files := productionGoFiles(t)

	// CONTROL 1: the walk found the module. Without it every assertion below is
	// vacuously true because the loop body never runs — the pasta.avx2 shape.
	if len(files) < 20 {
		t.Fatalf("the walk found only %d production files (%v); it is reading the wrong tree "+
			"and this sweep cannot fail", len(files), files)
	}
	seen := map[string]bool{}
	for _, f := range files {
		seen[f] = true
	}
	for _, want := range []string{
		conversionExemptFile,
		"internal/policy/resolve.go",
		"internal/profile/file.go",
		"internal/engine/engine.go",
		"cmd/snug/main.go",
	} {
		if !seen[want] {
			t.Fatalf("the walk did not reach %s, so a conversion there would be invisible", want)
		}
	}

	// CONTROL 2, and it is the load-bearing one: the DETECTOR must fire on real
	// code, not merely on a fixture. profilename.go contains the legal
	// conversions, so removing its exemption must produce violations. If it does
	// not, the predicate is broken and every clean file below is clean for the
	// wrong reason.
	fset := token.NewFileSet()
	exempt, err := parser.ParseFile(fset, filepath.Join(root, conversionExemptFile), nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", conversionExemptFile, err)
	}
	if n := len(profileNameConversions(fset, exempt)); n == 0 {
		t.Fatalf("%s contains NO ProfileName conversion, so the detector has never matched "+
			"anything real. Either the constructor stopped converting (in which case this "+
			"exemption is pointless) or profileNameConversions does not work", conversionExemptFile)
	}

	for _, rel := range files {
		if rel == conversionExemptFile {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", rel, err)
		}
		for _, line := range profileNameConversions(fset, f) {
			t.Errorf("%s:%d converts to policy.ProfileName.\n"+
				"A ProfileName is a profile name that has been through the grammar, and "+
				"policy.NewProfileName is the only thing that applies it. A conversion "+
				"bypasses it silently: nothing about `policy.ProfileName(s)` says the value "+
				"was never checked, and the compiler will not object.\n"+
				"Call policy.NewProfileName (or NewProfileNames for a list) and handle the "+
				"error. If you are re-marking or un-marking a name you already have, use "+
				"ProfileName.Marked / .Bare / .CutMark, which are closed over the grammar. "+
				"Only %s may write the conversion.", rel, line, conversionExemptFile)
		}
	}
}

// TestPositiveControlAProfileNameConversionTripsTheSweep proves the sweep can
// fail on the shape it exists to catch, in BOTH spellings, and that it does not
// fire on the four shapes the header comment calls safe.
//
// Control 2 above already proves the detector matches real code; this proves it
// matches the specific bypass a future patch would introduce, and — through the
// negative half — that it is not simply flagging every mention of the type.
func TestPositiveControlAProfileNameConversionTripsTheSweep(t *testing.T) {
	const bypass = `package main

import "github.com/gomoni/snug/internal/policy"

func sneakQualified(s string) policy.ProfileName {
	return policy.ProfileName(s)
}
`
	const bypassLocal = `package policy

func sneakBare(s string) ProfileName {
	return ProfileName(s)
}
`
	// Every shape the header comment says is legal, in one file. If the
	// predicate flags any of these it would reject the codebase as it stands.
	const clean = `package main

import "github.com/gomoni/snug/internal/policy"

type reg map[policy.ProfileName]*policy.Profile

func fine(r reg, n policy.ProfileName, raw string) (string, []policy.ProfileName, error) {
	_ = map[policy.ProfileName]*policy.Profile(r)   // named map -> underlying map
	_ = string(n)                                    // out of the type: safe direction
	list := []policy.ProfileName{"@sys", "@cwd-rw"}  // untyped constants
	out, err := policy.NewProfileName(raw)           // the door
	return string(out), list, err
}
`
	for _, tc := range []struct {
		name string
		src  string
		want int
	}{
		{"qualified", bypass, 1},
		{"bare", bypassLocal, 1},
		{"clean", clean, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, tc.name+".go", tc.src, 0)
			if err != nil {
				t.Fatalf("parsing the control source: %v", err)
			}
			got := profileNameConversions(fset, f)
			if len(got) != tc.want {
				t.Fatalf("profileNameConversions found %d conversions at %v, want %d.\n"+
					"For the two bypass cases this means TestOnlyTheConstructorConvertsToAProfileName "+
					"is clean for the wrong reason; for the clean case it means the sweep would "+
					"reject shapes the codebase legitimately uses.", len(got), got, tc.want)
			}
		})
	}
}

// TestNoDecodedStructFieldIsAProfileName closes the one door a conversion sweep
// structurally cannot see.
//
// go-toml (and encoding/json, and every other decoder) writes struct fields by
// REFLECTION. `Defaults []policy.ProfileName \`toml:"defaults"\“ would put a
// user's text straight into the type with no conversion in the source and no
// call to NewProfileName — the value would then be a ProfileName that had never
// met the grammar, and everything downstream would believe it had. So the raw
// decode structs hold plain strings and convert afterwards (see
// cmd/snug.userConfig.Defaults and internal/profile.rawProfile.Include, both of
// which say so at the field).
//
// The check is on the TAG rather than on a list of known decode structs, for
// the usual reason: a list is a copy of state held elsewhere. A field with no
// tag is not swept — a decoder can still reach an exported untagged field by
// its Go name — and that is a stated limit rather than a silent one. The tagged
// case is the one that exists today and the one a patch adds when it wires a
// new config key.
func TestNoDecodedStructFieldIsAProfileName(t *testing.T) {
	root, files := productionGoFiles(t)

	tagged := 0
	for _, rel := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(root, rel), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", rel, err)
		}
		for _, v := range decodedProfileNameFields(fset, f, &tagged) {
			t.Errorf("%s:%d field %q is decoded (%s) into a policy.ProfileName.\n"+
				"A decoder writes that field by reflection, so the value never passes "+
				"policy.NewProfileName and the grammar never runs — while its type claims it "+
				"did. Decode into a string and convert with NewProfileName, which is what "+
				"cmd/snug.userConfig.Defaults and internal/profile.rawProfile do.",
				rel, v.line, v.field, v.tag)
		}
	}

	// The positive control for the SCAN's coverage: there must be tagged fields
	// in the module at all, or "none of them is a ProfileName" is vacuous.
	if tagged == 0 {
		t.Fatal("the sweep saw no tagged struct fields anywhere in the module; it is not " +
			"reading the decode structs and cannot fail")
	}
}

type decodedFieldViolation struct {
	line  int
	field string
	tag   string
}

// decodedProfileNameFields finds struct fields that carry a toml/json/yaml tag
// AND whose type mentions ProfileName anywhere (scalar, slice, map key, map
// value, pointer — all of them are written by the same reflection). It counts
// every tagged field it saw into `tagged`, so the caller can prove the scan
// reached the decode structs.
func decodedProfileNameFields(fset *token.FileSet, f *ast.File, tagged *int) []decodedFieldViolation {
	var out []decodedFieldViolation
	ast.Inspect(f, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range st.Fields.List {
			if field.Tag == nil {
				continue
			}
			tag := field.Tag.Value
			if !strings.Contains(tag, "toml:") && !strings.Contains(tag, "json:") &&
				!strings.Contains(tag, "yaml:") {
				continue
			}
			*tagged++
			if !typeMentionsProfileName(field.Type) {
				continue
			}
			name := "<embedded>"
			if len(field.Names) > 0 {
				name = field.Names[0].Name
			}
			out = append(out, decodedFieldViolation{fset.Position(field.Pos()).Line, name, tag})
		}
		return true
	})
	return out
}

func typeMentionsProfileName(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.Ident:
			if e.Name == "ProfileName" {
				found = true
			}
		case *ast.SelectorExpr:
			if x, ok := e.X.(*ast.Ident); ok && x.Name == "policy" && e.Sel.Name == "ProfileName" {
				found = true
			}
		}
		return !found
	})
	return found
}

// TestPositiveControlADecodedProfileNameFieldTripsTheSweep reconstructs the
// exact shape TestNoDecodedStructFieldIsAProfileName forbids — the one a patch
// adding a config key would write without thinking about it — and asserts the
// predicate fires, in every position a name can occupy. The negative half in
// the same source proves it is not just flagging every tagged field.
func TestPositiveControlADecodedProfileNameFieldTripsTheSweep(t *testing.T) {
	const src = `package main

import "github.com/gomoni/snug/internal/policy"

type hostileConfig struct {
	Scalar policy.ProfileName            ` + "`toml:\"scalar\"`" + `
	List   []policy.ProfileName          ` + "`toml:\"list\"`" + `
	Ptr    *policy.ProfileName           ` + "`json:\"ptr\"`" + `
	Keyed  map[policy.ProfileName]string ` + "`toml:\"keyed\"`" + `

	// Legal: text in, converted afterwards. This is what userConfig does.
	Text []string ` + "`toml:\"text\"`" + `

	// Legal: not decoded at all, so reflection never reaches it.
	Untagged policy.ProfileName
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "control.go", src, 0)
	if err != nil {
		t.Fatalf("parsing the control source: %v", err)
	}
	tagged := 0
	got := map[string]bool{}
	for _, v := range decodedProfileNameFields(fset, f, &tagged) {
		got[v.field] = true
	}
	for _, want := range []string{"Scalar", "List", "Ptr", "Keyed"} {
		if !got[want] {
			t.Errorf("the sweep did not flag the tagged field %q, so a decoder could write a "+
				"ProfileName in that position and TestNoDecodedStructFieldIsAProfileName's "+
				"clean result would mean nothing", want)
		}
	}
	if got["Text"] {
		t.Error("the sweep flagged Text []string, which is the LEGAL shape every decode struct " +
			"in the module uses — it is no longer distinguishing the type from the tag")
	}
	if got["Untagged"] {
		t.Error("the sweep flagged Untagged, which carries no decode tag; the header comment " +
			"states that case as an accepted limit rather than a violation, so flagging it " +
			"would make the comment wrong in the other direction")
	}
	// Five, not six: Untagged carries no decode tag, so it is not counted and not
	// flagged. Pinning the number is what stops the counter quietly becoming
	// "every field", which would make the vacuity control above meaningless.
	if tagged != 5 {
		t.Errorf("the sweep counted %d tagged fields in the control, want 5 — its coverage "+
			"counter, which TestNoDecodedStructFieldIsAProfileName uses as its own positive "+
			"control, is not counting what it claims to", tagged)
	}
}
