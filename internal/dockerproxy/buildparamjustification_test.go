package dockerproxy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ── a nil build parameter cannot be silent ───────────────────────────────────
//
// A nil value in buildParams means the name is permitted and the value never
// looked at. That is a GRANT: it hands the engine a parameter snug has not
// judged. CLAUDE.md's working agreement requires an abuse sentence before any
// grant — "a hostile process inside the sandbox can use this to ___. If you
// cannot write it, the grant is not ready" — stated for profile TOML and never
// applied here.
//
// TestEveryBuildValidatorIsExercised guarantees every validator is tested and
// says nothing about every parameter having one, because its loop skipped the
// nil entries. The exemption cost two host reads (issue #331).
//
// THE PROPERTY, and why the obvious mechanism is not it. "A justification
// comment exists" fails on measurement: at 63874ee, BOTH host reads carried
// one.
//
//	// The CLI reads a --secret's file ITSELF, inside the sandbox, and ships the
//	// bytes in the context tar under a generated name. So this names no host
//	// path and grants no read the sandbox did not already have. Verified by
//	// recording: --secret id=s,src=/etc/hostname became
//	// secrets=["id=s,src=podman-build-secret-4284765652"].
//	"secrets": nil,
//	...
//	"idmappingoptions":        nil, // rootless bounds this; the CLI always sends it
//
// Four lines with a recorded verification, and a trailing one. Both describe
// what the friendly CLIENT does, which build.go's own regression note names as
// the error: "'The friendly client would never send that' is never a reason to
// skip a check." A comment convention passes both green.
//
// What discriminates is the FORM of the sentence. An abuse sentence is written
// from the attacker's side, so it cannot be satisfied by describing benign
// behaviour, and forcecompressionformat — the one justified entry — is the only
// one in the map that has one. Both historical strings are fixtures below, so
// the discrimination is asserted rather than argued.
//
// The shape is a type change, not a check: an unexamined parameter lives in
// unexaminedBuildParams, whose value type is a string, so the compiler requires
// the sentence and no entry can omit one. What the tests here add is that the
// string must BE an abuse sentence, that buildParams holds no nil, and that the
// two maps do not overlap.
//
// The limit, stated rather than implied: this guarantees an unexamined
// parameter cannot be SILENT. It cannot guarantee the sentence is TRUE — two
// false ones shipped. notYetAnalysed exists for that reason: an entry with no
// established analysis says so in a class that greps, instead of borrowing a
// neighbour's claim.

// abuseOpener is the form CLAUDE.md's working agreement requires. Matched
// case-insensitively on the opener alone: the sentence's CONTENT is a human
// judgement and a test that graded it would be pretending.
const abuseOpener = "a hostile process inside the sandbox can use th"

func hasAbuseSentence(reason string) bool {
	return strings.Contains(strings.ToLower(reason), abuseOpener)
}

// TestEveryUnexaminedBuildParamCarriesAnAbuseSentence is the sweep.
func TestEveryUnexaminedBuildParamCarriesAnAbuseSentence(t *testing.T) {
	if len(unexaminedBuildParams) == 0 {
		t.Fatal("unexaminedBuildParams is empty, so this sweep measures nothing")
	}
	for _, name := range sortedKeys(unexaminedBuildParams) {
		reason := unexaminedBuildParams[name]
		if !hasAbuseSentence(reason) {
			t.Errorf("build parameter %q is forwarded to the engine unexamined and its reason is "+
				"not an abuse sentence:\n  %q\n"+
				"       Write it from the attacker's side — %q — because a description of what "+
				"the friendly CLI does is not a security argument. Both parameters that turned "+
				"out to be host reads had a comment describing the client (issue #331). If no "+
				"analysis has been done, say that: notYetAnalysed.",
				name, reason, abuseOpener)
		}
	}
}

// TestAbuseSentenceDetectorRejectsTheTwoThatShipped is the positive control,
// and the measurement is the fixture set: the two strings that justified a host
// read must be rejected, and the four the map uses must be accepted. A check
// that accepted "rootless bounds this" would be re-permitting exactly what
// issue #331 measured.
func TestAbuseSentenceDetectorRejectsTheTwoThatShipped(t *testing.T) {
	reject := []struct{ name, reason string }{
		{"idmappingoptions, verbatim at 63874ee", "rootless bounds this; the CLI always sends it"},

		{"secrets, verbatim at 63874ee", "The CLI reads a --secret's file ITSELF, inside the " +
			"sandbox, and ships the bytes in the context tar under a generated name. So this " +
			"names no host path and grants no read the sandbox did not already have. Verified " +
			"by recording: --secret id=s,src=/etc/hostname became " +
			"secrets=[\"id=s,src=podman-build-secret-4284765652\"]."},

		{"empty", ""},
		{"whitespace", "   \n\t"},
		{"a bare identification", "image tag"},
		{"a section header", "── naming and output ────────────"},
		{"an assertion with no attacker in it", "this parameter is harmless and reaches nothing"},
		{"the podman CLI sends it", "the CLI sends it on every build"},
	}
	for _, tc := range reject {
		t.Run("reject "+tc.name, func(t *testing.T) {
			if hasAbuseSentence(tc.reason) {
				t.Errorf("accepted as an abuse sentence, so a parameter justified this way "+
					"ships green:\n  %q", tc.reason)
			}
		})
	}

	accept := map[string]string{
		"ordinaryBuildBehaviour": ordinaryBuildBehaviour,
		"resourceLimit":          resourceLimit,
		"forceCompressionFormat": forceCompressionFormat,
		"notYetAnalysed":         notYetAnalysed,
	}
	for _, name := range sortedKeys(accept) {
		t.Run("accept "+name, func(t *testing.T) {
			if !hasAbuseSentence(accept[name]) {
				t.Errorf("%s is rejected, so the sweep is unsatisfiable by its own classes:\n  %q",
					name, accept[name])
			}
		})
	}
}

// TestNoJudgedBuildParamIsNil is the static half. A nil in buildParams is
// refused at runtime (filterBuildQuery), which fails closed but only tells
// whoever runs a build; this says so at `go test` time, naming the fix.
func TestNoJudgedBuildParamIsNil(t *testing.T) {
	file, lit := findBuildParamsLiteral(t)
	nils := nilKeysIn(lit)
	if len(nils) != 0 {
		t.Errorf("%s: buildParams has %d nil value(s): %v.\n"+
			"       A nil permits the name and never looks at the value, which is a grant with "+
			"no abuse sentence — the defect issue #331 measured twice. Move it to "+
			"unexaminedBuildParams with the sentence for why the value cannot reach a host "+
			"resource, or give it a validator.", file, len(nils), nils)
	}
}

// TestNilDetectorSeesEveryNilSpelling is the positive control on the static
// half. Without it, a detector that matched nothing reports zero nils and reads
// as proof — and the map's real spellings include several entries per line and
// an aliased nil.
func TestNilDetectorSeesEveryNilSpelling(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"one per line", `package p
var buildParams = map[string]buildParamCheck{
	"t": nil,
}`, []string{"t"}},

		{"several per line, the map's own shape", `package p
var buildParams = map[string]buildParamCheck{
	"jobs": nil, "retry": nil, "retry-delay": nil,
}`, []string{"jobs", "retry", "retry-delay"}},

		{"a nil beside a real check", `package p
var buildParams = map[string]buildParamCheck{
	"volume": checkBuildVolume,
	"manifest": nil,
	"cacheto": refuseBuildParam("no"),
}`, []string{"manifest"}},

		{"a nil with a justification comment, which is not the property", `package p
var buildParams = map[string]buildParamCheck{
	// rootless bounds this; the CLI always sends it
	"idmappingoptions": nil,
}`, []string{"idmappingoptions"}},

		{"a nil behind a package-level alias", `package p
var permitted buildParamCheck = nil
var buildParams = map[string]buildParamCheck{
	"t": permitted,
}`, nil}, // NOT detected — stated as the residual, see below
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "fixture.go", tc.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("the fixture does not parse, so this control measures nothing: %v", err)
			}
			lit := buildParamsLiteralIn(f)
			if lit == nil {
				t.Fatal("the detector does not find buildParams in the fixture at all")
			}
			got := nilKeysIn(lit)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("detected %v, want %v:\n%s", got, tc.want, tc.src)
			}
		})
	}

	// The alias case above is the residual, and it is why the RUNTIME refusal
	// in filterBuildQuery exists rather than the static check alone: a nil
	// reaching the map by any spelling this parser cannot see is still refused
	// when a build arrives. TestANilJudgedParamIsRefusedNotForwarded is that
	// half.
}

// TestANilJudgedParamIsRefusedNotForwarded is the behavioural half, and the
// one that closes the static check's residual. It MUTATES the live map, which
// is the mutation issue #331 asks for: add the unjustified entry and observe
// the failure, rather than delete the check.
func TestANilJudgedParamIsRefusedNotForwarded(t *testing.T) {
	const name = "snugplantednilparam"
	if _, exists := buildParams[name]; exists {
		t.Fatalf("%s already exists, so this test would measure the wrong entry", name)
	}
	buildParams[name] = nil
	defer delete(buildParams, name)

	p := &Proxy{}
	q := url.Values{name: []string{"anything"}}

	forward, _, reason := p.filterBuildQuery(q)
	if reason == "" {
		t.Fatalf("a nil-valued buildParams entry was FORWARDED (%v) instead of refused. That is "+
			"the pass-through issue #331 measured: the name is permitted and the value never "+
			"looked at, with nothing anywhere saying why that is safe.", forward)
	}
	if !strings.Contains(reason, "unexaminedBuildParams") {
		t.Errorf("the refusal does not name the fix: %q", reason)
	}

	// POSITIVE CONTROL on the harness: the same parameter forwarded once it is
	// justified. Without this, the assertion above passes on a filter that
	// refuses everything.
	delete(buildParams, name)
	unexaminedBuildParams[name] = "A hostile process inside the sandbox can use this to do nothing " +
		"at all; it is a test fixture."
	defer delete(unexaminedBuildParams, name)

	forward, _, reason = p.filterBuildQuery(q)
	if reason != "" {
		t.Fatalf("the justified fixture is refused (%s), so the refusal above proves nothing", reason)
	}
	if got := forward.Get(name); got != "anything" {
		t.Errorf("the justified fixture forwarded %q, want the value unchanged", got)
	}
}

// TestBuildParamMapsAreDisjoint keeps the split honest. A name in both maps
// would be judged or forwarded depending on which lookup runs first, which is
// a policy decision made by statement order.
func TestBuildParamMapsAreDisjoint(t *testing.T) {
	for _, name := range sortedKeys(unexaminedBuildParams) {
		if _, both := buildParams[name]; both {
			t.Errorf("build parameter %q is in BOTH buildParams and unexaminedBuildParams. "+
				"filterBuildQuery consults the unexamined map first, so the validator would "+
				"never run — pick one.", name)
		}
	}
}

// ── the parser ──────────────────────────────────────────────────────────────

// findBuildParamsLiteral locates the composite literal wherever in the package
// buildParams is declared, rather than assuming a filename: a var that moves
// file must not silently stop being swept.
func findBuildParamsLiteral(t *testing.T) (string, *ast.CompositeLit) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(name)
		if rerr != nil {
			t.Fatal(rerr)
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, name, src, parser.ParseComments)
		if perr != nil {
			t.Fatal(perr)
		}
		if lit := buildParamsLiteralIn(f); lit != nil {
			return filepath.ToSlash(name), lit
		}
	}
	t.Fatal("buildParams is not declared in any non-test file of this package, so the sweep " +
		"found nothing to measure")
	return "", nil
}

func buildParamsLiteralIn(f *ast.File) *ast.CompositeLit {
	var lit *ast.CompositeLit
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if name.Name != "buildParams" || i >= len(vs.Values) {
				continue
			}
			if cl, ok := vs.Values[i].(*ast.CompositeLit); ok {
				lit = cl
			}
		}
		return true
	})
	return lit
}

// nilKeysIn returns the keys whose value is the identifier nil, in source
// order. It reads the VALUE rather than the key, so it is indifferent to how
// many entries share a line and to any comment above or beside them.
func nilKeysIn(lit *ast.CompositeLit) []string {
	var out []string
	for _, e := range lit.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		id, ok := kv.Value.(*ast.Ident)
		if !ok || id.Name != "nil" {
			continue
		}
		key, ok := kv.Key.(*ast.BasicLit)
		if !ok {
			out = append(out, fmt.Sprintf("%v", kv.Key))
			continue
		}
		out = append(out, strings.Trim(key.Value, `"`))
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
