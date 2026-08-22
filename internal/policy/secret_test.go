package policy

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// secretNeedle is a SYNTHETIC credential shape, not a real one. It is chosen
// to look exactly like what CLAUDE.md says leaked before Secret existed
// (`snug --dry-run -p @claude` puts an sk-ant key into Mount.Content), so a
// developer scanning test output recognises what class of value this guards.
const secretNeedle = "sk-ant-oat01-CANARY"

// secretVerbs is the verb sweep. No allowlist: every verb in this slice is
// asserted against below, and the sink table asserts its own completeness
// against this exact slice, so a verb quietly dropped from the loop cannot
// pass by never being asked.
var secretVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X"}

// secretNeedleEncodings is every spelling of the needle that must never
// appear at a sink. Plaintext, then the three encodings a naive
// strings.Contains(got, secretNeedle) would miss:
//
//   - base64 is not hypothetical — it is exactly what encoding/json rendered
//     a []byte Content as before this type existed, so a plain plaintext
//     check would have passed on the very bug this test exists to catch.
//   - hex, both cases, because %x and %X are two of the verbs in the sweep.
//   - the decimal byte-slice fmt renders for %d on a raw []byte (e.g.
//     "[115 107 ...]"), because that is what a leaky Content used to print
//     under Sprintf("%d", ...) — see
//     TestNoSerialisationOfMountContentControlLeakyTypeStillLeaks.
func secretNeedleEncodings() []string {
	b := []byte(secretNeedle)
	return []string{
		secretNeedle,
		base64.StdEncoding.EncodeToString(b),
		hex.EncodeToString(b),
		strings.ToUpper(hex.EncodeToString(b)),
		fmt.Sprintf("%d", b),
	}
}

// assertNoNeedle fails if got contains the needle under any of its
// encodings. Every sink assertion in this file funnels through here, so
// TestNoSerialisationOfMountContentControlDetectorFires — which feeds this
// function the raw needle and its encodings directly — is what proves it can
// actually fail; without that control a typo in secretNeedleEncodings makes
// the whole sink table vacuously green, the same failure mode CLAUDE.md
// records for the "pasta.avx2" leak-check bug.
func assertNoNeedle(t testing.TB, sink, got string) {
	t.Helper()
	for _, enc := range secretNeedleEncodings() {
		if strings.Contains(got, enc) {
			t.Errorf("sink %s leaked the needle (spelled %q):\n%s", sink, enc, got)
		}
	}
}

// assertRedactedPlaceholder fails unless got carries the placeholder for a
// Secret of length n. Without this, a sink that silently DROPS Content
// instead of redacting it would also pass "no needle found" — this is what
// makes the difference visible.
//
// jsonEscaped matches the one measured, documented divergence in secret.go:
// encoding/json HTML-escapes the angle brackets a MarshalJSON implementation
// returns, so a JSON sink carries "<...>", never the literal
// characters. That is not something to "fix" by changing the placeholder —
// it is a property of encoding/json, asserted here rather than assumed.
func assertRedactedPlaceholder(t testing.TB, sink, got string, n int, jsonEscaped bool) {
	t.Helper()
	want := fmt.Sprintf("<redacted %d bytes>", n)
	if jsonEscaped {
		want = fmt.Sprintf("\\u003credacted %d bytes\\u003e", n)
	}
	if !strings.Contains(got, want) {
		t.Errorf("sink %s does not carry %q — Content may have been silently DROPPED "+
			"rather than redacted, which a needle-absence check alone cannot catch:\n%s",
			sink, want, got)
	}
}

// secretSinks renders content through every sink this test covers, keyed by
// a name that also appears in failure messages. It is the single source of
// truth for "what did we check" — TestNoSerialisationOfMountContent asserts
// against every entry, and the verb-sweep completeness check below asserts
// this map actually contains one entry per verb in secretVerbs.
func secretSinks(t testing.TB, content Secret) map[string]string {
	t.Helper()
	m := Mount{Guest: "/generated", Kind: KindData, Content: content}

	sinks := map[string]string{}

	if b, err := json.Marshal(m); err != nil {
		t.Fatalf("json.Marshal(Mount): %v", err)
	} else {
		sinks["json.Marshal(Mount)"] = string(b)
	}

	if b, err := json.Marshal(map[string]Mount{"a": m}); err != nil {
		t.Fatalf("json.Marshal(map[string]Mount): %v", err)
	} else {
		sinks["json.Marshal(map[string]Mount)"] = string(b)
	}

	pol := &Policy{Mounts: map[string]Mount{"/generated": m}}
	if b, err := json.Marshal(pol); err != nil {
		t.Fatalf("json.Marshal(&Policy): %v", err)
	} else {
		sinks["json.Marshal(&Policy)"] = string(b)
	}

	for _, verb := range secretVerbs {
		// Format strings are built at runtime on purpose: `go vet`'s printf
		// checker refuses a literal "%s"/"%d"/... applied to a struct that
		// does not itself implement Stringer (Mount does not — only its
		// Content field does, via Secret.Format), and a variable format
		// string is exactly what a value assembled from user/profile input
		// would be, so this is not a synthetic dodge of the check.
		sinks["Sprintf("+verb+", Mount)"] = fmt.Sprintf(verb, m)
		sinks["Sprintf("+verb+", Content)"] = fmt.Sprintf(verb, content)
	}

	if b, err := content.MarshalText(); err != nil {
		t.Fatalf("Content.MarshalText(): %v", err)
	} else {
		sinks["Content.MarshalText()"] = string(b)
	}

	return sinks
}

// TestNoSerialisationOfMountContent is the permanent regression test for
// issue #51: Mount.Content carries the host's Claude accessToken/
// refreshToken/sk-ant key under @claude, and the gh token under an identity
// profile, so every sink that can render a Mount — deliberately or as a
// side effect of a failure message — must show "<redacted N bytes>" and
// never the bytes, in any encoding.
func TestNoSerialisationOfMountContent(t *testing.T) {
	content := Secret(secretNeedle)
	sinks := secretSinks(t, content)

	// Completeness: the sink table must actually contain one entry per verb
	// in the sweep, against both the Mount and the bare field, or the "no
	// verb leaks" claim below is about a verb nobody asked.
	for _, verb := range secretVerbs {
		for _, target := range []string{"Mount", "Content"} {
			key := "Sprintf(" + verb + ", " + target + ")"
			if _, ok := sinks[key]; !ok {
				t.Fatalf("sink table is missing %s — the verb sweep is not covering it", key)
			}
		}
	}

	names := make([]string, 0, len(sinks))
	for name := range sinks {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		got := sinks[name]
		assertNoNeedle(t, name, got)
		assertRedactedPlaceholder(t, name, got, len(secretNeedle), strings.Contains(name, "json.Marshal"))
	}

	// The deliberate escape hatch: an explicit conversion (or a function that
	// takes []byte, like bytes.Equal) must still reach the REAL bytes,
	// unredacted. resolve.go's join-equality check —
	// `bytes.Equal(old.Content, m.Content)` — depends on this: if it silently
	// became a comparison of two identical "<redacted N bytes>" strings, two
	// DIFFERENT generated files of the same length would compare equal and
	// join would stop refusing a genuine conflict.
	if string(content) != secretNeedle {
		t.Errorf("string(Content) = %q, want the raw needle back — the escape hatch is broken", string(content))
	}
	if !bytes.Equal(content, []byte(secretNeedle)) {
		t.Errorf("bytes.Equal(Content, []byte(needle)) = false; Secret must still compare as bytes")
	}
	other := Secret("sk-ant-oat01-DIFFERENT-BUT-SAME-LENGTH")
	if len(other) == len(content) && bytes.Equal(content, other) {
		t.Errorf("two DIFFERENT Secrets of equal length compared equal — bytes.Equal is reading " +
			"the redacted string rather than the bytes")
	}
}

// leakyMount reconstructs Mount's shape from before issue #51: Content as a
// plain []byte, no guard at all. This is the positive control for
// TestNoSerialisationOfMountContent — it proves the sink table, run against
// a type known to leak, actually FINDS the needle. Without this, "no sink in
// the table leaked the needle" could be true because the checks never really
// look at the rendered text, not because Secret works.
type leakyMount struct {
	Content []byte
}

// TestNoSerialisationOfMountContentControlLeakyTypeStillLeaks is control (a).
// It runs the identical needle against the pre-#51 shape and requires the
// needle to surface in at least %+v and json.Marshal — the two sinks CLAUDE.md
// names as how it was actually found (508 bytes of Claude credentials into
// Mount.Content, and json.Marshal renders a []byte as base64).
func TestNoSerialisationOfMountContentControlLeakyTypeStillLeaks(t *testing.T) {
	leaky := leakyMount{Content: []byte(secretNeedle)}

	plusV := fmt.Sprintf("%+v", leaky)
	jsonBytes, err := json.Marshal(leaky)
	if err != nil {
		t.Fatalf("json.Marshal(leakyMount): %v", err)
	}
	jsonText := string(jsonBytes)

	foundIn := func(name, got string) bool {
		for _, enc := range secretNeedleEncodings() {
			if strings.Contains(got, enc) {
				t.Logf("control: leakyMount leaked via %s, spelled %q: %s", name, enc, got)
				return true
			}
		}
		return false
	}

	if !foundIn("%+v", plusV) {
		t.Errorf("leakyMount's %%+v did not leak the needle in any encoding — the control "+
			"is not controlling anything: %s", plusV)
	}
	if !foundIn("json.Marshal", jsonText) {
		t.Errorf("leakyMount's json.Marshal did not leak the needle in any encoding "+
			"(expected base64, which is exactly what json.Marshal does to a bare []byte): %s",
			jsonText)
	}
}

// recordingTB is a minimal testing.TB that records whether Errorf was called,
// without actually failing the enclosing test. Embedding the (nil) interface
// satisfies TB's unexported method; every method actually reached by
// assertNoNeedle/assertRedactedPlaceholder is overridden below, and nothing
// else may be called on it.
type recordingTB struct {
	testing.TB
	failed bool
}

func (r *recordingTB) Helper()                           {}
func (r *recordingTB) Errorf(format string, args ...any) { r.failed = true }

// TestNoSerialisationOfMountContentControlDetectorFires is control (b): the
// needle detector itself must be able to fail. Feeding assertNoNeedle the raw
// needle, and separately each of its own encodings, must record a failure
// every time — otherwise a typo in secretNeedleEncodings (e.g. the wrong
// base64 alphabet, or a hex helper that never runs) makes
// TestNoSerialisationOfMountContent pass for the wrong reason, exactly the
// "pasta.avx2" shape CLAUDE.md warns about: a check that can never observe
// the thing it claims to measure.
func TestNoSerialisationOfMountContentControlDetectorFires(t *testing.T) {
	for _, enc := range secretNeedleEncodings() {
		rec := &recordingTB{}
		assertNoNeedle(rec, "control", enc)
		if !rec.failed {
			t.Errorf("assertNoNeedle did not fail when handed the raw encoding %q — "+
				"the detector cannot see what it is supposed to be looking for", enc)
		}
	}

	// And the placeholder detector must fail when the placeholder is absent.
	rec := &recordingTB{}
	assertRedactedPlaceholder(rec, "control", "nothing relevant here", len(secretNeedle), false)
	if !rec.failed {
		t.Errorf("assertRedactedPlaceholder did not fail on text carrying no placeholder at all")
	}

	// ...and must NOT fail when the placeholder IS present, or every real
	// sink assertion in TestNoSerialisationOfMountContent is a false alarm
	// waiting to happen.
	rec = &recordingTB{}
	assertRedactedPlaceholder(rec, "control", fmt.Sprintf("<redacted %d bytes>", len(secretNeedle)), len(secretNeedle), false)
	if rec.failed {
		t.Errorf("assertRedactedPlaceholder failed on text that DOES carry the placeholder")
	}
}

// ── Gap 1a — a leak fmt itself does not let Secret close ────────────────────
//
// redteam measured (2026, issue #51 follow-up): fmt's printValue only calls
// handleMethods — which is what checks a value for Formatter/Stringer, i.e.
// what makes Secret.Format ever run — when reflect.Value.CanInterface() is
// true, and CanInterface() is FALSE for anything reached through an
// UNEXPORTED struct field. So a Mount, a Policy, or a bare Secret sitting
// behind an unexported field is never handed to Secret.Format at all; fmt
// falls back to reflecting over the raw []byte and prints the credential in
// decimal (%d, and %v/%+v's default struct rendering), hex (%x/%X), or as the
// literal bytes (%s/%q). secret.go's own doc comment on Secret already names
// this as "a gap in fmt itself... not this type" — this is the standing,
// executable measurement of it.
//
// These four holder shapes are exactly what redteam used to demonstrate it;
// they are kept as the literal repro, not simplified, so a reader can compare
// this file against the finding directly.
type mountHolder struct{ m Mount }

type runByValue struct {
	name string
	pol  Policy
}

type unexportedHolder struct {
	name   string
	secret Secret
}

// pointerHolder is the other half of the same measurement: a POINTER under an
// unexported field IS safe, because fmt prints a bare address without ever
// dereferencing into the pointee — measured in production at
// internal/dockerproxy/proxy.go:41's `pol *policy.Policy`. This is what makes
// "by value, not any reference" the correct property for the reflect sweep in
// unexportedsecretfield_test.go to assert, rather than "any reachability at
// all".
//
// One caveat, and it is now IN the table below rather than only described here
// (issue #56). The pointer safety above holds for %v/%+v/%#v/%d/%x, but NOT for
// a verb that is invalid for the pointee's own type: fmt's bad-verb fallback
// formats the mismatched value with its own internal renderer, which walks
// straight through the pointer and does NOT consult CanInterface() either. So
// the same "%s where a %d-shaped verb was expected" trick that leaks %d-typed
// bytes elsewhere in this file also defeats the pointer boundary. It is not
// specific to Secret — it would expose any pointee's fields under a mismatched
// verb.
//
// MEASURED ON go1.26.5, ALL SEVEN VERBS, because "a %s leaks" is not the same
// claim as "the pointer boundary is gone":
//
//	%v %+v %#v %d %x   bare address, no leak — the boundary holds
//	%s %q              {%!s(*policy.Mount=&{/g 5 … [115 107 45 …] …})}
//
// THE TRAP FOR WHOEVER RE-MEASURES THIS: the leak is the DECIMAL BYTE FORM, not
// ASCII. `strings.Contains(out, secretNeedle)` returns FALSE on that output and
// reads as "safe" — the bytes [115 107 45 97 …] spell the needle exactly.
// secretNeedleEncodings() already carries fmt.Sprintf("%d", b) for precisely
// this reason, which is why the rows below fire; a hand-rolled check that looks
// only for the raw string will conclude the opposite.
//
// WHY THIS IS RECORDED RATHER THAN GUARDED, and why the other two options on
// issue #56 were declined:
//
//   - "Make the AST sweep flag pointer-to-Secret-bearing types under unexported
//     fields, and exempt dockerproxy." Declined: it starts the allowlist #51
//     deliberately avoided, and it would flag the one shipped field that is
//     correct today.
//   - "Assert that no format string in the tree applies a string-shaped verb to
//     such a struct." Declined because `go vet` ALREADY DOES IT, measured rather
//     than assumed — a literal fmt.Sprintf("%s", pointerHolder{&m}) fails
//     `go vet ./internal/policy/` with "format %s has arg ph of wrong type", and
//     `go vet ./...` is the first thing `make gate` runs. Re-implementing that in
//     an AST sweep would duplicate a check that already gates every commit.
//
// What neither vet nor a sweep catches is a COMPUTED format string, which is the
// residual this table exists to hold: the leak is real, nothing in this package
// can close it, and the day fmt's fallback changes these rows go red and say so.
type pointerHolder struct{ m *Mount }

// unexportedSecretLeakSinks is deliberately a SEPARATE table from
// secretSinks, not an addition to it. Every entry here is required to leak —
// assertNoNeedle would fail on all of them, forever, because there is no hook
// on Secret's type that fmt will consult when it cannot call Interface() on
// the containing reflect.Value at all (Go gives none; see secret.go's closing
// paragraph). Folding these into secretSinks and asserting redaction would
// make the suite permanently red for a defect this package cannot fix, and
// asserting nothing at all would let the one measured fact here — WHICH
// shapes leak and HOW — rot silently the day fmt's internals change. So this
// table is asserted to LEAK: if a future Go release closes this gap, this
// test goes red and says exactly which shape stopped leaking, which is the
// useful direction for a limit nothing in this package can close.
func unexportedSecretLeakSinks(content Secret) map[string]string {
	m := Mount{Guest: "/generated", Kind: KindData, Content: content}
	mh := mountHolder{m: m}
	rbv := runByValue{name: "r", pol: Policy{Mounts: map[string]Mount{"/g": m}}}
	uh := unexportedHolder{name: "n", secret: content}
	ph := pointerHolder{m: &Mount{Guest: "/generated", Kind: KindData, Content: content}}

	// Format strings are built at runtime, exactly as secretSinks does above
	// and for the identical reason: `go vet`'s printf checker refuses a
	// LITERAL "%d"/"%x"/"%s" applied to a struct that does not itself
	// implement Stringer (none of these holders do — only the Secret buried
	// inside them does, and CanInterface() is precisely what stops fmt from
	// reaching it). A variable format string sidesteps the check without
	// hiding anything: this is not a synthetic dodge, it is the same
	// resolution the shipped table already uses.
	verbPlusV, verbD, verbX, verbS, verbQ := "%+v", "%d", "%x", "%s", "%q"

	return map[string]string{
		"Sprintf(%+v, mountHolder)":     fmt.Sprintf(verbPlusV, mh),
		"Sprintf(%d, mountHolder)":      fmt.Sprintf(verbD, mh),
		"Sprintf(%x, mountHolder)":      fmt.Sprintf(verbX, mh),
		"Sprintf(%+v, runByValue)":      fmt.Sprintf(verbPlusV, rbv),
		"Sprintf(%d, runByValue)":       fmt.Sprintf(verbD, rbv),
		"Sprintf(%s, unexportedHolder)": fmt.Sprintf(verbS, uh),
		"Sprintf(%x, unexportedHolder)": fmt.Sprintf(verbX, uh),
		// ISSUE #56 — the bad-verb fallback walks THROUGH the pointer. These two
		// are the rows that make the pointerHolder caveat above a measurement the
		// suite re-runs rather than a sentence somebody has to believe.
		"Sprintf(%s, pointerHolder)": fmt.Sprintf(verbS, ph),
		"Sprintf(%q, pointerHolder)": fmt.Sprintf(verbQ, ph),
	}
}

// TestFmtLeaksASecretBehindAnUnexportedFieldKnownLimit is the permanent
// record of Gap 1a. It is named "KnownLimit" rather than something that reads
// as a regression test for a bug snug fixed, because there is nothing here
// for snug to fix — the assertion is that the leak is PRESENT, which is the
// opposite of every other test in this file.
func TestFmtLeaksASecretBehindAnUnexportedFieldKnownLimit(t *testing.T) {
	content := Secret(secretNeedle)
	sinks := unexportedSecretLeakSinks(content)

	names := make([]string, 0, len(sinks))
	for name := range sinks {
		names = append(names, name)
	}
	sort.Strings(names)

	if len(names) == 0 {
		t.Fatal("unexportedSecretLeakSinks returned nothing to check")
	}

	// The #56 rows are the reason this table grew, and a table asserted to LEAK
	// cannot notice one of its own rows going missing — deleting a row simply
	// asserts one fewer thing, which mutation testing confirmed survives the
	// suite. So their PRESENCE is asserted, not just their behaviour. Without
	// this, the measurement #56 exists to record is one tidy-up away from being
	// prose again.
	for _, required := range []string{"Sprintf(%s, pointerHolder)", "Sprintf(%q, pointerHolder)"} {
		if _, ok := sinks[required]; !ok {
			t.Errorf("%s is missing from unexportedSecretLeakSinks. It is the measured record "+
				"that fmt's bad-verb fallback walks THROUGH a pointer under an unexported "+
				"field (issue #56), which is the one case where the pointer boundary the "+
				"reflect sweep relies on does not hold. Removing it does not make the leak "+
				"go away, it makes the suite stop noticing if it ever changes", required)
		}
	}

	for _, name := range names {
		got := sinks[name]
		leaked := false
		for _, enc := range secretNeedleEncodings() {
			if strings.Contains(got, enc) {
				leaked = true
				break
			}
		}
		if !leaked {
			t.Errorf("sink %s did NOT leak the needle in any encoding: %s\n"+
				"This test asserts the OPPOSITE of every other test in this file: fmt reached "+
				"through an unexported field is a known, unfixable gap (see the comment above "+
				"unexportedSecretLeakSinks), and this sink was measured to leak through it. If it "+
				"no longer does, something about fmt's CanInterface() behaviour changed — say so "+
				"in the comment here and in secret.go's closing paragraph, do not just delete the "+
				"case", name, got)
		}
	}

	// The boundary this whole gap turns on: a POINTER under the same
	// unexported-field shape must NOT leak, or "by value, not any reference"
	// (the property the reflect sweep asserts) is the wrong property.
	ph := pointerHolder{m: &Mount{Guest: "/generated", Kind: KindData, Content: content}}
	verbPlusV := "%+v"
	gotPtr := fmt.Sprintf(verbPlusV, ph)
	for _, enc := range secretNeedleEncodings() {
		if strings.Contains(gotPtr, enc) {
			t.Errorf("pointerHolder leaked via encoding %q under %%+v: %s\n"+
				"The pointer/value boundary this package relies on (measured at "+
				"internal/dockerproxy/proxy.go:41) has changed — the reflect sweep's exemption "+
				"for pointer fields is no longer correct and must be revisited together with "+
				"this test", enc, gotPtr)
		}
	}
	if !strings.Contains(gotPtr, "0x") {
		t.Errorf("pointerHolder's %%+v does not look like a bare pointer address: %s", gotPtr)
	}
}

// ── Gap 2 — the guard can be bypassed by adding a field beside it ───────────
//
// redteam measured: reverting Mount.Content to a plain []byte fails loudly (8
// sink failures in TestNoSerialisationOfMountContent). But adding a brand-new
// field of a plain []byte type — e.g. `Preamble []byte` on Mount, holding
// generated bytes exactly like Content does — leaves `go test ./...` entirely
// green, because nothing constructs a Mount with that field populated inside
// this file's sink table. The type-level guard only ever covers the ONE field
// it was put on; a second field of the same underlying type re-opens the same
// hole one field over, and no test so far would notice.
//
// mountWithPreamble reconstructs that exact shape without touching the real
// Mount (this file may not edit types.go): Mount unchanged, embedded, plus
// one more field holding a plain byte slice sitting right beside Content.
type mountWithPreamble struct {
	Mount
	Preamble []byte
}

// byteSliceFieldsWithoutSecretGuard walks the direct fields of t (NOT
// transitively into nested structs — Mount and Policy are the only two types
// this rule is written for, see the Context discussion below) and returns
// "Type.Field" for every field whose underlying type is a byte slice and
// whose declared type is not exactly Secret.
//
// Matching on Kind()==Slice && Elem().Kind()==Uint8 rather than comparing
// against `reflect.TypeOf([]byte(nil))` on purpose: a future field of some
// OTHER named byte-slice type — `type Fingerprint []byte` used by mistake
// instead of Secret — must trip this exactly the same way a bare []byte
// would, because from fmt's point of view (see Gap 1) neither one is Secret
// and neither one is redacted.
func byteSliceFieldsWithoutSecretGuard(t reflect.Type) []string {
	secretType := reflect.TypeOf(Secret(nil))
	var bad []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Type == secretType {
			continue
		}
		if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
			bad = append(bad, t.Name()+"."+f.Name)
		}
	}
	return bad
}

// TestEveryByteSliceFieldOnMountAndPolicyIsASecret is the real guard for Gap
// 2. It has nothing to do with what any current sink renders — it is a
// property of the TYPE, checked once, so a field added beside Content next
// year is caught here even if nobody remembers to add it to secretSinks.
func TestEveryByteSliceFieldOnMountAndPolicyIsASecret(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(Mount{}), reflect.TypeOf(Policy{})} {
		if bad := byteSliceFieldsWithoutSecretGuard(typ); len(bad) > 0 {
			t.Errorf("%s has byte-slice field(s) that are not policy.Secret: %v.\n"+
				"Every field of Mount or Policy whose underlying type is a byte slice must be "+
				"Secret, or it inherits none of the fmt/json/text redaction Secret provides — "+
				"see TestPositiveControlPreambleFieldTripsTheByteSliceSweep for the exact shape "+
				"this predicate exists to catch.", typ.Name(), bad)
		}
	}
}

// TestPositiveControlPreambleFieldTripsTheByteSliceSweep proves
// byteSliceFieldsWithoutSecretGuard can actually fail. Without this, "Mount
// and Policy have no unguarded byte-slice fields" could be true because the
// predicate never really inspects field types, not because the types are
// clean — the same shape as every other positive control in this file.
func TestPositiveControlPreambleFieldTripsTheByteSliceSweep(t *testing.T) {
	bad := byteSliceFieldsWithoutSecretGuard(reflect.TypeOf(mountWithPreamble{}))
	if len(bad) != 1 || bad[0] != "mountWithPreamble.Preamble" {
		t.Fatalf("byteSliceFieldsWithoutSecretGuard(mountWithPreamble) = %v, want exactly "+
			"[\"mountWithPreamble.Preamble\"] — the predicate did not flag the fixture it exists "+
			"to catch, so the negative result on the real Mount/Policy types proves nothing",
			bad)
	}
}

// TestContextKnownHostsIsDeliberatelyNotASecret pins a decision rather than
// guarding a bug: policy.Context.KnownHosts is a plain []byte, and
// TestEveryByteSliceFieldOnMountAndPolicyIsASecret deliberately does not
// sweep Context at all. Both facts are asserted here so a future editor finds
// a failing test, not a silent gap, if either one drifts.
//
// Why the exemption is not the start of an allowlist: Context is scoped OUT
// by TYPE, not by field name. Context (environ.go) is the pre-resolution
// INPUT to Resolve — host facts gathered by the caller before a Policy
// exists — never the thing rendered by --dry-run or any of
// the fmt/json sinks TestNoSerialisationOfMountContent closes; those sinks
// all take a Mount or a Policy, never a Context. KnownHosts itself is host
// fingerprints for the pinned host (see environ.go's doc comment), not a
// credential — the byte value it holds is used exactly ONCE, at resolve.go's
// `Content: ctx.KnownHosts`, to construct a Mount whose Content field IS a
// Secret, which is where the guard actually needs to live and does. Widening
// TestEveryByteSliceFieldOnMountAndPolicyIsASecret to also cover Context
// would not close a gap; the moment a new field on Context needs to become
// the sensitive kind of bytes, the right fix is putting it into a Mount, not
// making Context grow a Secret field of its own.
func TestContextKnownHostsIsDeliberatelyNotASecret(t *testing.T) {
	ctxType := reflect.TypeOf(Context{})
	f, ok := ctxType.FieldByName("KnownHosts")
	if !ok {
		t.Fatal("Context no longer has a KnownHosts field — this test's premise is gone; " +
			"read the comment above before deleting it, in case the field moved rather than " +
			"disappeared")
	}
	byteSliceType := reflect.TypeOf([]byte(nil))
	if f.Type != byteSliceType {
		t.Errorf("Context.KnownHosts is %s, want plain []byte (%s) — if this changed to "+
			"Secret, update the comment on this test (and on "+
			"TestEveryByteSliceFieldOnMountAndPolicyIsASecret) to say why Context is now in "+
			"scope, rather than leaving this assertion to rot", f.Type, byteSliceType)
	}
	if bad := byteSliceFieldsWithoutSecretGuard(ctxType); len(bad) == 0 {
		t.Fatal("byteSliceFieldsWithoutSecretGuard(Context) found nothing to flag on a type " +
			"known to carry a plain []byte field — the predicate is broken, and the exemption " +
			"documented above is not being exercised by anything")
	}
}

// ── Informational — an accident that must not silently become a feature ────
//
// json.Unmarshal of a marshalled Mount fails today, rather than silently
// substituting the placeholder text for the real file body, but that is
// ACCIDENTAL: the placeholder happens not to be valid base64 (it contains
// spaces and angle brackets), and Secret has no UnmarshalJSON of its own to
// make the refusal deliberate. Pinned here so the day someone adds
// Secret.UnmarshalJSON — reasonably, to make round-tripping "work" — this
// test forces them to look at what "work" would mean: silently returning
// `Content: []byte("<redacted 19 bytes>")` in place of the real file body,
// which nothing downstream is positioned to notice.
func TestUnmarshalOfAMarshalledMountRefusesRatherThanSubstitutingThePlaceholder(t *testing.T) {
	content := Secret(secretNeedle)
	m := Mount{Guest: "/generated", Kind: KindData, Content: content}

	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal(Mount): %v", err)
	}

	var back Mount
	err = json.Unmarshal(b, &back)
	if err == nil {
		t.Fatalf("json.Unmarshal(Mount) succeeded and produced Content=%q (%d bytes) — the "+
			"accidental refusal this test pins has gone away, which means Secret is now "+
			"SILENTLY SUBSTITUTING the placeholder text for a real file body on round-trip. "+
			"That is a correctness and security regression, not a feature: give Secret an "+
			"UnmarshalJSON that returns an error instead of letting this pass", string(back.Content), len(back.Content))
	}
	// THE MOUNT-LEVEL REFUSAL IS NO LONGER EVIDENCE ABOUT Content, and that is
	// worth saying out loud rather than letting the assertion quietly change
	// meaning. Issue #52 gave Kind and Access a MarshalJSON (they are uint8
	// iota, so a machine-readable --dry-run must carry the word, not the
	// number) and deliberately no Unmarshal counterpart — so json.Unmarshal of
	// a marshalled Mount now fails at Kind, BEFORE it ever reaches Content.
	// Asserting "illegal base64 data" on this error would have started passing
	// for the wrong reason, or failing for one, either way testing nothing
	// about the placeholder.
	//
	// So the accidental refusal this test exists for is exercised where it
	// actually lives: on the content field alone.
	var fields struct {
		Content json.RawMessage `json:"Content"`
	}
	if uerr := json.Unmarshal(b, &fields); uerr != nil {
		t.Fatalf("reading the Content field back out of the marshalled Mount: %v", uerr)
	}
	var backContent Secret
	cerr := json.Unmarshal(fields.Content, &backContent)
	if cerr == nil {
		t.Fatalf("json.Unmarshal(Secret) succeeded and produced %q (%d bytes) — the accidental "+
			"refusal this test pins has gone away, which means Secret is now SILENTLY "+
			"SUBSTITUTING the placeholder text for a real file body on round-trip. That is a "+
			"correctness and security regression, not a feature: give Secret an UnmarshalJSON "+
			"that returns an error instead of letting this pass",
			string(backContent), len(backContent))
	}
	if !strings.Contains(cerr.Error(), "illegal base64 data") {
		t.Errorf("json.Unmarshal(Secret) failed for a different reason than the one this test "+
			"pins (%q); re-check whether the accidental refusal still works the same way: %v",
			"illegal base64 data", cerr)
	}
}
