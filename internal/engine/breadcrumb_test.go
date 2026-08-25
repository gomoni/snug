package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// keyDirWith writes raw contents at "store.json" inside a fresh directory and
// returns it opened as an *os.Root, the same shape ReadBreadcrumb's own doc
// comment says it is always handed: "already-opened, already-verified
// (owned, exactly 0700) per-key directory". contents == "" writes nothing at
// all, for the Missing case.
func keyDirWith(t *testing.T, contents string) *os.Root {
	t.Helper()
	dir := t.TempDir()
	if contents != "" {
		if err := os.WriteFile(filepath.Join(dir, "store.json"), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

// TestBreadcrumbKeyCheck tables ReadBreadcrumb's four BreadcrumbState values.
// "The name is the index" (orphansweep.go's rule, applied here to the
// store): a breadcrumb whose OWN claimed target does not hash to the
// directory name carrying it must never be trusted as OK, because that is
// exactly what a copied or hand-placed file looks like.
func TestBreadcrumbKeyCheck(t *testing.T) {
	target := "/proj/breadcrumb-key-check"
	realKey := KeyForTarget(target)
	otherKey := KeyForTarget("/proj/a-different-target")
	if realKey == otherKey {
		t.Fatalf("control failed: two different targets hashed to the same key")
	}

	validJSON := `{"schema":1,"target":"` + target + `","created":"2026-01-01T00:00:00Z","last_used":"2026-01-01T00:00:00Z"}`

	cases := []struct {
		name       string
		contents   string
		key        string
		wantState  BreadcrumbState
		wantTarget string
	}{
		{
			name:      "missing: no store.json at all",
			contents:  "",
			key:       realKey,
			wantState: BreadcrumbMissing,
		},
		{
			name:      "corrupt: not JSON",
			contents:  "not json at all",
			key:       realKey,
			wantState: BreadcrumbCorrupt,
		},
		{
			name:      "corrupt: unknown schema",
			contents:  `{"schema":99,"target":"` + target + `","created":"x","last_used":"x"}`,
			key:       realKey,
			wantState: BreadcrumbCorrupt,
		},
		{
			name:      "corrupt: empty target",
			contents:  `{"schema":1,"target":"","created":"x","last_used":"x"}`,
			key:       realKey,
			wantState: BreadcrumbCorrupt,
		},
		{
			name:       "mismatched: valid JSON, key does not match the directory",
			contents:   validJSON,
			key:        otherKey,
			wantState:  BreadcrumbMismatched,
			wantTarget: target,
		},
		{
			name:       "OK: valid, key matches",
			contents:   validJSON,
			key:        realKey,
			wantState:  BreadcrumbOK,
			wantTarget: target,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keyDir := keyDirWith(t, c.contents)
			bc, state := ReadBreadcrumb(keyDir, c.key)
			if state != c.wantState {
				t.Errorf("state = %v, want %v", state, c.wantState)
			}
			if c.wantTarget != "" && bc.Target != c.wantTarget {
				t.Errorf("Target = %q, want %q", bc.Target, c.wantTarget)
			}
			if state != BreadcrumbOK && state.Trustworthy() {
				t.Errorf("BreadcrumbState(%v).Trustworthy() = true, want false — only "+
					"BreadcrumbOK may be trusted", state)
			}
		})
	}

	// Trustworthy() itself, asserted directly rather than only through the
	// table above: BreadcrumbOK is the ONLY state `snug engine gc` may use
	// Target and LastUsed from.
	if !BreadcrumbOK.Trustworthy() {
		t.Error("BreadcrumbOK.Trustworthy() = false")
	}
	for _, s := range []BreadcrumbState{BreadcrumbMissing, BreadcrumbCorrupt, BreadcrumbMismatched} {
		if s.Trustworthy() {
			t.Errorf("%v.Trustworthy() = true, want false", s)
		}
	}
}

// TestBreadcrumbRejectsControlCharactersInTarget is the forging-rune half of
// the key check: a Target carrying a newline or ESC must never be read as
// OK, because breadcrumb.go's own doc comment names the abuse sentence
// directly — "a hostile process inside the sandbox can use a writable
// breadcrumb to ... print terminal escapes into the report" (closed by
// keeping the breadcrumb OUTSIDE the payload-writable storage/ tree in the
// first place) and "steer a human into deleting a store they meant to
// keep" (closed by never trusting an untrustworthy Target's text at all).
//
// It also asserts the SECOND half of the abuse sentence directly: whatever
// raw bytes a Target carries, policy.VisibleText (the function
// internal/cli's visibleValue calls, and the one every report call site in
// enginegc.go already runs bc.Target through before printing it) neutralises
// the forging rune rather than passing it through — so even a call site that
// printed an UNTRUSTED Target by mistake would not hand a human's terminal a
// raw escape sequence.
func TestBreadcrumbRejectsControlCharactersInTarget(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"newline", "/proj/one\n/proj/two"},
		{"ESC (terminal escape)", "/proj/one\x1b[1A\x1b[2K"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !strings.ContainsFunc(c.target, policy.IsForgingRune) {
				t.Fatalf("control failed: %q contains no forging rune by policy.IsForgingRune's "+
					"own predicate — this case tests nothing", c.target)
			}

			key := KeyForTarget(c.target)
			contents := `{"schema":1,"target":` + jsonQuote(c.target) +
				`,"created":"2026-01-01T00:00:00Z","last_used":"2026-01-01T00:00:00Z"}`
			keyDir := keyDirWith(t, contents)

			bc, state := ReadBreadcrumb(keyDir, key)
			if state != BreadcrumbCorrupt {
				t.Errorf("state = %v, want BreadcrumbCorrupt — a control character in Target "+
					"must be flagged, not silently accepted as OK", state)
			}
			if state.Trustworthy() {
				t.Errorf("a Target carrying a forging rune must never be Trustworthy()")
			}

			// The screening property: whatever ReadBreadcrumb decided, the raw
			// bytes it parsed must not reach a screen unescaped. This is the
			// same predicate every print site in enginegc.go already runs
			// bc.Target through (visibleValue -> policy.VisibleText).
			visible := policy.VisibleText(bc.Target)
			if visible == bc.Target {
				t.Errorf("policy.VisibleText did not change %q at all — it must escape the "+
					"forging rune before this text reaches a human-read report", bc.Target)
			}
			if strings.ContainsFunc(visible, policy.IsForgingRune) {
				t.Errorf("policy.VisibleText(%q) = %q still contains a forging rune", bc.Target, visible)
			}
		})
	}
}

// jsonQuote renders s as a JSON string literal, byte for byte — encoding/json
// rather than a hand-rolled escape, so the fixture's control characters
// survive the trip through the same encoder writeBreadcrumb itself uses.
func jsonQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
