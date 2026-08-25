package engine

// reclaimablestorekey_test.go is issue #349's legacy-key half: the rename
// that put "sha256_" into every NEW store name must not strand what snug
// already wrote under the old bare-digest name. ReclaimableStoreKey is the
// predicate that decides what `snug engine gc` will still SEE; a predicate
// that silently narrowed back to the labelled shape alone would make every
// bare-digest store invisible to --dry-run, --unattributed and the CLI's own
// argument check, with no error — the store would simply stop being listed.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/targetkey"
)

// TestReclaimableStoreKeyAcceptsBothShapesAndRejectsEverythingElse is a
// table over the three shapes ReclaimableStoreKey must accept (StoreKey's own
// labelled form, the bare 64-hex digest that preceded the label, and the
// 16-hex truncation that preceded the full digest) and the near-miss shapes
// it must reject — each one differs from a valid key in exactly one way, so
// a table entry that started passing would name precisely which check
// loosened.
func TestReclaimableStoreKeyAcceptsBothShapesAndRejectsEverythingElse(t *testing.T) {
	hex64 := strings.Repeat("a", 64)

	cases := []struct {
		name string
		s    string
		want bool
	}{
		{"labelled, valid", "sha256_" + hex64, true},
		{"legacy bare hex, valid", hex64, true},
		// The 16-char truncation is a THIRD generation, and 554 of them sit
		// under engines/ on the maintainer's box: unreachable by the GC even
		// before the label landed, because its pattern already demanded 64.
		{"legacy truncated 16, valid", hex64[:16], true},
		{"truncated, one char short", hex64[:15], false},
		{"truncated, one char long", hex64[:17], false},
		{"legacy, one char short", hex64[:63], false},
		{"legacy, one char long", hex64 + "a", false},
		{"legacy, uppercase", strings.Repeat("A", 64), false},
		{"labelled with wrong algorithm label", "sha1_" + hex64, false},
		{"labelled, hex one char short", "sha256_" + hex64[:63], false},
		{"labelled, hex one char long", "sha256_" + hex64 + "a", false},
		{"path traversal", "../" + hex64, false},
		{"path traversal, labelled", "sha256_../" + hex64, false},
		{"empty string", "", false},
		{"just the label, no digest", "sha256_", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ReclaimableStoreKey(c.s); got != c.want {
				t.Errorf("ReclaimableStoreKey(%q) = %v, want %v", c.s, got, c.want)
			}
		})
	}
}

// TestReclaimableStoreKeyPositiveControlsAgainstRealFunctions is the
// positive control the table above cannot supply on its own: a key that
// KeyForTarget (the labelled form) or targetkey.Hash's bare digest (the
// legacy form, stripped of its label) actually produces must be accepted —
// proving the predicate matches what this codebase really writes, not
// merely a hand-built string shaped like it.
func TestReclaimableStoreKeyPositiveControlsAgainstRealFunctions(t *testing.T) {
	labelled := KeyForTarget("/proj/reclaimable-control")
	if !ReclaimableStoreKey(labelled) {
		t.Errorf("ReclaimableStoreKey rejected KeyForTarget's own output %q", labelled)
	}
	legacy := strings.TrimPrefix(targetkey.Hash("/proj/reclaimable-control"), "sha256_")
	if !ReclaimableStoreKey(legacy) {
		t.Errorf("ReclaimableStoreKey rejected a legacy bare digest %q", legacy)
	}
}

// TestListEngineEntriesSeesLabelledAndLegacyLeavesTheRestAlone builds one
// fixture directory holding every shape ListEngineEntries has to tell apart:
// a labelled store, a legacy bare-hex store (issue #349 — written before the
// label existed), a leftover naming each of those two key shapes, an
// unrelated directory snug never produced, and a plain file shaped like a
// valid key. It asserts exactly which four are returned and with what
// Key/Leftover, so a change that starts returning the ignored two, or stops
// returning one of the four, fails here directly rather than in an end-to-
// end CLI test three layers away.
func TestListEngineEntriesSeesLabelledAndLegacyLeavesTheRestAlone(t *testing.T) {
	dir := t.TempDir()

	labelledKey := KeyForTarget("/proj/list-entries-labelled")
	legacyKey := strings.TrimPrefix(targetkey.Hash("/proj/list-entries-legacy"), "sha256_")
	labelledLeftover := ".gc-" + labelledKey + "-111-222"
	legacyLeftover := ".gc-" + legacyKey + "-333-444"

	mustMkdir := func(name string) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mustMkdir(labelledKey)
	mustMkdir(legacyKey)
	mustMkdir(labelledLeftover)
	mustMkdir(legacyLeftover)
	mustMkdir("a-random-word") // never produced by snug's own naming: ignored
	// A FILE, not a directory, shaped exactly like a valid labelled key —
	// ListEngineEntries must skip it on e.IsDir() alone, before the name
	// pattern ever enters into it.
	fileShapedLikeAKey := KeyForTarget("/proj/list-entries-file-not-dir")
	if err := os.WriteFile(filepath.Join(dir, fileShapedLikeAKey), []byte("not a store"), 0o600); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	entries, err := ListEngineEntries(root)
	if err != nil {
		t.Fatalf("ListEngineEntries: %v", err)
	}

	got := map[string]EngineEntry{}
	for _, e := range entries {
		got[e.Name] = e
	}

	if len(got) != 4 {
		names := make([]string, 0, len(got))
		for n := range got {
			names = append(names, n)
		}
		t.Fatalf("ListEngineEntries returned %d entries, want 4 (labelled store, legacy store, "+
			"two leftovers): %v", len(got), names)
	}

	want := map[string]EngineEntry{
		labelledKey:      {Name: labelledKey, Key: labelledKey, Leftover: false},
		legacyKey:        {Name: legacyKey, Key: legacyKey, Leftover: false},
		labelledLeftover: {Name: labelledLeftover, Key: labelledKey, Leftover: true},
		legacyLeftover:   {Name: legacyLeftover, Key: legacyKey, Leftover: true},
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("ListEngineEntries did not report %s at all", name)
			continue
		}
		if g != w {
			t.Errorf("ListEngineEntries reported %s as %+v, want %+v", name, g, w)
		}
	}
	for name := range got {
		if _, expected := want[name]; !expected {
			t.Errorf("ListEngineEntries reported %s, which should have been left alone (either "+
				"the random-word directory or the file shaped like a key)", name)
		}
	}
}

// TestStoreKeyRejectsWhatReclaimableStoreKeyAccepts is the contrast the two
// predicates exist to draw: StoreKey is what parseEngineGCArgs used to gate
// every key typed on the command line against, and it must accept ONLY the
// current, labelled shape — the two legacy generations are reclaimable (the
// GC must still SEE and LIST them) but are not what KeyForTarget derives
// today, so a caller asking "is this shaped like the name snug would write
// NOW" (a golden-file assertion, a fresh-write check) must get "no" for
// either legacy form even though ReclaimableStoreKey says "yes".
func TestStoreKeyRejectsWhatReclaimableStoreKeyAccepts(t *testing.T) {
	hex64 := strings.Repeat("a", 64)
	for _, s := range []string{hex64, hex64[:16]} {
		if StoreKey(s) {
			t.Errorf("StoreKey(%q) = true, want false — only the labelled form is StoreKey's own shape", s)
		}
		if !ReclaimableStoreKey(s) {
			t.Errorf("control failed: ReclaimableStoreKey(%q) = false — this fixture is supposed "+
				"to be a legacy shape ReclaimableStoreKey DOES accept, or the contrast this test "+
				"draws is not real", s)
		}
	}
	labelled := "sha256_" + hex64
	if !StoreKey(labelled) {
		t.Errorf("StoreKey(%q) = false, want true — this is StoreKey's own shape", labelled)
	}
}
