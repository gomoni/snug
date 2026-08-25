package cli

import (
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// jsonEnvEntryKeys is the EXACT key set one `environment[].entries[]` object
// emits, in the order the struct declares them. It is pinned here, away from
// the type, so that a change to the type is a change to two files and shows up
// as a diff in a file whose only job is to say what the format promises.
//
// Why this entry and not another. `environment[]` is where issue #332's F1a
// landed: the key `note` carried snug's own AUTHORSHIP reason ("base", "podman
// stub") while a consumer read it as the annotation policy.EnvNote produces —
// so `EDITOR=/bin/nvim` came back as `{"note":"", "unchecked":false}`, an empty
// string and a false boolean, which reads as approval for the one entry on the
// screen that carried a warning. The fix renamed three keys and added a fourth
// (`note`→`authored_by`, `unchecked`→`type_unknown`, new `value_note`,
// `grant`/`grants_inside`), and a rename is exactly the change this test exists
// to make loud: format 1's promise is that a field keeps its name, its type AND
// its meaning, and the version integer alone has never held that for anybody —
// issue #52's survey found five projects that had drifted from their own
// documented format.
//
// It is also what BACKS the cross-references. dryrunjson.go's jsonEnvEntry and
// report.go's reportEnvEntry point at each other in prose, and prose pointing
// at a key name is only as true as the last person who moved the key. Rename
// `type_unknown` and this test names the field, which puts a human in front of
// the comment that has to move with it.
//
// The freed key `note` is DELIBERATELY not reused for the other meaning, and
// this list is where that is enforced: a consumer pinned to the old format
// fails on a key that vanished, and silently misreads one whose meaning changed
// underneath it.
var jsonEnvEntryKeys = []string{
	"value",
	"value_bytes",
	"verb",
	"from",
	"authored_by",
	"type_unknown",
	"value_note",
	"grant",
	"grants_inside",
}

// jsonEnvEntryOmitted is the subset of jsonEnvEntryKeys carrying `omitempty` —
// the keys a consumer must branch on rather than read. Everything else is
// ALWAYS present, including `grant` and `grants_inside`, where "" and 0 are
// themselves the fact "nothing to say" (see jsonEnvEntry.Grant).
//
// Pinned separately because moving a key across this line is a breaking change
// that changes no key name and no type: a consumer that reads `entry["grant"]`
// without a presence check keeps working right up until `grant` becomes
// omitempty, and the golden fixtures cannot show it — a value that is "" in
// every golden looks identical to a key that was dropped.
var jsonEnvEntryOmitted = map[string]bool{
	"value_bytes": true,
	"value_note":  true,
}

// TestTheJSONEnvironmentEntryKeySetIsPinned checks the pinned set three ways,
// and none of the three is redundant: the struct tags say what the type
// PROMISES, a populated value says what encoding/json actually EMITS, and a
// zero value says which keys a consumer may find missing.
func TestTheJSONEnvironmentEntryKeySetIsPinned(t *testing.T) {
	want := append([]string(nil), jsonEnvEntryKeys...)

	// ── 1. the type's own tags, in declaration order ─────────────────────
	rt := reflect.TypeOf(jsonEnvEntry{})
	var declared []string
	for i := range rt.NumField() {
		f := rt.Field(i)
		tag, ok := f.Tag.Lookup("json")
		if !ok {
			t.Errorf("jsonEnvEntry.%s has no json tag; encoding/json would emit it under its "+
				"GO name, which is not a name this format promised anybody", f.Name)
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		declared = append(declared, name)
		if got := strings.Contains(opts, "omitempty"); got != jsonEnvEntryOmitted[name] {
			t.Errorf("jsonEnvEntry.%s (%q) omitempty=%v, pinned %v. A key that starts or "+
				"stops being omittable changes what a consumer must branch on, with no key "+
				"name and no type changing — the one format change a golden fixture cannot "+
				"show.", f.Name, name, got, jsonEnvEntryOmitted[name])
		}
	}
	if strings.Join(declared, " ") != strings.Join(want, " ") {
		t.Errorf("jsonEnvEntry's json keys are\n  %s\nand the pinned set is\n  %s\n"+
			"A NEW key must be named here before it ships — format 1 is additive, so an "+
			"unnamed field is a promise nobody wrote down. A RENAMED or REMOVED key is a "+
			"breaking change: say so where the format's guarantee is documented "+
			"(dryRunFormat's doc comment), and check whether a doc comment cross-referencing "+
			"the old name moved with it.",
			strings.Join(declared, " "), strings.Join(want, " "))
	}

	// ── 2. what a POPULATED entry emits ──────────────────────────────────
	//
	// Every field non-zero, so the omitempty ones are present too. This is the
	// half that catches a tag naming one thing and this list another: part 1
	// reads the same tag string the encoder does, and would agree with itself
	// on a key the encoder never writes.
	full := jsonEnvEntry{
		Value:        "/bin/nvim",
		ValueBytes:   byteList{0x2f},
		Verb:         "set",
		From:         []string{"@claude"},
		AuthoredBy:   "base",
		TypeUnknown:  true,
		ValueNote:    "the value is a command",
		Grant:        grantNotGranted,
		GrantsInside: 2,
	}
	if got := marshalledKeys(t, full); strings.Join(got, " ") != strings.Join(sortedCopy(want), " ") {
		t.Errorf("a fully populated jsonEnvEntry emits\n  %s\nand the pinned set is\n  %s",
			strings.Join(got, " "), strings.Join(sortedCopy(want), " "))
	}

	// ── 3. what a ZERO entry emits ───────────────────────────────────────
	var always []string
	for _, k := range want {
		if !jsonEnvEntryOmitted[k] {
			always = append(always, k)
		}
	}
	sort.Strings(always)
	if got := marshalledKeys(t, jsonEnvEntry{}); strings.Join(got, " ") != strings.Join(always, " ") {
		t.Errorf("a ZERO jsonEnvEntry emits\n  %s\nand the always-present set is\n  %s\n"+
			"These are the keys a consumer may read without a presence check.",
			strings.Join(got, " "), strings.Join(always, " "))
	}

	// ── 4. and the document snug really renders ──────────────────────────
	//
	// The three checks above are about the TYPE. This one drives the renderer,
	// because a type is only the format if it is the type the document is
	// built from — and a block whose entries never reached the output would
	// pass all three above by describing a struct nobody marshals.
	doc := jsonGoldenReport(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw"}, false)
	var parsed struct {
		Environment []struct {
			Name    string                       `json:"name"`
			Entries []map[string]json.RawMessage `json:"entries"`
		} `json:"environment"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("the machine format did not parse: %v", err)
	}
	seen := 0
	for _, v := range parsed.Environment {
		for _, e := range v.Entries {
			seen++
			for k := range e {
				if !slices.Contains(want, k) {
					t.Errorf("environment %q emits the key %q, which is not in the pinned "+
						"set", v.Name, k)
				}
			}
			for _, k := range always {
				if _, ok := e[k]; !ok {
					t.Errorf("environment %q is missing the always-present key %q", v.Name, k)
				}
			}
		}
	}
	// POSITIVE CONTROL: a document with no entries at all satisfies both loops
	// above, and would report a format nobody emitted as pinned.
	if seen == 0 {
		t.Fatal("the rendered document carried NO environment entries, so the loops above " +
			"asserted nothing; the fixture or the renderer is not producing the block this " +
			"test is about")
	}
}

// TestTheJSONEnvironmentCarriesPWD is the seventh of issue #332's producers,
// and the one the AST sweep in factproducersweep_test.go structurally cannot
// see: describeBwrapAuthoredEnv takes an io.Writer, so it is a renderer by that
// test's predicate, and its counterpart in buildReport is a SYNTHETIC entry
// rather than a shared call. Two renderers agreeing here is therefore checked
// by execution or not at all.
//
// PWD is not in policy.Policy.Env: bwrap authors it from --chdir, which is why
// describeBwrapAuthoredEnv exists at all — the human block once claimed a
// variable count that was one short, and the JSON block shipped with the same
// gap (#332 F1g: 16 entries for a sandbox that will have 17).
func TestTheJSONEnvironmentCarriesPWD(t *testing.T) {
	sel := []policy.ProfileName{"@sys", "@home", "@cwd-rw"}

	doc := jsonGoldenReport(t, sel, false)
	var parsed struct {
		Environment []struct {
			Name    string `json:"name"`
			Entries []struct {
				Value      string   `json:"value"`
				Verb       string   `json:"verb"`
				AuthoredBy string   `json:"authored_by"`
				From       []string `json:"from"`
			} `json:"entries"`
		} `json:"environment"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("the machine format did not parse: %v", err)
	}

	var pwd string
	names := make([]string, 0, len(parsed.Environment))
	for _, v := range parsed.Environment {
		names = append(names, v.Name)
		if v.Name != "PWD" {
			continue
		}
		if len(v.Entries) != 1 {
			t.Fatalf("PWD carries %d entries; bwrap authors exactly one", len(v.Entries))
		}
		pwd = v.Entries[0].Value
		if v.Entries[0].AuthoredBy == "" {
			t.Error("the PWD entry carries no authored_by, so the document does not say who " +
				"wrote it — the whole reason this row is synthetic")
		}
	}
	if pwd == "" {
		t.Fatalf("PWD is not in the machine document. The variables it does carry are %s.\n"+
			"A consumer counting entries gets one fewer than the sandbox will have, which is "+
			"the claim describeBwrapAuthoredEnv exists to stop the HUMAN screen making.",
			strings.Join(names, " "))
	}

	// The two renderers must agree on the VALUE, not merely on the key. bwrap
	// derives PWD from --chdir, so the fact has one source and two printers.
	human := jsonGoldenHumanScreen(t, sel)
	if !strings.Contains(human, "PWD") {
		t.Fatalf("the human ENVIRONMENT block has no PWD row, so this test is comparing the "+
			"JSON against nothing:\n%s", human)
	}
	if !strings.Contains(human, pwd) {
		t.Errorf("the JSON says PWD=%q and the human screen does not print that value:\n%s",
			pwd, human)
	}
}

// jsonGoldenHumanScreen renders the HUMAN dry run for the same fixture host
// jsonGoldenReport uses, so the two can be compared without either one being
// re-derived from the other.
func jsonGoldenHumanScreen(t *testing.T, sel []policy.ProfileName) string {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}
	return dryRunText(p, p.BwrapArgs(0, 0), config{}, nil)
}

func marshalledKeys(t *testing.T, v jsonEnvEntry) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling jsonEnvEntry: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("re-reading the marshalled entry: %v", err)
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
