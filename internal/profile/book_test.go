package profile

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The user guide under docs/src is hand-written prose over machine-checked
// facts. These tests are the checks: every profile example parses, the key
// table lists exactly the keys the decoder accepts, and no example teaches a
// spelling TOML 1.0 does not have.

func bookPages(t *testing.T) []string {
	t.Helper()
	var pages []string
	for _, pat := range []string{"../../docs/src/*.md", "../../docs/src/*/*.md"} {
		m, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, m...)
	}
	if len(pages) == 0 {
		t.Fatal("no pages under ../../docs/src; the book moved and this test did not")
	}
	return pages
}

// TestBookExampleProfilesParse runs every complete profile example in the
// book through parse, the path a file in profiles.d takes. The extraction
// rule is TestDocumentedExampleProfilesParse's.
func TestBookExampleProfilesParse(t *testing.T) {
	var all []docCandidate
	for _, p := range bookPages(t) {
		all = append(all, extractProfileExamples(t, p)...)
	}
	// Non-vacuity: the book holds eight complete examples; a rule that stops
	// matching must fail here rather than check nothing.
	const floor = 8
	if len(all) < floor {
		t.Fatalf("found %d profile example(s) in the book, want at least %d; the "+
			"extraction rule stopped matching or the examples were removed", len(all), floor)
	}
	for _, c := range all {
		if _, err := parse([]byte(c.text), c.source, false); err != nil {
			t.Errorf("%s does not parse as a snug profile:\n%v\n--- example ---\n%s", c.source, err, c.text)
		}
	}
}

// TestBookHasNoMultiLineInlineTable refuses an inline table `{ … }` that
// spans lines in any code block of the book. TOML 1.0 requires an inline
// table on one line; go-toml accepts more, so an example written that way
// would work in snug and fail in any strict parser — and users copy the
// guide. Anything longer than a line is a [table] header, as in Cargo.toml.
// A ```go fence is skipped: Go braces are not TOML, and a Go block carries no
// profile. Every other fence is checked, untagged ones and shell heredocs
// included, because that is where profiles are written.
func TestBookHasNoMultiLineInlineTable(t *testing.T) {
	for _, p := range bookPages(t) {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range extractFences(string(data)) {
			if f.lang == "go" {
				continue
			}
			for i, line := range strings.Split(f.text, "\n") {
				if strings.Count(stripTOMLStrings(line), "{") > strings.Count(stripTOMLStrings(line), "}") {
					t.Errorf("%s %s (+%d): an inline table opens and does not close on the same "+
						"line; TOML 1.0 has no multi-line inline table. Use a [table] header:\n  %s",
						p, f.source, i, line)
				}
			}
		}
	}
}

var tomlString = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'[^']*'`)

// stripTOMLStrings drops quoted strings, whose braces — "{home}" — are text.
func stripTOMLStrings(line string) string {
	if i := strings.Index(line, "#"); i >= 0 && !strings.Contains(line[:i], `"`) {
		line = line[:i]
	}
	return tomlString.ReplaceAllString(line, "")
}

// tomlKeys walks a decode struct and returns every dotted key it accepts. A
// struct-valued field is a TOML table and contributes its own keys under its
// name; a slice of structs is an array of tables and is one key.
func tomlKeys(t reflect.Type, prefix string) []string {
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("toml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct {
			out = append(out, tomlKeys(ft, prefix+tag+".")...)
			continue
		}
		out = append(out, prefix+tag)
	}
	return out
}

var keyRow = regexp.MustCompile("(?m)^\\| `([a-z_.]+)` \\|")

// TestBookProfileKeysTableListsEveryKey compares the key table in
// docs/src/reference/profile-keys.md with the keys the strict decoder
// accepts, in both directions.
func TestBookProfileKeysTableListsEveryKey(t *testing.T) {
	const page = "../../docs/src/reference/profile-keys.md"
	data, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	var documented []string
	for _, m := range keyRow.FindAllStringSubmatch(string(data), -1) {
		documented = append(documented, m[1])
	}
	accepted := tomlKeys(reflect.TypeOf(rawProfile{}), "")
	for _, k := range accepted {
		if !slices.Contains(documented, k) {
			t.Errorf("%s does not list %q, which a profile may write", page, k)
		}
	}
	for _, k := range documented {
		if !slices.Contains(accepted, k) {
			t.Errorf("%s lists %q, which the decoder refuses as an unknown key", page, k)
		}
	}
}

var mdLink = regexp.MustCompile(`\]\(([^)#:]+\.md)(#[^)]*)?\)`)

// TestBookLinksResolve checks that every relative page link in the book,
// the summary page included, names a page that exists. Anchors are mdBook's to
// render and are not checked here.
func TestBookLinksResolve(t *testing.T) {
	for _, p := range bookPages(t) {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range mdLink.FindAllStringSubmatch(string(data), -1) {
			target := filepath.Join(filepath.Dir(p), m[1])
			if _, err := os.Stat(target); err != nil {
				t.Errorf("%s links to %s, which does not exist", p, m[1])
			}
		}
	}
}
