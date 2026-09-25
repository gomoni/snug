package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The value lists for `network`, `podman` and `git` are written out in three
// places a profile author reads — the doc comment on each Profile field, and
// the lattice table in INDEX.md §2.3 — and each drifted from the parser
// independently: `network` was documented as `isolated < egress < host` in
// both while ParseNetMode refused "host", and the Podman comment omitted
// "build". These tests fail when a documented value is refused, or an accepted
// value is undocumented, in either place.
//
// What they do not cover: prose outside the Profile comments and the §2.3
// table. A value named in a paragraph elsewhere is not graded.

type modeParser struct {
	key    string
	values func() []string
	parse  func(string) error
}

// enumerate walks a mode's constants upward from zero until String() repeats.
// Every String() here falls back to the floor's spelling for an out-of-range
// value, so the first repeat is one past the top.
func enumerate(str func(i uint8) string) []string {
	seen := map[string]bool{}
	var out []string
	for i := uint8(0); ; i++ {
		s := str(i)
		if seen[s] {
			break
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

var modeParsers = []modeParser{
	{"network",
		func() []string { return enumerate(func(i uint8) string { return NetMode(i).String() }) },
		func(s string) error { _, err := ParseNetMode(s); return err }},
	{"podman",
		func() []string { return enumerate(func(i uint8) string { return PodmanMode(i).String() }) },
		func(s string) error { _, err := ParsePodmanMode(s); return err }},
	{"git",
		func() []string { return enumerate(func(i uint8) string { return GitMode(i).String() }) },
		func(s string) error { _, err := ParseGitMode(s); return err }},
}

func sameSet(t *testing.T, where, key string, documented, accepted []string, parse func(string) error) {
	t.Helper()
	for _, v := range documented {
		if err := parse(v); err != nil {
			t.Errorf("%s documents %s = %q and the parser refuses it: %v", where, key, v, err)
		}
	}
	doc := map[string]bool{}
	for _, v := range documented {
		doc[v] = true
	}
	for _, v := range accepted {
		if !doc[v] {
			t.Errorf("%s does not list %s = %q, which the parser accepts (documented: %v)",
				where, key, v, documented)
		}
	}
}

var quoted = regexp.MustCompile(`"([^"]*)"`)

func TestProfileFieldCommentsListExactlyTheParsedModes(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "profile.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing profile.go: %v", err)
	}
	docs := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Profile" {
			return true
		}
		for _, fld := range ts.Type.(*ast.StructType).Fields.List {
			if fld.Doc == nil {
				continue
			}
			for _, name := range fld.Names {
				docs[name.Name] = fld.Doc.Text()
			}
		}
		return false
	})

	for _, m := range modeParsers {
		field := strings.ToUpper(m.key[:1]) + m.key[1:]
		text, ok := docs[field]
		if !ok {
			t.Errorf("Profile.%s has no doc comment in profile.go; this test grades its value list", field)
			continue
		}
		// The value list is the first line holding a ` | `-separated run.
		var line string
		for _, l := range strings.Split(text, "\n") {
			if strings.Contains(l, `" | "`) {
				line = l
				break
			}
		}
		if line == "" {
			t.Errorf("Profile.%s's comment has no `\"a\" | \"b\"` value list: %q", field, text)
			continue
		}
		var documented []string
		for _, q := range quoted.FindAllStringSubmatch(line, -1) {
			documented = append(documented, q[1])
		}
		sameSet(t, "profile.go's Profile."+field+" comment", m.key, documented, m.values(), m.parse)
	}
}

var latticeRow = regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\| `([^`]+)` \\|")

func TestINDEXLatticeTableListsExactlyTheParsedModes(t *testing.T) {
	index := filepath.Join("..", "..", ".claude", "design", "INDEX.md")
	body, err := os.ReadFile(index)
	if err != nil {
		t.Fatalf("cannot read %s: %v", index, err)
	}
	rows := map[string]string{}
	for _, m := range latticeRow.FindAllStringSubmatch(string(body), -1) {
		if strings.Contains(m[2], " < ") {
			rows[m[1]] = m[2]
		}
	}
	for _, m := range modeParsers {
		domain, ok := rows[m.key]
		if !ok {
			t.Errorf("INDEX.md has no `| `%s` | `a < b` |` row in §2.3's lattice table; "+
				"if the table was reshaped, update latticeRow rather than deleting the check", m.key)
			continue
		}
		documented := strings.Split(domain, " < ")
		accepted := m.values()
		sameSet(t, "INDEX.md §2.3", m.key, documented, accepted, m.parse)
		// The table claims an ORDER, and the join is max over the constants'
		// order, so the order is part of the claim.
		if strings.Join(documented, " < ") != strings.Join(accepted, " < ") {
			t.Errorf("INDEX.md §2.3 orders %s as %q; the constants join by max in the order %q",
				m.key, domain, strings.Join(accepted, " < "))
		}
	}
}
