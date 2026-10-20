package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"testing"
)

// The value lists for `network` and `podman` are written out in three
// places a profile author reads — the doc comment on each Profile field, and
// the book — and each drifted from the parser
// independently: `network` was documented as `isolated < egress < host` in
// both while ParseNetMode refused "host", and the Podman comment omitted
// "build". These tests fail when a documented value is refused, or an accepted
// value is undocumented, in the comments (the book is held by bookmodes_test.go).
//
// What they do not cover: prose outside the Profile comments. A value named in a paragraph elsewhere is not graded.

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
}

// sameSet grades a documented value list against a mode's constants. The first
// constant is the floor: it is display-only, so the documentation must list it
// (String() spells it) and the parser must refuse it; every other value must
// be listed and accepted.
func sameSet(t *testing.T, where, key string, documented, accepted []string, parse func(string) error) {
	t.Helper()
	floor := accepted[0]
	for _, v := range documented {
		err := parse(v)
		if v == floor {
			if err == nil {
				t.Errorf("%s documents %s = %q, the floor, and the parser accepts it; a profile can only add", where, key, v)
			}
			continue
		}
		if err != nil {
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
