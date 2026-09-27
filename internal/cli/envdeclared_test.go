package cli

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// declaredRegistry is profile.Builtins() plus four USER profiles carrying
// environ.types — no builtin can (internal/profile's mark refuses one), so
// every screen row a declaration produces is only reachable through a fixture
// like this:
//   - gems-a, gems-b: both declare GEM_PATH a path-list and merge their own
//     directory into it; gems-a's second element has a SPACE, which the screen
//     must quote because the resolver made GEM_PATH a list (elementValue reads
//     EnvVar.List, not the roster).
//   - toolroot: declares MY_TOOL_ROOT a path and sets it.
//   - ldlibs: declares LD_MY_LIBS a path-list and merges a directory it grants
//     OPTIONALLY and the fixture host lacks. Unrostered, declared, annotated
//     (the LD_ family sentence) and not granted: the one row carrying all four
//     marks.
func declaredRegistry(t *testing.T) map[policy.ProfileName]*policy.Profile {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["gems-a"] = &policy.Profile{Name: "gems-a", RO: []string{"/opt/gems-a", "/opt/gem store"},
		Environ: policy.EnvGrants{
			Types: map[string]policy.EnvKind{"GEM_PATH": policy.EnvKindPathList},
			Merge: map[string][]string{"GEM_PATH": {"/opt/gems-a", "/opt/gem store"}}}}
	m["gems-b"] = &policy.Profile{Name: "gems-b", RO: []string{"/opt/gems-b"},
		Environ: policy.EnvGrants{
			Types: map[string]policy.EnvKind{"GEM_PATH": policy.EnvKindPathList},
			Merge: map[string][]string{"GEM_PATH": {"/opt/gems-b"}}}}
	m["toolroot"] = &policy.Profile{Name: "toolroot", RO: []string{"/opt/tool"},
		Environ: policy.EnvGrants{
			Types: map[string]policy.EnvKind{"MY_TOOL_ROOT": policy.EnvKindPath},
			Set:   map[string]string{"MY_TOOL_ROOT": "/opt/tool"}}}
	m["ldlibs"] = &policy.Profile{Name: "ldlibs", RO: []string{"/opt/ld-gone"}, Optional: []string{"/opt/ld-gone"},
		Environ: policy.EnvGrants{
			Types: map[string]policy.EnvKind{"LD_MY_LIBS": policy.EnvKindPathList},
			Merge: map[string][]string{"LD_MY_LIBS": {"/opt/ld-gone"}}}}
	return m
}

// declaredEnv adds what gems-a, gems-b and toolroot grant. /opt/ld-gone is
// deliberately absent.
func declaredEnv(env *envFakeEnv) {
	for _, d := range []string{"/opt/gems-a", "/opt/gem store", "/opt/gems-b", "/opt/tool"} {
		env.dirs[d] = true
	}
}

func declaredSelection() []policy.ProfileName {
	return append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "gems-a", "gems-b", "toolroot", "ldlibs")
}

func resolveDeclared(t *testing.T) (*policy.Policy, *envFakeEnv) {
	t.Helper()
	env := newEnvFakeEnv()
	declaredEnv(env)
	p, err := policy.Resolve(declaredRegistry(t), declaredSelection(), envGoldenCtx(), env)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return p, env
}

// TestDryRunJSONCarriesDeclaredBy would catch the machine document dropping
// the declaration the human screen renders — a consumer would see
// type_unknown with no way to tell a declared list from a name nobody typed.
func TestDryRunJSONCarriesDeclaredBy(t *testing.T) {
	p, env := resolveDeclared(t)
	rep := buildReport(env, p, p.BwrapArgs(0, 0), config{json: true}, nil, pinnedSignaturePolicy)
	var buf bytes.Buffer
	if err := renderJSON(&buf, rep); err != nil {
		t.Fatalf("renderJSON: %v", err)
	}
	var doc struct {
		Environment []struct {
			Name         string   `json:"name"`
			DeclaredKind string   `json:"declared_kind"`
			DeclaredBy   []string `json:"declared_by"`
			Entries      []struct {
				Value       string `json:"value"`
				TypeUnknown bool   `json:"type_unknown"`
			} `json:"entries"`
		} `json:"environment"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("the machine format did not parse: %v", err)
	}
	want := map[string]struct {
		kind string
		by   []string
	}{
		"GEM_PATH":     {"path-list", []string{"gems-a", "gems-b"}},
		"MY_TOOL_ROOT": {"path", []string{"toolroot"}},
		"LD_MY_LIBS":   {"path-list", []string{"ldlibs"}},
	}
	seen := 0
	for _, v := range doc.Environment {
		w, declared := want[v.Name]
		if !declared {
			// NEGATIVE: an undeclared variable carries neither key.
			if v.DeclaredKind != "" || v.DeclaredBy != nil {
				t.Errorf("%s carries declared_kind=%q declared_by=%v and nothing declared it",
					v.Name, v.DeclaredKind, v.DeclaredBy)
			}
			continue
		}
		seen++
		if v.DeclaredKind != w.kind || !slices.Equal(v.DeclaredBy, w.by) {
			t.Errorf("%s: declared_kind=%q declared_by=%v, want %q %v", v.Name, v.DeclaredKind,
				v.DeclaredBy, w.kind, w.by)
		}
		for _, e := range v.Entries {
			if !e.TypeUnknown {
				t.Errorf("%s entry %q has type_unknown=false; a declaration is not a roster row",
					v.Name, e.Value)
			}
		}
	}
	if seen != len(want) {
		t.Fatalf("found %d of the %d declared variables in the document:\n%s", seen, len(want), buf.String())
	}
	// POSITIVE CONTROL for the negative above: the wire spelling is there, so
	// its absence elsewhere is omitempty, not a renderer that never wrote it.
	if !strings.Contains(buf.String(), `"declared_by": [`) {
		t.Errorf("the literal key declared_by is not in the document:\n%s", buf.String())
	}
}

// TestProfileShowRendersEnvironTypes would catch `snug profile show` hiding a
// declaration: the types block, the declared mark on the row it governs, and
// the note on a redundant one, which is the only place a redundant declaration
// is visible at all.
func TestProfileShowRendersEnvironTypes(t *testing.T) {
	got := map[string][]string{}
	showEnviron("ruby", policy.EnvGrants{
		Types: map[string]policy.EnvKind{
			"GEM_PATH":   policy.EnvKindPathList,
			"PYTHONPATH": policy.EnvKindPathList,
		},
		Merge: map[string][]string{
			"GEM_PATH":   {"{home}/.gem"},
			"PYTHONPATH": {"{home}/py"},
		},
		Set: map[string]string{"MY_TOOL_MODE": "fast"},
	}, func(label string, vals []string) {
		if len(vals) > 0 {
			got[label] = vals
		}
	})

	types := got["environ.types"]
	if !slices.Equal(types, []string{
		"GEM_PATH = path-list",
		"PYTHONPATH = path-list  ← redundant: snug's roster types this name, and the row governs",
	}) {
		t.Errorf("environ.types rendered %q", types)
	}
	var gem, py string
	for _, v := range got["environ.merge"] {
		switch {
		case strings.HasPrefix(v, "GEM_PATH"):
			gem = v
		case strings.HasPrefix(v, "PYTHONPATH"):
			py = v
		}
	}
	if gem == "" || py == "" {
		t.Fatalf("environ.merge did not render both rows: %q", got["environ.merge"])
	}
	if !strings.Contains(gem, "← declared path-list by ruby") {
		t.Errorf("GEM_PATH's merge row carries no declared mark: %q", gem)
	}
	if i, j := strings.Index(gem, "unchecked"), strings.Index(gem, "declared"); i < 0 || j < 0 || i > j {
		t.Errorf("want unchecked before declared on %q", gem)
	}
	// NEGATIVE: the redundant declaration's row is governed by the roster, so
	// it is neither unchecked nor declared.
	if strings.Contains(py, "declared") || strings.Contains(py, "unchecked") {
		t.Errorf("PYTHONPATH (rostered, redundantly declared) rendered %q", py)
	}
	// NEGATIVE: an undeclared unrostered row is unchecked and not declared.
	if v := got["environ.set"]; len(v) != 1 || !strings.Contains(v[0], "unchecked") || strings.Contains(v[0], "declared") {
		t.Errorf("environ.set MY_TOOL_MODE rendered %q", v)
	}
}

// TestProfileShowRendersNoTypesBlockWhenNothingIsDeclared: the block is new,
// and a profile without it must not grow an empty heading on every screen.
func TestProfileShowRendersNoTypesBlockWhenNothingIsDeclared(t *testing.T) {
	called := false
	showEnviron("mine", policy.EnvGrants{Set: map[string]string{"EDITOR": "vim"}}, func(label string, vals []string) {
		if label == "environ.types" && len(vals) > 0 {
			t.Errorf("environ.types rendered %q with nothing declared", vals)
		}
		if label == "environ.set" && len(vals) > 0 {
			called = true
		}
	})
	if !called {
		t.Fatal("control: environ.set never rendered, so the callback measured nothing")
	}
}
