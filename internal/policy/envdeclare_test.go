package policy

import (
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
)

// ── environ.types: a profile declaring a type for a name the roster lacks ────
//
// Read envdeclare.go's EnvKind comment first. A declaration is trusted-layer
// text that changes which verbs ONE profile's author may write for ONE name, and
// every test here is about keeping it that narrow: it never overrides a roster
// row, never reaches a name snug writes, never licenses sanitise, never travels
// through include or across a selection, and never lets a selection that was
// refused become admitted by adding a profile.

// declaredProbeSelection is the golden's selection: two declarers of one list,
// one declarer of a scalar path.
func declaredProbeSelection() []ProfileName {
	return []ProfileName{"@sys", "@target-rw", "gems-a", "gems-b", "toolroot"}
}

// declaredProbeEnv is a host that HAS a GEM_PATH and a MY_TOOL_ROOT of its own.
// Nothing in declaredProbeSelection inherits or sanitises either, so neither
// host value may appear anywhere in the result.
func declaredProbeEnv() *fakeEnv {
	env := newFakeEnv()
	env.env["GEM_PATH"] = "/srv/host-gems:/opt/gems-a"
	env.env["MY_TOOL_ROOT"] = "/srv/host-tool"
	return env
}

// usedDeclaration is g with the one verb line a declaration of kind needs to
// pass checkEnvTypes' "unused" arm, so a test about another arm is not
// answered by that one first.
func usedDeclaration(name string, kind EnvKind) EnvGrants {
	g := EnvGrants{Types: map[string]EnvKind{name: kind}}
	switch kind {
	case EnvKindPathList:
		g.Merge = map[string][]string{name: {"/opt/x"}}
	case EnvKindPath:
		g.Set = map[string]string{name: "/opt/x"}
	}
	return g
}

func mustContain(t *testing.T, what string, err error, wants ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: accepted", what)
	}
	for _, w := range wants {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("%s: refusal does not say %q:\n%v", what, w, err)
		}
	}
}

// ── 1. the grammar of a kind ────────────────────────────────────────────────

// TestParseEnvKindAcceptsTheNamedSetOnly would catch ParseEnvKind reading a
// near-miss as the kind it resembles — "Path", "path_list", "list" — which
// would hand an author a type their file does not spell (CLAUDE.md: an
// unrecognised value refuses).
func TestParseEnvKindAcceptsTheNamedSetOnly(t *testing.T) {
	for _, k := range EnvKinds() {
		got, err := ParseEnvKind(k.String())
		if err != nil || got != k {
			t.Errorf("ParseEnvKind(%q) = %v, %v; want %v, nil", k.String(), got, err, k)
		}
	}
	// POSITIVE CONTROL for the loop above: the set is exactly the two
	// spellings the TOML documents, so an empty EnvKinds() cannot pass it.
	if got := []string{EnvKinds()[0].String(), EnvKinds()[1].String()}; len(EnvKinds()) != 2 ||
		got[0] != "path" || got[1] != "path-list" {
		t.Fatalf("EnvKinds() = %v; the accepted set is path and path-list", EnvKinds())
	}
	for _, s := range []string{"Path", "PATH-LIST", "path_list", "pathlist", "list", "scalar",
		"", " path", "path ", "unset"} {
		k, err := ParseEnvKind(s)
		if err == nil {
			t.Errorf("ParseEnvKind(%q) accepted it as %v", s, k)
			continue
		}
		if k != envKindUnset {
			t.Errorf("ParseEnvKind(%q) refused but returned %v, not the zero kind", s, k)
		}
		for _, want := range []string{fmt.Sprintf("%q", s), "want path or path-list"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("ParseEnvKind(%q): %q does not contain %q", s, err, want)
			}
		}
	}
}

// ── 2. checkEnvTypes, arm by arm ────────────────────────────────────────────

// TestDeclarationOfASnugNameIsRefused would catch a declaration reaching a name
// snug writes. HOME is the sharp case: typeOf has no row for it, so a declared
// `HOME = "path-list"` read through typeOf would exempt it from
// checkEnvOwnership and let `merge HOME` through.
func TestDeclarationOfASnugNameIsRefused(t *testing.T) {
	owned := append([]string(nil), SnugOwnedEnv...)
	cond := ConditionalEnvClaimed()
	// POSITIVE CONTROL: both sets are non-empty, and HOME — the name with no
	// roster row — is in the first, so the HOME case below is the one the
	// ownership exemption would have opened.
	if len(owned) == 0 || len(cond) == 0 || !slices.Contains(owned, "HOME") {
		t.Fatalf("owned=%v conditional=%v; this test sweeps nothing useful", owned, cond)
	}
	if _, known := typeOf("HOME"); known {
		t.Fatal("HOME has a roster row now; the case this test was written around is gone — " +
			"find another snug-owned name with no row, or delete the HOME assertions deliberately")
	}
	for _, name := range append(owned, cond...) {
		for _, k := range EnvKinds() {
			err := ValidateEnvGrants(usedDeclaration(name, k))
			if err == nil {
				t.Errorf("environ.types %s = %q was accepted; snug writes that name", name, k)
				continue
			}
			if !strings.Contains(err.Error(), "environ.types names "+name) {
				t.Errorf("environ.types %s = %q was refused by some other rule, so the "+
					"declaration arm is not what stopped it: %v", name, k, err)
			}
		}
	}
	err := ValidateEnvGrants(EnvGrants{Types: map[string]EnvKind{"HOME": EnvKindPathList},
		Merge: map[string][]string{"HOME": {"/opt/x"}}})
	mustContain(t, "HOME path-list + merge", err, "environ.types names HOME", "snug writes itself")

	// CONTROL: the same shape on a name snug does not write is accepted.
	if err := ValidateEnvGrants(usedDeclaration("GEM_PATH", EnvKindPathList)); err != nil {
		t.Fatalf("control: GEM_PATH path-list + merge refused: %v", err)
	}
}

// TestDeclarationNeverOverridesTheRoster would catch a declaration that widens
// what a roster row allows — `LD_LIBRARY_PATH = "path-list"` licensing a merge
// the row forbids, `BASH_ENV = "path"` putting a pathNoGrant scalar under a
// different rule. Every row is swept against both kinds; the verdict must be
// exactly compatibleWith, and the hand-written spot checks below are what make
// that more than compatibleWith agreeing with itself.
func TestDeclarationNeverOverridesTheRoster(t *testing.T) {
	compatible, contradicting := 0, 0
	for name, row := range envTypes {
		if slices.Contains(SnugOwnedEnv, name) || slices.Contains(ConditionalEnvClaimed(), name) {
			continue // TestDeclarationOfASnugNameIsRefused
		}
		for _, k := range EnvKinds() {
			err := ValidateEnvGrants(usedDeclaration(name, k))
			if k.compatibleWith(row) {
				compatible++
				if err != nil {
					t.Errorf("environ.types %s = %q is compatible with its row (%s) and was "+
						"refused: %v", name, k, row.describe(), err)
				}
				continue
			}
			contradicting++
			if err == nil || !strings.Contains(err.Error(), "snug's roster already types it") {
				t.Errorf("environ.types %s = %q contradicts its row (%s) and was not refused "+
					"for it: %v", name, k, row.describe(), err)
			}
		}
	}
	if compatible == 0 || contradicting == 0 {
		t.Fatalf("compatible=%d contradicting=%d; a sweep with one side empty cannot tell the "+
			"rule from a constant", compatible, contradicting)
	}

	for _, tc := range []struct {
		name string
		kind EnvKind
		ok   bool
	}{
		{"LD_PRELOAD", EnvKindPathList, false},      // not mergeable
		{"LD_LIBRARY_PATH", EnvKindPathList, false}, // not mergeable
		{"CDPATH", EnvKindPathList, false},          // not mergeable
		{"GOFLAGS", EnvKindPathList, false},         // separated by ' ', not paths
		{"BASH_ENV", EnvKindPath, false},            // pathNoGrant, not path
		{"EDITOR", EnvKindPath, false},              // not a path at all
		{"XDG_CONFIG_HOME", EnvKindPath, true},
		{"PYTHONPATH", EnvKindPathList, true},
		{"CLASSPATH", EnvKindPathList, true},
	} {
		err := ValidateEnvGrants(usedDeclaration(tc.name, tc.kind))
		if tc.ok && err != nil {
			t.Errorf("%s = %q is a redundant declaration and must be accepted: %v", tc.name, tc.kind, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s = %q contradicts snug's row and was accepted", tc.name, tc.kind)
		}
	}

	// A REDUNDANT DECLARATION IS INERT: the row still governs every check.
	// CLASSPATH's row reads ';' as a second separator; a declaration saying
	// "':'-joined" must not switch that check off.
	err := ValidateEnvGrants(EnvGrants{Types: map[string]EnvKind{"CLASSPATH": EnvKindPathList},
		Merge: map[string][]string{"CLASSPATH": {"/a;/b"}}})
	mustContain(t, "redundant CLASSPATH with a ';' element", err, "CLASSPATH")
	// PYTHONPATH's row is not sanitisable; a declaration does not make it so.
	err = ValidateEnvGrants(EnvGrants{Types: map[string]EnvKind{"PYTHONPATH": EnvKindPathList},
		Merge:    map[string][]string{"PYTHONPATH": {"/opt/py"}},
		Sanitise: []string{"PYTHONPATH"}})
	mustContain(t, "redundant PYTHONPATH + sanitise", err, "PYTHONPATH", "sanitise")
	// ...and nothing is stamped on the resolved variable: the row governs.
	reg := testRegistry()
	reg["py"] = &Profile{Name: "py", RO: []string{"/opt/py"}, Environ: EnvGrants{
		Types: map[string]EnvKind{"PYTHONPATH": EnvKindPathList},
		Merge: map[string][]string{"PYTHONPATH": {"/opt/py"}}}}
	env := newFakeEnv()
	env.dirs["/opt/py"] = true
	p, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "py"}, testCtx(), env)
	if err != nil {
		t.Fatalf("a redundant PYTHONPATH declaration did not resolve: %v", err)
	}
	v, ok := p.Env["PYTHONPATH"]
	if !ok || len(v.Entries) == 0 {
		t.Fatalf("control: PYTHONPATH never reached the policy: %+v", p.Env["PYTHONPATH"])
	}
	if v.DeclaredKind != envKindUnset || v.DeclaredBy != nil {
		t.Errorf("a redundant declaration was stamped on PYTHONPATH (%v by %v); the row governs, "+
			"and --dry-run would claim a profile typed a name snug types", v.DeclaredKind, v.DeclaredBy)
	}
	if IsUncheckedEnv("PYTHONPATH", VerbMerge) {
		t.Error("a redundant declaration made PYTHONPATH read as unchecked")
	}
}

// TestUnusedDeclarationIsRefused would catch a declaration that does nothing
// in its own profile being accepted — the shape an author writes believing it
// types the name for a profile that includes this one, which it does not.
func TestUnusedDeclarationIsRefused(t *testing.T) {
	for _, tc := range []struct {
		why  string
		g    EnvGrants
		want string
	}{
		{"path-list alone", EnvGrants{Types: map[string]EnvKind{"GEM_PATH": EnvKindPathList}},
			"neither merges nor prepends"},
		{"path-list beside inherit only", EnvGrants{Types: map[string]EnvKind{"GEM_PATH": EnvKindPathList},
			Inherit: []string{"GEM_PATH"}}, "neither merges nor prepends"},
		{"path alone", EnvGrants{Types: map[string]EnvKind{"MY_TOOL_ROOT": EnvKindPath}},
			"does not environ.set it"},
		{"path beside inherit only", EnvGrants{Types: map[string]EnvKind{"MY_TOOL_ROOT": EnvKindPath},
			Inherit: []string{"MY_TOOL_ROOT"}}, "does not environ.set it"},
		{"path beside merge only", EnvGrants{Types: map[string]EnvKind{"MY_TOOL_ROOT": EnvKindPath},
			Merge: map[string][]string{"MY_TOOL_ROOT": {"/opt/x"}}}, "does not environ.set it"},
		{"redundant path, unused", EnvGrants{Types: map[string]EnvKind{"XDG_CONFIG_HOME": EnvKindPath}},
			"does not environ.set it"},
	} {
		mustContain(t, tc.why, ValidateEnvGrants(tc.g), tc.want)
	}
	// CONTROLS: each kind with the verb it is for.
	for _, g := range []EnvGrants{
		usedDeclaration("MY_TOOL_ROOT", EnvKindPath),
		usedDeclaration("GEM_PATH", EnvKindPathList),
		{Types: map[string]EnvKind{"GEM_PATH": EnvKindPathList},
			Prepend: map[string][]string{"GEM_PATH": {"/opt/x"}}},
	} {
		if err := ValidateEnvGrants(g); err != nil {
			t.Errorf("control: %+v refused: %v", g, err)
		}
	}
}

// TestDeclaredVerbRefusals would catch checkDeclaredVerbType letting a verb
// through that the declared kind cannot carry — `set` wholesale-replacing a
// list other profiles merge into, `sanitise` on a list whose empty element
// snug has to assume is an instruction.
func TestDeclaredVerbRefusals(t *testing.T) {
	list := func(extra EnvGrants) EnvGrants {
		extra.Types = map[string]EnvKind{"GEM_PATH": EnvKindPathList}
		if extra.Merge == nil {
			extra.Merge = map[string][]string{"GEM_PATH": {"/opt/gems"}}
		}
		return extra
	}
	path := func(extra EnvGrants) EnvGrants {
		extra.Types = map[string]EnvKind{"MY_TOOL_ROOT": EnvKindPath}
		if extra.Set == nil {
			extra.Set = map[string]string{"MY_TOOL_ROOT": "/opt/tool"}
		}
		return extra
	}
	for _, tc := range []struct {
		why   string
		g     EnvGrants
		wants []string
	}{
		{"path-list + set", list(EnvGrants{Set: map[string]string{"GEM_PATH": "/opt/x"}}),
			[]string{"environ.set on GEM_PATH", "declares path-list", "environ.merge"}},
		{"path-list + inherit", list(EnvGrants{Inherit: []string{"GEM_PATH"}}),
			[]string{"environ.inherit on GEM_PATH", "declares path-list"}},
		{"path-list + sanitise", list(EnvGrants{Sanitise: []string{"GEM_PATH"}}),
			[]string{"environ.sanitise on GEM_PATH", "EMPTY element", "ADDS directories"}},
		{"path + merge", path(EnvGrants{Merge: map[string][]string{"MY_TOOL_ROOT": {"/opt/x"}}}),
			[]string{"environ.merge on MY_TOOL_ROOT", "declares path — a scalar"}},
		{"path + prepend", path(EnvGrants{Prepend: map[string][]string{"MY_TOOL_ROOT": {"/opt/x"}}}),
			[]string{"environ.prepend on MY_TOOL_ROOT", "declares path — a scalar"}},
		{"path + sanitise", path(EnvGrants{Sanitise: []string{"MY_TOOL_ROOT"}}),
			[]string{"environ.sanitise on MY_TOOL_ROOT", "declares path — a scalar"}},
	} {
		mustContain(t, tc.why, ValidateEnvGrants(tc.g), tc.wants...)
	}
	// CONTROLS: the verbs each kind licenses.
	for why, g := range map[string]EnvGrants{
		"path-list + merge":    list(EnvGrants{}),
		"path-list + prepend":  list(EnvGrants{Merge: map[string][]string{}, Prepend: map[string][]string{"GEM_PATH": {"/opt/x"}}}),
		"path + set":           path(EnvGrants{}),
		"path + set + inherit": path(EnvGrants{Inherit: []string{"MY_TOOL_ROOT"}}),
	} {
		if err := ValidateEnvGrants(g); err != nil {
			t.Errorf("control %s: refused: %v", why, err)
		}
	}
}

// ── 3. what a declaration puts in scope ─────────────────────────────────────

// TestDeclaredPathIsCoupled would catch a declared path escaping the coupling
// rule — a profile typing MY_TOOL_ROOT a path and pointing it somewhere it
// never granted. The control is the same value UNdeclared, which the coupling
// rule deliberately does not judge (isPathValued's comment): if that were
// refused too, the refusal above would not be about the declaration.
func TestDeclaredPathIsCoupled(t *testing.T) {
	reg := testRegistry()
	reg["liar"] = &Profile{Name: "liar", Environ: EnvGrants{
		Types: map[string]EnvKind{"MY_TOOL_ROOT": EnvKindPath},
		Set:   map[string]string{"MY_TOOL_ROOT": "/opt/tool"}}}
	reg["rel"] = &Profile{Name: "rel", Environ: EnvGrants{
		Types: map[string]EnvKind{"MY_TOOL_ROOT": EnvKindPath},
		Set:   map[string]string{"MY_TOOL_ROOT": "tool"}}}
	reg["plain"] = &Profile{Name: "plain", Environ: EnvGrants{
		Set: map[string]string{"MY_TOOL_ROOT": "/opt/tool"}}}

	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "liar"}, testCtx(), newFakeEnv())
	mustContain(t, "declared path, ungranted", err, `profile "liar"`, "MY_TOOL_ROOT=/opt/tool", "which it does not grant")

	_, err = Resolve(reg, []ProfileName{"@sys", "@target-rw", "rel"}, testCtx(), newFakeEnv())
	mustContain(t, "declared path, relative", err, "MY_TOOL_ROOT", "must be an absolute path")

	if _, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "toolroot"}, testCtx(), newFakeEnv()); err != nil {
		t.Errorf("a declared path the profile grants was refused: %v", err)
	}
	p, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "plain"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("control: the UNdeclared name was refused, so the refusal above is not about "+
			"the declaration: %v", err)
	}
	if !IsUncheckedEnv("MY_TOOL_ROOT", VerbSet) {
		t.Error("control: MY_TOOL_ROOT reads as rostered")
	}
	if v := p.Env["MY_TOOL_ROOT"]; v.DeclaredBy != nil {
		t.Errorf("control: an undeclared name was stamped declared by %v", v.DeclaredBy)
	}
}

// TestDeclaredListElementsAreAbsolute would catch a declared list admitting an
// element that does not begin with '/': the continuation-column argument in
// TestEveryMergeableListIsPathValued depends on it, and a relative element in a
// path list is the current directory's child, which inside snug is the target.
func TestDeclaredListElementsAreAbsolute(t *testing.T) {
	for _, bad := range []string{"gems", "./gems", "\u2003← not granted", "~/gems"} {
		reg := testRegistry()
		reg["rel"] = &Profile{Name: "rel", RO: []string{"/opt/gems-a"}, Environ: EnvGrants{
			Types: map[string]EnvKind{"GEM_PATH": EnvKindPathList},
			Merge: map[string][]string{"GEM_PATH": {"/opt/gems-a", bad}}}}
		_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "rel"}, testCtx(), newFakeEnv())
		if err == nil {
			t.Errorf("declared GEM_PATH accepted the element %q", bad)
		}
	}
	// The same through prepend.
	reg := testRegistry()
	reg["relp"] = &Profile{Name: "relp", Environ: EnvGrants{
		Types:   map[string]EnvKind{"GEM_PATH": EnvKindPathList},
		Prepend: map[string][]string{"GEM_PATH": {"gems"}}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "relp"}, testCtx(), newFakeEnv())
	mustContain(t, "declared prepend, relative", err, "GEM_PATH", "must be an absolute path")

	// CONTROL: the absolute element alone resolves.
	if _, err := Resolve(testRegistry(), []ProfileName{"@sys", "@target-rw", "gems-a"}, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("control: gems-a refused: %v", err)
	}
	// And the separator inside one element is refused at parse, as it is for a
	// rostered list: two elements written as one would skip the per-element checks.
	err = ValidateEnvGrants(EnvGrants{Types: map[string]EnvKind{"GEM_PATH": EnvKindPathList},
		Merge: map[string][]string{"GEM_PATH": {"/a:/b"}}})
	mustContain(t, "separator inside a declared element", err, "GEM_PATH")
}

// ── 4. across a selection ───────────────────────────────────────────────────

// TestTwoProfilesDeclaringTheSameListCompose is the case the feature exists for:
// two profiles on one machine each adding their own directory to one tool's
// search list.
func TestTwoProfilesDeclaringTheSameListCompose(t *testing.T) {
	reg := testRegistry()
	// A third declarer merging an element gems-a also merges: one entry, both
	// credited.
	reg["gems-both"] = &Profile{Name: "gems-both", RO: []string{"/opt/gems-a"}, Environ: EnvGrants{
		Types: map[string]EnvKind{"GEM_PATH": EnvKindPathList},
		Merge: map[string][]string{"GEM_PATH": {"/opt/gems-a"}}}}
	p, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "gems-b", "gems-both", "gems-a"},
		testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("two profiles declaring and merging one list were refused: %v", err)
	}
	v, ok := p.Env["GEM_PATH"]
	if !ok {
		t.Fatal("GEM_PATH never reached the policy")
	}
	if !v.List || v.Sep != ":" {
		t.Errorf("GEM_PATH List=%v Sep=%q; a declared path-list is a ':' list", v.List, v.Sep)
	}
	if got, _ := p.EnvValue("GEM_PATH"); got != "/opt/gems-a:/opt/gems-b" {
		t.Errorf("GEM_PATH = %q, want /opt/gems-a:/opt/gems-b", got)
	}
	want := []struct {
		value string
		from  []string
	}{
		{"/opt/gems-a", []string{"gems-a", "gems-both"}},
		{"/opt/gems-b", []string{"gems-b"}},
	}
	if len(v.Entries) != len(want) {
		t.Fatalf("GEM_PATH entries = %+v, want %d", v.Entries, len(want))
	}
	for i, w := range want {
		e := v.Entries[i]
		if e.Value != w.value || e.Verb != VerbMerge || !slices.Equal(e.From, w.from) {
			t.Errorf("entry %d = %+v, want %s merge from %v", i, e, w.value, w.from)
		}
	}
	if v.DeclaredKind != EnvKindPathList {
		t.Errorf("DeclaredKind = %v, want path-list", v.DeclaredKind)
	}
	if !slices.Equal(v.DeclaredBy, []string{"gems-a", "gems-b", "gems-both"}) {
		t.Errorf("DeclaredBy = %v, want [gems-a gems-b gems-both]", v.DeclaredBy)
	}
	// The mark is still true: snug's roster has no row for GEM_PATH.
	if !IsUncheckedEnv("GEM_PATH", VerbMerge) {
		t.Error("a declared name stopped reading as unchecked; the declaration is the author's " +
			"statement, not a roster row")
	}
}

// refusalDeclaredListVsSet: one profile declares GEM_PATH a list and merges
// into it, another writes it as one value. Joining would make the scalar one
// element of a list it was never written as; keeping it would discard every
// merge.
func refusalDeclaredListVsSet(t testing.TB) error {
	reg := testRegistry()
	reg["gemset"] = &Profile{Name: "gemset", Environ: EnvGrants{
		Set: map[string]string{"GEM_PATH": "/opt/other-gems"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "gems-a", "gemset"}, testCtx(), newFakeEnv())
	return err
}

// refusalDeclaredListVsDeclaredPath: the two sides each DECLARED, differently.
func refusalDeclaredListVsDeclaredPath(t testing.TB) error {
	reg := testRegistry()
	reg["gempath"] = &Profile{Name: "gempath", RO: []string{"/opt/gems-b"}, Environ: EnvGrants{
		Types: map[string]EnvKind{"GEM_PATH": EnvKindPath},
		Set:   map[string]string{"GEM_PATH": "/opt/gems-b"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "gems-a", "gempath"}, testCtx(), newFakeEnv())
	return err
}

// refusalDeclaredListVsInheritAbsentOnHost: `inherit` is judged from the
// profile's TEXT. The fixture host has no GEM_PATH, and the selection is
// refused anyway — so the same selection cannot resolve on one machine and not
// on the next.
func refusalDeclaredListVsInheritAbsentOnHost(t testing.TB) error {
	reg := testRegistry()
	reg["geminherit"] = &Profile{Name: "geminherit", Environ: EnvGrants{Inherit: []string{"GEM_PATH"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "gems-a", "geminherit"}, testCtx(), newFakeEnv())
	return err
}

// refusalDeclaredPathUncoupled: a declared path the declaring profile does not
// grant.
func refusalDeclaredPathUncoupled(t testing.TB) error {
	reg := testRegistry()
	reg["liar"] = &Profile{Name: "liar", Environ: EnvGrants{
		Types: map[string]EnvKind{"MY_TOOL_ROOT": EnvKindPath},
		Set:   map[string]string{"MY_TOOL_ROOT": "/opt/tool"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "liar"}, testCtx(), newFakeEnv())
	return err
}

// refusalDeclaredRelativeMerge: a relative element in a declared list.
func refusalDeclaredRelativeMerge(t testing.TB) error {
	reg := testRegistry()
	reg["relgems"] = &Profile{Name: "relgems", Environ: EnvGrants{
		Types: map[string]EnvKind{"GEM_PATH": EnvKindPathList},
		Merge: map[string][]string{"GEM_PATH": {"vendor/gems"}}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "relgems"}, testCtx(), newFakeEnv())
	return err
}

// refusalDeclarationDoesNotTravelThroughInclude: gems-a declares GEM_PATH; a
// profile including gems-a merges into it without declaring it itself.
func refusalDeclarationDoesNotTravelThroughInclude(t testing.TB) error {
	reg := testRegistry()
	reg["ruby"] = &Profile{Name: "ruby", Include: []ProfileName{"gems-a"}, RO: []string{"/opt/gems-b"},
		Environ: EnvGrants{Merge: map[string][]string{"GEM_PATH": {"/opt/gems-b"}}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "ruby"}, testCtx(), newFakeEnv())
	return err
}

// TestDeclaredShapeConflictIsRefusedSymmetrically would catch the list-vs-value
// verdict depending on selection order or on the host: an `inherit` counted
// only when the host has the variable would make one profile set resolve on
// one machine and be refused on the next.
func TestDeclaredShapeConflictIsRefusedSymmetrically(t *testing.T) {
	reg := testRegistry()
	reg["gemset"] = &Profile{Name: "gemset", Environ: EnvGrants{
		Set: map[string]string{"GEM_PATH": "/opt/other-gems"}}}
	reg["gempath"] = &Profile{Name: "gempath", RO: []string{"/opt/gems-b"}, Environ: EnvGrants{
		Types: map[string]EnvKind{"GEM_PATH": EnvKindPath},
		Set:   map[string]string{"GEM_PATH": "/opt/gems-b"}}}
	reg["geminherit"] = &Profile{Name: "geminherit", Environ: EnvGrants{Inherit: []string{"GEM_PATH"}}}

	withHost := newFakeEnv()
	withHost.env["GEM_PATH"] = "/opt/gems-a"

	for _, other := range []ProfileName{"gemset", "gempath", "geminherit"} {
		var first string
		for _, env := range []*fakeEnv{newFakeEnv(), withHost} {
			for _, sel := range [][]ProfileName{
				{"@sys", "@target-rw", "gems-a", other},
				{other, "gems-a", "@target-rw", "@sys"},
				{"gems-a", "@sys", other, "@target-rw"},
			} {
				_, err := Resolve(reg, sel, testCtx(), env)
				if err == nil {
					t.Errorf("gems-a beside %s resolved (selection %v)", other, sel)
					continue
				}
				if first == "" {
					first = err.Error()
					for _, want := range []string{"GEM_PATH is typed two ways",
						"gems-a (environ.types) declares it path-list and merges",
						string(other) + " (environ.", "drop one of " + JoinNames(sortedPair("gems-a", other), ", ")} {
						if !strings.Contains(first, want) {
							t.Errorf("gems-a vs %s: refusal does not say %q:\n%s", other, want, first)
						}
					}
					continue
				}
				if err.Error() != first {
					t.Errorf("gems-a vs %s: refusal changed with order or host:\n%s\n--- vs\n%s",
						other, err, first)
				}
			}
		}
	}
	// CONTROL: gems-a and gems-b (both declared lists) do not conflict, so the
	// refusals above are about the shapes and not about two profiles.
	if _, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "gems-a", "gems-b"}, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("control: two declared lists refused: %v", err)
	}
}

func sortedPair(a, b ProfileName) []ProfileName {
	out := []ProfileName{a, b}
	slices.Sort(out)
	return out
}

// TestDeclaredPathAndUndeclaredSetAgree would catch the declaration turning an
// agreeing pair of scalar writers into a conflict — or a disagreeing pair into
// an agreement. Declared `path` is still a scalar: equal values join, unequal
// ones meet the ordinary disagreement refusal.
func TestDeclaredPathAndUndeclaredSetAgree(t *testing.T) {
	reg := testRegistry()
	reg["same"] = &Profile{Name: "same", Environ: EnvGrants{Set: map[string]string{"MY_TOOL_ROOT": "/opt/tool"}}}
	reg["other"] = &Profile{Name: "other", Environ: EnvGrants{Set: map[string]string{"MY_TOOL_ROOT": "/opt/elsewhere"}}}

	p, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "toolroot", "same"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("a declared path and an undeclared set of the SAME value were refused: %v", err)
	}
	v := p.Env["MY_TOOL_ROOT"]
	if got, _ := p.EnvValue("MY_TOOL_ROOT"); got != "/opt/tool" || v.List {
		t.Errorf("MY_TOOL_ROOT = %q (list=%v), want the scalar /opt/tool", got, v.List)
	}
	if v.DeclaredKind != EnvKindPath || !slices.Equal(v.DeclaredBy, []string{"toolroot"}) {
		t.Errorf("declared %v by %v, want path by [toolroot]", v.DeclaredKind, v.DeclaredBy)
	}

	_, err = Resolve(reg, []ProfileName{"@sys", "@target-rw", "toolroot", "other"}, testCtx(), newFakeEnv())
	mustContain(t, "declared path vs a different set", err, "MY_TOOL_ROOT", "toolroot", "other",
		"/opt/tool", "/opt/elsewhere")
}

// TestResolveIsCommutativeWithDeclarations would catch DeclaredBy, DeclaredKind
// or the merged order depending on the order profiles were named, or on a
// profile being named twice.
func TestResolveIsCommutativeWithDeclarations(t *testing.T) {
	reg := testRegistry()
	reg["same"] = &Profile{Name: "same", Environ: EnvGrants{Set: map[string]string{"MY_TOOL_ROOT": "/opt/tool"}}}
	all := []ProfileName{"@sys", "@target-rw", "gems-a", "gems-b", "toolroot", "same", "envy"}
	res := func(sel []ProfileName) string {
		t.Helper()
		p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
		if err != nil {
			t.Fatalf("Resolve(%v): %v", sel, err)
		}
		return canon(p)
	}
	want := res(all)
	// POSITIVE CONTROL: canon renders the declaration, so a DeclaredBy that
	// moved would move the string compared below.
	for _, s := range []string{"env GEM_PATH declared path-list by [gems-a gems-b]",
		"env MY_TOOL_ROOT declared path by [toolroot]"} {
		if !strings.Contains(want, s) {
			t.Fatalf("canon does not render %q, so this test compares nothing about "+
				"declarations:\n%s", s, want)
		}
	}
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 100; i++ {
		sh := append([]ProfileName(nil), all...)
		rng.Shuffle(len(sh), func(a, b int) { sh[a], sh[b] = sh[b], sh[a] })
		if got := res(sh); got != want {
			t.Fatalf("order changed the result\norder: %v\n--- got\n%s\n--- want\n%s", sh, got, want)
		}
	}
	for _, name := range []ProfileName{"gems-a", "gems-b", "toolroot"} {
		once := res([]ProfileName{"@sys", "@target-rw", name})
		twice := res([]ProfileName{"@sys", "@target-rw", name, name})
		if once != twice {
			t.Errorf("%s: selecting twice differs from once\n--- once\n%s\n--- twice\n%s", name, once, twice)
		}
	}
}

// TestDeclarationDoesNotTravelThroughInclude would catch a declaration in one
// profile licensing a list verb in another — through include, or by being
// selected beside it. Either would make one file's legality depend on a file
// its reader is not looking at.
func TestDeclarationDoesNotTravelThroughInclude(t *testing.T) {
	err := refusalDeclarationDoesNotTravelThroughInclude(t)
	mustContain(t, "merge in a profile including the declarer", err,
		`profile "ruby"`, "environ.merge on GEM_PATH, which snug has no entry for",
		"A declaration in a profile this one includes does not apply here")

	reg := testRegistry()
	reg["beside"] = &Profile{Name: "beside", RO: []string{"/opt/gems-b"},
		Environ: EnvGrants{Merge: map[string][]string{"GEM_PATH": {"/opt/gems-b"}}}}
	_, err = Resolve(reg, []ProfileName{"@sys", "@target-rw", "gems-a", "beside"}, testCtx(), newFakeEnv())
	mustContain(t, "merge beside the declarer", err, `profile "beside"`, "which snug has no entry for")

	// CONTROL: the including profile declaring it too is admitted, and both
	// declarers are credited.
	reg["ruby"] = &Profile{Name: "ruby", Include: []ProfileName{"gems-a"}, RO: []string{"/opt/gems-b"},
		Environ: EnvGrants{Types: map[string]EnvKind{"GEM_PATH": EnvKindPathList},
			Merge: map[string][]string{"GEM_PATH": {"/opt/gems-b"}}}}
	p, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "ruby"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("control: a profile declaring its own merge was refused: %v", err)
	}
	if v := p.Env["GEM_PATH"]; !slices.Equal(v.DeclaredBy, []string{"gems-a", "ruby"}) {
		t.Errorf("DeclaredBy = %v, want [gems-a ruby]", v.DeclaredBy)
	}
}

// TestAddingAProfileNeverAdmitsADeclaredVerb is monotonicity for this feature:
// for every selection over a fixture set that includes both shapes, adding one
// more profile never turns a refusal into an admission, and where both resolve
// no GEM_PATH or MY_TOOL_ROOT entry disappears.
func TestAddingAProfileNeverAdmitsADeclaredVerb(t *testing.T) {
	reg := testRegistry()
	reg["gemset"] = &Profile{Name: "gemset", Environ: EnvGrants{
		Set: map[string]string{"GEM_PATH": "/opt/other-gems"}}}
	reg["geminherit"] = &Profile{Name: "geminherit", Environ: EnvGrants{Inherit: []string{"GEM_PATH"}}}
	reg["same"] = &Profile{Name: "same", Environ: EnvGrants{Set: map[string]string{"MY_TOOL_ROOT": "/opt/tool"}}}
	reg["other"] = &Profile{Name: "other", Environ: EnvGrants{Set: map[string]string{"MY_TOOL_ROOT": "/opt/elsewhere"}}}
	pool := []ProfileName{"gems-a", "gems-b", "toolroot", "gemset", "geminherit", "same", "other"}
	base := []ProfileName{"@sys", "@target-rw"}

	resolve := func(sub []ProfileName) (*Policy, error) {
		return Resolve(reg, append(append([]ProfileName{}, base...), sub...), testCtx(), newFakeEnv())
	}
	refused, admitted := 0, 0
	for mask := 0; mask < 1<<len(pool); mask++ {
		var sub []ProfileName
		for i, n := range pool {
			if mask&(1<<i) != 0 {
				sub = append(sub, n)
			}
		}
		was, errWas := resolve(sub)
		if errWas != nil {
			refused++
		} else {
			admitted++
		}
		for i, extra := range pool {
			if mask&(1<<i) != 0 {
				continue
			}
			now, errNow := resolve(append(append([]ProfileName{}, sub...), extra))
			if errWas != nil && errNow == nil {
				t.Errorf("%v was refused (%v) and adding %s ADMITTED it", sub, errWas, extra)
				continue
			}
			if errWas != nil || errNow != nil {
				continue
			}
			for _, name := range []string{"GEM_PATH", "MY_TOOL_ROOT"} {
				for _, e := range was.Env[name].Entries {
					if !slices.ContainsFunc(now.Env[name].Entries, func(f EnvEntry) bool { return f.Value == e.Value }) {
						t.Errorf("%v: adding %s removed the %s entry %q", sub, extra, name, e.Value)
					}
				}
			}
		}
	}
	// POSITIVE CONTROL: the sweep met both verdicts.
	if refused == 0 || admitted == 0 {
		t.Fatalf("refused=%d admitted=%d; the sweep never exercised one side", refused, admitted)
	}
}

// TestSanitiseIsUnreachableForADeclaredName would catch sanitiseHostList being
// handed a declared type. Its filter rests on the row's empty-element kind, and
// a declared list's is an ASSUMPTION (emptyOperator), under which filtering can
// add directories rather than remove them.
func TestSanitiseIsUnreachableForADeclaredName(t *testing.T) {
	for _, g := range []EnvGrants{
		{Types: map[string]EnvKind{"GEM_PATH": EnvKindPathList},
			Merge: map[string][]string{"GEM_PATH": {"/opt/gems-a"}}, Sanitise: []string{"GEM_PATH"}},
		{Types: map[string]EnvKind{"MY_TOOL_ROOT": EnvKindPath},
			Set: map[string]string{"MY_TOOL_ROOT": "/opt/tool"}, Sanitise: []string{"MY_TOOL_ROOT"}},
		// Undeclared, for completeness: the no-row refusal still stands.
		{Sanitise: []string{"GEM_PATH"}},
	} {
		mustContain(t, "sanitise on a declared or unrostered name", ValidateEnvGrants(g), "environ.sanitise on")
	}
	// Through the resolver, with a host GEM_PATH carrying a granted element and
	// an ungranted one: neither appears, and nothing is recorded as dropped,
	// because no filter ran over the host's value at all.
	env := newFakeEnv()
	env.env["GEM_PATH"] = "/opt/gems-b:/srv/host-gems"
	p, err := Resolve(testRegistry(), []ProfileName{"@sys", "@target-rw", "gems-a", "gems-b"}, testCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	v := p.Env["GEM_PATH"]
	if len(v.Entries) == 0 {
		t.Fatal("control: GEM_PATH never reached the policy")
	}
	for _, e := range v.Entries {
		if e.Verb != VerbMerge || e.Value == "/srv/host-gems" {
			t.Errorf("a GEM_PATH entry came from somewhere other than a merge: %+v", e)
		}
	}
	if len(v.Dropped) != 0 {
		t.Errorf("GEM_PATH records drops %+v; a filter ran over the host value", v.Dropped)
	}
}

// ── 5. the argv ─────────────────────────────────────────────────────────────

// TestDeclaredProbeArgvCarriesNoHostValue asserts on the golden's argv directly
// what its comment claims, so that claim is checked even when the golden is
// regenerated without reading.
func TestDeclaredProbeArgvCarriesNoHostValue(t *testing.T) {
	p, err := Resolve(testRegistry(), declaredProbeSelection(), testCtx(), declaredProbeEnv())
	if err != nil {
		t.Fatal(err)
	}
	args := p.BwrapArgs(1000, 1000)
	got := map[string]string{}
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "--setenv" {
			got[args[i+1]] = args[i+2]
		}
	}
	if got["GEM_PATH"] != "/opt/gems-a:/opt/gems-b" {
		t.Errorf("--setenv GEM_PATH %q, want /opt/gems-a:/opt/gems-b", got["GEM_PATH"])
	}
	if got["MY_TOOL_ROOT"] != "/opt/tool" {
		t.Errorf("--setenv MY_TOOL_ROOT %q, want /opt/tool", got["MY_TOOL_ROOT"])
	}
	for _, a := range args {
		if strings.Contains(a, "/srv/host-") {
			t.Errorf("a host value reached the argv: %q", a)
		}
	}
}
