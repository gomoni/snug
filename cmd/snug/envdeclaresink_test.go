package main

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// ── issue #44: the roster sweep, and the "unchecked" mark at every sink ─────
//
// The roster (internal/policy/envtypes.go) is what a shipped profile is
// implicitly trusted against: no builtin may `environ.declare`
// (internal/profile's mark refuses it), so every name a builtin writes must
// have a row. This file is the regression test that makes the NEXT roster
// deletion fail loudly — a name deleted from envtypes.go while a builtin
// still inherits or sets it — instead of shipping quietly and breaking at
// runtime the way §44's own history (three red-team rounds, each closing
// names the last one missed) shows it otherwise would.
//
// It also covers the other half of the design: `environ.declare` has to be
// VISIBLE, at every sink that renders an environment name, not just the one
// somebody remembered — the same "assert the SET of sinks" shape as
// TestNoSnugScreenEmitsARawControlCharacter in visible_test.go, whose own
// comment records what happens when a fixture only ever drove one of them.

// TestEveryBuiltinEnvVarHasARosterRow resolves every shipped profile at once
// (mirroring TestResolvedPolicyAuthorsOnlyOwnedNames's fixture) and asserts
// that nothing in the result reads as "unchecked" — a builtin cannot declare,
// so an unchecked entry here can only mean a roster row was deleted out from
// under a profile that still relies on it.
func TestEveryBuiltinEnvVarHasARosterRow(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	var sel []policy.ProfileName
	for name, p := range reg {
		// @net-host wants the host network namespace and @tmp-shared wants a
		// host directory the caller allocates; neither touches the
		// environment and both would make Resolve fail for reasons unrelated
		// to this sweep.
		if p.Network == "host" || name == "@tmp-shared" {
			continue
		}
		sel = append(sel, name)
	}
	slices.Sort(sel)

	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}

	checked := 0
	for name, v := range p.Env {
		for _, e := range v.Entries {
			checked++
			if policy.IsUncheckedEnv(name, e.Verb) {
				t.Errorf("%s (environ.%s, from %v) has no roster row. A builtin cannot "+
					"reach environ.declare (internal/profile's mark refuses it), so this is "+
					"either a roster row deleted out from under a profile that still writes "+
					"this name, or IsUncheckedEnv itself misreporting a snug-authored entry",
					name, e.Verb, e.From)
			}
		}
	}

	// POSITIVE CONTROL: a sweep over zero entries would pass vacuously. This
	// selection includes @claude, which writes EDITOR/VISUAL/PAGER/NO_COLOR/
	// ANTHROPIC_BASE_URL through `inherit` — all rows this PR added — so the
	// sweep is exercising exactly the roster the flip depends on.
	if checked == 0 {
		t.Fatal("no environment entries were resolved at all; this sweep checked nothing")
	}
}

// leakyEnvRegistry builds a builtin-plus-one-user-profile registry, where the
// user profile declares and sets a name with no roster row. Shared by the two
// sink tests below so both drive the identical fixture.
func leakyEnvRegistry(t *testing.T) map[policy.ProfileName]*policy.Profile {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["leaky"] = &policy.Profile{
		Name:    "leaky",
		Include: []policy.ProfileName{"@sys", "@home", "@cwd-rw"},
		Environ: policy.EnvGrants{
			Declare: []string{"MY_TOOL_MODE"},
			Set:     map[string]string{"MY_TOOL_MODE": "fast"},
		},
	}
	return m
}

// TestDryRunMarksADeclaredNameAsUnchecked drives the real --dry-run rendering
// path (describeEnvironment -> envLines -> policy.IsUncheckedEnv), the same
// function envgolden_test.go's goldens exercise, rather than a
// re-implementation of it.
func TestDryRunMarksADeclaredNameAsUnchecked(t *testing.T) {
	m := leakyEnvRegistry(t)
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "leaky", "@claude")
	p, err := policy.Resolve(m, sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}

	got := captureFile(t, func(f *os.File) { describeEnvironment(f, p) })

	// POSITIVE CONTROL: the declared value actually reached the screen. Without
	// this, a fixture that never resolved the "leaky" profile at all would
	// pass the assertions below on an empty ENVIRONMENT block.
	if !strings.Contains(got, "MY_TOOL_MODE") {
		t.Fatalf("MY_TOOL_MODE never reached the ENVIRONMENT block, so this test measures "+
			"nothing:\n%s", got)
	}
	if !strings.Contains(got, "unchecked (environ.declare; snug has no entry for this name)") {
		t.Errorf("a declared, unrostered name was not marked unchecked in --dry-run:\n%s", got)
	}

	// NEGATIVE CONTROL: EDITOR is a roster row (@claude inherits it, and the
	// fake host supplies a value for it), so its line must NOT carry the
	// mark. A version of the mark that fired for every user-writable name —
	// rather than only for a genuinely unrostered one — would pass the
	// positive assertion above too.
	editorMarked := false
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "EDITOR") && strings.Contains(line, "unchecked") {
			editorMarked = true
		}
	}
	if editorMarked {
		t.Errorf("EDITOR, a rostered name, was marked unchecked:\n%s", got)
	}
}

// ── the unchecked mark JOINS the grant mark, it does not replace it ─────────
//
// REGRESSION (redteam + independent review, 2026-08-15): dryrun.go's envLines
// used to REPLACE grantMark's verdict with the unchecked mark for a declared
// name. Measured on the base commit, the identical profile text rendered
// `← not granted` before the roster flip and only `← unchecked` after it — the
// screen LOST the statement that a declared name's value does not resolve to
// anything inside the sandbox. It also inverted the pair between two kinds of
// entry: a ROSTERED code-carrying scalar (`set BASH_ENV = "/var/lib/x"`) kept
// its "not granted" verdict, while the UNROSTERED sibling lost its own. The fix
// concatenates: the unchecked mark first, then whatever grantMark returns.
//
// markJoinRegistry builds one profile that exercises every combination this
// test needs, so all of it is checked against a single --dry-run render:
//   - MY_TOOL_UNGRANTED: declared, value is an absolute path nothing grants
//   - MY_TOOL_GRANTED:   declared, value IS granted (the fixture $HOME, via @home)
//   - MY_TOOL_MODE:      declared, value is not path-shaped at all ("fast")
//   - BASH_ENV:          NOT declared (it has a roster row — forbidInheritOnly,
//     set legal), same ungranted value as MY_TOOL_UNGRANTED. This is the
//     POSITIVE CONTROL: it is what distinguishes "both marks fire correctly"
//     from "the mark string happens to contain both substrings" — a rostered
//     name must show `not granted` alone, with no `unchecked` anywhere on its
//     line, on the SAME value that produces both marks for a declared name.
//   - PATH:              merged with the fixture $HOME, a writable tmpfs, so the
//     shadow-slot mark fires. PATH has a roster row, so IsUncheckedEnv can never
//     be true for it, and this line asserts the writable mark is not doubled up
//     with an unchecked mark it structurally cannot carry.
func markJoinRegistry(t *testing.T) map[policy.ProfileName]*policy.Profile {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["markjoin"] = &policy.Profile{
		Name:    "markjoin",
		Include: []policy.ProfileName{"@sys", "@home", "@cwd-rw"},
		Environ: policy.EnvGrants{
			Declare: []string{"MY_TOOL_UNGRANTED", "MY_TOOL_GRANTED", "MY_TOOL_MODE"},
			Set: map[string]string{
				"MY_TOOL_UNGRANTED": "/var/lib/nowhere",
				"MY_TOOL_GRANTED":   "{home}",
				"MY_TOOL_MODE":      "fast",
				"BASH_ENV":          "/var/lib/nowhere",
			},
			Merge: map[string][]string{"PATH": {"{home}"}},
		},
	}
	return m
}

// lineFor returns the single ENVIRONMENT-block line naming want, for a rendered
// --dry-run text. Fails the test if it is not found exactly once, so a typo in
// the fixture value fails loudly instead of silently comparing "" == "".
func lineFor(t *testing.T, rendered, want string) string {
	t.Helper()
	var hit string
	n := 0
	for _, line := range strings.Split(rendered, "\n") {
		if strings.Contains(line, want) {
			hit = line
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly one line containing %q, found %d:\n%s", want, n, rendered)
	}
	return hit
}

func TestUncheckedMarkJoinsRatherThanReplacesTheGrantMark(t *testing.T) {
	m := markJoinRegistry(t)
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "markjoin")
	p, err := policy.Resolve(m, sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	got := captureFile(t, func(f *os.File) { describeEnvironment(f, p) })

	// 1. Declared name, ungranted absolute-path value: BOTH marks, in order.
	ungranted := lineFor(t, got, "MY_TOOL_UNGRANTED")
	if !strings.Contains(ungranted, "unchecked") || !strings.Contains(ungranted, "not granted") {
		t.Errorf("declared+ungranted line lost one of the two marks:\n%s", ungranted)
	}
	if i, j := strings.Index(ungranted, "unchecked"), strings.Index(ungranted, "not granted"); i < 0 || j < 0 || i > j {
		t.Errorf("want `unchecked` before `not granted` on the declared+ungranted line, got:\n%s", ungranted)
	}

	// 2. Declared name, GRANTED value: unchecked, and no "not granted" — proves
	// the join is a real concatenation of grantMark's actual verdict, not a
	// constant string that happens to contain both substrings.
	granted := lineFor(t, got, "MY_TOOL_GRANTED")
	if !strings.Contains(granted, "unchecked") {
		t.Errorf("declared+granted line lost the unchecked mark:\n%s", granted)
	}
	if strings.Contains(granted, "not granted") {
		t.Errorf("declared+granted line wrongly claims not granted:\n%s", granted)
	}

	// 3. Declared name, non-path value: unchecked alone.
	mode := lineFor(t, got, "MY_TOOL_MODE")
	if !strings.Contains(mode, "unchecked") {
		t.Errorf("declared+non-path line lost the unchecked mark:\n%s", mode)
	}
	if strings.Contains(mode, "not granted") || strings.Contains(mode, "writable") {
		t.Errorf("declared+non-path line acquired a grant verdict it cannot have "+
			"(grantMark never judges a value that is not spelled like an absolute path):\n%s", mode)
	}

	// 4. POSITIVE CONTROL: rostered scalar (BASH_ENV), same ungranted value as
	// case 1. Must show `not granted` and NO `unchecked` — this is what proves
	// cases 1-3 are not passing because the mark string is a constant that
	// happens to contain "unchecked" and "not granted" together.
	bashEnv := lineFor(t, got, "BASH_ENV")
	if !strings.Contains(bashEnv, "not granted") {
		t.Errorf("control: rostered BASH_ENV with an ungranted path must show not-granted:\n%s", bashEnv)
	}
	if strings.Contains(bashEnv, "unchecked") {
		t.Errorf("control: rostered BASH_ENV must never carry the unchecked mark:\n%s", bashEnv)
	}

	// 5. PATH's shadow-slot mark still fires, and is not doubled with an
	// unchecked mark it structurally cannot carry (PATH has a roster row).
	pathLine := lineFor(t, got, "writable from inside")
	if !strings.Contains(pathLine, "PATH") {
		t.Fatalf("expected the writable-from-inside mark on the PATH line, got:\n%s", pathLine)
	}
	if strings.Contains(pathLine, "unchecked") {
		t.Errorf("PATH is rostered, so IsUncheckedEnv can never fire for it; the writable mark "+
			"must not be joined with one anyway:\n%s", pathLine)
	}
}

// TestProfileShowMarksADeclaredNameAsUnchecked drives showEnviron directly —
// the same entry point TestProfileShowRendersEveryEnvironVerb in
// config_test.go uses — with a grant block carrying both a declared name and
// a rostered one, so the mark can be shown to be selective rather than
// blanket.
func TestProfileShowMarksADeclaredNameAsUnchecked(t *testing.T) {
	g := policy.EnvGrants{
		Declare: []string{"MY_TOOL_MODE"},
		Set:     map[string]string{"MY_TOOL_MODE": "fast", "XDG_DATA_HOME": "{home}/.local/share"},
		Inherit: []string{"EDITOR"},
	}
	got := map[string][]string{}
	showEnviron(g, func(label string, vals []string) {
		if len(vals) > 0 {
			got[label] = vals
		}
	})

	declared, ok := got["environ.declare"]
	if !ok {
		t.Fatal("environ.declare was not rendered at all")
	}
	// POSITIVE CONTROL: the name is actually on the line, so the mark
	// assertion below cannot pass on an empty or mismatched declare block.
	if !strings.Contains(declared[0], "MY_TOOL_MODE") {
		t.Fatalf("environ.declare did not render MY_TOOL_MODE at all: %q", declared[0])
	}
	if !strings.Contains(declared[0], "unchecked") {
		t.Errorf("environ.declare rendered %q with no unchecked mark", declared[0])
	}

	// NEGATIVE CONTROL: environ.set and environ.inherit's OWN lines must not
	// carry the mark. `snug profile show` states the licence once, in the
	// declare block, and does not repeat it on every line that uses it — but
	// that is a design choice to VERIFY, not to assume, and a version of the
	// mark that leaked onto every line naming the same variable would still
	// pass the assertion above.
	for label, vals := range got {
		if label == "environ.declare" {
			continue
		}
		for _, v := range vals {
			if strings.Contains(v, "unchecked") {
				t.Errorf("%s rendered %q with an unchecked mark; only environ.declare should "+
					"carry one", label, v)
			}
		}
	}
}
