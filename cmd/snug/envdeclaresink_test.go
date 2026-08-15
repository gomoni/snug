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
