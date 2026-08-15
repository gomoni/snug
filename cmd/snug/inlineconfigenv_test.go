package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// No shipped profile may hand the payload a variable whose VALUE IS a tool's
// setting rather than a POINTER at a file snug generated.
//
// THE RULE, stated so the next person does not have to re-derive it: issue #26
// measured that git's GIT_CONFIG_COUNT/GIT_CONFIG_KEY_n family enters git at
// the COMMAND-LINE scope — above the global file, above the repository's own
// .git/config, above any `include` the generated file could carry. There is no
// fix for a payload setting these in ITS OWN environment; the payload owns its
// environment exactly as it owns PATH (see GIT-CONFIG.md §9, CLAUDE.md's
// "Generate, don't bind" bullet). What snug DOES own, and can assert
// mechanically, is narrower: the environment snug ITSELF hands over must never
// ship one of these pre-installed. policy.IsInlineConfigEnv tells the pointer
// spellings (GIT_CONFIG_GLOBAL, a path to a file a human can read) from the
// inline spellings (GIT_CONFIG_KEY_0, the setting itself, reviewable nowhere).
//
// This sweeps the RESOLVED policy's p.Env, not the TOML source, because that is
// where the class of bug actually lives. `forbiddenEnvPrefixes` marks PIP_ as
// forbidInheritOnly, and appliesTo(forbidInheritOnly, VerbSet) is false — so
// `environ.set PIP_INDEX_URL = "…"` passes parse-time validation TODAY (see
// TestPositiveControlEnvironSetPipIndexUrlTripsInlineConfigSweep below). A
// sweep over the TOML would inherit exactly that blind spot; a sweep over
// p.Env does not, because p.Env is what actually reaches the payload
// regardless of which verb put it there.
//
// npm_config_ USED to be this section's example — it was forbidInheritOnly
// when this test was written — but a second-pass review promoted it to
// forbidBoth (npm_config_script_shell/npm_config_node_gyp measured to name a
// program npm executes, the same shape as CARGO_BUILD_RUSTC_WRAPPER), so
// `environ.set npm_config_script_shell` is refused at parse time now and can
// no longer demonstrate this gap. PIP_ is the one prefix left at
// forbidInheritOnly (checked, not assumed — see the control below); if it is
// ever promoted too, NO prefix-covered name will remain able to reach this
// sweep through `set`, and the sweep's remaining job would be the
// inlineConfigNames "belt and braces" case (RUSTC_WRAPPER and friends,
// already forbidBoth, covered by IsInlineConfigEnv purely so its own promise
// holds — see that map's comment in envtypes.go) rather than a live parse-time
// gap. That would be worth restating here, not silently losing.
func TestNoBuiltinHandsOverAnInlineConfigVariable(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	names := make([]policy.ProfileName, 0, len(reg))
	for name := range reg {
		names = append(names, name)
	}
	slices.Sort(names)

	checked := 0
	sawNonEmptyEnv := 0
	for _, name := range names {
		sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), name)
		p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
		if err != nil {
			// A selection this fake host cannot resolve says nothing either
			// way, but it must be VISIBLE: a sweep that silently skipped every
			// profile would pass on a binary with no profiles at all.
			t.Logf("skipped %s: %v", name, err)
			continue
		}
		checked++
		if len(p.Env) > 0 {
			sawNonEmptyEnv++
		}
		for envName, v := range p.Env {
			if !v.Present() {
				continue
			}
			if policy.IsInlineConfigEnv(envName) {
				t.Errorf("builtin %s hands over %s, whose value the tool reads AS THE SETTING "+
					"itself, at a scope above every config file (measured for git: "+
					"'command line', above global, above the repository's own .git/config — "+
					"see .claude/design/GIT-CONFIG.md §9, issue #26).\n"+
					"This does NOT stop the payload setting it itself — nothing can, see issue "+
					"#26 — it stops snug shipping the override PRE-INSTALLED.\n"+
					"Point the tool at a generated file with its POINTER variable instead "+
					"(GIT_CONFIG_GLOBAL, NPM_CONFIG_USERCONFIG, PIP_CONFIG_FILE, CARGO_HOME, "+
					"GH_CONFIG_DIR, DOCKER_CONFIG) — see policy.IsInlineConfigEnv's doc comment "+
					"for the pointer/inline distinction and internal/policy/envtypes.go's "+
					"inlineConfigPointers for the exemption list.",
					name, envName)
			}
		}
	}

	// A sweep is only as good as the number of selections it actually resolved,
	// and a sweep over an EMPTY environment proves nothing about this predicate
	// at all — CLAUDE.md's standing rule that a negative test needs a positive
	// control proving the thing measured was actually present. The pasta-comm
	// test that could never fail is why this guard exists twice in this file.
	if checked < len(names)/2 {
		t.Fatalf("only %d of %d builtins resolved on the fake host; the sweep is not "+
			"covering enough to mean anything", checked, len(names))
	}
	if sawNonEmptyEnv < checked/2 {
		t.Fatalf("only %d of %d resolved builtins had a non-empty p.Env; the sweep would "+
			"pass on a policy that hands over no environment at all, which proves nothing "+
			"about whether an inline-config variable would be caught", sawNonEmptyEnv, checked)
	}
}

// The positive control for the test above: policy.IsInlineConfigEnv must
// actually TRIP on a name that parse-time validation still accepts via
// `environ.set` today, or "no builtin hands over an inline-config variable"
// is a sentence about a predicate that always answers false — and about a
// sweep that no legal profile could ever reach in the first place.
//
// This test was rewritten rather than edited. Its ENTIRE premise — three
// case spellings of npm_config_script_shell, chosen because parse-time did
// NOT catch `set` for that prefix — stopped being true when a second-pass
// review promoted npm_config_ to forbidBoth (see the header comment above):
// `environ.set npm_config_script_shell` is refused now, at every case
// spelling, so a fixture using it would no longer resolve and could not
// control anything. Patching the old spellings in place would have hidden
// that the whole reason this test existed had disappeared.
//
// So the first question this test answers, explicitly, is whether any name
// with that property — genuinely forbidInheritOnly (not forbidBoth), so
// `environ.set` reaches the resolved policy while `environ.inherit` is
// refused — still exists. CHECKED, not assumed: PIP_ is the answer, and it is
// the only one. GIT_CONFIG_, npm_config_ and CARGO_ are all forbidBoth now;
// LD_ and BASH_FUNC_ always were. If a future promotion closes PIP_ too, this
// test needs the same rewrite again, not a spelling change — and that would
// be worth stating in CLAUDE.md as "every known prefix now refuses `set`",
// because it changes what this control is even testing.
//
// PIP_INDEX_URL is the name: it matches the PIP_ prefix, it is not
// PIP_CONFIG_FILE (the one pointer exemption), and PIP_'s case rule is
// case-SENSITIVE (measured for pip's own get_environ_vars, documented in
// prefixCaseFold's comment — pip is not installed on this host to measure
// directly), so unlike the old npm control there is no second case spelling
// to demonstrate here: PIP_INDEX_URL is the only spelling PIP_'s rule
// recognises at all.
func TestPositiveControlEnvironSetPipIndexUrlTripsInlineConfigSweep(t *testing.T) {
	const name = "PIP_INDEX_URL"

	if policy.IsInlineConfigEnv("pip_index_url") {
		t.Fatalf("IsInlineConfigEnv(\"pip_index_url\") = true, but PIP_'s case rule is "+
			"documented case-sensitive — if this now passes, PIP_ has been re-measured "+
			"case-insensitive and %s needs a second spelling the same way the old npm "+
			"control did", "PIP_INDEX_URL")
	}

	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["leaky"] = &policy.Profile{
		Name:    "leaky",
		Include: []policy.ProfileName{"@sys", "@home"},
		Environ: policy.EnvGrants{Set: map[string]string{name: "http://evil.example/simple"}},
	}

	p, err := policy.Resolve(m, append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "leaky"),
		envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve refused environ.set %s: %v — that would mean PIP_ has been "+
			"promoted to forbidBoth too, and per this test's own header comment, that means "+
			"NO prefix-covered name can demonstrate \"parse-time misses set, only the sweep "+
			"catches it\" any more. State that explicitly (this test's header comment, and "+
			"CLAUDE.md's inline-config paragraph) rather than hunting for a replacement "+
			"spelling — there may not be one", name, err)
	}

	v, ok := p.Env[name]
	if !ok || !v.Present() {
		t.Fatalf("the fixture profile's environ.set %s never reached p.Env, so this control "+
			"is not controlling anything — either Resolve silently dropped it or the fixture "+
			"is wrong", name)
	}

	if !policy.IsInlineConfigEnv(name) {
		t.Fatalf("policy.IsInlineConfigEnv(%q) = false. PIP_INDEX_URL matches the PIP_ prefix "+
			"in inlineConfigPrefixes and is not PIP_CONFIG_FILE, the one pointer exemption — "+
			"a predicate that misses it misses the whole PIP_ prefix", name)
	}

	// And the sweep this control exists for must actually fail loudly on this
	// fixture — run the same check TestNoBuiltinHandsOverAnInlineConfigVariable
	// performs, inline, so a future edit to that test's walk cannot quietly stop
	// looking at p.Env without this control noticing.
	tripped := false
	for envName, ev := range p.Env {
		if ev.Present() && policy.IsInlineConfigEnv(envName) {
			tripped = true
		}
	}
	if !tripped {
		t.Fatalf("the fixture hands over %s in p.Env and IsInlineConfigEnv agrees it is "+
			"inline config, yet a walk of p.Env identical to the sweep's found nothing to "+
			"flag — the sweep and this control have drifted apart", name)
	}
}

// The case-sensitivity table itself, locked down per name rather than per
// prefix, because §"IsInlineConfigEnv's case handling" of the issue #26
// review found the table WRONG in one direction (npm_config_ missed its own
// idiomatic upper-case spelling) and the fix now carries FOUR independent
// case rules, one per tool, each set from a measurement recorded as a comment
// beside the table in internal/policy/envtypes.go. A test that only re-reads
// that table proves nothing; this one pins the OUTCOME so a future edit that
// "tidies" every prefix to one case rule — in either direction — fails here
// and sends whoever made the change back to the measurement, not to a
// rebase.
//
// Every case below cites the measurement it is defending, so the next person
// does not have to go spelunking in envtypes.go's history to find out
// whether a failure here is real or is the table catching up to reality.
func TestIsInlineConfigEnvCaseRules(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
		why   string
	}{
		// npm — measured case-INSENSITIVE (node 22 + npm 10.9.8, npm-cli.js
		// vendored on this host): npm_config_script_shell, NPM_CONFIG_SCRIPT_SHELL
		// and Npm_Config_Script_Shell all won. All three must trip.
		{"npm_config_script_shell", "npm_config_script_shell", true,
			"measured: npm 10.9.8 honours the lower-case spelling"},
		{"NPM_CONFIG_SCRIPT_SHELL", "NPM_CONFIG_SCRIPT_SHELL", true,
			"measured: npm 10.9.8 honours the upper-case spelling identically — " +
				"this is the one the review found IsInlineConfigEnv missing"},
		{"Npm_Config_Script_Shell", "Npm_Config_Script_Shell", true,
			"measured: npm 10.9.8 honours mixed case too"},

		// npm's pointer exemption folds case for exactly the same reason its
		// inline prefix does: NPM_CONFIG_USERCONFIG must stay exempt in every
		// spelling npm itself would honour, or the fix for the false negative
		// above becomes a false positive that refuses a variable snug must be
		// able to set.
		{"NPM_CONFIG_USERCONFIG canonical", "NPM_CONFIG_USERCONFIG", false,
			"the pointer exemption's canonical spelling"},
		{"npm_config_userconfig lower-case", "npm_config_userconfig", false,
			"the pointer exemption must fold case the same way npm itself does, " +
				"or this spelling would be misidentified as inline config"},
		{"Npm_Config_Userconfig mixed-case", "Npm_Config_Userconfig", false,
			"same as above, mixed case"},

		// git — measured case-SENSITIVE (git 2.55.0, this host): only the
		// upper-case spelling is read; git_config_count and Git_Config_Count
		// both fall through to the file (getenv(3) is case-sensitive on Linux,
		// git does no folding of its own). The lower-case and mixed-case
		// spellings must NOT trip, or IsInlineConfigEnv would refuse a name git
		// never reads as inline config in the first place.
		{"GIT_CONFIG_COUNT canonical", "GIT_CONFIG_COUNT", true,
			"measured: git 2.55.0 reads this at the command-line scope (issue #26 §1)"},
		{"git_config_count lower-case", "git_config_count", false,
			"measured: git 2.55.0 does NOT read this spelling — falls through to the file"},
		{"Git_Config_Count mixed-case", "Git_Config_Count", false,
			"measured: git 2.55.0 does NOT read this spelling — falls through to the file"},
		{"GIT_CONFIG_GLOBAL pointer exemption", "GIT_CONFIG_GLOBAL", false,
			"the pointer exemption, case-sensitive to match its prefix's own rule"},

		// cargo — measured case-SENSITIVE (cargo 1.97.1, this host): only the
		// upper-case spelling is read; cargo_build_target_dir and
		// Cargo_Build_Target_Dir both fall through to .cargo/config.toml
		// (std::env::var is a case-sensitive lookup on Linux).
		{"CARGO_BUILD_TARGET_DIR canonical", "CARGO_BUILD_TARGET_DIR", true,
			"measured: cargo 1.97.1 reads this and creates FROM-ENV/, not FROM-FILE/"},
		{"cargo_build_target_dir lower-case", "cargo_build_target_dir", false,
			"measured: cargo 1.97.1 does NOT read this spelling"},
		{"Cargo_Build_Target_Dir mixed-case", "Cargo_Build_Target_Dir", false,
			"measured: cargo 1.97.1 does NOT read this spelling"},
		{"CARGO_HOME pointer exemption", "CARGO_HOME", false,
			"the pointer exemption, case-sensitive to match its prefix's own rule"},

		// pip — documented, not measured (pip is not installed on this host):
		// pip/_internal/configuration.py's Configuration.get_environ_vars does
		// key.startswith("PIP_") against os.environ, a case-sensitive mapping
		// on Linux, so only the exact-case spelling should be recognised.
		{"PIP_INDEX_URL canonical", "PIP_INDEX_URL", true,
			"documented: pip's get_environ_vars does a case-sensitive startswith(\"PIP_\")"},
		{"pip_index_url lower-case", "pip_index_url", false,
			"documented: pip's startswith(\"PIP_\") check is case-sensitive, so this " +
				"spelling is not recognised"},
		{"PIP_CONFIG_FILE pointer exemption", "PIP_CONFIG_FILE", false,
			"the pointer exemption, case-sensitive to match its prefix's own rule"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := policy.IsInlineConfigEnv(tc.value)
			if got != tc.want {
				t.Errorf("IsInlineConfigEnv(%q) = %v, want %v — %s.\n"+
					"If this is failing because a case rule in "+
					"internal/policy/envtypes.go's inlineConfigPrefixes or "+
					"inlineConfigPointers was changed, that change needs a measurement of "+
					"the CONSUMING TOOL to justify it (see the per-entry comments there), "+
					"not a rebase of this test.",
					tc.value, got, tc.want, tc.why)
			}
		})
	}
}

// ── RUSTC_WRAPPER / RUSTC_WORKSPACE_WRAPPER / RUSTC ──────────────────────────
//
// Confirmed end to end by redteam, issue #26 follow-up: a profile carrying
//
//	[profile.leaky.environ.set]
//	RUSTC_WRAPPER = "/run/snug/bin/evil"
//
// reached the bwrap argv as `--setenv RUSTC_WRAPPER /run/snug/bin/evil`, and
// `RUSTC_WRAPPER=./wrap.sh cargo build` then ran `wrap.sh rustc -vV` as the
// sandbox's own uid — cargo executes whatever program the variable names as
// its compiler driver. RUSTC and RUSTC_WORKSPACE_WRAPPER carry the identical
// capability. All three were reachable through `environ.set`, which is the
// SAME shape as issue #26's npm_config_ finding — a value that IS the
// setting, in the environment snug itself would hand over — except here the
// name did not start with a listed prefix at all (CARGO_BUILD_RUSTC_WRAPPER,
// same capability, was already caught by the CARGO_ prefix), so the prefix
// table structurally could not have found it.
//
// The fix landed in two places, and both fail independently, so both get
// their own test:
//   - forbiddenEnv now marks all three forbidBoth, so environ.set AND
//     environ.inherit are both refused at PARSE TIME. That half is pinned in
//     internal/policy/envtypes_test.go's TestForbidListSplitsBySetAndInherit,
//     extending the existing forbidBoth table rather than starting a second
//     one.
//   - inlineConfigNames makes IsInlineConfigEnv true for all three, so the
//     SINK sweep (TestNoBuiltinHandsOverAnInlineConfigVariable) would also
//     catch them if the parse-time refusal above were ever weakened or
//     bypassed by a route that does not go through ValidateEnvGrants.

// The asymmetry with the PIP_INDEX_URL positive control, stated rather than
// papered over: PIP_INDEX_URL passes parse-time validation today (PIP_ is
// only forbidInheritOnly — see that control's own header comment for why it
// is the LAST prefix-covered name that still can), so a fixture profile
// setting it resolves successfully and
// TestPositiveControlEnvironSetPipIndexUrlTripsInlineConfigSweep can sweep
// the RESULT. RUSTC_WRAPPER is forbidBoth, precisely because of the finding
// this test is guarding — so the honest control here is the opposite shape:
// assert Resolve REJECTS the fixture. Building a resolved policy that
// contains RUSTC_WRAPPER to sweep would mean bypassing the very refusal this
// test exists to confirm, which would make the control test nothing real.
func TestPositiveControlEnvironSetRustcWrapperIsRefusedAtParseTime(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	// The control fixture: the identical selection and profile shape, minus
	// the one environ.set line. If THIS resolves cleanly, a refusal on the
	// fixture below can only be about the variable under test — not about
	// @sys/@home's fake-host requirements, a Context field this test forgot,
	// or anything else that would make "err != nil" pass for the wrong
	// reason.
	reg2, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m2 := map[policy.ProfileName]*policy.Profile(reg2)
	m2["control"] = &policy.Profile{
		Name:    "control",
		Include: []policy.ProfileName{"@sys", "@home"},
	}
	if _, err := policy.Resolve(m2, append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "control"),
		envGoldenCtx(), newEnvFakeEnv()); err != nil {
		t.Fatalf("the control fixture (identical shape, no environ.set at all) was refused: "+
			"%v — that means the fixtures below would fail regardless of the RUSTC_WRAPPER "+
			"family, and would prove nothing about them", err)
	}

	for _, name := range []string{"RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC"} {
		t.Run(name, func(t *testing.T) {
			m := map[policy.ProfileName]*policy.Profile(reg)
			m["leaky"] = &policy.Profile{
				Name:    "leaky",
				Include: []policy.ProfileName{"@sys", "@home"},
				Environ: policy.EnvGrants{
					Set: map[string]string{name: "/run/snug/bin/evil"},
				},
			}

			_, err := policy.Resolve(m, append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "leaky"),
				envGoldenCtx(), newEnvFakeEnv())
			if err == nil {
				t.Fatalf("Resolve accepted environ.set %s. Confirmed by redteam (issue #26 "+
					"follow-up): cargo executes whatever this variable names as its compiler "+
					"driver, so accepting it here means a profile can run an arbitrary program "+
					"as the sandbox's own uid the moment `cargo build` runs. It must be refused "+
					"at parse time exactly like GIT_SSH_COMMAND and JAVA_TOOL_OPTIONS are", name)
			}
			// Not just "an error", because the control fixture above already
			// proves the shape resolves cleanly on its own — an unrelated
			// future failure of this fixture (a changed @sys/@home include, a
			// new required Context field) must NOT be mistaken for this
			// refusal, and the only way to tell them apart is that THIS
			// refusal names the variable.
			if !strings.Contains(err.Error(), name) {
				t.Errorf("Resolve refused environ.set %s, but the error does not name it: %v.\n"+
					"A refusal that doesn't name the variable can't be told apart from an "+
					"unrelated fixture failure (a changed @sys/@home include, a new required "+
					"Context field) — the control fixture above rules that out for a passing "+
					"run, but a future change to the ERROR text could still make this test "+
					"pass for the wrong reason", name, err)
			}
		})
	}
}

// The second half, and it is not decoration: forbiddenEnv refusing the name
// is what makes the fixture above unresolvable, but IsInlineConfigEnv is a
// SEPARATE table (inlineConfigNames), read by TestNoBuiltinHandsOverAnInline-
// ConfigVariable's sweep over the resolved p.Env of every builtin. If a future
// edit narrowed forbiddenEnv's RUSTC_WRAPPER entry back to forbidInheritOnly
// (the npm/pip shape) without updating inlineConfigNames, a builtin could then
// ship `environ.set RUSTC_WRAPPER = …` and reach a resolved policy — and the
// sink sweep is the only thing left standing between that policy and the
// payload. This test cannot go through Resolve for the reason stated above
// (parse-time refuses it today, correctly), so it asserts the predicate
// directly — this IS the "belt and braces" defense-in-depth the comment above
// inlineConfigNames describes, made concrete rather than left as prose.
func TestIsInlineConfigEnvCoversTheRustcWrapperFamily(t *testing.T) {
	for _, name := range []string{"RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC"} {
		if !policy.IsInlineConfigEnv(name) {
			t.Errorf("IsInlineConfigEnv(%q) = false. Confirmed by redteam (issue #26 "+
				"follow-up): this name makes cargo execute an arbitrary program as its "+
				"compiler driver, the identical capability CARGO_BUILD_RUSTC_WRAPPER already "+
				"carries under the CARGO_ prefix. It must be in inlineConfigNames — this is "+
				"the second, independent layer behind forbiddenEnv's parse-time refusal, and "+
				"it is the only one left if that refusal is ever narrowed without this table "+
				"being updated in step", name)
		}
	}
}
