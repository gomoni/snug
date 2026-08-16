package main

import (
	"os"
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
// where the class of bug actually lives — and the reason is now much simpler
// than it was. Parse-time validation refuses NO name: the forbidden-name and
// forbidden-prefix tables became annotations (policy.EnvNote), because a
// profile's author is a human on the trusted side of snug's boundary. So a
// sweep over the TOML would be measuring a gate that is not there, while p.Env
// is what actually reaches the payload regardless of which verb put it there.
//
// WHAT THIS SWEEP IS AND IS NOT, restated because the previous version of this
// comment was an argument about which prefix was `forbidInheritOnly` and that
// vocabulary is gone. It is BUILTIN-ONLY. It asserts CLAUDE.md's rule — "the
// environment snug ITSELF hands over must not ship the override pre-installed" —
// over the profiles snug SHIPS. A user's own profile may hand over
// GIT_CONFIG_KEY_0 or PIP_INDEX_URL and this sweep will never see it; what that
// user gets is the annotation on --dry-run, which is the design and not a gap.
//
// What keeps a BUILTIN out of this class is two independent things, and both
// have to hold: internal/profile's checkBuiltinEnvRoster (a shipped profile may
// write only a name on the roster, and no inline-config name has a roster row)
// and this sweep. The first is a rule about names; this is a rule about what
// resolves. A route into p.Env that does not go through a profile's grant block
// — a future adapter authoring a variable, say — would be invisible to the first
// and caught here.
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
// actually TRIP on a name a profile can hand over, or "no builtin hands over an
// inline-config variable" is a sentence about a predicate that always answers
// false — and about a sweep that no legal profile could ever reach in the first
// place.
//
// THE PREMISE OF THIS CONTROL HAS BEEN REWRITTEN TWICE and it is worth knowing
// why, because the second rewrite deleted the whole idea it was built on. It
// once demonstrated a narrow parse-time gap: `set` reached the resolved policy
// for a prefix marked forbidInheritOnly while `inherit` was refused, and the
// interesting question was which prefix still had that property (npm_config_ did
// until it was promoted; PIP_ was the last one left). There is no such gap any
// more, because there is no parse-time refusal: EVERY name reaches the resolved
// policy through a user profile now. So the control no longer demonstrates an
// asymmetry — it demonstrates the ordinary case, and its job is narrower and
// clearer: prove the sweep's predicate fires on something a resolved policy can
// actually contain.
//
// PIP_INDEX_URL is kept as the name, for continuity with the finding and because
// it is a genuine inline setting under a prefix with a MEASURED case rule:
// case-SENSITIVE (documented for pip's own get_environ_vars in prefixCaseFold's
// comment — pip is not installed on this host to measure directly), so
// pip_index_url must NOT trip, and that half is asserted below.
//
// The fixture is a USER profile, and that is load-bearing rather than
// incidental: PIP_INDEX_URL has no roster row, so a BUILTIN cannot write it at
// all (internal/profile's `mark`). The sweep being builtin-only is exactly why
// this control has to be a user profile.
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
	// A USER profile: see this test's header. A builtin cannot write this name;
	// a user profile can, at every verb, and the sink sweep is builtin-only.
	m["leaky"] = &policy.Profile{
		Name:    "leaky",
		Include: []policy.ProfileName{"@sys", "@home"},
		Environ: policy.EnvGrants{
			Set: map[string]string{name: "http://evil.example/simple"},
		},
	}

	p, err := policy.Resolve(m, append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "leaky"),
		envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve refused environ.set %s: %v — a user profile writing a name in its "+
			"own file is not something snug refuses. If a refusal has been reintroduced here, "+
			"it is a policy change (see policy.EnvNote and ENVIRONMENT-VARIABLES.md §2.1) and "+
			"this control needs a name that is still reachable", name, err)
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
// their own test. Read both bullets against ENVIRONMENT-VARIABLES.md §2.9,
// because the first one no longer refuses anything:
//   - all three carry an ANNOTATION at every verb (policy.EnvNote), so a profile
//     writing one says on screen that cargo will run it. That half is pinned in
//     internal/policy/envtypes_test.go's TestAnnotationSplitsBySetAndInherit and
//     in internal/policy/testdata/annotations.txt. It used to be a parse-time
//     refusal; a human's own profile is not something snug refuses.
//   - inlineConfigNames makes IsInlineConfigEnv true for all three, so the
//     SINK sweep (TestNoBuiltinHandsOverAnInlineConfigVariable) catches a
//     BUILTIN handing one over. With the parse-time refusal gone, this and the
//     roster rule are the two things left, and they are builtin-only by design.

// THE CONTROL IS THE OPPOSITE SHAPE NOW, and the inversion is the finding.
//
// This test used to assert that `policy.Resolve` REFUSED a profile carrying
// `environ.set RUSTC_WRAPPER`, because forbiddenEnv marked it forbidBoth. That
// refusal is gone: the table is an annotation table, snug has only allowlists,
// and a profile's author is a human on the trusted side of the boundary. So the
// fixture now RESOLVES, the variable reaches p.Env, and the two things left
// standing are the two this test measures:
//
//   - the row is ANNOTATED, so a human reading --dry-run is told that cargo runs
//     this in place of rustc;
//   - IsInlineConfigEnv still names it, so the builtin-only sink sweep
//     (TestNoBuiltinHandsOverAnInlineConfigVariable) would still catch a SHIPPED
//     profile handing it over.
//
// Note what that second bullet does NOT say, because the old comment here said
// the opposite and it was true when written: parse-time validation is no longer
// "the real, load-bearing gate" for a USER profile. There is no gate for a user
// profile, by decision. What stops a BUILTIN is checkBuiltinEnvRoster (no roster
// row, so a shipped profile may not write the name) plus this sweep.
//
// It is also, incidentally, the same shape as the PIP_INDEX_URL control below —
// which used to be the LAST name that could demonstrate "parse-time misses
// `set`, only the sweep catches it". Every prefix-covered name can demonstrate
// it now, so that control's uniqueness argument is retired with this comment
// rather than left standing as a fact about a table that changed.
func TestEnvironSetRustcWrapperIsCarriedAndAnnotated(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
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

			p, err := policy.Resolve(m, append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "leaky"),
				envGoldenCtx(), newEnvFakeEnv())
			if err != nil {
				t.Fatalf("Resolve refused environ.set %s: %v.\nA human writing this in their own "+
					"profile is opening a hole in their own sandbox, which snug does not refuse — "+
					"see policy.EnvNote. If this refusal is deliberate, it is a policy change and "+
					"belongs in ENVIRONMENT-VARIABLES.md, not in a table edit", name, err)
			}
			v, ok := p.Env[name]
			if !ok || !v.Present() {
				t.Fatalf("environ.set %s never reached p.Env; the fixture measures nothing", name)
			}

			// The annotation is the whole of what a human gets for this now.
			note := policy.EnvNote(name, policy.VerbSet)
			if note == "" {
				t.Fatalf("%s reaches the payload with NOTHING said about it. Confirmed by redteam "+
					"(issue #26 follow-up): cargo executes whatever this variable names as its "+
					"compiler driver, so `cargo build` runs an arbitrary program as the sandbox's "+
					"own uid. Silence here is strictly worse than the refusal this replaced", name)
			}
			if !strings.Contains(note, "cargo") {
				t.Errorf("EnvNote(%s, set) = %q, which does not name the tool that runs it. The "+
					"sentence exists so a reader can act on it", name, note)
			}

			// And it reaches the ENVIRONMENT block WITH the mark, because a
			// sentence only a test can see is not a disclosure.
			got := captureFile(t, func(f *os.File) { describeEnvironment(f, p) })
			var line string
			for _, l := range strings.Split(got, "\n") {
				if strings.Contains(l, name+" ") || strings.HasPrefix(strings.TrimSpace(l), name) {
					line = l
					break
				}
			}
			if line == "" {
				t.Fatalf("%s does not appear in the ENVIRONMENT block at all:\n%s", name, got)
			}
			if !strings.Contains(line, "cargo runs this") {
				t.Errorf("the --dry-run row for %s carries no annotation:\n%s\nThe table is only "+
					"worth having if it reaches the screen a human reads", name, line)
			}
		})
	}
}

// The second half, and it is LESS decorative than it was: nothing refuses these
// names at parse time any more, so IsInlineConfigEnv naming them is one of the
// two things standing between a SHIPPED profile and the payload (the other is
// checkBuiltinEnvRoster). It is a separate table from the annotation one
// (inlineConfigNames), read by TestNoBuiltinHandsOverAnInlineConfigVariable's
// sweep over the resolved p.Env of every builtin. If a future edit gave
// RUSTC_WRAPPER a roster row — to make some list verb work, say — the roster
// rule would stop covering it and this predicate would be the only thing left.
// That is the residual worth watching, and it is why this assertion is direct
// rather than routed through Resolve.
func TestIsInlineConfigEnvCoversTheRustcWrapperFamily(t *testing.T) {
	for _, name := range []string{"RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC"} {
		if !policy.IsInlineConfigEnv(name) {
			t.Errorf("IsInlineConfigEnv(%q) = false. Confirmed by redteam (issue #26 "+
				"follow-up): this name makes cargo execute an arbitrary program as its "+
				"compiler driver, the identical capability CARGO_BUILD_RUSTC_WRAPPER already "+
				"carries under the CARGO_ prefix. It must be in inlineConfigNames — with no "+
				"parse-time refusal left anywhere (ENVIRONMENT-VARIABLES.md §2.9), this and "+
				"the roster rule are the only two things standing between a SHIPPED profile "+
				"and the payload, and the roster rule stops covering this name the day anyone "+
				"gives it a type row", name)
		}
	}
}
