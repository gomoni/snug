package policy

import (
	"strings"
	"testing"
)

// ── issue #44: environ.set/inherit flips from a denylist to an allowlist ────
//
// The implementer's own tests (envtypes_test.go's positive controls,
// refusals_test.go's env_unrostered_*/env_declare_* goldens) confirm the
// mechanism the code was WRITTEN with in mind. This file is written by a
// different agent, on purpose (CLAUDE.md), and asks the attacker's questions
// instead: does the flip actually close every verb, does the escape hatch
// widen anything it should not, does a licence leak between profiles that
// never asked for it, and does a case-folded spelling of a rostered name slip
// back into "unrostered, therefore declarable" — the exact "one table
// disagrees with itself across two case spellings" defect this codebase has
// already recorded twice (npm_config_userconfig, and the inherit-exemption
// bug it was found a level deeper than).

// ── 1. the flip itself ───────────────────────────────────────────────────────

// TestUnrosteredNameIsRefusedAtEveryVerb is the flip, checked as a SET rather
// than as one sample: a name snug has never heard of must be refused at set,
// merge, prepend, inherit AND sanitise — not just the one verb whichever
// fixture happened to exercise.
func TestUnrosteredNameIsRefusedAtEveryVerb(t *testing.T) {
	const name = "MY_TOOL_MODE"

	negatives := []struct {
		verb string
		g    EnvGrants
	}{
		{"set", EnvGrants{Set: map[string]string{name: "fast"}}},
		{"merge", EnvGrants{Merge: map[string][]string{name: {"/opt/x"}}}},
		{"prepend", EnvGrants{Prepend: map[string][]string{name: {"/opt/x"}}}},
		{"inherit", EnvGrants{Inherit: []string{name}}},
		{"sanitise", EnvGrants{Sanitise: []string{name}}},
	}
	for _, tc := range negatives {
		err := ValidateEnvGrants(tc.g)
		if err == nil {
			t.Errorf("environ.%s accepted %s, which snug has never heard of — the allowlist has "+
				"a hole at this verb", tc.verb, name)
			continue
		}
		// The message names the fix: a profile author reads this and needs to
		// know there IS one, not just that the line was rejected.
		if !strings.Contains(err.Error(), "environ.declare") && !strings.Contains(err.Error(), "environ.set") {
			t.Errorf("environ.%s refusal for %s does not name a fix: %v", tc.verb, name, err)
		}
	}

	// POSITIVE CONTROL, and it is load-bearing: without it, a build that
	// refuses EVERY name (including declared ones) would pass every negative
	// assertion above and this test would be worthless. The same name,
	// declared in the same profile, must be accepted at the two verbs the
	// hatch actually licenses.
	if err := ValidateEnvGrants(EnvGrants{
		Declare: []string{name}, Set: map[string]string{name: "fast"},
	}); err != nil {
		t.Errorf("control: a DECLARED name was refused at set: %v", err)
	}
	if err := ValidateEnvGrants(EnvGrants{
		Declare: []string{name}, Inherit: []string{name},
	}); err != nil {
		t.Errorf("control: a DECLARED name was refused at inherit: %v", err)
	}

	// The hatch does not extend to the three list verbs — declaring buys
	// nothing there, because a list verb needs a separator and an
	// empty-element rule that no profile can hand over.
	for _, tc := range []struct {
		verb string
		g    EnvGrants
	}{
		{"merge", EnvGrants{Declare: []string{name}, Merge: map[string][]string{name: {"/opt/x"}}}},
		{"prepend", EnvGrants{Declare: []string{name}, Prepend: map[string][]string{name: {"/opt/x"}}}},
		{"sanitise", EnvGrants{Declare: []string{name}, Sanitise: []string{name}}},
	} {
		if err := ValidateEnvGrants(tc.g); err == nil {
			t.Errorf("environ.%s accepted a DECLARED but unrostered name; the hatch has no "+
				"reach into the list verbs and must not gain one silently", tc.verb)
		}
	}
}

// ── 2. the hatch does not widen anything else ────────────────────────────────

// TestDeclarationDoesNotReachAForbiddenName asserts that `environ.declare`
// cannot be used to route around forbiddenEnv (the exact-name table) or
// forbiddenEnvPrefixes: a declaration is a licence for a name snug has NO
// opinion about, and every one of these is a name snug has an opinion about
// already.
func TestDeclarationDoesNotReachAForbiddenName(t *testing.T) {
	cases := []struct {
		why  string
		name string
	}{
		{"an exact forbidBoth entry", "GIT_SSH_COMMAND"},
		{"the LD_ prefix", "LD_ANYTHING"},
		{"the BASH_FUNC_ prefix", "BASH_FUNC_x"},
	}
	for _, tc := range cases {
		if err := ValidateEnvGrants(EnvGrants{Declare: []string{tc.name}}); err == nil {
			t.Errorf("environ.declare accepted %s (%s) — the hatch reached a name snug already "+
				"refuses outright", tc.name, tc.why)
		}
	}
}

// TestDeclarationDoesNotReachASnugOwnedName: the ownership check runs on a
// declaration itself (checkDeclarations calls checkEnvOwnership at
// VerbDeclare), so a profile cannot declare its way past "no profile may
// write a name snug writes".
func TestDeclarationDoesNotReachASnugOwnedName(t *testing.T) {
	for _, name := range []string{"HOME", "PS1", "SNUG_PROFILES", "PATH"} {
		if err := ValidateEnvGrants(EnvGrants{Declare: []string{name}}); err == nil {
			t.Errorf("environ.declare accepted %s, which snug writes itself", name)
		}
	}
}

// TestDeclarationDoesNotReachAnUngrammaticalName: checkEnvName's grammar rule
// runs on a declaration exactly as it runs on every other verb, so the hatch
// cannot be used to smuggle a name that would corrupt the environment's own
// wire format.
func TestDeclarationDoesNotReachAnUngrammaticalName(t *testing.T) {
	cases := map[string]string{
		"contains '='":         "A=B",
		"starts with a digit":  "1FOO",
		"contains a newline":   "FOO\nBAR",
		"contains a NUL byte":  "FOO\x00BAR",
		"contains a raw space": "FOO BAR",
	}
	for why, name := range cases {
		if err := ValidateEnvGrants(EnvGrants{Declare: []string{name}}); err == nil {
			t.Errorf("environ.declare accepted a name that %s: %q", why, name)
		}
	}
}

// TestDeclaredNameStillRefusesAControlCharacterValue: checkEnvValue runs
// unconditionally on every environ.set/merge/prepend value, whether or not
// the name is declared — a declaration is a licence for the NAME, and it must
// not be readable as a licence for the VALUE too. The NUL spelling is the
// escape sequence, not a raw NUL, because go-toml refuses a raw control
// character in a basic string and never lets one this far (see
// TestEnvValueRefusesControlCharacters, which pins the same rule against a
// ROSTERED name — EDITOR — and does not by itself say anything about a
// declared one).
func TestDeclaredNameStillRefusesAControlCharacterValue(t *testing.T) {
	const name = "MY_TOOL_MODE"
	bad := map[string]string{
		"a NUL, which ends the flag and starts a new one": "vim\x00--ro-bind\x00/etc\x00/etc",
		"a newline, which forges a row in --dry-run":      "vim\n  ro     /etc/shadow",
		"an ESC, which rewrites the terminal":             "fast\x1b[1A\r  ro   /usr/share/doc",
	}
	for why, value := range bad {
		g := EnvGrants{Declare: []string{name}, Set: map[string]string{name: value}}
		if err := ValidateEnvGrants(g); err == nil {
			t.Errorf("a DECLARED name's environ.set accepted a value containing %s — the hatch "+
				"licensed the name, not the value, and this value should still be refused", why)
		}
	}

	// POSITIVE CONTROL: an ordinary value on the same declared name is fine, so
	// the refusals above are about the control character and not about
	// something else in the declaration.
	if err := ValidateEnvGrants(EnvGrants{
		Declare: []string{name}, Set: map[string]string{name: "fast"},
	}); err != nil {
		t.Errorf("control: a DECLARED name with an ordinary value was refused: %v", err)
	}
}

// ── 3. the declaration is per-profile and does not travel ───────────────────

// TestDeclarationDoesNotTravelThroughInclude: a profile that pulls in a
// declaration via `include` may not use it. Responsibility is the author's,
// and it is decided from the profile's OWN text (ValidateEnvGrants sees one
// profile's EnvGrants at a time).
func TestDeclarationDoesNotTravelThroughInclude(t *testing.T) {
	const name = "MY_TOOL_MODE"
	reg := testRegistry()
	reg["declarer"] = &Profile{Name: "declarer", Environ: EnvGrants{
		Declare: []string{name}, Set: map[string]string{name: "fast"}}}
	// Includes declarer, writes the SAME name, but never declares it itself.
	reg["user"] = &Profile{Name: "user", Include: []ProfileName{"declarer"},
		Environ: EnvGrants{Set: map[string]string{name: "fast"}}}

	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "user"}, testCtx(), newFakeEnv()); err == nil {
		t.Fatal("a profile wrote an unrostered name reachable only because an INCLUDED profile " +
			"declared it, and Resolve accepted the selection — the licence travelled")
	}

	// POSITIVE CONTROL: the same shape, except "user" declares the name
	// itself. This must succeed, or the refusal above could be explained by
	// something unrelated to travel (e.g. the two `set`s disagreeing, or the
	// include itself being malformed).
	reg["user2"] = &Profile{Name: "user2", Include: []ProfileName{"declarer"},
		Environ: EnvGrants{Declare: []string{name}, Set: map[string]string{name: "fast"}}}
	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "user2"}, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("control: a profile declaring its own use of the name, alongside an include "+
			"that also declares it, was refused: %v", err)
	}
}

// TestDeclarationDoesNotTravelAcrossSiblingProfiles is the `-p a -p b` shape:
// two profiles selected directly, side by side, rather than one including the
// other. The licence still must not cross from "a" to "b".
func TestDeclarationDoesNotTravelAcrossSiblingProfiles(t *testing.T) {
	const name = "MY_TOOL_MODE"
	reg := testRegistry()
	reg["a"] = &Profile{Name: "a", Environ: EnvGrants{
		Declare: []string{name}, Set: map[string]string{name: "fast"}}}
	reg["b"] = &Profile{Name: "b", Environ: EnvGrants{
		Set: map[string]string{name: "fast"}}} // b does NOT declare

	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "a", "b"}, testCtx(), newFakeEnv()); err == nil {
		t.Fatal("-p a -p b: b wrote an unrostered name without declaring it, and was accepted " +
			"because a sibling profile (a) happened to declare the same name")
	}

	// POSITIVE CONTROL: both declare and agree on the value — this is the
	// shape TestConflictingScalarSetsAreRefused's own positive control uses,
	// and it must still succeed once each profile takes its own responsibility.
	reg["b2"] = &Profile{Name: "b2", Environ: EnvGrants{
		Declare: []string{name}, Set: map[string]string{name: "fast"}}}
	if _, err := Resolve(reg, []ProfileName{"@sys", "@cwd-rw", "a", "b2"}, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("control: two sibling profiles, each declaring and agreeing on the value, "+
			"were refused: %v", err)
	}
}

// ── 5. case-folded spellings agree with each other, and stay off the hatch ──

// TestCaseFoldedSpellingsOfARosteredNameCannotBeDeclared is the defect this
// codebase has already recorded twice, met one layer further on: typeOf folds
// case for names under a case-folding prefix (npm_config_ here), so an exact,
// case-sensitive roster lookup would treat two of the three spellings of
// NPM_CONFIG_USERCONFIG as unrostered — which would make them DECLARABLE, the
// one thing a name snug has an opinion about must never become. All three
// spellings must agree, at every verb, and none may reach the hatch.
func TestCaseFoldedSpellingsOfARosteredNameCannotBeDeclared(t *testing.T) {
	spellings := []string{
		"npm_config_userconfig",
		"NPM_CONFIG_USERCONFIG",
		"Npm_Config_Userconfig",
	}
	for _, name := range spellings {
		// set: legal. NPM_CONFIG_USERCONFIG is a roster row (path-valued
		// pointer, exempted from the npm_config_ forbid-prefix by name), and
		// the roster lookup must recognise every spelling as that same row.
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "/tmp/x"}}); err != nil {
			t.Errorf("environ.set %s was refused: %v — a case-folded spelling of a rostered "+
				"pointer must resolve to the same row as the canonical spelling", name, err)
		}
		// inherit: refused in every spelling — a pointer must never be pulled
		// from the host (noInherit), and the prefix rule refuses it too.
		if err := ValidateEnvGrants(EnvGrants{Inherit: []string{name}}); err == nil {
			t.Errorf("environ.inherit %s was accepted; every spelling of NPM_CONFIG_USERCONFIG "+
				"must be refused at inherit", name)
		}
		// declare: refused in every spelling. This is the assertion the
		// defect is actually about: if the roster lookup ever regresses to an
		// exact-string match, npm_config_userconfig and Npm_Config_Userconfig
		// would read as "snug has no entry for this name" and become
		// declarable, silently reopening the exact hole prefixCaseFold exists
		// to close one layer up.
		if err := ValidateEnvGrants(EnvGrants{Declare: []string{name}}); err == nil {
			t.Errorf("environ.declare accepted %s — a case-folded spelling of a name the roster "+
				"already governs must not become declarable", name)
		}
	}
}
