package policy

import (
	"testing"
)

// ── issue #44: the roster, and what it does and does not refuse ─────────────
//
// The implementer's own tests (envtypes_test.go's positive controls,
// refusals_test.go's env_unrostered_merge golden) confirm the mechanism the
// code was WRITTEN with in mind. This file is written by a different agent, on
// purpose (CLAUDE.md), and asks the attacker's questions instead: does the
// list-verb refusal actually close every list verb, does a name with no roster
// row slip past the rules that are NOT about the roster, and does a case-folded
// spelling of a rostered name read as unrostered — the exact "one table
// disagrees with itself across two case spellings" defect this codebase has
// already recorded twice (npm_config_userconfig, and the inherit-exemption bug
// it was found a level deeper than).
//
// It was written against `environ.declare`, the per-profile escape hatch that
// existed for one milestone and was removed before it shipped. What survived
// the removal is every assertion that was never about the hatch: the questions
// above are the same questions, asked of the shape that shipped.

// ── 1. the roster's reach, by verb ──────────────────────────────────────────

// TestUnrosteredNameIsRefusedAtEveryListVerb checks the refusal as a SET rather
// than as one sample: a name snug has never heard of must be refused at merge,
// prepend AND sanitise — not just the one verb whichever fixture happened to
// exercise — and must be CARRIED at set and inherit, which is the other half of
// the same decision and the half a refusal-only test would let regress.
func TestUnrosteredNameIsRefusedAtEveryListVerb(t *testing.T) {
	const name = "MY_TOOL_MODE"

	for _, tc := range []struct {
		verb string
		g    EnvGrants
	}{
		{"merge", EnvGrants{Merge: map[string][]string{name: {"/opt/x"}}}},
		{"prepend", EnvGrants{Prepend: map[string][]string{name: {"/opt/x"}}}},
		{"sanitise", EnvGrants{Sanitise: []string{name}}},
	} {
		if err := ValidateEnvGrants(tc.g); err == nil {
			t.Errorf("environ.%s accepted %s, which snug has no roster row for — a list verb "+
				"needs the separator and the empty-element kind, and neither is something a "+
				"profile can supply", tc.verb, name)
		}
	}

	// POSITIVE CONTROL, and it is load-bearing in both directions: without it, a
	// build that refused EVERY unrostered name would pass every assertion above
	// and this test would be measuring a rule snug does not have. The two scalar
	// verbs carry the name; the screen marks it.
	for _, tc := range []struct {
		verb string
		g    EnvGrants
	}{
		{"set", EnvGrants{Set: map[string]string{name: "fast"}}},
		{"inherit", EnvGrants{Inherit: []string{name}}},
	} {
		if err := ValidateEnvGrants(tc.g); err != nil {
			t.Errorf("control: environ.%s refused %s, a name with no roster row — a user "+
				"profile writing one is a named hole in an empty environment, carried and "+
				"marked, not refused: %v", tc.verb, name, err)
		}
	}
	if !IsUncheckedEnv(name, VerbSet) || !IsUncheckedEnv(name, VerbInherit) {
		t.Errorf("%s is carried at set/inherit but IsUncheckedEnv says snug knows it; the "+
			"carry and the mark must be the same fact", name)
	}
}

// ── 2. the rules that are NOT the roster still apply to an unrostered name ──

// TestUnrosteredNameStillMeetsTheAnnotationTables: this asked, in the attacker's
// direction, whether having no roster row was a way PAST the forbidden-name and
// forbidden-prefix tables. It is the same question inverted now — those tables
// refuse nothing, so the way past them is to be handed over with nothing said —
// and the two rules are still applied independently: EnvNote reads the
// annotation tables, checkEnvVerbType reads the roster. A name with no row in
// either is carried and marked `unchecked`; a name with no ROSTER row but an
// annotation is carried, marked unchecked, AND told about, which is two true
// statements rather than a contradiction.
//
// The verdict a user profile gets is no longer a refusal, so what an attacker
// would want is silence. That is what this measures.
func TestUnrosteredNameStillMeetsTheAnnotationTables(t *testing.T) {
	cases := []struct {
		why  string
		name string
	}{
		{"an exact annotated name", "GIT_SSH_COMMAND"},
		{"the LD_ prefix", "LD_ANYTHING"},
		{"the BASH_FUNC_ prefix", "BASH_FUNC_x"},
	}
	for _, tc := range cases {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{tc.name: "x"}}); err != nil {
			t.Errorf("environ.set refused %s (%s): %v — a human's own profile may open this "+
				"hole; snug's job is to say what it is", tc.name, tc.why, err)
		}
		if EnvNote(tc.name, VerbSet) == "" {
			t.Errorf("environ.set %s (%s) is handed over with NOTHING said about it. None of "+
				"these three has a roster row, so the annotation is the only thing standing "+
				"between this row and a human reading it as ordinary", tc.name, tc.why)
		}
		// …and the unchecked mark is still there too, from the roster, which is
		// what the builtin gate is written on. Both marks, not one instead of the
		// other.
		if !IsUncheckedEnv(tc.name, VerbSet) {
			t.Errorf("%s reads as CHECKED. An annotation is not a roster row: if it were, a "+
				"profile snug SHIPS could write this name", tc.name)
		}
	}
}

// TestUnrosteredNameStillMeetsOwnership: checkEnvOwnership runs before the type
// rules, so a profile cannot reach a name snug writes itself by virtue of that
// name having no roster row — and most of them do not have one, deliberately
// (ownership refuses them for every verb, which is the stronger statement, and a
// row would invite someone to read it as permission).
func TestUnrosteredNameStillMeetsOwnership(t *testing.T) {
	for _, name := range []string{"HOME", "PS1", "SNUG_PROFILES"} {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "x"}}); err == nil {
			t.Errorf("environ.set accepted %s, which snug writes itself", name)
		}
	}
	// PATH is the one name ownership deliberately does NOT refuse for a list
	// verb: a profile's merge contributes its own band and displaces nothing
	// (§2.4). Asserting it here keeps the negative above from being read as
	// "no profile may name PATH".
	if err := ValidateEnvGrants(EnvGrants{Merge: map[string][]string{"PATH": {"/opt/x/bin"}}}); err != nil {
		t.Errorf("control: environ.merge on PATH is how a profile puts a tool on PATH: %v", err)
	}
}

// TestUnrosteredNameStillMeetsTheGrammar: checkEnvName's grammar rule runs at
// every verb, so a name with no roster row cannot smuggle in something that
// would corrupt the environment's own wire format.
func TestUnrosteredNameStillMeetsTheGrammar(t *testing.T) {
	cases := map[string]string{
		"contains '='":         "A=B",
		"starts with a digit":  "1FOO",
		"contains a newline":   "FOO\nBAR",
		"contains a NUL byte":  "FOO\x00BAR",
		"contains a raw space": "FOO BAR",
	}
	for why, name := range cases {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "x"}}); err == nil {
			t.Errorf("environ.set accepted a name that %s: %q", why, name)
		}
	}
}

// TestUnrosteredNameStillRefusesAControlCharacterValue: checkEnvValue runs
// unconditionally on every environ.set/merge/prepend value, whether or not the
// name is on the roster — snug knowing nothing about a NAME must never read as
// snug having nothing to say about its VALUE, because the value is what becomes
// three elements of a NUL-separated bwrap flag list. The NUL spelling is the
// escape sequence, not a raw NUL, because go-toml refuses a raw control
// character in a basic string and never lets one this far (see
// TestEnvValueRefusesControlCharacters, which pins the same rule against a
// ROSTERED name — EDITOR — and does not by itself say anything about an
// unrostered one).
func TestUnrosteredNameStillRefusesAControlCharacterValue(t *testing.T) {
	const name = "MY_TOOL_MODE"
	bad := map[string]string{
		"a NUL, which ends the flag and starts a new one": "vim\x00--ro-bind\x00/etc\x00/etc",
		"a newline, which forges a row in --dry-run":      "vim\n  ro     /etc/shadow",
		"an ESC, which rewrites the terminal":             "fast\x1b[1A\r  ro   /usr/share/doc",
	}
	for why, value := range bad {
		if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: value}}); err == nil {
			t.Errorf("an unrostered name's environ.set accepted a value containing %s — snug "+
				"knows nothing about the name, which says nothing about the value", why)
		}
	}

	// POSITIVE CONTROL: an ordinary value on the same name is fine, so the
	// refusals above are about the control character and not about the name.
	if err := ValidateEnvGrants(EnvGrants{Set: map[string]string{name: "fast"}}); err != nil {
		t.Errorf("control: an unrostered name with an ordinary value was refused: %v", err)
	}
}

// ── 3. case-folded spellings agree with each other ──────────────────────────

// TestCaseFoldedSpellingsOfARosteredNameAgree is the defect this codebase has
// already recorded twice, met one layer further on: typeOf folds case for names
// under a case-folding prefix (npm_config_ here), so an exact, case-sensitive
// roster lookup would treat two of the three spellings of NPM_CONFIG_USERCONFIG
// as unrostered. All three must resolve to the same row, at every verb, and none
// may read as a name snug has never heard of — which is now visible directly
// through IsUncheckedEnv, the predicate that draws the screen's mark AND is what
// internal/profile's `mark` holds a builtin to.
func TestCaseFoldedSpellingsOfARosteredNameAgree(t *testing.T) {
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
		// inherit: accepted in every spelling, and ANNOTATED in every spelling.
		// This was a refusal (the roster's `noInherit` bit, plus the prefix rule)
		// and is now the sentence saying what taking the host's value does —
		// which is the half that has to fold case, because the exact-name table
		// does not: npm_config_userconfig reaches its sentence through the
		// npm_config_ prefix, NPM_CONFIG_USERCONFIG through its own row, and a
		// reader must not be able to tell which by whether they were told
		// anything.
		if err := ValidateEnvGrants(EnvGrants{Inherit: []string{name}}); err != nil {
			t.Errorf("environ.inherit %s was refused: %v", name, err)
		}
		if EnvNote(name, VerbInherit) == "" {
			t.Errorf("environ.inherit %s carries no annotation; this spelling pulls the host's "+
				".npmrc — auth tokens included — into the sandbox with nothing said about it, "+
				"and the lower-case spelling is the exact one that slipped through the last "+
				"time this rule was written for one of its two case halves", name)
		}
		// unchecked: false in every spelling. If the roster lookup ever
		// regresses to an exact-string match, npm_config_userconfig and
		// Npm_Config_Userconfig would read as "snug has no entry for this
		// name" — the screen would say snug knew nothing about a name it has a
		// row for, and internal/profile's `mark` would refuse a builtin
		// writing the folded spelling of a name it permits in the canonical one.
		if IsUncheckedEnv(name, VerbSet) {
			t.Errorf("IsUncheckedEnv(%q) is true — a case-folded spelling of a name the roster "+
				"already governs must not read as one snug has never heard of", name)
		}
	}
}
