package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ── issue #17: ~/.claude/settings.json is a COMMAND TABLE ────────────────────
//
// These tests exercise the pure filter only (no filesystem, no exec — see
// CLAUDE.md's "Keep internal/policy pure"). The impure half (reading the
// host's real file, printing the stderr lines) lives in internal/cli/claude.go and
// is covered by internal/cli/claudestagedset_test.go and the integration suite.

// TestClaudeSettingsFilterDropsEveryExecutingKey feeds a document containing
// EVERY key in ClaudeExecutingKeys, named explicitly (the issue's DoD requires
// the dropped keys be listed, not merely "some keys"), plus one representative
// of a key that is NOT itself spelled out in the catalogue but falls into a
// §3.3 drop class by construction: an unnamed key is dropped by the allowlist
// exactly like a named one, and this is the assertion that the catalogue's
// incompleteness is safe rather than merely convenient.
//
// Both the KEY NAMES and their VALUES are asserted absent from the rendered
// file — a test that only checked key names would pass on a filter that
// dropped the key but somehow let a value ride in under a different name.
func TestClaudeSettingsFilterDropsEveryExecutingKey(t *testing.T) {
	if len(ClaudeExecutingKeys) == 0 {
		t.Fatal("control: ClaudeExecutingKeys is empty, so this test would assert nothing")
	}

	raw := map[string]any{}
	for name := range ClaudeExecutingKeys {
		// A distinct, greppable marker per key: a leaked VALUE names the key it
		// leaked from in the failure message.
		raw[name] = "VALUE-FOR-" + name
	}
	// Representative of a key that is dropped by the allowlist's default
	// ("copy only what is named") but has no entry of its own in
	// ClaudeExecutingKeys — CLAUDE-SETTINGS.md §3.3(e) names `worktree.sparsePaths`
	// as path-valued; the code's catalogue does not spell it out because it is
	// a NESTED field, not a top-level key, and R-SCALAR already refuses any
	// allowlisted key whose value is a container (TestClaudeSettingsCarriesNoContainer).
	// Here it arrives as an ordinary unlisted top-level key and must be dropped
	// the same way any future, wholly unanticipated key would be.
	raw["worktree"] = map[string]any{"sparsePaths": []any{"/etc/shadow"}}

	carried, drops := FilterClaudeSettings(raw)

	// None of these keys is on the allowlist, so FilterClaudeSettings should
	// never even reach the point of refusing one of their VALUES — refusal is
	// for an allowlisted key whose value failed a check, which is a different
	// thing from a key that was never going to be looked at.
	if len(drops.Refused) != 0 {
		t.Fatalf("an executing key was reported as a refused VALUE rather than a plain drop: %+v — "+
			"none of these keys are on the allowlist, so their values should never be inspected "+
			"closely enough to be refused", drops.Refused)
	}
	// Every key from ClaudeExecutingKeys IS catalogued, so none of THOSE names
	// should land in Unknown — Unknown is for names on NEITHER list, and
	// "worktree" (added below) is the one name in this document that belongs
	// there.
	for _, name := range drops.Unknown {
		if _, known := ClaudeExecutingKeys[name]; known {
			t.Errorf("catalogued executing key %q was reported as Unknown instead of Executing", name)
		}
	}

	for name := range ClaudeExecutingKeys {
		if _, ok := carried[name]; ok {
			t.Errorf("executing key %q was carried into the filtered set", name)
		}
	}
	if _, ok := carried["worktree"]; ok {
		t.Error("the unnamed path-valued key \"worktree\" was carried into the filtered set")
	}

	body := string(ClaudeSettingsJSON(carried))
	for name := range ClaudeExecutingKeys {
		if strings.Contains(body, name) {
			t.Errorf("rendered settings.json mentions the dropped key name %q:\n%s", name, body)
		}
		if strings.Contains(body, "VALUE-FOR-"+name) {
			t.Errorf("rendered settings.json carries the VALUE of dropped key %q:\n%s", name, body)
		}
	}
	if strings.Contains(body, "/etc/shadow") || strings.Contains(body, "sparsePaths") {
		t.Errorf("rendered settings.json carries the unnamed path-valued key's content:\n%s", body)
	}

	// "worktree" is on NEITHER list, so it must be reported as Unknown — the
	// regression this test guards: a dropped key on no list, reported nowhere.
	foundWorktree := false
	for _, name := range drops.Unknown {
		if name == "worktree" {
			foundWorktree = true
		}
	}
	if !foundWorktree {
		t.Errorf("\"worktree\" is on neither catalogue and was dropped, but is not named in "+
			"drops.Unknown: %+v", drops.Unknown)
	}

	// The stderr-line half of invariant 5: every dropped executing key must be
	// NAMED in the report, or a human has no way to know snug withheld it.
	// Executing ∪ Overridden, not Executing alone: crossSessionInbound and
	// isolatePeerMachines are catalogued in ClaudeExecutingKeys AND authored
	// (ClaudeAuthoredSettings, issue #87), so a host document setting them
	// lands in drops.Overridden rather than drops.Executing — a fourth,
	// disjoint report of the same "your value did not survive" fact (see
	// ClaudeSettingDrops' doc comment on Overridden). Either slice satisfies
	// this test's actual claim: the drop was reported somewhere.
	named := map[string]bool{}
	for _, d := range drops.Executing {
		named[d] = true
	}
	for _, d := range drops.Overridden {
		named[d] = true
	}
	for name := range ClaudeExecutingKeys {
		if !named[name] {
			t.Errorf("the dropped-executing report does not name %q; stageClaudeSettings would "+
				"stay silent about withholding it", name)
		}
	}
}

// TestClaudeSettingsFilterCarriesAnOrdinarySetting is the positive control the
// issue's definition of done requires: model and theme, from the shape of a
// real host file (CLAUDE-SETTINGS.md §1.1), survive alongside a filter that
// correctly drops enabledPlugins and extraKnownMarketplaces from the SAME
// document. A filter that dropped everything fails this test, not the ones
// above.
func TestClaudeSettingsFilterCarriesAnOrdinarySetting(t *testing.T) {
	raw := map[string]any{
		"model": "opus[1m]",
		"enabledPlugins": map[string]any{
			"gopls-lsp@claude-plugins-official": true, "caveman@caveman": true,
		},
		"extraKnownMarketplaces": map[string]any{
			"caveman": map[string]any{
				"source": map[string]any{"source": "github", "repo": "JuliusBrussee/caveman"},
			},
		},
		"skipWorkflowUsageWarning": true,
		"theme":                    "dark",
	}
	carried, drops := FilterClaudeSettings(raw)
	if len(drops.Refused) != 0 {
		t.Fatalf("an ordinary value from a real host file's shape was refused: %+v", drops.Refused)
	}
	if len(drops.Unknown) != 0 {
		t.Fatalf("every dropped key in this document is catalogued in ClaudeExecutingKeys; "+
			"none should be reported as Unknown: %+v", drops.Unknown)
	}

	body := string(ClaudeSettingsJSON(carried))
	for _, want := range []string{`"model": "opus[1m]"`, `"theme": "dark"`, `"skipWorkflowUsageWarning": true`} {
		if !strings.Contains(body, want) {
			t.Errorf("an ordinary host preference did not survive the filter; a filter that "+
				"dropped everything must fail here — wanted %q in:\n%s", want, body)
		}
	}
	for _, name := range []string{"enabledPlugins", "extraKnownMarketplaces", "gopls-lsp", "JuliusBrussee"} {
		if strings.Contains(body, name) {
			t.Errorf("%q leaked into the generated file:\n%s", name, body)
		}
	}

	wantDropped := map[string]bool{"enabledPlugins": true, "extraKnownMarketplaces": true}
	for _, d := range drops.Executing {
		if !wantDropped[d] {
			t.Errorf("unexpected name in the dropped-executing report: %q", d)
		}
		delete(wantDropped, d)
	}
	if len(wantDropped) != 0 {
		t.Errorf("the dropped-executing report is missing %v", wantDropped)
	}
}

// TestClaudeSettingsAllowlistAndExecutingCatalogueAreDisjoint asserts a name
// cannot appear on both lists — that would mean a key both carried and named as
// dangerous — with a control that the catalogue is non-empty (an empty
// catalogue would make disjointness trivially true, the exact shape of the
// pasta.avx2 scar CLAUDE.md records: a check that cannot fail).
func TestClaudeSettingsAllowlistAndExecutingCatalogueAreDisjoint(t *testing.T) {
	if len(ClaudeExecutingKeys) == 0 {
		t.Fatal("control: ClaudeExecutingKeys is empty, so disjointness would be trivially true")
	}
	if len(ClaudeSettingAllowlist) == 0 {
		t.Fatal("control: ClaudeSettingAllowlist is empty, so disjointness would be trivially true")
	}
	for _, k := range ClaudeSettingAllowlist {
		if _, ok := ClaudeExecutingKeys[k.Name]; ok {
			t.Errorf("%q is on both ClaudeSettingAllowlist and ClaudeExecutingKeys", k.Name)
		}
	}
}

// TestClaudeSettingsCarriesNoContainer is R-SCALAR: an allowlisted name whose
// value is an object or array is dropped rather than copied verbatim, and
// every entry in ClaudeSettingAllowlist declares one of the three scalar
// kinds — there is no ClaudeObject or ClaudeArray constant to declare, and
// this test is what would catch one being added.
func TestClaudeSettingsCarriesNoContainer(t *testing.T) {
	for _, k := range ClaudeSettingAllowlist {
		switch k.Kind {
		case ClaudeString, ClaudeBool, ClaudeNumber:
			// scalar, as required
		default:
			t.Errorf("allowlist entry %q declares kind %v, which is none of the three scalar "+
				"kinds — R-SCALAR is enforced by ClaudeSettingKind having no container "+
				"constant, so this can only fire if that invariant itself is broken", k.Name, k.Kind)
		}
	}

	// The §5.2 exhibit: `permissions` smuggled through a hypothetically
	// allowlisted `model`. If R-SCALAR held only "by convention" rather than by
	// construction, this object would ride in under a scalar-kind name.
	raw := map[string]any{
		"model": map[string]any{
			"defaultMode": "bypassPermissions", "additionalDirectories": []any{"/home/u/.ssh"},
		},
		"verbose": []any{"true"},
	}
	carried, drops := FilterClaudeSettings(raw)
	if _, ok := carried["model"]; ok {
		t.Error("an allowlisted STRING key whose value is an OBJECT was carried")
	}
	if _, ok := carried["verbose"]; ok {
		t.Error("an allowlisted BOOL key whose value is an ARRAY was carried")
	}
	body := string(ClaudeSettingsJSON(carried))
	if strings.Contains(body, "bypassPermissions") || strings.Contains(body, ".ssh") {
		t.Errorf("a container smuggled through an allowlisted key's value reached the "+
			"rendered file:\n%s", body)
	}

	names := map[string]bool{}
	for _, r := range drops.Refused {
		names[r.Name] = true
	}
	if !names["model"] || !names["verbose"] {
		t.Errorf("the object/array values were dropped silently rather than REPORTED as "+
			"refused values (invariant 5): %+v", drops.Refused)
	}
}

// TestClaudeSettingsRefusesAControlCharacter is R-VALUE item 1, checked in both
// places it is enforced: FilterClaudeSettings (the normal path) and
// ClaudeSettingsJSON (the backstop for a caller that never went through the
// filter — mirroring GitConfigFrom's own re-check of control characters,
// gitextract.go).
func TestClaudeSettingsRefusesAControlCharacter(t *testing.T) {
	poisoned := "dark\x1b[1A\rPWNED"

	carried, drops := FilterClaudeSettings(map[string]any{"theme": poisoned})
	if v, ok := carried["theme"]; ok {
		t.Fatalf("a control character survived FilterClaudeSettings: %q", v)
	}
	if len(drops.Refused) != 1 || drops.Refused[0].Name != "theme" {
		t.Errorf("the control character was not reported as a refused value: %+v", drops.Refused)
	}
	if !strings.Contains(drops.Refused[0].Reason, "control character") {
		t.Errorf("the refusal reason does not say WHY: %q", drops.Refused[0].Reason)
	}

	// The backstop. Built by hand rather than through FilterClaudeSettings, the
	// way "a test fixture building a ClaudeSettings by hand" (the renderer's own
	// doc comment) would.
	bad := ClaudeSettings{"theme": poisoned}
	if _, ok := bad["theme"]; !ok {
		t.Fatal("control: the fixture does not carry the value under test")
	}
	body := string(ClaudeSettingsJSON(bad))
	if strings.ContainsAny(body, "\x1b\r") {
		t.Errorf("ClaudeSettingsJSON rendered a raw control character that bypassed the "+
			"filter:\n%q", body)
	}
	if strings.Contains(body, `"theme"`) {
		t.Errorf("ClaudeSettingsJSON's backstop rendered the theme KEY at all for a poisoned "+
			"value; the whole entry must be omitted, not merely escaped:\n%s", body)
	}
}

// TestClaudeSettingsRefusesAPathOrURLValue is R-NOPATH, mechanised: model and
// theme values shaped like an ARN, a provider path, a home-relative path or a
// URL are all dropped by the per-key charset check.
func TestClaudeSettingsRefusesAPathOrURLValue(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"model", "arn:aws:bedrock:us-east-1::foundation-model/claude"},
		{"model", "bedrock/anthropic.claude-3"},
		{"model", "~/models/custom"},
		{"model", "http://example.invalid/model"},
		{"theme", "http://example.invalid/theme.json"},
		{"theme", "~/themes/x"},
		{"theme", "some/path/theme"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			carried, drops := FilterClaudeSettings(map[string]any{tc.key: tc.value})
			if v, ok := carried[tc.key]; ok {
				t.Errorf("%q=%q was carried; a path- or URL-shaped value must never reach the "+
					"generated file (R-NOPATH)", tc.key, v)
			}
			if len(drops.Refused) != 1 || drops.Refused[0].Name != tc.key {
				t.Errorf("the refusal was not reported: %+v", drops.Refused)
			}
		})
	}
}

// TestClaudeSettingsRendersDeterministically covers §5.4's rendering contract:
// sorted keys, a trailing newline, and "{}\n" for the empty set.
func TestClaudeSettingsRendersDeterministically(t *testing.T) {
	if got := string(ClaudeSettingsJSON(ClaudeSettings{})); got != "{}\n" {
		t.Errorf("empty settings render %q, want \"{}\\n\" — the mount is unconditional (§7.3), "+
			"so there must always be a well-formed document to write", got)
	}

	s := ClaudeSettings{"theme": "dark", "model": "opus", "verbose": true}
	out := string(ClaudeSettingsJSON(s))
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("rendered file has no trailing newline:\n%q", out)
	}

	iModel := strings.Index(out, `"model"`)
	iTheme := strings.Index(out, `"theme"`)
	iVerbose := strings.Index(out, `"verbose"`)
	if iModel < 0 || iTheme < 0 || iVerbose < 0 {
		t.Fatalf("not all three keys are present in the rendered output:\n%s", out)
	}
	if !(iModel < iTheme && iTheme < iVerbose) {
		t.Errorf("keys are not sorted alphabetically (model, theme, verbose):\n%s", out)
	}

	if again := string(ClaudeSettingsJSON(s)); again != out {
		t.Error("rendering the same ClaudeSettings twice produced different bytes — the golden " +
			"diff this format exists for depends on determinism")
	}
}

// TestClaudeSettingsLastDuplicateWinsAndIsRenderedOnce is §5.4: JSON permits a
// duplicate object key, Go's decoder resolves it to the last occurrence before
// FilterClaudeSettings ever sees the document, and the generated file must
// therefore contain that ONE value, rendered ONCE — there is no second parser
// in this pipeline for the two occurrences to disagree in front of.
func TestClaudeSettingsLastDuplicateWinsAndIsRenderedOnce(t *testing.T) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(`{"theme":"first","theme":"second"}`), &raw); err != nil {
		t.Fatal(err)
	}
	// Control: confirm what Go's own decoder actually did with the duplicate,
	// so the assertions below are about FilterClaudeSettings and not a claim
	// about encoding/json that happens to be true today.
	if raw["theme"] != "second" {
		t.Fatalf("control: encoding/json resolved the duplicate to %q, not \"second\" — this "+
			"test's premise about json.Unmarshal's own behaviour does not hold", raw["theme"])
	}

	carried, drops := FilterClaudeSettings(raw)
	if len(drops.Refused) != 0 {
		t.Fatalf("unexpected refusal: %+v", drops.Refused)
	}
	if got := carried["theme"]; got != "second" {
		t.Fatalf("carried theme = %v, want the last duplicate (\"second\")", got)
	}

	out := string(ClaudeSettingsJSON(carried))
	if n := strings.Count(out, `"theme"`); n != 1 {
		t.Errorf("theme appears %d times in the rendered file, want exactly 1:\n%s", n, out)
	}
	if strings.Contains(out, "first") {
		t.Errorf("the overridden duplicate's value survived into the rendered file:\n%s", out)
	}
	if !strings.Contains(out, "second") {
		t.Errorf("the winning duplicate's value did not survive:\n%s", out)
	}
}

// TestClaudeSettingsReportsWhyAnAllowlistedValueWasRefused is the regression
// test for the defect FilterClaudeSettings' own doc comment names: before the
// third return value existed, an allowlisted key whose value failed a check
// was dropped with NOTHING on any screen — measured, a `model` shaped like a
// Bedrock ARN (exactly the §3.2 trap the charset check exists to catch)
// produced empty stderr. The reporting must also distinguish a TYPE failure
// from a CHARSET failure, because "your model has the wrong shape" and "your
// verbose is not a boolean at all" are different mistakes for a human to fix.
func TestClaudeSettingsReportsWhyAnAllowlistedValueWasRefused(t *testing.T) {
	raw := map[string]any{
		"model":   "arn:aws:bedrock:us-east-1::foundation-model/claude", // charset (R-NOPATH)
		"verbose": "yes",                                                // wrong JSON type
	}
	_, drops := FilterClaudeSettings(raw)
	if len(drops.Refused) == 0 {
		t.Fatal("no refusal was reported at all — this is the exact defect this test guards " +
			"against: a value that failed a check with nothing on any screen")
	}

	byName := map[string]string{}
	for _, r := range drops.Refused {
		byName[r.Name] = r.Reason
	}
	if _, ok := byName["model"]; !ok {
		t.Fatal("model's refused value was not reported")
	}
	if _, ok := byName["verbose"]; !ok {
		t.Fatal("verbose's refused value was not reported")
	}
	if !strings.Contains(byName["model"], "shape") {
		t.Errorf("model's refusal reason does not name a SHAPE/charset failure: %q", byName["model"])
	}
	if !strings.Contains(byName["verbose"], "boolean") {
		t.Errorf("verbose's refusal reason does not name a TYPE failure: %q", byName["verbose"])
	}
	if byName["model"] == byName["verbose"] {
		t.Errorf("a charset failure and a type failure produced the SAME reason text, so a "+
			"human reading stderr cannot tell which mistake they made: %q", byName["model"])
	}
}

// TestClaudeSettingsFilterReportsUnknownKeys is the regression test for the
// third drop class: a dropped key that is on NEITHER catalogue — not
// ClaudeSettingAllowlist, not ClaudeExecutingKeys — reported nowhere.
//
// The document is the red team's exact reproduction: {"model":"opus",
// "postToolWrapper":"/bin/sh -c curl|sh","newUpstreamHelper":"/usr/bin/evil",
// "someFuturePreference":true}. Before ClaudeSettingDrops existed,
// `snug -v --dry-run -p @claude` said only `carried: model` for this
// document — two keys that NAME A PROGRAM, and one ordinary future
// preference, all vanished with no line anywhere. Neither
// "postToolWrapper" nor "newUpstreamHelper" is spelled out in
// ClaudeExecutingKeys (the catalogue cannot be complete — see its own doc
// comment — this is a plausible NEXT key upstream could ship, not one
// already catalogued), which is exactly the case Unknown exists to catch:
// ClaudeExecutingKeys' incompleteness is safe for what gets CARRIED, but was
// not safe for what gets REPORTED.
func TestClaudeSettingsFilterReportsUnknownKeys(t *testing.T) {
	raw := map[string]any{
		"model":                "opus",
		"postToolWrapper":      "/bin/sh -c curl|sh",
		"newUpstreamHelper":    "/usr/bin/evil",
		"someFuturePreference": true,
	}
	for _, name := range []string{"postToolWrapper", "newUpstreamHelper", "someFuturePreference"} {
		if _, known := ClaudeExecutingKeys[name]; known {
			t.Fatalf("control: %q is already in ClaudeExecutingKeys, so this test would exercise "+
				"the Executing class rather than the Unknown class it is named for", name)
		}
	}

	carried, drops := FilterClaudeSettings(raw)
	if _, ok := carried["model"]; !ok {
		t.Fatal("control: `model` was not carried, so this fixture would not show the mixed " +
			"carried/dropped shape the red team's reproduction had")
	}
	if len(drops.Executing) != 0 {
		t.Errorf("nothing in this document is catalogued in ClaudeExecutingKeys; got %v", drops.Executing)
	}
	if len(drops.Refused) != 0 {
		t.Errorf("nothing in this document is allowlisted-but-invalid; got %+v", drops.Refused)
	}

	got := map[string]bool{}
	for _, name := range drops.Unknown {
		got[name] = true
	}
	for _, want := range []string{"postToolWrapper", "newUpstreamHelper", "someFuturePreference"} {
		if !got[want] {
			t.Errorf("%q was dropped but not reported in drops.Unknown: %v", want, drops.Unknown)
		}
	}
	if len(drops.Unknown) != 3 {
		t.Errorf("drops.Unknown = %v, want exactly the 3 keys on neither catalogue", drops.Unknown)
	}

	// Sorted, for deterministic stderr/--dry-run output — the same contract
	// Executing and Refused already carry.
	sorted := append([]string(nil), drops.Unknown...)
	sort.Strings(sorted)
	for i, name := range drops.Unknown {
		if name != sorted[i] {
			t.Errorf("drops.Unknown is not sorted: %v", drops.Unknown)
			break
		}
	}
}

// ── issue #87: snug AUTHORS crossSessionInbound and isolatePeerMachines ──────
//
// These cover the structural claims ClaudeAuthoredSetting's doc comment makes
// about the authored table itself (disjoint from the allowlist, catalogued as
// executing, scalar-typed) and the two renderers that consume it
// (ClaudeUserSettingsJSON, ClaudeSettingsJSON).

// TestClaudeAuthoredKeysAreDisjointFromTheAllowlist is what makes a collision
// between a carried name and an authored name UNREACHABLE rather than merely
// resolved by write order: ClaudeUserSettingsJSON's own doc comment says
// authored keys are written last "because the disjointness test fails the
// build first" — this is that test.
func TestClaudeAuthoredKeysAreDisjointFromTheAllowlist(t *testing.T) {
	if len(ClaudeAuthoredSettings) == 0 {
		t.Fatal("control: ClaudeAuthoredSettings is empty, so disjointness would be trivially true")
	}
	if len(ClaudeSettingAllowlist) == 0 {
		t.Fatal("control: ClaudeSettingAllowlist is empty, so disjointness would be trivially true")
	}
	allowed := make(map[string]bool, len(ClaudeSettingAllowlist))
	for _, k := range ClaudeSettingAllowlist {
		allowed[k.Name] = true
	}
	for _, a := range ClaudeAuthoredSettings {
		if allowed[a.Name] {
			t.Errorf("%q is on both ClaudeAuthoredSettings and ClaudeSettingAllowlist", a.Name)
		}
	}
}

// TestClaudeAuthoredKeysAreRefusedFromTheHost is the load-bearing test of this
// pair: it is what makes "snug overrides Claude Code's default, never a
// carried human decision" TRUE rather than merely asserted in the doc
// comment. Every authored name must also be catalogued in ClaudeExecutingKeys,
// so a host document setting either one is refused (as Overridden, condition
// 3's own catalogue entry) rather than silently carried the way an
// unlisted key would be.
func TestClaudeAuthoredKeysAreRefusedFromTheHost(t *testing.T) {
	if len(ClaudeAuthoredSettings) == 0 {
		t.Fatal("control: ClaudeAuthoredSettings is empty, so this test would assert nothing")
	}
	for _, a := range ClaudeAuthoredSettings {
		if _, ok := ClaudeExecutingKeys[a.Name]; !ok {
			t.Errorf("authored key %q is not catalogued in ClaudeExecutingKeys — a host "+
				"document setting it would not be recognised as a refused host decision at all",
				a.Name)
		}
	}
}

// TestClaudeAuthoredValuesMatchTheirDeclaredKind is R-SCALAR applied to
// ClaudeAuthoredSettings itself: each entry's Value must decode to the Go
// type its own Kind promises (string for ClaudeString, bool for ClaudeBool,
// float64 for ClaudeNumber), the same three shapes ClaudeUserSettingsJSON's
// switch expects when it writes the value straight into the output map with
// no further check. Why must also be non-empty — it is what --dry-run's CLAUDE
// block and claudeGuidance render for a human and an agent respectively, and
// an empty string there would print a blank line with nothing to explain it.
func TestClaudeAuthoredValuesMatchTheirDeclaredKind(t *testing.T) {
	for _, a := range ClaudeAuthoredSettings {
		switch a.Kind {
		case ClaudeString:
			if _, ok := a.Value.(string); !ok {
				t.Errorf("%q declares Kind ClaudeString but Value is %T", a.Name, a.Value)
			}
		case ClaudeBool:
			if _, ok := a.Value.(bool); !ok {
				t.Errorf("%q declares Kind ClaudeBool but Value is %T", a.Name, a.Value)
			}
		case ClaudeNumber:
			if _, ok := a.Value.(float64); !ok {
				t.Errorf("%q declares Kind ClaudeNumber but Value is %T", a.Name, a.Value)
			}
		default:
			t.Errorf("%q declares an unrecognised Kind %v", a.Name, a.Kind)
		}
		if a.Why == "" {
			t.Errorf("%q has an empty Why — --dry-run's CLAUDE block and claudeGuidance both "+
				"render this string and have nothing else to explain the key with", a.Name)
		}
	}
}

// TestClaudeAuthoredSettingsAreScalars is R-SCALAR, mechanised the same way
// TestClaudeSettingsCarriesNoContainer checks it for the allowlist: every
// Kind on ClaudeAuthoredSettings must be one of the three scalar constants,
// which holds by construction (ClaudeSettingKind has no container constant to
// declare) but is worth asserting directly rather than only inferring it from
// the kind-switch above never hitting `default`.
func TestClaudeAuthoredSettingsAreScalars(t *testing.T) {
	if len(ClaudeAuthoredSettings) == 0 {
		t.Fatal("control: ClaudeAuthoredSettings is empty, so this test would assert nothing")
	}
	for _, a := range ClaudeAuthoredSettings {
		switch a.Kind {
		case ClaudeString, ClaudeBool, ClaudeNumber:
			// scalar, as required
		default:
			t.Errorf("authored entry %q declares kind %v, which is none of the three scalar "+
				"kinds", a.Name, a.Kind)
		}
	}
}

// TestClaudeUserSettingsIgnoreTheHostsValueForAnAuthoredKey is NEGATIVE: a
// host file that sets both authored keys to the PERMISSIVE value must not
// move either one into the rendered user-scope file. Both names must also
// land in drops.Overridden and in NEITHER drops.Executing nor drops.Unknown —
// Overridden is the one class where a value is both dropped and replaced, and
// a name counted twice (once as Overridden, once as Executing or Unknown)
// would double-report the same host decision under two different meanings.
func TestClaudeUserSettingsIgnoreTheHostsValueForAnAuthoredKey(t *testing.T) {
	raw := map[string]any{"crossSessionInbound": "accept", "isolatePeerMachines": false}
	carried, drops := FilterClaudeSettings(raw)

	wantOverridden := map[string]bool{"crossSessionInbound": true, "isolatePeerMachines": true}
	got := map[string]bool{}
	for _, name := range drops.Overridden {
		got[name] = true
	}
	for name := range wantOverridden {
		if !got[name] {
			t.Errorf("%q was not reported in drops.Overridden: %v", name, drops.Overridden)
		}
	}
	for _, name := range drops.Executing {
		if wantOverridden[name] {
			t.Errorf("%q was reported in drops.Executing as well as drops.Overridden — the two "+
				"classes must be disjoint", name)
		}
	}
	for _, name := range drops.Unknown {
		if wantOverridden[name] {
			t.Errorf("%q was reported in drops.Unknown — it is catalogued, not on neither list",
				name)
		}
	}

	body := string(ClaudeUserSettingsJSON(carried))
	if !strings.Contains(body, `"crossSessionInbound": "refuse"`) {
		t.Errorf("rendered user settings.json does not carry snug's own \"refuse\" value:\n%s", body)
	}
	if !strings.Contains(body, `"isolatePeerMachines": true`) {
		t.Errorf("rendered user settings.json does not carry snug's own true value:\n%s", body)
	}
	if strings.Contains(body, "accept") {
		t.Errorf("the host's \"accept\" value for crossSessionInbound reached the rendered "+
			"file:\n%s", body)
	}
}

// TestClaudeProjectSettingsAuthorNothing is NEGATIVE: the project-scope
// renderer, ClaudeSettingsJSON, is UNCHANGED by issue #87 — it must never
// carry either authored name, and the empty-input, "{}\n" contract it has
// always had must still hold. Only ClaudeUserSettingsJSON authors anything;
// see that function's own doc comment on why user scope alone is enough.
func TestClaudeProjectSettingsAuthorNothing(t *testing.T) {
	if got := string(ClaudeSettingsJSON(ClaudeSettings{})); got != "{}\n" {
		t.Errorf("ClaudeSettingsJSON({}) = %q, want \"{}\\n\" — project scope must still be "+
			"reachable with nothing carried and nothing authored", got)
	}

	carried := ClaudeSettings{"model": "opus[1m]", "theme": "dark"}
	body := string(ClaudeSettingsJSON(carried))
	for _, name := range ClaudeAuthoredNames() {
		if strings.Contains(body, name) {
			t.Errorf("project-scope ClaudeSettingsJSON output contains the authored key %q; "+
				"only ClaudeUserSettingsJSON may author anything:\n%s", name, body)
		}
	}
}

// TestGoldenClaudeUserSettingsJSON pins the exact bytes ClaudeUserSettingsJSON
// renders — the review artifact for issue #87, since the change lives in FILE
// CONTENT rather than in bwrap argv (internal/cli/testdata/bwrap.claude.txt
// does not change: an authored setting is never an argv, so a golden of the
// rendered document is the only place this change is visible as a diff).
func TestGoldenClaudeUserSettingsJSON(t *testing.T) {
	cases := []struct {
		name    string
		carried ClaudeSettings
	}{
		// An ordinary carried set, alongside the two authored keys — the shape
		// a real host with model/theme preferences produces.
		{"claude-settings.user.json", ClaudeSettings{"model": "opus[1m]", "theme": "dark"}},
		// The empty-carried-set arm: a host with no settings.json (or one that
		// filtered to nothing) still gets the two authored keys, unconditionally
		// — unlike ClaudeSettingsJSON's "{}\n", "{}\n" is unreachable here.
		{"claude-settings.user-empty.json", ClaudeSettings{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(ClaudeUserSettingsJSON(tc.carried))
			path := filepath.Join("testdata", tc.name)
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run: go test ./internal/policy -update)", err)
			}
			if got != string(want) {
				t.Errorf("ClaudeUserSettingsJSON(%v) changed.\n--- got\n%s--- want\n%s",
					tc.carried, got, string(want))
			}
		})
	}
}
