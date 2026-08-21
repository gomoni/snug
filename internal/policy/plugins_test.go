package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

const hostManifestFixture = `{
  "version": 2,
  "plugins": {
    "caveman@caveman": [{"scope":"user","installPath":"/h/.claude/plugins/cache/caveman/x","version":"1"}],
    "superpowers@claude-plugins-official": [{"scope":"user","installPath":"/h/sp","version":"6"}],
    "code-review@claude-plugins-official": [{"scope":"user","installPath":"/h/cr","version":"1"}]
  }
}`

func pluginKeys(t *testing.T, body []byte) []string {
	t.Helper()
	var m struct {
		Plugins map[string]json.RawMessage `json:"plugins"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("generated manifest does not parse: %v\n%s", err, body)
	}
	out := make([]string, 0, len(m.Plugins))
	for k := range m.Plugins {
		out = append(out, k)
	}
	return out
}

// TestFilterKeepsExactlyTheAllowlistedPlugins is issue #68's core: the
// regenerated manifest names the plugins the allowlist named AND NO OTHERS. A
// bare name matches by the part before "@", so `["caveman"]` keeps
// `caveman@caveman` and drops the two official plugins.
func TestFilterKeepsExactlyTheAllowlistedPlugins(t *testing.T) {
	body, err := FilterInstalledPlugins([]byte(hostManifestFixture), []string{"caveman", "superpowers"})
	if err != nil {
		t.Fatal(err)
	}
	got := pluginKeys(t, body)
	want := map[string]bool{"caveman@caveman": true, "superpowers@claude-plugins-official": true}
	if len(got) != len(want) {
		t.Fatalf("kept %v, want exactly %v", got, want)
	}
	for _, k := range got {
		if !want[k] {
			t.Errorf("kept %q, which the allowlist did not name — every un-named plugin must be "+
				"dropped, or the fix hands back the tree it exists to filter", k)
		}
	}
	// The entry bytes for a kept plugin are the host's, verbatim — snug forwards
	// them, it does not author them (the installPath points into the read-only
	// bind that is already there).
	if !strings.Contains(string(body), "/h/.claude/plugins/cache/caveman/x") {
		t.Error("the kept plugin's own install entry was not carried through")
	}
}

// TestEmptyAllowlistReplacesWithAnEmptyManifest is the strict default and the
// whole security point: naming NOTHING still REPLACES the host's file, so no
// plugin auto-loads. A host manifest present, allowlist empty -> zero plugins.
func TestEmptyAllowlistReplacesWithAnEmptyManifest(t *testing.T) {
	body, err := FilterInstalledPlugins([]byte(hostManifestFixture), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := pluginKeys(t, body); len(got) != 0 {
		t.Errorf("empty allowlist kept %v; it must name nothing — that is what makes the default "+
			"strict rather than open", got)
	}
	// And it is a VALID manifest (parses, has the version), not an empty file
	// Claude Code might treat as corrupt.
	if !strings.Contains(string(body), `"version"`) {
		t.Error("the empty manifest dropped the version field")
	}
}

// TestNamedButNotInstalledIsAnError is invariant 5: a plugin the profile named
// but the host has not installed fails the run, rather than being silently
// omitted from the manifest.
func TestNamedButNotInstalledIsAnError(t *testing.T) {
	_, err := FilterInstalledPlugins([]byte(hostManifestFixture), []string{"caveman", "ghost-plugin"})
	if err == nil {
		t.Fatal("a named-but-not-installed plugin was silently omitted; invariant 5 requires an error")
	}
	if !strings.Contains(err.Error(), "ghost-plugin") {
		t.Errorf("the error does not name the missing plugin, so a human cannot tell which of "+
			"several names was wrong:\n%v", err)
	}
	// POSITIVE CONTROL: the same call without the bad name succeeds, so the
	// error above is about ghost-plugin and not about the fixture.
	if _, err := FilterInstalledPlugins([]byte(hostManifestFixture), []string{"caveman"}); err != nil {
		t.Fatalf("control: the allowlist without the missing plugin should succeed: %v", err)
	}
}

// TestNamedPluginsAgainstNoHostManifestIsAnError: a non-empty allowlist with no
// host manifest to validate against cannot confirm the plugins are installed,
// so it errors rather than producing a manifest naming un-validated plugins.
func TestNamedPluginsAgainstNoHostManifestIsAnError(t *testing.T) {
	_, err := FilterInstalledPlugins(nil, []string{"caveman"})
	if err == nil {
		t.Fatal("naming a plugin with no host manifest to validate it was accepted")
	}
	// But an EMPTY allowlist with no host manifest is fine — the strict default.
	body, err := FilterInstalledPlugins(nil, nil)
	if err != nil {
		t.Fatalf("empty allowlist + no host manifest should yield an empty manifest, not an error: %v", err)
	}
	if got := pluginKeys(t, body); len(got) != 0 {
		t.Errorf("empty everything produced %v, want an empty manifest", got)
	}
}

// TestFullKeyDisambiguates: a bare name matches by the part before "@", but a
// fully-qualified name pins one marketplace. Both are accepted; the full key is
// how a human resolves two plugins that share a name.
func TestFullKeyDisambiguates(t *testing.T) {
	body, err := FilterInstalledPlugins([]byte(hostManifestFixture),
		[]string{"code-review@claude-plugins-official"})
	if err != nil {
		t.Fatal(err)
	}
	got := pluginKeys(t, body)
	if len(got) != 1 || got[0] != "code-review@claude-plugins-official" {
		t.Errorf("full-key allowlist kept %v, want exactly the one named", got)
	}
}

// TestUnparseableHostManifestIsAnError: a host manifest snug cannot read is an
// error, not a silent fall-back to the empty default — the empty default could
// hide a plugin the run named (invariant 5).
func TestUnparseableHostManifestIsAnError(t *testing.T) {
	if _, err := FilterInstalledPlugins([]byte("{not json"), []string{"caveman"}); err == nil {
		t.Fatal("an unparseable host manifest was accepted")
	}
}
