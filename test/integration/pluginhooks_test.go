//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// Issue #68's whole claim is that snug's REGENERATED installed_plugins.json is an
// independent gate on a third party's binary: a plugin the profile did not name is
// dropped from the manifest, and Claude Code then does not load its hooks. The unit
// tests (TestFilterKeepsExactlyTheAllowlistedPlugins, the staged-set tests) assert
// what snug WRITES. None of them can assert what the binary DOES with it, and the
// binary is exactly the part that drifts: enabledPlugins moved from ~/.claude.json
// to settings.json between versions, which is what made CLAUDE-SETTINGS.md §4.4's
// "regardless of enabledPlugins" go stale. A doc records what is true on one
// version; this test notices when the next one changes it — the same reason
// TestBwrapUnshareSetIsExhaustive reads `bwrap --help` as an independent oracle
// rather than trusting a written list.
//
// SCOPE, kept narrow the way §4.4 is. This drives the REAL claude binary against a
// REAL policy.FilterInstalledPlugins output, so it covers the MANIFEST gate — the
// file snug generates, fed to the binary, decides which plugin's SessionStart hook
// runs. It does NOT exercise the sandbox mount that DELIVERS that file inside a run;
// that is claudestagedset_test.go and TestClaudeJSONInsideCarriesNoHostProjectInventory
// reading the staged file from inside a real sandbox.
//
// Why this cannot be an IN-SANDBOX test with a positive control. Inside @claude,
// snug's own settings.json filter DROPS enabledPlugins (internal/policy/claudesettings.go),
// and on 2.1.238 an empty enabledPlugins means NO plugin hook fires at all (the
// enablement row below). So "the named plugin's hook fires" — the positive control
// that makes "the unnamed one's did not" mean anything — cannot exist inside the
// sandbox. The control only exists where enabledPlugins survives, which is here, on
// the host, against the binary directly. Do not move this into a sandbox: you would
// be left with a negative that passes because nothing ran.
func TestManifestGatesPluginHookFiring(t *testing.T) {
	budget(t, 90*time.Second)

	claudeBin, err := exec.LookPath("claude")
	if err != nil {
		// t.Skip, NOT skipOrFail: SNUG_REQUIRE_SANDBOX asks "can this host run
		// sandboxes", which is a different question from "is Claude Code installed
		// here". A CI runner with bwrap but no claude must skip this, not fail it —
		// the same call TestClaudeJSONInsideCarriesNoHostProjectInventory makes for
		// a missing ~/.claude.json.
		t.Skipf("no claude binary on PATH (%v); this test needs the real third-party "+
			"binary to observe whether it loads a plugin, and cannot be faked", err)
	}

	// Row 3, the BASELINE and positive control: with both plugins enabled AND both
	// in the manifest, BOTH hooks fire. Without this, the assertion below cannot
	// tell "the manifest gated the unnamed plugin" apart from "nothing fired at
	// all, and the test is measuring a dead sandbox".
	{
		home, fireDir, hostBoth := buildPluginFixture(t)
		writeManifestAndEnabled(t, home, hostBoth, []string{"named", "unnamed"})
		named, unnamed := fireClaude(t, claudeBin, home, fireDir)
		if !named || !unnamed {
			t.Fatalf("baseline: with both plugins enabled and both in installed_plugins.json, "+
				"both SessionStart hooks must fire (named=%v unnamed=%v). They did not, so this "+
				"host's claude does not fire plugin hooks the way #68 assumes, and the assertion "+
				"below would pass for the wrong reason. Nothing else in this test can be trusted "+
				"until this row is green.", named, unnamed)
		}
	}

	// Row 2, THE ASSERTION: both plugins enabled in settings.json, but the manifest
	// is snug's real FilterInstalledPlugins output naming only "named". The unnamed
	// plugin is enabled and physically present on disk, and it STILL must not fire —
	// because the regenerated manifest does not name it. That is #68's gate, on the
	// real binary.
	{
		home, fireDir, hostBoth := buildPluginFixture(t)
		filtered, err := policy.FilterInstalledPlugins(hostBoth, []string{"named"})
		if err != nil {
			t.Fatalf("FilterInstalledPlugins(hostBoth, [named]): %v", err)
		}
		// Guard the fixture, not the binary: if the filter did not actually drop
		// unnamed, the run below proves nothing about the gate.
		if bytes.Contains(filtered, []byte("unnamed@fix")) {
			t.Fatalf("the filtered manifest still names unnamed@fix, so this row cannot test "+
				"the gate:\n%s", filtered)
		}
		writeManifestAndEnabled(t, home, filtered, []string{"named", "unnamed"})
		named, unnamed := fireClaude(t, claudeBin, home, fireDir)
		if !named {
			t.Errorf("the named plugin is in the regenerated manifest and enabled, yet its " +
				"SessionStart hook did not fire — the positive control failed, so a passing " +
				"'unnamed did not fire' would be meaningless")
		}
		if unnamed {
			t.Errorf("the unnamed plugin's SessionStart hook FIRED though snug's regenerated " +
				"installed_plugins.json does not name it (it is only enabled in settings.json and " +
				"present on disk). The manifest is not gating hook loading on this claude version — " +
				"issue #68's guarantee has regressed or the binary's plugin-loading changed. " +
				"Re-measure both gates (CLAUDE-SETTINGS.md §4.4) before trusting the fix.")
		}
	}

	// Row 4, the ENABLEMENT gate: the named plugin is in the manifest but NOTHING is
	// enabled in settings.json. On 2.1.238 nothing fires. This row is not #68 — it is
	// the SECOND gate snug leans on (its settings.json filter drops enabledPlugins),
	// and it is why the assertion above had to be host-level: inside a sandbox this
	// row is the ONLY reachable state, so no positive control can live there.
	{
		home, fireDir, hostBoth := buildPluginFixture(t)
		writeManifestAndEnabled(t, home, hostBoth, nil)
		named, unnamed := fireClaude(t, claudeBin, home, fireDir)
		if named || unnamed {
			t.Errorf("with enabledPlugins empty, no plugin hook should fire on this claude "+
				"version (named=%v unnamed=%v). If one did, enablement is no longer required and "+
				"the note in §4.4 that snug's enabledPlugins drop is an independent second gate is "+
				"now false — the version has drifted again.", named, unnamed)
		}
	}
}

// buildPluginFixture writes a throwaway $HOME whose ~/.claude carries a marketplace
// "fix" with two plugins, "named" and "unnamed", each a SessionStart hook (matcher
// startup|resume) that touches FIREDIR/FIRED-<plugin>. It returns the home, the
// marker directory, and the host-style installed_plugins.json bytes that name BOTH
// plugins — the caller decides per row whether to write those bytes verbatim or feed
// them through policy.FilterInstalledPlugins first.
//
// A FRESH fixture per claude run is mandatory, not tidiness: claude mutates plugin
// state under ~/.claude between runs, and a reused fixture then fails to fire on a
// second pass — a false negative that would make this test pass for the wrong
// reason. Every row above calls this anew.
func buildPluginFixture(t *testing.T) (home, fireDir string, hostManifest []byte) {
	t.Helper()
	home = t.TempDir()
	fireDir = t.TempDir()

	claudeDir := filepath.Join(home, ".claude")
	pluginsDir := filepath.Join(claudeDir, "plugins")
	mk := filepath.Join(pluginsDir, "marketplaces", "fix")
	cache := filepath.Join(pluginsDir, "cache")

	mustMkdir(t, filepath.Join(mk, ".claude-plugin"))
	// hasCompletedOnboarding so claude does not stop at the trust/onboarding prompt
	// before a session (and therefore before SessionStart) exists.
	mustWrite(t, filepath.Join(home, ".claude.json"),
		[]byte(`{"hasCompletedOnboarding":true,"bypassPermissionsModeAccepted":true}`))
	mustWrite(t, filepath.Join(pluginsDir, "known_marketplaces.json"), []byte(fmt.Sprintf(
		`{"fix":{"source":{"source":"github","repo":"x/fix"},"installLocation":%q,"lastUpdated":"2026-08-21T00:00:00.000Z"}}`,
		mk)))
	mustWrite(t, filepath.Join(mk, ".claude-plugin", "marketplace.json"), []byte(
		`{"name":"fix","owner":{"name":"t"},"plugins":[`+
			`{"name":"named","source":"./plugins/named"},`+
			`{"name":"unnamed","source":"./plugins/unnamed"}]}`))

	entries := map[string]json.RawMessage{}
	for _, p := range []string{"named", "unnamed"} {
		installPath := filepath.Join(cache, p, "0.0.1")
		hook := fmt.Sprintf(
			`{"hooks":{"SessionStart":[{"matcher":"startup|resume","hooks":[`+
				`{"type":"command","command":"touch %s"}]}]}}`,
			filepath.Join(fireDir, "FIRED-"+p))
		// The hook lives at both the marketplace copy and the cache installPath;
		// claude loads from the installPath recorded in installed_plugins.json.
		for _, base := range []string{filepath.Join(mk, "plugins", p), installPath} {
			mustMkdir(t, filepath.Join(base, "hooks"))
			mustMkdir(t, filepath.Join(base, ".claude-plugin"))
			mustWrite(t, filepath.Join(base, ".claude-plugin", "plugin.json"),
				[]byte(fmt.Sprintf(`{"name":%q,"version":"0.0.1"}`, p)))
			mustWrite(t, filepath.Join(base, "hooks", "hooks.json"), []byte(hook))
		}
		entries[p+"@fix"] = json.RawMessage(fmt.Sprintf(
			`[{"scope":"user","installPath":%q,"version":"0.0.1"}]`, installPath))
	}

	manifest, err := json.Marshal(map[string]any{"version": 2, "plugins": entries})
	if err != nil {
		t.Fatalf("marshalling host manifest: %v", err)
	}
	return home, fireDir, manifest
}

// writeManifestAndEnabled drops installed_plugins.json (verbatim bytes — the caller
// chose them) and a settings.json enabling the named plugins into an already-built
// fixture.
func writeManifestAndEnabled(t *testing.T, home string, installedJSON []byte, enabled []string) {
	t.Helper()
	mustWrite(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), installedJSON)

	en := map[string]bool{}
	for _, e := range enabled {
		en[e+"@fix"] = true
	}
	settings, err := json.Marshal(map[string]any{"enabledPlugins": en})
	if err != nil {
		t.Fatalf("marshalling settings.json: %v", err)
	}
	mustWrite(t, filepath.Join(home, ".claude", "settings.json"), settings)
}

// fireClaude runs the real claude binary once against home and reports which plugin
// markers appeared. SessionStart hooks fire at session INIT, BEFORE the first API
// turn — so a DEAD endpoint (nothing listening on 127.0.0.1:9) with a junk key is
// enough to observe firing, and that is the whole reason this test is hermetic and
// free. Do NOT add real credentials or a live base URL to "make it pass": a
// completed API turn is not what this measures, and adding them turns a free offline
// test into a paid networked one that also cannot run in CI.
//
// claude then hangs retrying the dead endpoint, so it is killed once the markers
// have had time to land. The wait is bounded: a hook that is going to fire does so
// within a couple of seconds of init, well inside the poll window.
func fireClaude(t *testing.T, claudeBin, home, fireDir string) (named, unnamed bool) {
	t.Helper()

	cmd := exec.Command(claudeBin, "-p", "x")
	cmd.Env = []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"ANTHROPIC_BASE_URL=http://127.0.0.1:9",
		"ANTHROPIC_API_KEY=sk-none",
	}
	// Immediate-EOF stdin: without it claude waits 3s for piped input before
	// starting, padding every row for nothing.
	cmd.Stdin = bytes.NewReader(nil)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting claude: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	fired := func(p string) bool {
		_, err := os.Stat(filepath.Join(fireDir, "FIRED-"+p))
		return err == nil
	}

	// Poll for either marker, then a short grace for the other, so a run where one
	// fires and one does not is decided on evidence rather than on which arrived
	// first. A run where NEITHER fires (the enablement row) waits the full window —
	// that is inherent to proving an absence and is why budget() is generous here.
	const window = 12 * time.Second
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if fired("named") || fired("unnamed") {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond)
	return fired("named"), fired("unnamed")
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
