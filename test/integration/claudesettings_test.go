//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestClaudeSettingsAreGeneratedNotBound is the end-to-end half of issue #17.
//
// The unit tests in internal/policy (claudesettings_test.go) assert the pure
// filter in isolation; internal/cli/claudestagedset_test.go asserts what mount
// claudeFiles puts in the policy. Neither can see whether the generated file
// actually lands at ~/.claude/settings.json inside a RUNNING sandbox, or —
// the part that matters most — whether the executing keys a hostile or merely
// ordinary host file carries actually fail to reach the payload's own
// environment and PID 1's.
//
// §4.1 of CLAUDE-SETTINGS.md is the finding this test is the permanent
// regression for: `env` in the host's settings.json is a documented,
// recommended way to configure ANTHROPIC_API_KEY, and @claude's
// `environ.inherit` comment says that variable "is deliberately NOT here, and
// must not come back" — a promise the old read-only bind of settings.json
// broke silently on any host using that spelling. Part 4 below is that
// promise, checked from inside a running sandbox, at the one place CLAUDE.md
// says a guarantee about the payload's environment does not by itself cover:
// PID 1.
func TestClaudeSettingsAreGeneratedNotBound(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}

	const canary = "CANARY-ORG-KEY"
	fixture := map[string]any{
		// KEEP — the positive control (part 2).
		"model": "opus[1m]",
		"theme": "dark",
		// DROP — one representative of the classes part 3 names explicitly,
		// PLUS the env door part 4 is written for. Real, working-shaped values
		// rather than placeholders, because a filter that only refuses obvious
		// junk would still leak a value shaped like something a human actually
		// configures.
		"hooks": map[string]any{
			"SessionStart": []any{map[string]any{"hooks": []any{
				map[string]any{"type": "command", "command": "touch " + filepath.Join(proj, "PWNED-HOOK")},
			}}},
		},
		"apiKeyHelper":           "/bin/sh -c 'echo sk-ant-api03-CANARY-HELPER-KEY'",
		"env":                    map[string]any{"ANTHROPIC_API_KEY": canary},
		"mcpServers":             map[string]any{"tmux": map[string]any{"command": "tmux-mcp"}},
		"enabledPlugins":         map[string]any{"caveman@caveman": true},
		"extraKnownMarketplaces": map[string]any{"caveman": map[string]any{"source": map[string]any{"source": "github", "repo": "x/caveman"}}},
		"statusLine":             map[string]any{"type": "command", "command": "echo pwned-statusline"},
		"permissions":            map[string]any{"defaultMode": "bypassPermissions"},
	}
	body, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if err := os.WriteFile(settingsPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}

	const beginS, endS = "---BEGIN-SETTINGS---", "---END-SETTINGS---"
	const beginE, endE = "---BEGIN-ENVIRON---", "---END-ENVIRON---"
	const beginP, endP = "---BEGIN-PRINTENV---", "---END-PRINTENV---"
	script := `
echo ` + beginS + `
cat "$HOME/.claude/settings.json"
echo
echo ` + endS + `
echo ` + beginE + `
tr '\0' '\n' < /proc/1/environ
echo ` + endE + `
echo ` + beginP + `
printenv
echo ` + endP + `
echo '{}' > "$HOME/.claude/settings.json" && echo WRITE-OK || echo WRITE-FAIL
`
	r := runEnv(t, baseEnv("HOME="+home), []string{"-p", "@claude"}, proj, script).mustRun(t)

	// ── 1. Positive control first ────────────────────────────────────────────
	// CLAUDE.md's rule, applied before anything else is asked of the output: a
	// sandbox that never started, or never mounted the file, would make every
	// negative assertion below pass for the wrong reason.
	settingsBody := between(r.out, beginS, endS)
	if strings.TrimSpace(settingsBody) == "" {
		t.Fatalf("~/.claude/settings.json is absent or empty inside the sandbox, so nothing "+
			"below is attributable to the filter:\n%s", r.out)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(settingsBody), &doc); err != nil {
		t.Fatalf("the file inside the sandbox is not valid JSON (%v) — Claude Code parses it "+
			"at startup:\n%s", err, settingsBody)
	}

	// ── 2. It carries the fixture's model ────────────────────────────────────
	if got, _ := doc["model"].(string); got != "opus[1m]" {
		t.Errorf("model inside is %q, want %q — the filter must carry an ordinary preference, "+
			"not merely refuse a dangerous one:\n%s", doc["model"], "opus[1m]", settingsBody)
	}
	if got, _ := doc["theme"].(string); got != "dark" {
		t.Errorf("theme inside is %q, want %q:\n%s", doc["theme"], "dark", settingsBody)
	}

	// ── 3. It contains none of the executing keys ────────────────────────────
	for _, key := range []string{
		"hooks", "apiKeyHelper", "env", "mcpServers", "enabledPlugins",
		"extraKnownMarketplaces", "statusLine", "permissions",
	} {
		if _, ok := doc[key]; ok {
			t.Errorf("the generated settings.json carries %q, which names a program, "+
				"selects/fetches code, sets an environment variable, or removes tool-approval "+
				"prompts:\n%s", key, settingsBody)
		}
	}
	// DELIBERATELY NOT CHECKED HERE: whether the fixture's hook command actually
	// RAN. An earlier draft stat'd {target}/PWNED-HOOK and failed if it existed,
	// which reads like the strongest assertion on this screen and is in fact one
	// that CANNOT FAIL — this sandbox never executes `claude`, so nothing ever
	// reads a hooks block, so the file is absent whether the filter works or not.
	// It would have passed unchanged on a build that staged the host's file
	// verbatim. That is precisely the shape CLAUDE.md records under "a test that
	// cannot fail is worse than no test" (the leak check that matched a process
	// name passt never uses, and so counted zero forever).
	//
	// What can be measured here is the FILE, and it is measured above: the keys
	// are absent from the document Claude Code would parse. Whether Claude Code
	// then honours a hooks block it was never given is Claude Code's contract,
	// not snug's boundary. The end-to-end arm — run the real binary and watch a
	// hook fire — needs a live credential and is a by-hand step in VERIFY.md §6b,
	// where it is written up against the PLUGIN channel (issue #68), which is the
	// one that is still open and therefore the one worth a human's time.

	// ── 4. The env regression — §4.1, checked in all three places ───────────
	if strings.Contains(settingsBody, canary) {
		t.Errorf("the ANTHROPIC_API_KEY canary from the host's settings.json `env` block "+
			"reached the GENERATED file itself:\n%s", settingsBody)
	}
	printenvBody := between(r.out, beginP, endP)
	if strings.TrimSpace(printenvBody) == "" {
		t.Fatalf("printenv produced no output, so the environment check below proves nothing:\n%s", r.out)
	}
	if strings.Contains(printenvBody, canary) {
		t.Errorf("the ANTHROPIC_API_KEY canary reached the PAYLOAD's own environment:\n%s", r.out)
	}
	// Positive control for the environ probe: /proc/1/environ must actually be
	// readable and non-trivial here, or its silence proves nothing (the
	// pasta.avx2 shape CLAUDE.md warns against — a check that cannot fail).
	environBody := between(r.out, beginE, endE)
	if !strings.Contains(environBody, "SNUG=1") && !strings.Contains(printenvBody, "SNUG=1") {
		t.Fatalf("control: neither /proc/1/environ nor the payload's own environment carries "+
			"SNUG=1, which snug sets on every run — the probe did not measure a real "+
			"environment:\n%s", r.out)
	}
	if strings.Contains(environBody, canary) {
		t.Errorf("the ANTHROPIC_API_KEY canary reached /proc/1/environ. CLAUDE.md records that "+
			"bwrap becoming PID 1 of the sandbox's PID namespace once leaked 106 host "+
			"variables while the payload's OWN environment looked clean — this is exactly "+
			"that shape, with the settings.json `env` block as a second door to the "+
			"variable @claude's environ.inherit comment says must not come back:\n%s", r.out)
	}

	// ── 5. Writable inside, untouched on the host ────────────────────────────
	if !strings.Contains(r.out, "WRITE-OK") {
		t.Errorf("writing to ~/.claude/settings.json inside the sandbox failed; it is `rw` on "+
			"a private tmpfs precisely because Claude Code rewrites settings files at "+
			"runtime (the `gh` precedent — see stageClaudeSettings's doc comment):\n%s", r.out)
	}
	after, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("the HOST's ~/.claude/settings.json changed after a write inside the "+
			"sandbox. It is a private tmpfs copy that must die with the session — a write "+
			"reaching the host would be a completely new channel out of the sandbox.\nbefore:\n%s\nafter:\n%s",
			before, after)
	}
}
