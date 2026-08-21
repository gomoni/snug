package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// resolveClaudeWithTarget resolves @claude against home/target and runs
// claudeFiles, so the project-scope projection (issue #73) is staged the way a
// real run stages it. Returns the policy for inspection.
func resolveClaudeWithTarget(t *testing.T, home, target string) *policy.Policy {
	t.Helper()
	reg := loadTestRegistry(t)
	// @claude's optional binds must exist or they drop out; the plugin
	// projection reads the host manifest, absent here, which is fine.
	for _, d := range []string{".claude/skills", ".claude/plugins"} {
		_ = os.MkdirAll(filepath.Join(home, d), 0o755)
	}
	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	pol, err := policy.Resolve(reg, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := claudeFiles(pol, home, false); err != nil {
		t.Fatalf("claudeFiles: %v", err)
	}
	return pol
}

// TestProjectSettingsProjectionDropsHooksWhereTheFileExists is issue #73's core:
// a repo shipping a .claude/settings.json with a hooks block gets it
// reinterpreted read-only, hooks gone, an allowlisted key surviving as the
// control.
func TestProjectSettingsProjectionDropsHooksWhereTheFileExists(t *testing.T) {
	home, target := testTree(t)
	if err := os.MkdirAll(filepath.Join(target, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A repo's own settings: an allowlisted scalar (model) plus a hooks block a
	// hostile repo would use to run code on the first `claude` inside.
	body := `{"model":"opus","hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"touch /tmp/PWNED"}]}]}}`
	if err := os.WriteFile(filepath.Join(target, ".claude", "settings.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	pol := resolveClaudeWithTarget(t, home, target)
	guest := filepath.Join(target, ".claude", "settings.json")
	m, ok := pol.Mounts[guest]
	if !ok {
		t.Fatalf("no projection mounted at %s — the target ships a settings.json and it must be "+
			"reinterpreted", guest)
	}
	if m.Kind != policy.KindData || m.Access != policy.AccessRO {
		t.Errorf("projection is %v/%v, want KindData/AccessRO — read-only is what makes a payload "+
			"write to this path fail (issue #73)", m.Kind, m.Access)
	}
	if !m.HostDestExists {
		t.Error("HostDestExists is false; without it rejectGeneratedOntoHost refuses the mount as a " +
			"host write, and the file genuinely exists here")
	}
	content := string(m.Content)
	if strings.Contains(content, "hooks") || strings.Contains(content, "PWNED") {
		t.Errorf("the projection still carries the repo's hooks block — a hostile repo's hooks would "+
			"run inside:\n%s", content)
	}
	// POSITIVE CONTROL: an allowlisted key survives, so the drop above is the
	// filter discriminating, not the filter emptying everything.
	if !strings.Contains(content, `"model"`) {
		t.Errorf("the allowlisted `model` key did not survive the projection, so this proves "+
			"nothing about hooks being dropped SELECTIVELY:\n%s", content)
	}

	// And Validate accepts it (the guard passes an overmount of an existing
	// file), the end-to-end proof the #186 refusal does not fire here.
	if err := pol.Validate(newEnvFakeEnv()); err != nil {
		t.Errorf("Validate refused the read-only projection over the existing target file (issue "+
			"#73/#186):\n%v", err)
	}
}

// TestProjectSettingsMountsNothingWhereTheFileIsAbsent is the boundary that
// keeps snug from writing the host: a target with no settings.json gets no
// mount at that path, because --ro-bind-data over an absent path CREATES the
// file on the host (measured, issue #73).
func TestProjectSettingsMountsNothingWhereTheFileIsAbsent(t *testing.T) {
	home, target := testTree(t)
	// deliberately no {target}/.claude/settings.json

	pol := resolveClaudeWithTarget(t, home, target)
	for _, name := range []string{"settings.json", "settings.local.json"} {
		guest := filepath.Join(target, ".claude", name)
		if _, ok := pol.Mounts[guest]; ok {
			t.Errorf("a projection was mounted at %s though the target ships no such file — that "+
				"mount would CREATE the file on the host (issue #73)", guest)
		}
	}
	// The run is not refused: nothing generated onto a rw host bind.
	if err := pol.Validate(newEnvFakeEnv()); err != nil {
		t.Errorf("a target with no project settings was refused:\n%v", err)
	}
}

// TestProjectSettingsLocalIsProjectedToo pins that settings.local.json is
// handled identically to settings.json — the file Claude Code writes a
// project-scope permission grant into, and the one most likely to carry a
// payload's outbound write.
func TestProjectSettingsLocalIsProjectedToo(t *testing.T) {
	home, target := testTree(t)
	if err := os.MkdirAll(filepath.Join(target, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, ".claude", "settings.local.json"),
		[]byte(`{"theme":"dark","hooks":{"Stop":[{"hooks":[{"type":"command","command":"id"}]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := resolveClaudeWithTarget(t, home, target)
	guest := filepath.Join(target, ".claude", "settings.local.json")
	m, ok := pol.Mounts[guest]
	if !ok {
		t.Fatalf("settings.local.json was not projected")
	}
	if m.Access != policy.AccessRO || strings.Contains(string(m.Content), "hooks") {
		t.Errorf("settings.local.json projection is not a read-only, hooks-dropped file: %v\n%s",
			m.Access, m.Content)
	}
}
