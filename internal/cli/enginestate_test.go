package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestDryRunRefusesAGrantOverTheEngineStore: redteam setup r7 follow-up,
// engine state. The CLI is what fills Context.EngineDataRoots, and an empty
// set disables the refusal, so this runs --dry-run end to end with a scratch
// $XDG_DATA_HOME and asserts the refusal names that root. The control is the
// same run granting a sibling of the store, which resolves.
func TestDryRunRefusesAGrantOverTheEngineStore(t *testing.T) {
	home, proj := accountHomeFixture(t)
	t.Setenv("HOME", home)
	stubHostAccount(t, home)
	t.Setenv("SNUG_PODMAN_ROOT", "")
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	root := filepath.Join(data, "snug")
	sibling := filepath.Join(data, "other")
	for _, d := range []string{filepath.Join(root, "engines"), sibling} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "snug", "profiles.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	toml := "[profile.peek]\ndescription = \"t\"\nro = [\"" + filepath.Join(root, "engines") + "\"]\n" +
		"[profile.beside]\ndescription = \"t\"\nro = [\"" + sibling + "\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "t.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := captureRun(t, config{dryRun: true, target: proj, profiles: []policy.ProfileName{"beside"}})
	if code != 0 {
		t.Fatalf("control: ro over a sibling of the engine store was refused (exit %d):\n%s", code, stderr)
	}

	_, stderr, code = captureRun(t, config{dryRun: true, target: proj, profiles: []policy.ProfileName{"peek"}})
	if code != exitPolicy {
		t.Fatalf("exit %d, want %d:\n%s", code, exitPolicy, stderr)
	}
	if !strings.Contains(stderr, "engine store "+root) {
		t.Errorf("the refusal does not name the engine store %s:\n%s", root, stderr)
	}
}
