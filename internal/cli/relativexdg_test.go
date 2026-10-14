package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestRelativeXDGRootsAreStillProtected would catch a relative
// $XDG_CONFIG_HOME or $XDG_DATA_HOME turning the config-root and engine-store
// refusals off: the producers join the variable verbatim, so the root list
// holds a relative path, and a grant is always absolute. Run end to end with
// --dry-run from a scratch working directory, granting rw over the absolute
// spelling of where the relative variable lands. The profile that makes the
// grant is itself loaded through the same relative variable, which is how a
// hostile checkout would arrange it. It does not reach a later run started
// from a different working directory.
func TestRelativeXDGRootsAreStillProtected(t *testing.T) {
	for _, tc := range []struct {
		name, env, sub, sentence string
	}{
		{"config", "XDG_CONFIG_HOME", "profiles.d", "trusted configuration (profiles.d, config.toml)"},
		{"data", "XDG_DATA_HOME", "engines", "engine store "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Skip("GAP: profile.TrustedConfigRoots/engine.DataRoots keep a relative $XDG_* verbatim, so an absolute rw grant over where it lands resolves (--dry-run exit 0, want 77)")
			home, proj := accountHomeFixture(t)
			t.Setenv("HOME", home)
			stubHostAccount(t, home)
			t.Setenv("SNUG_PODMAN_ROOT", "")
			cwd := t.TempDir()
			t.Chdir(cwd)
			t.Setenv("XDG_DATA_HOME", t.TempDir())
			t.Setenv(tc.env, "rel")
			granted := filepath.Join(cwd, "rel", "snug", tc.sub)
			cfgDir := filepath.Join(cwd, "rel", "snug", "profiles.d")
			for _, d := range []string{granted, cfgDir} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			toml := "[profile.peek]\ndescription = \"t\"\nrw = [\"" + granted + "\"]\n"
			if err := os.WriteFile(filepath.Join(cfgDir, "t.toml"), []byte(toml), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.env == "XDG_DATA_HOME" {
				// The profile store is the config side here; put it where config is read.
				t.Setenv("XDG_CONFIG_HOME", t.TempDir())
				dir := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "snug", "profiles.d")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "t.toml"), []byte(toml), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			_, stderr, code := captureRun(t, config{dryRun: true, target: proj, profiles: []policy.ProfileName{"peek"}})
			if code != exitPolicy || !strings.Contains(stderr, tc.sentence) {
				t.Fatalf("rw %s under a relative %s: exit %d, want %d with %q:\n%s",
					granted, tc.env, code, exitPolicy, tc.sentence, stderr)
			}
		})
	}
}
