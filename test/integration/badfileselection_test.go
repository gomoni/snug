//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAFileWhoseNamesAreUnknownRefusesEveryRun is red team F1 on #624: a
// profiles.d file snug cannot read the names of (not TOML, unreadable) may
// define the very name another file defines. Before the fix `-p foo` ran with
// the good file's `rw /opt` while the broken file's `ro /opt` went unread,
// and the note claimed every selected profile had loaded from other files.
func TestAFileWhoseNamesAreUnknownRefusesEveryRun(t *testing.T) {
	budget(t)
	proj, _ := target(t)
	for _, tc := range []struct {
		name string
		body string
		mode os.FileMode
	}{
		{"not toml", "[profile.foo]\nro = [\"/opt\"\n", 0o644},
		{"unreadable", "[profile.foo]\nro = [\"/opt\"]\n", 0o000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.mode == 0 && os.Geteuid() == 0 {
				t.Skip("root reads a mode-000 file")
			}
			env := envProfileLayer(t, "a.toml", "[profile.foo]\nrw = [\"/opt\"]\n", os.Getenv("PATH"))
			var cfg string
			for _, e := range env {
				if v, ok := strings.CutPrefix(e, "XDG_CONFIG_HOME="); ok {
					cfg = v
				}
			}
			b := filepath.Join(cfg, "snug", "profiles.d", "b.toml")
			if err := os.WriteFile(b, []byte(tc.body), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(b, tc.mode); err != nil {
				t.Fatal(err)
			}

			out, code := cli(t, env, "--dry-run", "-p", "foo", proj)
			if code != exitPolicyCode {
				t.Fatalf("want exit %d beside a file whose names are unknown, got %d:\n%s",
					exitPolicyCode, code, out)
			}
			if !strings.Contains(out, "b.toml") || !strings.Contains(out, "cannot read which profiles") {
				t.Errorf("the refusal does not name the file or say why:\n%s", out)
			}

			// CONTROL: the same good file alone runs, so the refusal above is
			// b.toml's and not the fixture's.
			if err := os.Remove(b); err != nil {
				t.Fatal(err)
			}
			if out, code := cli(t, env, "--dry-run", "-p", "foo", proj); code != 0 {
				t.Errorf("control: -p foo with only a.toml exited %d:\n%s", code, out)
			}
		})
	}
}

// TestABadFileDoesNotRefuseARunThatDoesNotReachIt is #624's point: a
// profiles.d file with a key this snug does not know refuses the runs that
// select one of its profiles, and only those.
func TestABadFileDoesNotRefuseARunThatDoesNotReachIt(t *testing.T) {
	budget(t)
	proj, _ := target(t)
	env := envProfileLayer(t, "future.toml", "[profile.future]\nnet_hosts = [\"github.com\"]\n", os.Getenv("PATH"))

	out, code := cli(t, env, "--dry-run", proj)
	if code != 0 {
		t.Fatalf("a run selecting nothing from future.toml exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "future.toml") || !strings.Contains(out, "net_hosts") {
		t.Errorf("the run does not name the file that did not load, or its error:\n%s", out)
	}

	out, code = cli(t, env, "--dry-run", "-p", "future", proj)
	if code != exitPolicyCode || !strings.Contains(out, `"future" is defined in`) {
		t.Errorf("-p future: want exit %d naming the file, got %d:\n%s", exitPolicyCode, code, out)
	}
}
