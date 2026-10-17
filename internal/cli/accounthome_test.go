package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// accountHomeFixture returns a scratch home and a target two levels under it,
// and points XDG_CONFIG_HOME at an empty directory so the developer's
// profiles are not read.
func accountHomeFixture(t *testing.T) (home, proj string) {
	t.Helper()
	home = t.TempDir()
	proj = filepath.Join(home, "src", "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	return home, proj
}

// TestAccountLookupFailureRefusesBeforeProfilesLoad fails if the account is
// looked up after the profile directories are read. A $HOME that is not the
// account's must stop the run before any file under it is parsed, and a failed
// lookup must be the refusal the human reads, not whatever a profile file
// happened to say first. The canary is a profile file that does not parse:
// with a working account it is reported, which shows the loader does read it;
// with a failing account the refusal is the account's and the file is never
// mentioned.
func TestAccountLookupFailureRefusesBeforeProfilesLoad(t *testing.T) {
	home, proj := accountHomeFixture(t)
	t.Setenv("HOME", home)
	cfg := os.Getenv("XDG_CONFIG_HOME")
	dir := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "canary-broken.toml"), []byte("[profile\nnot toml"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func() (string, string, int) {
		return captureRun(t, config{dryRun: true, target: proj})
	}

	// Control: with a working account the broken file is the thing reported.
	stubHostAccount(t, home)
	_, stderr, code := run()
	if code == 0 || !strings.Contains(stderr, "canary-broken.toml") {
		t.Fatalf("control: the loader did not report the broken profile file (exit %d), so it "+
			"cannot show the account is looked up first:\n%s", code, stderr)
	}

	orig := lookupHostAccount
	t.Cleanup(func() { lookupHostAccount = orig })
	lookupHostAccount = func() (name, pwHome, gname, from string, err error) {
		return "", "", "", "", errors.New("ACCOUNT-LOOKUP-FAILED: getent is not installed")
	}
	stdout, stderr, code := run()
	if code != exitPolicy {
		t.Errorf("exit %d, want %d:\n%s", code, exitPolicy, stderr)
	}
	if !strings.Contains(stderr, "ACCOUNT-LOOKUP-FAILED: getent is not installed") {
		t.Errorf("the refusal does not carry the lookup's own text, verbatim:\n%s", stderr)
	}
	if strings.Contains(stderr, "canary-broken.toml") {
		t.Errorf("the profile directory was read before the account was known:\n%s", stderr)
	}
	if strings.Contains(stdout, "FILESYSTEM") {
		t.Errorf("a policy was described without an account:\n%s", stdout)
	}
}

// TestRunIgnoresTheHostHOME fails if the HOME snug is started with changes the
// run: a HOME naming another directory, a relative one and an unset one must
// each produce the dry-run the account's own HOME produces, byte for byte, with
// no refusal. Afterwards HOME is the account's, so later os.UserHomeDir()
// readers agree with the policy. The comparison can fail: the control is that
// a different ACCOUNT home changes the output.
func TestRunIgnoresTheHostHOME(t *testing.T) {
	home, proj := accountHomeFixture(t)
	stubHostAccount(t, home)
	run := func() (string, string, int) {
		return captureRun(t, config{dryRun: true, target: proj})
	}

	t.Setenv("HOME", home)
	want, stderr, code := run()
	if code != 0 || !strings.Contains(want, "FILESYSTEM") {
		t.Fatalf("control: HOME equal to the account's home was refused (exit %d):\n%s", code, stderr)
	}

	for name, host := range map[string]string{
		"another directory": t.TempDir(),
		"relative":          "u",
		"missing":           filepath.Join(home, "nowhere"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("HOME", host)
			got, stderr, code := run()
			if code != 0 {
				t.Fatalf("HOME=%q refused (exit %d):\n%s", host, code, stderr)
			}
			if got != want {
				t.Errorf("HOME=%q changed the dry-run", host)
			}
			if h := os.Getenv("HOME"); h != home {
				t.Errorf("HOME after the run is %q, want the account's %q", h, home)
			}
		})
	}

	t.Run("unset", func(t *testing.T) {
		t.Setenv("HOME", "")
		if err := os.Unsetenv("HOME"); err != nil {
			t.Fatal(err)
		}
		got, stderr, code := run()
		if code != 0 || got != want {
			t.Fatalf("HOME unset: exit %d, same output %v:\n%s", code, got == want, stderr)
		}
		if h := os.Getenv("HOME"); h != home {
			t.Errorf("HOME after the run is %q, want the account's %q", h, home)
		}
	})

	t.Run("control: another account home changes the output", func(t *testing.T) {
		other, otherProj := accountHomeFixture(t)
		stubHostAccount(t, other)
		t.Setenv("HOME", other)
		got, _, code := captureRun(t, config{dryRun: true, target: otherProj})
		if code != 0 || got == want {
			t.Errorf("exit %d, output identical to the first account's: %v", code, got == want)
		}
	})
}

// TestClaudeMountsLandUnderTheSandboxHOME fails if the generated Claude files
// are staged under any directory other than the sandbox's $HOME. Staging uses
// the policy's own home (Policy.Home), so the mounts it adds and the keys the
// dry-run block looks them up by are the same string.
//
// It does NOT reach the case the fix was for, a home whose raw spelling differs
// from its canonical one through a symlink: a link this test can create is
// owned by the invoking user, and Resolve refuses a home reached through one.
// What it holds is the part reachable unprivileged: a $HOME spelled with a
// "..", which the account check accepts as the same directory, ends up with
// every Claude mount at the canonical home, the creds block saying the
// credential is projected, and main.go handing claudeFiles the policy's home.
func TestClaudeMountsLandUnderTheSandboxHOME(t *testing.T) {
	home := writeHostCredential(t, `{"claudeAiOauth":{"accessToken":"sk-ant-oat-FIXTURE"}}`)
	if err := os.MkdirAll(filepath.Join(home, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(home, "src", "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", home+"/sub/..")
	stubHostAccount(t, home)

	stdout, stderr, code := captureRun(t, config{
		dryRun: true, target: proj, profiles: []policy.ProfileName{"@claude"},
	})
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, stderr)
	}
	for _, rel := range []string{".claude.json", ".claude/.credentials.json", ".claude/settings.json"} {
		want := "data   " + filepath.Join(home, rel)
		if !strings.Contains(stdout, want) {
			t.Errorf("no mount line %q: the generated file is not under the sandbox's home:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "staged NOTHING") {
		t.Errorf("the creds block denies a credential the mount table stages:\n%s", stdout)
	}
	if !strings.Contains(stdout, "is PROJECTED from the host's") {
		t.Errorf("the creds block does not say the credential is projected:\n%s", stdout)
	}

	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "claudeFiles(pol, pol.Home, notes)") {
		t.Errorf("main.go no longer hands claudeFiles the policy's home")
	}
}
