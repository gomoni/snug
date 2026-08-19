// Package guard tests bin/blast-radius from the HOST, where the assets really
// are and the answer must always be "refuse".
//
// No build tag, on purpose. The in-sandbox half needs a real sandbox and lives
// in test/integration; this half needs nothing, so it runs in `make gate` on
// every machine and in CI. The expensive assertion is "it says yes when the
// assets are out of reach"; the one that protects a home directory is "it says
// no when they are not", and that one must never be skippable.
package guard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func script(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "bin", "blast-radius"))
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("bin/blast-radius is missing (%v). redteam.md tells the agent to guard every "+
			"destructive payload with it; if it is gone that instruction is a no-op", err)
	}
	if fi.Mode()&0o111 == 0 {
		t.Fatalf("bin/blast-radius is not executable (%v), so `blast-radius && …` fails open "+
			"at the shell rather than refusing", fi.Mode())
	}
	return p
}

// The guard has to be IN the repository, not merely on the machine that wrote
// it. bin/ is gitignored — it is where build output lands — and that rule
// swallowed this script's predecessor on the commit that introduced it: `git
// add -A` skipped it, `git status` stayed clean, every test here passed locally,
// and CI was the first thing to notice the file was not in the repository at
// all. Existence and trackedness are different questions and only the second
// survives a clone.
func TestTheGuardIsTracked(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("SKIP: no git to ask")
	}
	cmd := exec.Command(git, "ls-files", "--error-unmatch", "bin/blast-radius")
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bin/blast-radius is not tracked by git (%v: %s). A clone would not have it. "+
			"bin/ is gitignored; .gitignore carries an explicit negation for this path", err, out)
	}
}

func run(t *testing.T, env ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(script(t))
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running %s: %v", script(t), err)
	}
	return string(out), code
}

// THE ASSERTION THAT PROTECTS A HOME DIRECTORY.
func TestTheGuardRefusesWhereTheAssetsAre(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("SKIP: no HOME to check against")
	}
	out, code := run(t, "HOME="+home)
	if code == 0 {
		t.Fatalf("bin/blast-radius exited 0 against the real $HOME. Every `blast-radius && "+
			"<destructive>` an agent writes would then run its second half where the keys "+
			"actually are:\n%s", out)
	}
	if !strings.Contains(out, "REACHABLE FROM HERE") {
		t.Errorf("the refusal does not name what it found, so a human reading a failed guarded "+
			"command cannot tell the guard from the command:\n%s", out)
	}
}

// The ordinary way to work in this repository: a host shell with HOME pointed at
// a scratch directory. This MUST pass, and it is the half that keeps the guard
// usable — a check that refuses the sanctioned workflow is a check somebody
// deletes.
func TestTheGuardPassesWithAScratchHome(t *testing.T) {
	out, code := run(t, "HOME="+t.TempDir())
	if code != 0 {
		t.Fatalf("bin/blast-radius refused a scratch HOME with nothing in it. That is the "+
			"workflow redteam.md mandates, and if it refuses there the instruction and the "+
			"tool contradict each other:\n%s", out)
	}
}

// Each asset in turn, planted alone in an otherwise empty scratch home. This is
// what stops the catalogue rotting into a list nobody reads: remove an entry and
// its row here fails.
func TestEachAssetIsDetectedOnItsOwn(t *testing.T) {
	// `want` is what the refusal must NAME, and it is not always the planted
	// path: the catalogue guards ~/.gnupg as a directory, so planting a keyring
	// inside it is caught at the directory. Asserting the planted path there
	// would be asserting an implementation detail the guard is right not to have.
	for _, tc := range []struct {
		name, rel, body, want string
	}{
		{"an ssh private key", ".ssh/id_ed25519", "PRIVATE KEY MATERIAL\n", ".ssh/id_ed25519"},
		{"gnupg", ".gnupg/pubring.kbx", "keys\n", ".gnupg"},
		{"aws credentials", ".aws/credentials", "[default]\naws_access_key_id=AKIA\n", ".aws/credentials"},
		{"a gh token store", ".config/gh/hosts.yml", "github.com:\n  oauth_token: gho_x\n", ".config/gh/hosts.yml"},
		{"netrc", ".netrc", "machine example.com password hunter2\n", ".netrc"},
		{"git credentials", ".git-credentials", "https://u:p@github.com\n", ".git-credentials"},
		// Not a path test but a CONTENT test: snug stages a copy of this file
		// INSIDE at the same path, minus the refreshToken (issue #58). So the
		// file existing is normal and the refresh token is what identifies the
		// host's own.
		{"the host's Claude credential", ".claude/.credentials.json",
			`{"claudeAiOauth":{"accessToken":"a","refreshToken":"r"}}`, ".claude/.credentials.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, tc.rel)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			out, code := run(t, "HOME="+home)
			if code == 0 {
				t.Fatalf("%s was reachable and the guard said proceed:\n%s", tc.rel, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("the refusal does not name %s, so it does not say what is at risk:\n%s",
					tc.want, out)
			}
		})
	}
}

// The staged credential must NOT trip it, or the guard refuses inside every
// sandbox that stages one — which would turn every guarded payload into a silent
// no-op, the failure mode that reads as safety and is not.
func TestTheStagedCredentialIsNotMistakenForTheHostsOwn(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", ".credentials.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// The staged shape, measured: access token, no refreshToken, read-only.
	if err := os.WriteFile(path, []byte(`{"claudeAiOauth":{"accessToken":"a","expiresAt":1}}`), 0o400); err != nil {
		t.Fatal(err)
	}
	if out, code := run(t, "HOME="+home); code != 0 {
		t.Fatalf("the guard refused a home carrying only the STAGED credential, which is what "+
			"every @claude sandbox looks like from inside:\n%s", out)
	}
}

// The canary marks the real home as the real home — the one piece of evidence
// snug does not produce and a payload cannot manufacture.
func TestTheCanaryMarksTheRealHome(t *testing.T) {
	home := t.TempDir()
	cmd := exec.Command(script(t), "--install-canary")
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("--install-canary failed: %v\n%s", err, out)
	}
	out, code := run(t, "HOME="+home)
	if code == 0 {
		t.Fatalf("the canary was installed and the guard still said proceed:\n%s", out)
	}
	if !strings.Contains(out, "the real host home") {
		t.Errorf("refused, but not on the canary — this test exists to prove it is read:\n%s", out)
	}
}
