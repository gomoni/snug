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

// paths asks the script itself which paths it checks, rather than repeating the
// catalogue here. A list written twice is a list where one copy is wrong and
// nothing says which.
func paths(t *testing.T, home string) []string {
	t.Helper()
	cmd := exec.Command(script(t), "--paths")
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("blast-radius --paths failed: %v", err)
	}
	var list []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			list = append(list, line)
		}
	}
	if len(list) == 0 {
		t.Fatal("blast-radius --paths printed nothing, so the guard checks an empty catalogue " +
			"and passes everywhere")
	}
	return list
}

// THE ASSERTION THAT PROTECTS A HOME DIRECTORY — stated as a biconditional,
// because the obvious form of it was wrong.
//
// The first version asserted that the real $HOME must always be refused. That
// held on the developer machine this was written on and failed in CI, where the
// runner's home has no keyring, no ssh key and no ~/.claude: "nothing here is
// worth losing" is the CORRECT verdict there, and the test was asserting one
// machine's furniture as a law.
//
// So: refuse if and only if something is actually present. That can still fail
// in both directions — a guard that always passes fails on a developer box, and
// a guard that always refuses fails on a bare runner — which is what a test
// about a verdict has to be able to do.
func TestTheVerdictOnTheRealHomeMatchesWhatIsThere(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("SKIP: no HOME to check against")
	}
	var present []string
	for _, p := range paths(t, home) {
		if _, err := os.Stat(p); err == nil {
			present = append(present, p)
		}
	}

	out, code := run(t, "HOME="+home)
	if len(present) == 0 {
		if code != 0 {
			t.Fatalf("nothing in the catalogue exists under %s, and the guard still refused. "+
				"A guard that refuses everywhere makes every `blast-radius && <command>` a "+
				"silent no-op:\n%s", home, out)
		}
		t.Logf("this host has none of the catalogued assets under %s, so the verdict is "+
			"correctly \"proceed\". The refusal direction is exercised by "+
			"TestEachAssetIsDetectedOnItsOwn and by the canary.", home)
		return
	}
	if code == 0 {
		t.Fatalf("%d catalogued asset(s) exist under %s — starting with %s — and the guard "+
			"said proceed. Every `blast-radius && <destructive>` an agent writes would run "+
			"its second half where the keys actually are:\n%s",
			len(present), home, present[0], out)
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
		// file existing is normal, and the refresh token is what identifies the
		// host's own.
		//
		// The fixture is written READ-ONLY below, deliberately: a writable copy
		// is refused by the writability check instead, and this row then passes
		// with the content test deleted — which is exactly what a mutation run
		// showed. The refusal must also NAME the key it matched on, or the row
		// is back to proving whichever check happened to fire first.
		{"the host's Claude credential", ".claude/.credentials.json",
			`{"claudeAiOauth":{"accessToken":"a","refreshToken":"r"}}`, "refreshToken"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, tc.rel)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			mode := os.FileMode(0o600)
			if strings.Contains(tc.rel, "credentials.json") {
				mode = 0o400
			}
			if err := os.WriteFile(path, []byte(tc.body), mode); err != nil {
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

// The transcript archive and the hook scripts are not credentials, and they were
// the expensive loss in the incident that produced this script: the recovery ran
// on transcripts, and one hook script survived only because nothing referenced it
// any more. They are guarded on WRITABILITY rather than on existence — a
// read-only view of them cannot be destroyed, and refusing there would refuse
// inside every sandbox that legitimately mounts them read-only.
//
// Written because a mutation run deleted this check and no test noticed.
func TestTheTranscriptArchiveIsGuardedOnWritability(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		want int
	}{
		{"writable", 0o700, 1},
		{"read-only", 0o500, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			archive := filepath.Join(home, ".claude", "projects")
			if err := os.MkdirAll(archive, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(archive, tc.mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(archive, 0o700) })

			out, code := run(t, "HOME="+home)
			if code != tc.want {
				t.Fatalf("a %s transcript archive gave exit %d, want %d:\n%s",
					tc.name, code, tc.want, out)
			}
			if tc.want != 0 && !strings.Contains(out, "projects") {
				t.Errorf("refused, but without naming the archive:\n%s", out)
			}
		})
	}
}

// A CATALOGUE THAT SHRINKS IS THE FAILURE NOTHING ELSE HERE CAN SEE.
//
// Every other test in this file reasons from what the catalogue says: the
// biconditional asks --paths what exists, and the per-asset rows plant a file
// and expect a refusal. Delete an entry and BOTH adjust — the guard stops
// checking it, --paths stops naming it, the biconditional stops expecting it,
// and the row that planted it is the only thing left, which a shrinking diff
// removes in the same edit.
//
// So the expected set is written here BY HAND. It is not a duplicate mechanism,
// it is an expectation: these are the things this repository has decided are
// worth refusing over, and removing one has to be a visible act rather than a
// quiet one. Found by mutation — emptying the catalogue changed no result.
func TestTheCatalogueNamesTheThingsThatMatter(t *testing.T) {
	home := "/nonexistent-home-for-catalogue-inspection"
	got := map[string]bool{}
	for _, p := range paths(t, home) {
		got[strings.TrimPrefix(p, home+"/")] = true
	}
	for _, want := range []struct{ path, why string }{
		{".ssh/id_rsa", "key material"},
		{".ssh/id_ecdsa", "key material"},
		{".ssh/id_ed25519", "key material"},
		{".gnupg", "key material"},
		{".aws/credentials", "cloud keys"},
		{".config/gh/hosts.yml", "a GitHub OAuth token"},
		{".netrc", "passwords in plaintext"},
		{".git-credentials", "git passwords in plaintext"},
		{".claude/.credentials.json", "the host's API token"},
		{".claude/projects", "the transcript archive — what the last recovery actually ran on"},
		{".claude/hooks", "hook scripts, one of which survived the incident only by being unreferenced"},
		{".claude/settings.json", "a command table: hooks, apiKeyHelper, mcpServers"},
		{".snug-host-canary", "the marker that identifies the real home"},
	} {
		if !got[want.path] {
			t.Errorf("the catalogue no longer names %s (%s). Removing an entry is a decision "+
				"about what this project is willing to lose, and it should be argued in a diff "+
				"rather than disappear from a list", want.path, want.why)
		}
	}
}

// Read and write are both refusals, and they are not the same sentence. "A
// payload that can read a key can copy it" and "this run can destroy it" send a
// human to different places, and only the second one explains an empty file
// afterwards. Mutation showed the two branches were interchangeable as far as
// every other test was concerned.
func TestTheRefusalDistinguishesReadableFromWritable(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		want string
	}{
		{"writable", 0o600, "WRITABLE"},
		{"read-only", 0o400, "readable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".ssh", "id_ed25519")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("KEY\n"), tc.mode); err != nil {
				t.Fatal(err)
			}
			out, code := run(t, "HOME="+home)
			if code == 0 {
				t.Fatalf("a %s private key was reachable and the guard said proceed:\n%s",
					tc.name, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("a %s key was refused without saying so (wanted %q):\n%s",
					tc.name, tc.want, out)
			}
		})
	}
}
