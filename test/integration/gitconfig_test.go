//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// `@git-ro` used to bind ~/.gitconfig read-only. It now reads the host's config
// as DATA and generates the file the sandbox sees, because ~/.gitconfig is a
// command table: credential.helper, alias = !cmd, core.pager, core.sshCommand,
// diff.*.textconv. A read-only bind does not stop those, it supplies them.
//
// These tests run the real binary against a fixture config and check the three
// things that can go wrong: the whitelist leaks, the conditional include is not
// honoured, or it is honoured for the wrong directory.

func gitFixture(t *testing.T) (globalFile, matching, other string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	matching = filepath.Join(root, "work", "proj")
	other = filepath.Join(root, "personal", "proj")
	for _, d := range []string{matching, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("git", "init", "-q", d).CombinedOutput(); err != nil {
			t.Fatalf("git init: %v\n%s", err, out)
		}
	}

	inc := filepath.Join(root, "work.inc")
	if err := os.WriteFile(inc, []byte(
		"[user]\n\temail = included@example.invalid\n"+
			// Both of these must be dropped: one names a program, the other
			// turns every commit into a hard failure when the key is absent.
			"[credential]\n\thelper = !echo CREDENTIAL-HELPER-RAN\n"+
			"[commit]\n\tgpgsign = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	globalFile = filepath.Join(root, "gitconfig")
	if err := os.WriteFile(globalFile, []byte(
		"[user]\n\tname = Fixture User\n\temail = global@example.invalid\n"+
			"[init]\n\tdefaultBranch = trunk\n"+
			"[alias]\n\tboom = !echo ALIAS-RAN\n"+
			"[includeIf \"gitdir:"+filepath.Join(root, "work")+"/\"]\n\tpath = "+inc+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return globalFile, matching, other
}

func gitExtractEnv(t *testing.T, globalFile string) []string {
	t.Helper()
	cfg := t.TempDir()
	pd := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pd, "gitex.toml"), []byte(
		"[profile.gitex]\n"+
			"description = \"extract the host's git identity\"\n"+
			"git = \"extract\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return baseEnv("XDG_CONFIG_HOME="+cfg, "GIT_CONFIG_GLOBAL="+globalFile)
}

func TestGitExtractHonoursAConditionalIncludeForTheTargetOnly(t *testing.T) {
	globalFile, matching, other := gitFixture(t)
	env := gitExtractEnv(t, globalFile)

	script := `echo "email=$(git config --get user.email)"
echo "name=$(git config --get user.name)"
echo "branch=$(git config --get init.defaultBranch)"`

	in := runEnv(t, env, []string{"-p", "gitex"}, matching, script).mustRun(t)
	if !strings.Contains(in.out, "email=included@example.invalid") {
		t.Errorf("the conditional include did not fire for a target inside its gitdir "+
			"pattern; a per-directory identity silently becomes the global one:\n%s", in.out)
	}
	// The control, and it is the half that proves the matcher is a matcher
	// rather than "always true": a target outside the pattern keeps the global
	// identity.
	out := runEnv(t, env, []string{"-p", "gitex"}, other, script).mustRun(t)
	if !strings.Contains(out.out, "email=global@example.invalid") {
		t.Errorf("the conditional include fired for a target OUTSIDE its gitdir pattern, "+
			"so the sandbox commits under an identity the host would not use:\n%s", out.out)
	}
	// Keys unrelated to the condition still come across.
	if !strings.Contains(out.out, "name=Fixture User") || !strings.Contains(out.out, "branch=trunk") {
		t.Errorf("whitelisted keys from the global file did not survive:\n%s", out.out)
	}
}

func TestGitExtractCarriesNothingThatNamesAProgram(t *testing.T) {
	globalFile, matching, _ := gitFixture(t)
	env := gitExtractEnv(t, globalFile)

	r := runEnv(t, env, []string{"-p", "gitex"}, matching,
		`echo "helper=[$(git config --get credential.helper)]"
echo "alias=[$(git config --get alias.boom)]"
echo "gpgsign=[$(git config --get commit.gpgsign)]"
echo "email=[$(git config --get user.email)]"
grep -c . "$HOME/.gitconfig"`).mustRun(t)

	// The positive control first: extraction happened at all, so the empty
	// values below are attributable to the whitelist and not to a profile that
	// did nothing.
	if !strings.Contains(r.out, "email=[included@example.invalid]") {
		t.Fatalf("nothing was extracted, so this test proves nothing:\n%s", r.out)
	}
	for _, forbidden := range []string{"helper=[!", "alias=[!", "gpgsign=[true]"} {
		if strings.Contains(r.out, forbidden) {
			t.Errorf("a key that names a program (or breaks every commit) crossed into "+
				"the sandbox: %q\n%s", forbidden, r.out)
		}
	}
}

// The red team's finding, mechanised. A whitelist of KEYS does not bound what a
// VALUE can say: git config values may span lines, so
//
//	[user]
//	  name = "evil\n[alias]\n\tanything = !touch <target>/PWNED"
//
// closed the `name = …` line in the file snug generates and opened a real
// `[alias]` section in it. `git anything` inside the sandbox then ran the
// command — the exact class of key this profile exists to strip, arriving
// through the value channel instead of the key channel.
//
// The assertion is deliberately behavioural rather than textual: the artifact is
// created or it is not.
func TestNoHostGitValueCanRunACommandInsideTheSandbox(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	proj := filepath.Join(root, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	global := filepath.Join(root, "gitconfig")
	if err := os.WriteFile(global, []byte(
		"[user]\n\tname = \"evil\\n[alias]\\n\\tanything = !touch "+proj+"/PWNED\"\n"+
			"\temail = ok@example.invalid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := gitExtractEnv(t, global)

	r := runEnv(t, env, []string{"-p", "gitex"}, proj,
		`echo "alias=[$(git config --get alias.anything)]"
git anything 2>&1 | head -1
echo "email=[$(git config --get user.email)]"`).mustRun(t)

	// Positive control first: extraction ran at all, so an absent alias is
	// attributable to the guard rather than to a profile that did nothing.
	if !strings.Contains(r.out, "email=[ok@example.invalid]") {
		t.Fatalf("nothing was extracted, so this test proves nothing:\n%s", r.out)
	}
	if _, err := os.Stat(filepath.Join(proj, "PWNED")); err == nil {
		t.Errorf("a value in the host's git config ran a command inside the sandbox:\n%s", r.out)
	}
	if !strings.Contains(r.out, "alias=[]") {
		t.Errorf("the injected directive survived into the generated config:\n%s", r.out)
	}
}

func TestGitExtractNeverBindsTheHostFile(t *testing.T) {
	globalFile, matching, _ := gitFixture(t)
	env := gitExtractEnv(t, globalFile)

	out, code := cli(t, env, "--dry-run", "-p", "gitex", matching)
	if code != 0 {
		t.Fatalf("snug --dry-run exited %d:\n%s", code, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, ".gitconfig") {
			continue
		}
		if strings.Contains(line, "ro ") || strings.Contains(line, "--ro-bind ") {
			t.Errorf("the host's git config is BOUND, not generated — the whole point of "+
				"this profile is that a read-only bind supplies the commands the file "+
				"names: %q", strings.TrimSpace(line))
		}
	}
	if !strings.Contains(out, "data ") || !strings.Contains(out, ".gitconfig") {
		t.Errorf("no generated ~/.gitconfig row in the policy:\n%s", out)
	}
}
