package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The extractor is the half of the git work that touches the filesystem, so it
// cannot live in internal/policy and cannot be covered by the resolver's tests.
// It is also where the two measured facts about git bite: the condition must be
// evaluated by snug (asking git lets the repository vote), and the value must be
// read from the FILE rather than from `git config --get` in the target.
func writeGitFixture(t *testing.T) (globalFile, workRepo, otherRepo string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	workRepo = filepath.Join(root, "work", "proj")
	otherRepo = filepath.Join(root, "personal", "proj")
	for _, d := range []string{workRepo, otherRepo} {
		if err := os.MkdirAll(filepath.Join(d, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	inc := filepath.Join(root, "work.inc")
	if err := os.WriteFile(inc, []byte(
		"[user]\n\temail = included@example.invalid\n"+
			"[credential]\n\thelper = !echo RAN\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	globalFile = filepath.Join(root, "gitconfig")
	if err := os.WriteFile(globalFile, []byte(
		"[user]\n\tname = Fixture User\n\temail = global@example.invalid\n"+
			"[init]\n\tdefaultBranch = trunk\n"+
			"[includeIf \"gitdir:"+filepath.Join(root, "work")+"/\"]\n\tpath = "+inc+"\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	return globalFile, workRepo, otherRepo
}

func TestExtractGitConfigHonoursGitdirIncludes(t *testing.T) {
	globalFile, work, other := writeGitFixture(t)
	t.Setenv("GIT_CONFIG_GLOBAL", globalFile)

	got := extractGitConfig("/home/u", work, false)
	if got["user.email"] != "included@example.invalid" {
		t.Errorf("user.email = %q, want the included value: a gitdir condition that "+
			"does not fire silently gives the sandbox the wrong identity", got["user.email"])
	}
	if got["user.name"] != "Fixture User" || got["init.defaultbranch"] != "trunk" {
		t.Errorf("whitelisted keys from the global file did not survive: %+v", got)
	}

	// The control: a target outside the pattern keeps the global identity. A
	// matcher that always fires would pass the assertion above.
	got = extractGitConfig("/home/u", other, false)
	if got["user.email"] != "global@example.invalid" {
		t.Errorf("user.email = %q for a target outside the gitdir pattern, want the "+
			"global value", got["user.email"])
	}
}

func TestExtractGitConfigCarriesNoKeyThatNamesAProgram(t *testing.T) {
	globalFile, work, _ := writeGitFixture(t)
	t.Setenv("GIT_CONFIG_GLOBAL", globalFile)

	got := extractGitConfig("/home/u", work, false)
	if len(got) == 0 {
		t.Fatal("nothing extracted, so this proves nothing")
	}
	for k := range got {
		switch k {
		case "user.name", "user.email", "init.defaultbranch":
		default:
			t.Errorf("extracted %q, which is not on the whitelist", k)
		}
	}
}
