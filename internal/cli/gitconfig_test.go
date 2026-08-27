package cli

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

	got, err := extractGitConfig("/home/u", work)
	if err != nil {
		t.Fatal(err)
	}
	if got["user.email"] != "included@example.invalid" {
		t.Errorf("user.email = %q, want the included value: a gitdir condition that "+
			"does not fire silently gives the sandbox the wrong identity", got["user.email"])
	}
	if got["user.name"] != "Fixture User" || got["init.defaultbranch"] != "trunk" {
		t.Errorf("whitelisted keys from the global file did not survive: %+v", got)
	}

	// The control: a target outside the pattern keeps the global identity. A
	// matcher that always fires would pass the assertion above.
	got, err = extractGitConfig("/home/u", other)
	if err != nil {
		t.Fatal(err)
	}
	if got["user.email"] != "global@example.invalid" {
		t.Errorf("user.email = %q for a target outside the gitdir pattern, want the "+
			"global value", got["user.email"])
	}
}

// The extractor is where the value channel has to be closed, because the
// renderer is not the only consumer and a dropped value should be REPORTED. A
// multi-line value in the host's config authored a real `[alias] x = !cmd`
// section in the generated file, and `git x` ran it inside the sandbox.
func TestExtractGitConfigDropsAValueThatWouldAuthorADirective(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	global := filepath.Join(root, "gitconfig")
	// The `"…"` quoting with a \n escape is how git spells a multi-line value,
	// and it is the spelling anyone re-testing this needs.
	if err := os.WriteFile(global, []byte(
		"[user]\n\tname = \"evil\\n[alias]\\n\\tanything = !touch /tmp/PWNED\"\n"+
			"\temail = ok@example.invalid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", global)

	got, err := extractGitConfig("/home/u", filepath.Join(root, "proj"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["user.name"]; ok {
		t.Errorf("a multi-line user.name survived extraction: %q", got["user.name"])
	}
	// And the rest of the file still comes through: dropping one poisoned value
	// must not quietly disable the profile.
	if got["user.email"] != "ok@example.invalid" {
		t.Errorf("user.email = %q, want the ordinary value beside the dropped one",
			got["user.email"])
	}
}

// TestExtractGitConfigMergesTheTwoGlobalFilesHomeWins exercises the ONE
// branch of globalGitFiles (gitconfig.go:134) that every other test in this
// file steps around: the two-file return at gitconfig.go:142 fires only when
// GIT_CONFIG_GLOBAL is unset, and TestExtractGitConfigHonoursGitdirIncludes,
// TestExtractGitConfigDropsAValueThatWouldAuthorADirective and
// TestExtractGitConfigCarriesNoKeyThatNamesAProgram all t.Setenv it, so that
// branch has never actually run.
//
// Setting it to the empty string rather than never setting it at all: the
// function reads it with `os.Getenv("GIT_CONFIG_GLOBAL")` and only checks
// `f != ""`, so a blank value is indistinguishable from an absent one to the
// code under test, and t.Setenv restores the surrounding environment
// afterwards — an os.Unsetenv with no matching restore would leak into
// whatever test runs next in this package.
func TestExtractGitConfigMergesTheTwoGlobalFilesHomeWins(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	xdg := filepath.Join(root, "xdgconfig")
	if err := os.MkdirAll(filepath.Join(xdg, "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	// CONFLICTING user.email in both files, so a merge that picked the wrong
	// one, or the wrong ORDER, is visible rather than accidentally correct.
	if err := os.WriteFile(filepath.Join(xdg, "git", "config"), []byte(
		"[user]\n\temail = xdg@example.invalid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(
		"[user]\n\temail = dotfile@example.invalid\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GIT_CONFIG_GLOBAL", "")
	t.Setenv("XDG_CONFIG_HOME", xdg)

	got, err := extractGitConfig(home, filepath.Join(root, "proj"))
	if err != nil {
		t.Fatal(err)
	}
	// POSITIVE CONTROL: something was extracted at all, so a globalGitFiles
	// that silently returned no files (or two files neither of which is
	// readable) would not read as a pass below.
	if len(got) == 0 {
		t.Fatal("nothing extracted, so this test cannot tell a real two-file merge from a no-op")
	}
	// globalGitFiles lists $XDG_CONFIG_HOME/git/config FIRST and
	// ~/.gitconfig SECOND — the same order git itself reads them, where the
	// LAST file read wins a conflicting single-valued key (measured: real
	// git with both files present and XDG_CONFIG_HOME/HOME pointed at this
	// same fixture also reports the ~/.gitconfig value). If this reads
	// "xdg@example.invalid" instead, either the order in globalGitFiles
	// changed or only one of the two files is being read at all.
	if got["user.email"] != "dotfile@example.invalid" {
		t.Errorf("user.email = %q, want %q (the ~/.gitconfig value) — globalGitFiles lists "+
			"it AFTER $XDG_CONFIG_HOME/git/config, and a later file must win a conflicting key",
			got["user.email"], "dotfile@example.invalid")
	}
}

func TestExtractGitConfigCarriesNoKeyThatNamesAProgram(t *testing.T) {
	globalFile, work, _ := writeGitFixture(t)
	t.Setenv("GIT_CONFIG_GLOBAL", globalFile)

	got, err := extractGitConfig("/home/u", work)
	if err != nil {
		t.Fatal(err)
	}
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
