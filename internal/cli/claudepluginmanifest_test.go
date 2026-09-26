package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// WHAT IS AT ~/.claude/plugins/installed_plugins.json DECIDES WHETHER @claude
// RUNS AT ALL, and the three shapes below are the ones a real host produces.
//
// snug regenerates that manifest (issue #68) and mounts it read-only INSIDE
// @claude's read-only bind of ~/.claude/plugins, so bwrap never gets to create
// the destination: it can only bind over an inode that is already there. The
// shapes and what bwrap does with each were MEASURED on bubblewrap 0.12.0, with
// the destination inside a --ro-bind:
//
//	regular file   --ro-bind-data succeeds
//	absent         bwrap: Can't create file <path>: Read-only file system
//	symlink        bwrap: Can't mount on symlink destination <path>
//	directory      bwrap: Destination is not a file <path>
//
// The first version of the #580 fix asked os.Stat, which FOLLOWS the name, so a
// symlink read as "a regular file is there": the mount was staged carrying
// HostDestExists, rejectGeneratedOntoHost's exemption skipped every check, and
// the run died on bwrap's sentence — the failure #580 exists to remove,
// arriving through #580's own code. A dotfiles manager is all it takes; stow and
// chezmoi both symlink files into ~/.claude.
//
// os.Lstat, via projectableTargetFile, is what asks bwrap's question.

// claudePluginManifestHome builds a home with @claude's two directory grants
// present and NO manifest, then lets the caller put whatever shape it is
// testing at the manifest path before staging runs.
func claudePluginManifestHome(t *testing.T) (home, target string) {
	t.Helper()
	home, target = testTree(t)
	for _, dir := range []string{".claude/skills", ".claude/plugins"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return home, target
}

// stageClaudeInto resolves @claude against this home and runs the real staging
// code, returning what it said.
func stageClaudeInto(t *testing.T, home, target string) (*policy.Policy, error) {
	t.Helper()
	reg := loadTestRegistry(t)
	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", HostUserName: "u", HostGroupName: "u", Command: []string{"/bin/sh"}}
	pol, err := policy.Resolve(reg,
		[]policy.ProfileName{"@sys", "@home", "@target-rw", "@claude"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return pol, claudeFiles(pol, home, nil)
}

func TestPluginManifestThatIsASymlinkOnTheHostIsRefused(t *testing.T) {
	home, target := claudePluginManifestHome(t)
	real := filepath.Join(home, "dotfiles-installed_plugins.json")
	if err := os.WriteFile(real, []byte(`{"version":2,"plugins":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	guest := filepath.Join(home, ".claude/plugins/installed_plugins.json")
	if err := os.Symlink(real, guest); err != nil {
		t.Fatal(err)
	}

	pol, err := stageClaudeInto(t, home, target)
	if err == nil {
		t.Fatal("staged the regenerated manifest onto a SYMLINK. bwrap does not follow the " +
			"name — `Can't mount on symlink destination …` — so the run dies on bwrap's " +
			"message rather than on snug's, which is what a dotfiles manager's ~/.claude gets")
	}
	for _, want := range []string{"installed_plugins.json", "a symlink", "regular file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q:\n%v", want, err)
		}
	}
	if m, ok := pol.Mounts[guest]; ok && m.HostDestExists {
		t.Error("a mount was staged at the manifest path with HostDestExists set, which " +
			"tells rejectGeneratedOntoHost the destination is an existing FILE — the " +
			"exemption that let this reach bwrap in the first place")
	}
}

func TestPluginManifestThatIsADirectoryOnTheHostIsRefused(t *testing.T) {
	home, target := claudePluginManifestHome(t)
	guest := filepath.Join(home, ".claude/plugins/installed_plugins.json")
	if err := os.MkdirAll(guest, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := stageClaudeInto(t, home, target)
	if err == nil {
		t.Fatal("staged the regenerated manifest onto a DIRECTORY; bwrap refuses that with " +
			"`Destination is not a file …` and the run does not start")
	}
	for _, want := range []string{"installed_plugins.json", "a directory", "regular file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q:\n%v", want, err)
		}
	}
}

// TestPluginManifestAbsentStagesNothing is #580's own case, and the positive
// control for the two refusals above: an empty plugins directory is what one
// looks like before the first plugin, it is not anomalous, and it must still
// run. Nothing is staged, and nothing is lost — there is no host manifest to
// displace, so the read-only bind exposes none either way.
func TestPluginManifestAbsentStagesNothing(t *testing.T) {
	home, target := claudePluginManifestHome(t)

	pol, err := stageClaudeInto(t, home, target)
	if err != nil {
		t.Fatalf("refused a host whose ~/.claude/plugins holds no manifest: %v", err)
	}
	guest := filepath.Join(home, ".claude/plugins/installed_plugins.json")
	if _, ok := pol.Mounts[guest]; ok {
		t.Error("staged a generated manifest where the host has none — bwrap would have to " +
			"CREATE that file inside @claude's read-only bind, and the run dies on " +
			"`Can't create file …: Read-only file system` (issue #580)")
	}
	if _, err := os.Lstat(guest); !os.IsNotExist(err) {
		t.Errorf("staging created something at %s on the HOST (%v); snug must not write the "+
			"host during setup (issue #186)", guest, err)
	}
}
