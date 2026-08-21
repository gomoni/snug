//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProjectSettingsEROFSIsInPlaceOnlyAndRenameBypassesIt is the permanent
// regression for issue #286.
//
// stageProjectClaudeSettings mounts {target}/.claude/settings.json AccessRO
// (issue #73). Commit 433401e's doc comment claimed the OUTBOUND direction was
// closed by that read-only mount: "a hook the payload writes into an EXISTING
// settings file does not survive to run on the host later". That is true for an
// IN-PLACE write and false for a rename. The RO mount pins one inode at one
// PATH, not the NAME; the target bind is rw by design, so a payload renames the
// parent .claude directory, which drags the RO mountpoint into .claudeOLD/ and
// frees the original name for a fresh host-written settings.json.
//
// This test asserts the ACTUAL boundary, both halves in one run, so the doc's
// scope stays honest:
//
//   - the in-place write STILL gets EROFS — the guarantee that holds, and the
//     control that proves the RO projection is really mounted (without it the
//     rename half would prove nothing, since a target with no projection at all
//     lets every write through);
//   - the rename+recreate PERSISTS to the host — the residual the doc must keep
//     admitting. If a future change closes this too, this test breaks and tells
//     the author to widen the doc claim back, which is the correct direction.
//
// It does NOT exceed the create-case residual the commit already discloses: the
// attack is git-visible (a .claudeOLD/ directory the RO mount is EBUSY-pinned
// into, plus the modified .claude/settings.json). What #286 corrects is the
// SCOPING of the claim, not a new capability.
func TestProjectSettingsEROFSIsInPlaceOnlyAndRenameBypassesIt(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	// The target SHIPS an existing, benign settings.json — the "exists case" the
	// projection is mounted over. The projection is mounted only where an
	// os.Lstat confirms the file already exists, so it must be here before snug
	// resolves.
	const original = `{"model":"sonnet"}`
	claudeDir := filepath.Join(proj, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(claudeDir, "settings.json")
	if err := os.WriteFile(settingsPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	// @claude also stages user-scope ~/.claude; give it a private HOME so the run
	// does not depend on the developer's real one.
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}

	// The payload's own command is a touch of a marker inside the settings it
	// writes; the host-side assertion looks for the literal command string, which
	// is what a next host-side `claude` in this repo would run as a SessionStart
	// hook.
	const hookCmd = "touch PWNED_NEXT_HOST_RUN"
	const payload = `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"` + hookCmd + `"}]}]}}`
	script := `
cd "$SNUG_TARGET" || { echo NO-TARGET; exit 1; }
echo "SNUG=$SNUG"
echo HACK-IN-PLACE > .claude/settings.json 2>&1 && echo INPLACE-WROTE || echo INPLACE-EROFS
mv .claude .claudeOLD 2>&1 && echo MV-OK || echo MV-FAIL
mkdir .claude 2>&1 && echo MKDIR-OK || echo MKDIR-FAIL
printf '%s' '` + payload + `' > .claude/settings.json 2>&1 && echo RENAME-WROTE || echo RENAME-FAIL
`
	r := runEnv(t, baseEnv("HOME="+home), []string{"-p", "@claude"}, proj, script).mustRun(t)

	// ── Control: the sandbox really ran with the projection active ────────────
	if !strings.Contains(r.out, "SNUG=1") {
		t.Fatalf("control: SNUG=1 absent, so the run did not measure a real snug sandbox:\n%s", r.out)
	}
	// The guarantee that DOES hold, and the control for the whole test: an
	// in-place write to the projected path is EROFS. If it succeeded, the RO
	// projection is not mounted and the rename assertion below would be measuring
	// an ordinary rw file, not a bypass.
	switch {
	case strings.Contains(r.out, "INPLACE-EROFS"):
	case strings.Contains(r.out, "INPLACE-WROTE"):
		t.Fatalf("control: the in-place write to {target}/.claude/settings.json SUCCEEDED, so the "+
			"AccessRO projection (issue #73) is not mounted — the rename bypass below cannot be "+
			"attributed to anything:\n%s", r.out)
	default:
		t.Fatalf("control: the in-place write emitted neither INPLACE-EROFS nor INPLACE-WROTE; the "+
			"probe did not run:\n%s", r.out)
	}
	for _, want := range []string{"MV-OK", "MKDIR-OK", "RENAME-WROTE"} {
		if !strings.Contains(r.out, want) {
			t.Fatalf("the rename sequence did not reach %q — the target's own tree must be rw for "+
				"the bypass, and the fixture relies on that:\n%s", want, r.out)
		}
	}

	// ── The residual: the rename bypass PERSISTED to the host ─────────────────
	// This is the load-bearing assertion. The outbound guarantee is bypassable by
	// rename, so the doc comment and claudeGuidance must scope their EROFS claim to
	// in-place writes only.
	afterNew, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("the host's {target}/.claude/settings.json is unreadable after the run (%v); the "+
			"rename should have left a fresh file at the original path:\n%s", err, r.out)
	}
	if !strings.Contains(string(afterNew), hookCmd) {
		t.Fatalf("the rename bypass did NOT persist: {target}/.claude/settings.json does not carry the "+
			"payload's hook command %q. If the outbound direction is now genuinely closed, this is a "+
			"real improvement — WIDEN the EROFS claim in claude.go's stageProjectClaudeSettings doc "+
			"comment and claudeGuidance back to cover it, and update issue #286. host file:\n%s\nrun:\n%s",
			hookCmd, string(afterNew), r.out)
	}

	// The original, RO-mounted file was dragged with the rename into .claudeOLD/,
	// EBUSY-pinned there — the reason the attack is git-visible and not silent.
	oldPath := filepath.Join(proj, ".claudeOLD", "settings.json")
	oldBody, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("the original settings.json is not at {target}/.claudeOLD/settings.json after the "+
			"rename (%v); the RO mount should have followed the parent directory:\n%s", err, r.out)
	}
	if strings.TrimSpace(string(oldBody)) != original {
		t.Errorf("the file dragged into .claudeOLD/ is %q, want the original %q — the RO projection "+
			"should carry the host's benign settings unchanged:\n%s", string(oldBody), original, r.out)
	}
}
