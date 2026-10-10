package bwrapinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckBindFDHelp(t *testing.T) {
	both := "Usage:\n    --bind-fd FD DEST            Bind open directory\n    --ro-bind-fd FD DEST         read-only\n"
	if err := checkBindFDHelp(both); err != nil {
		t.Fatalf("a help listing both flags was refused: %v", err)
	}
	for _, missing := range []string{"--ro-bind-fd", "--bind-fd"} {
		help := strings.ReplaceAll(both, missing+" ", "--x ")
		err := checkBindFDHelp(help)
		if err == nil || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "upgrade bubblewrap") {
			t.Errorf("help without %s: err = %v", missing, err)
		}
	}
}

// fakeBwrap writes an executable whose --help prints help and whose exit
// status is status, standing in for the bubblewrap RequireBindFD asks.
func fakeBwrap(t *testing.T, help string, status int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bwrap")
	script := fmt.Sprintf("#!/bin/sh\ncat <<'EOF'\n%sEOF\nexit %d\n", help, status)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestMissingBindFDSupportRefuses fails if a bubblewrap that lacks the
// descriptor binds is accepted: every run would then die with an option-parse
// error from inside bwrap instead of a refusal that names the missing flag.
// The control is a fake whose help lists both flags, which must pass, and
// a bwrap that cannot be run at all, which must not be read as a pass.
func TestMissingBindFDSupportRefuses(t *testing.T) {
	withFlags := "Usage: bwrap [OPTION...] COMMAND\n    --ro-bind-fd FD DEST         x\n    --bind-fd FD DEST            y\n"
	if err := RequireBindFD(fakeBwrap(t, withFlags, 0)); err != nil {
		t.Fatalf("control: a bwrap listing both flags was refused: %v", err)
	}

	without := "Usage: bwrap [OPTION...] COMMAND\n    --ro-bind SRC DEST           x\n    --bind SRC DEST              y\n"
	err := RequireBindFD(fakeBwrap(t, without, 0))
	if err == nil || !strings.Contains(err.Error(), "--ro-bind-fd") || !strings.Contains(err.Error(), "upgrade bubblewrap") {
		t.Errorf("a bwrap without the flags: err = %v, want a refusal naming --ro-bind-fd and the fix", err)
	}

	if err := RequireBindFD(filepath.Join(t.TempDir(), "no-such-bwrap")); err == nil {
		t.Error("a bwrap that cannot be run was accepted")
	}
}
