package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEmptyDefaultsMeansEmpty pins the fix for the bug TODO.md's MVY0 findings
// recorded: `defaults = []` used to silently fall back to the built-in four,
// because Defaults was a plain []string and could not distinguish an explicit
// empty list from an absent key — both decode to len 0. Defaults is now
// *[]string precisely so the written intent survives decoding, in both
// directions.
func TestEmptyDefaultsMeansEmpty(t *testing.T) {
	// An explicit empty list must mean empty.
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "snug")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte("defaults = []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)

	names, source := defaultProfiles()
	if len(names) != 0 {
		t.Errorf("defaults = [] resolved to %v, want empty — the written intent was silently widened", names)
	}
	if source == "built-in" {
		t.Errorf("defaults = [] reported its source as built-in, contradicting the file that set it")
	}

	// CONTROL, the other direction: an ABSENT key must still fall back to the
	// built-in four. Without this, "defaultProfiles returns empty" above could
	// mean the *[]string distinction broke the other way — every config now
	// resolving to nothing, which would make a bare `snug <dir>` grant nothing
	// on every host with no config file at all.
	absentDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", absentDir)
	names, source = defaultProfiles()
	if len(names) == 0 {
		t.Error("an absent config.toml resolved to an empty default selection; " +
			"a bare `snug <dir>` would grant nothing")
	}
	if source != "built-in" {
		t.Errorf("an absent config.toml should report its source as built-in, got %q", source)
	}
}
