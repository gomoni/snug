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

// TestUnreadableConfigIsFatal — the MVY0 red team's finding, and the same class
// as TestEmptyDefaultsMeansEmpty above: a parse error was fatal, a READ error
// was not. `chmod 000` on a file saying `defaults = []` returned the zero config
// and so widened the sandbox back to the built-in four, while `snug config`
// reported the source as "built-in" with os.Stat proving the file was there.
// Invariant 5: no silent downgrade.
//
// loadUserConfig exits the process on this path, so the assertion is on the
// helper that decides — os.IsNotExist is the ONLY non-fatal read error. A test
// that re-implemented the condition would prove nothing, so this one asserts
// the two errors are distinguishable and leaves the exit to the integration
// tier, which runs the real binary.
func TestOnlyAMissingConfigIsANonEvent(t *testing.T) {
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "snug")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfgDir, "config.toml")
	if err := os.WriteFile(path, []byte("defaults = []\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() == 0 {
		t.Skip("running as root: mode 000 is still readable, so this cannot be tested here")
	}

	_, err := os.ReadFile(path)
	if err == nil {
		t.Fatal("control: a mode-000 file was readable; the rest of this test proves nothing")
	}
	if os.IsNotExist(err) {
		t.Fatalf("an unreadable file reported as not-existing (%v); loadUserConfig would "+
			"treat it as 'no config file' and silently widen the sandbox", err)
	}

	// CONTROL, the other direction: a genuinely absent file MUST classify as
	// not-exist, or the fix turns every host without a config.toml into a hard
	// failure.
	_, err = os.ReadFile(filepath.Join(t.TempDir(), "config.toml"))
	if !os.IsNotExist(err) {
		t.Errorf("control: an absent config.toml classified as %v, want not-exist — "+
			"snug would refuse to start on every host that has no config file", err)
	}
}

// TestDryRunCreatesNoHostTmpDir — `--dry-run` says "It starts no process and
// creates no file", and prepareHostTmpDir ran before the dry-run branch, so
// `--dry-run -p @tmp-shared` left a /tmp/snug-* behind. The name is now computed
// without the side effect. Asserting on the pure function keeps this test off
// the real /tmp.
func TestDryRunCreatesNoHostTmpDir(t *testing.T) {
	target := filepath.Join(t.TempDir(), "proj")
	path := hostTmpDirPath(target)
	if path == "" {
		t.Fatal("hostTmpDirPath returned nothing; --dry-run would have no path to show")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("hostTmpDirPath(%q) created or found %s (err %v); naming a path must have "+
			"no side effect, or --dry-run contradicts its own first line", target, path, err)
	}
	// CONTROL: the name must be stable and target-derived, or --dry-run would be
	// showing a path the real run will not use.
	if again := hostTmpDirPath(target); again != path {
		t.Errorf("hostTmpDirPath is not deterministic: %s then %s", path, again)
	}
	if other := hostTmpDirPath(target + "-other"); other == path {
		t.Error("two different targets produced the same host tmp dir; they would share a cache")
	}
}
