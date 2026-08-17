package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestEmptyDefaultsMeansEmpty pins the fix for a bug found while retiring the
// @null profile: `defaults = []` used to silently fall back to the built-in four,
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

// TestUnreadableConfigIsFatal — a red team finding from the same round, and the same class
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

// `snug profile show` must render ALL FIVE verbs.
//
// The line this replaced was `show("env", p.Env)`, which rendered one of the two
// keys that existed and never rendered `path` at all — so a profile putting a
// directory on the sandbox's PATH looked, on this screen, like a profile that
// granted nothing to the environment. A display that omits a grant is worse than
// no display, because it is read as complete.
//
// It is also half of §2.3's argument: the environment rules are checked at parse
// time so `snug profile show` can report a verdict with no target, and showing
// what it checked is the other half.
func TestProfileShowRendersEveryEnvironVerb(t *testing.T) {
	g := policy.EnvGrants{
		Set:      map[string]string{"XDG_DATA_HOME": "{home}/.local/share"},
		Merge:    map[string][]string{"PATH": {"{home}/.local/bin", "/opt/tools/bin"}},
		Prepend:  map[string][]string{"PATH": {"/opt/first/bin"}},
		Inherit:  []string{"EDITOR"},
		Sanitise: []string{"PKG_CONFIG_PATH"},
	}
	got := map[string][]string{}
	showEnviron(g, func(label string, vals []string) {
		if len(vals) > 0 {
			got[label] = vals
		}
	})

	want := map[string]string{
		// The prefix is the TOML's own spelling. Bare "set" and "merge" sit
		// directly under "ro" and "tmpfs" on this screen and read as two more
		// kinds of filesystem grant.
		"environ.set":      "XDG_DATA_HOME = {home}/.local/share",
		"environ.merge":    "PATH = {home}/.local/bin /opt/tools/bin",
		"environ.prepend":  "PATH = /opt/first/bin",
		"environ.inherit":  "EDITOR",
		"environ.sanitise": "PKG_CONFIG_PATH",
	}
	// PREFIX, not equality: a row may carry marks after the grant it renders —
	// `← unchecked` for a name with no roster row, and since the annotation flip
	// a sentence saying what the tool DOES with the value (EDITOR is inherited
	// here and git runs whatever it names). What this test is about is that every
	// verb renders its grant at all, so it asserts the grant is the START of the
	// line and leaves the marks to the tests that own them
	// (TestProfileShowMarksAnUnrosteredNameAsUnchecked,
	// TestProfileShowRendersTheAnnotation).
	for label, first := range want {
		vals, ok := got[label]
		if !ok {
			t.Errorf("%s was not rendered at all — a profile using it would look, on this "+
				"screen, like a profile that granted nothing to the environment", label)
			continue
		}
		if !strings.HasPrefix(vals[0], first) {
			t.Errorf("%s rendered %q, want it to start with %q", label, vals[0], first)
		}
	}

	// NEGATIVE CONTROL: a verb nobody used must not print an empty heading, or
	// the reader learns to skim the block.
	if len(got) != len(want) {
		t.Errorf("rendered %d verbs, want exactly %d: %v", len(got), len(want), got)
	}
}
