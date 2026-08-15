//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Issue #67: policy.NewProfileName is the only door into a validated profile
// name, and this is the half of that claim a unit test cannot make — the real
// binary, the real argv, the real config file.
//
// The three doors a HUMAN can push on are exercised here, one subtest each:
// `-p`, `--profile=`, and the `defaults` list in config.toml. (The fourth, a
// TOML table key inside a profile file, was already covered at parse time by
// internal/profile's TestNameGrammarIsEnforcedByParse.) In every case a name
// the grammar refuses must stop the run and say why, naming the offending byte
// — not reach the resolver and come back as `unknown profile`, which is a
// different and misleading claim: snug is not saying "I looked and there is no
// such profile", it is saying "that is not a name".
//
// It needs no sandbox: every case fails before a namespace is created. That is
// deliberate — requireSandbox would make the one test that exercises the
// argument parser skip on exactly the hosts where someone is debugging why
// their profile will not load.
func TestAnIllegalProfileNameIsRefusedBeforeAnythingRuns(t *testing.T) {
	budget(t)
	proj, _ := target(t)

	// One fixture per refusal path in policy.NewProfileName, plus the ESC case
	// that issue #20 was opened for: a name carrying ESC[1A CR erases the row
	// above it on any terminal, so a refusal quoting it raw would forge the very
	// screen that reports the refusal.
	cases := []struct {
		name string
		arg  string
		want string // a substring the refusal must carry
	}{
		{"space", "a b", `" "`},
		{"comma", "a,b", `","`},
		{"colon", "a:b", `":"`},
		{"underscore", "my_profile", `"_"`},
		{"dot", "my.tool", `"."`},
		{"esc", "a\x1b[1A\rFORGED", `\x1b`},
		{"bare-sigil", "@", "nothing but the"},
		{"double-sigil", "@@net", `"@"`},
		{"empty", "", "may not be empty"},
	}

	for _, tc := range cases {
		t.Run("p/"+tc.name, func(t *testing.T) {
			// --dry-run, so that a case which somehow got PAST the grammar would
			// still not start a sandbox — the assertion below is about the
			// refusal, and a fixture that ran a payload to prove it would be
			// measuring the wrong thing.
			out, code := cli(t, nil, "--dry-run", "-p", tc.arg, proj)
			assertNameRefusal(t, out, code, tc.arg, tc.want)
		})
		t.Run("profile-equals/"+tc.name, func(t *testing.T) {
			out, code := cli(t, nil, "--dry-run", "--profile="+tc.arg, proj)
			assertNameRefusal(t, out, code, tc.arg, tc.want)
		})
	}

	// CONTROL, and it is the one that stops every assertion above being true of
	// a binary that refuses EVERY -p: a legal name still resolves.
	out, code := cli(t, nil, "--dry-run", "-p", "@git-ro", proj)
	if code != 0 {
		t.Fatalf("`--dry-run -p @git-ro` exited %d; the cases above prove nothing if snug "+
			"refuses every profile name:\n%s", code, out)
	}
	if !strings.Contains(out, "@git-ro") {
		t.Fatalf("`--dry-run -p @git-ro` did not name the profile:\n%s", out)
	}
}

// assertNameRefusal is the shared verdict: snug must exit non-zero, explain
// which byte it refused, never emit that byte raw, and never have got as far as
// the resolver's "unknown profile".
func assertNameRefusal(t *testing.T, out string, code int, arg, want string) {
	t.Helper()
	if code == 0 {
		t.Fatalf("snug accepted the profile name %q (exit 0):\n%s", arg, out)
	}
	if !strings.Contains(out, want) {
		t.Errorf("the refusal of %q does not contain %q, so it does not say what is wrong "+
			"with the name:\n%s", arg, want, out)
	}
	if strings.Contains(out, "unknown profile") {
		t.Errorf("the refusal of %q reads as `unknown profile`, which is a different claim: "+
			"the name never reached the registry, it is not a legal name at all. It should "+
			"have been refused by policy.NewProfileName at argument-parsing time:\n%s", arg, out)
	}
	if strings.ContainsAny(out, "\x1b\r") {
		t.Errorf("the refusal of %q emitted a raw ESC or CR, forging a row on the screen that "+
			"reports the refusal:\n%s", arg, strings.ReplaceAll(out, "\x1b", "<ESC>"))
	}
}

// The `defaults` setting is the third door, and it is the one with a silent
// downgrade available: continuing with the built-in four after refusing a name
// the file asked for would widen the sandbox past what the human wrote
// (invariant 5), exactly as an unreadable config.toml would.
//
// This drives `snug config` rather than a sandbox because that is the command
// whose entire job is "say what is in effect" — the place a lie would be worst.
func TestAnIllegalNameInDefaultsIsFatalRatherThanIgnored(t *testing.T) {
	budget(t)

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "snug"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "snug", "config.toml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(), "XDG_CONFIG_HOME="+dir, "SNUG_TEST=1")

	// CONTROL first: a legal list is accepted and reported, so the refusal below
	// is about the NAME and not about this fixture's config file being unusable.
	write("defaults = [\"@sys\", \"@cwd-rw\"]\n")
	out, code := cli(t, env, "config")
	if code != 0 {
		t.Fatalf("`snug config` with a legal `defaults` exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "@sys") || !strings.Contains(out, "@cwd-rw") {
		t.Fatalf("`snug config` did not report the configured defaults:\n%s", out)
	}

	write("defaults = [\"@sys\", \"a b\"]\n")
	out, code = cli(t, env, "config")
	if code == 0 {
		t.Fatalf("`snug config` accepted an illegal name in `defaults` (exit 0). Falling back "+
			"to the built-in list would silently widen the sandbox past what the file "+
			"asked for:\n%s", out)
	}
	if !strings.Contains(out, "entry 2") {
		t.Errorf("the refusal does not say WHICH entry is wrong:\n%s", out)
	}
	if !strings.Contains(out, "config.toml") {
		t.Errorf("the refusal does not name the file it came from:\n%s", out)
	}
}
