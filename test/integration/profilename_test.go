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
	out, code := cli(t, nil, "--dry-run", "-p", "@git", proj)
	if code != 0 {
		t.Fatalf("`--dry-run -p @git` exited %d; the cases above prove nothing if snug "+
			"refuses every profile name:\n%s", code, out)
	}
	if !strings.Contains(out, "@git") {
		t.Fatalf("`--dry-run -p @git` did not name the profile:\n%s", out)
	}
}

// assertNameRefusal is the shared verdict: snug must exit exactly 64 (a USAGE
// error — the name never got as far as the resolver, so this is not a policy
// refusal), explain which byte it refused, print the flag help that follows
// every usage error, never emit the offending byte raw, never have reached the
// resolver's "unknown profile", and never render the FILESYSTEM block a run
// that actually resolved a policy would print.
func assertNameRefusal(t *testing.T, out string, code int, arg, want string) {
	t.Helper()
	if code == 0 {
		t.Fatalf("snug accepted the profile name %q (exit 0):\n%s", arg, out)
	}
	// This is a USAGE error, exit 64, never the
	// policy exit (77) a resolved-but-refused run would use — the name never
	// reached the registry at all.
	if code != exitUsageCode {
		t.Errorf("the refusal of %q exited %d, want %d (a usage error, per policy.NewProfileName "+
			"firing before parseArgs even returns):\n%s", arg, code, exitUsageCode, out)
	}
	if !strings.Contains(out, want) {
		t.Errorf("the refusal of %q does not contain %q, so it does not say what is wrong "+
			"with the name:\n%s", arg, want, out)
	}
	// usage() is what main.go prints alongside every exitUsage — "flags:" is a
	// line only it emits, so this fails if a refusal path ever stops calling it.
	if !strings.Contains(out, "flags:") || !strings.Contains(out, "-p, --profile NAME") {
		t.Errorf("the refusal of %q is not followed by the flag help:\n%s", arg, out)
	}
	// FILESYSTEM only ever renders once a policy has been resolved — a usage
	// error must never get that far, or the screen would read as "it ran
	// anyway, mostly".
	if strings.Contains(out, "FILESYSTEM") {
		t.Errorf("the refusal of %q also rendered a FILESYSTEM block, so this was not the usage "+
			"error it claims to be:\n%s", arg, out)
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

// exitUsageCode mirrors internal/cli's unexported exitUsage (64), the same way
// exitPolicyCode already mirrors exitPolicy (sandbox_test.go) — this package
// drives the real binary and cannot import internal/cli's own constant.
const exitUsageCode = 64

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
	write("defaults = [\"@sys\", \"@target-rw\"]\n")
	out, code := cli(t, env, "config")
	if code != 0 {
		t.Fatalf("`snug config` with a legal `defaults` exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "@sys") || !strings.Contains(out, "@target-rw") {
		t.Fatalf("`snug config` did not report the configured defaults:\n%s", out)
	}

	write("defaults = [\"@sys\", \"a b\"]\n")
	out, code = cli(t, env, "config")
	if code == 0 {
		t.Fatalf("`snug config` accepted an illegal name in `defaults` (exit 0). Falling back "+
			"to the built-in list would silently widen the sandbox past what the file "+
			"asked for:\n%s", out)
	}
	// Exactly the POLICY exit, not merely non-zero: this name resolved as far
	// as being READ from a config file that snug DOES trust — a different
	// failure from the usage errors above, which never get that far.
	if code != exitPolicyCode {
		t.Errorf("`snug config` with an illegal `defaults` entry exited %d, want %d:\n%s",
			code, exitPolicyCode, out)
	}
	if !strings.Contains(out, "entry 2") {
		t.Errorf("the refusal does not say WHICH entry is wrong:\n%s", out)
	}
	if !strings.Contains(out, "config.toml") {
		t.Errorf("the refusal does not name the file it came from:\n%s", out)
	}
}

// TestAnAtNamedProfilesDEntryIsRefusedEndToEnd is the wiring
// internal/profile/namegrammar_test.go:TestNameGrammarIsEnforcedByParse never
// reached: that test drives parse() directly and stops at "this file did not
// parse". Nothing before this test ran the REAL BINARY against a profiles.d
// file carrying an @-marked table key and checked its exit code — grepping
// this suite and internal/cli for a profile named "@x" finds nothing. Writing
// [profile."@x"] into a user's own profiles.d is exactly the file
// refuseBadFiles (internal/cli/badfiles.go) exists to make fatal for a real
// run: the bad file might be the one granting what this run asked for, so a
// sandbox assembled from whatever else loaded would be a silent downgrade
// (invariant 5).
func TestAnAtNamedProfilesDEntryIsRefusedEndToEnd(t *testing.T) {
	budget(t)
	proj, _ := target(t)
	env := envProfileLayer(t, "atnamed.toml", "[profile.\"@x\"]\nro = [\"/usr\"]\n", os.Getenv("PATH"))

	out, code := cli(t, env, "--dry-run", proj)
	if code == 0 {
		t.Fatalf("snug --dry-run started despite a profiles.d file carrying an @-marked table "+
			"key (exit 0):\n%s", out)
	}
	if code != exitPolicyCode {
		t.Errorf("want exit %d, got %d:\n%s", exitPolicyCode, code, out)
	}
	if !strings.Contains(out, "did not load") {
		t.Errorf("the refusal does not say the file failed to load:\n%s", out)
	}
	if strings.Contains(out, "FILESYSTEM") {
		t.Errorf("a --dry-run that refuses to start must not also render the FILESYSTEM block — "+
			"a screen naming grants alongside a fatal refusal reads as \"it ran anyway\":\n%s", out)
	}

	// POSITIVE CONTROL: `snug profile list`, the diagnostic command, still
	// reports a builtin — proving this file was isolated as ONE bad file
	// rather than having taken the whole registry down with it, which would
	// make the refusal above prove nothing about THIS file specifically.
	listOut, listCode := cli(t, env, "profile", "list")
	if listCode != exitPolicyCode {
		t.Errorf("`snug profile list` exited %d, want %d — it must still carry a non-zero exit "+
			"for the bad file even though it reports what did load:\n%s", listCode, exitPolicyCode, listOut)
	}
	if !strings.Contains(listOut, "@sys") {
		t.Errorf("`snug profile list` did not list a builtin profile, so the bad @-named file "+
			"took the whole registry down with it rather than being isolated:\n%s", listOut)
	}
}
