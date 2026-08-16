package main

import (
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// THE TWO PATHS SNUG PRINTS BEFORE IT PRINTS ANYTHING ELSE (issue #65).
//
// TARGET and HOME are host paths, and the attacker controls only a directory
// NAME — no profile file, no grant, no cooperation from the host user, just
// `mkdir`. A host path is not snug's to refuse, for the reason policy's
// describeNode gives about the host path in a masking refusal: refusing it
// would mean refusing a directory somebody has every right to have. So
// RENDERING is the only guard these two rows have.
//
// They sat four lines above a PROFILES row that had been escaping since the
// value class was found. That is the shape CLAUDE.md records — a guard added to
// one block and not to the one above it — and this test is written as a sweep
// over the WHOLE screen rather than over the two rows the issue named, so the
// next row added to this header is covered without anyone extending a list.
func TestTheDryRunHeaderNeverRendersAHostPathRaw(t *testing.T) {
	// TARGET carries the bidi override, and its marker is written BACKWARDS in
	// the source so that a bidi-rendering terminal shows "FORGED-BY-A-PATH"
	// after it. HOME carries pure C1 instead — U+009B is CSI, the
	// single-character form of ESC-[ — so no ASCII control in the same value can
	// make %q escape it on snug's behalf, and the two rows exercise the two
	// halves of IsForgingRune rather than one of them twice.
	const markerTarget = "HTAP-A-YB-DEGROF"
	const markerHome = "FORGED-BY-A-HOME"

	target := "/home/u/proj/w‮" + markerTarget
	home := "/home/u1A\r" + markerHome
	ctx := policy.Context{
		Target:  target,
		Home:    home,
		Shell:   "/usr/bin/bash",
		Command: []string{"/bin/sh"},
	}

	// The fake host has to CONTAIN the poisoned directories, or Resolve refuses
	// before anything is rendered and this test measures the refusal instead.
	env := newEnvFakeEnv()
	env.dirs[target] = true
	env.dirs[home] = true

	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		profile.BuiltinDefaults(), ctx, env)

	// THE POLICY IS REFUSED, AND THAT IS THE CASE UNDER TEST, not an accident of
	// the fixture. Since the round-3 sweep, Validate refuses a forging rune in a
	// GUEST path, and the target is bound at its own path inside, so this
	// selection cannot run. But Resolve's contract returns the policy anyway and
	// `snug --dry-run` RENDERS it — that is the whole reproduction in issue #65,
	// where the attacker's only move is `mkdir`. A version of this test that
	// stopped at the error would assert the refusal, which is not the property
	// this screen needs.
	if err != nil && p == nil {
		t.Fatalf("Resolve returned no policy to render: %v", err)
	}
	if err == nil {
		t.Fatal("the fixture was accepted; the refused-policy path this test exists for " +
			"was never reached, so it is measuring a different screen")
	}

	got := captureStdout(t, func() { dryRun(p, p.BwrapArgs(0, 0), config{}, nil) })

	// The positive controls, and they are load-bearing twice over: without them
	// a dry run that failed to render either path would pass every assertion
	// below, and so would a fixture whose Context never reached the policy.
	if !strings.Contains(got, markerTarget) {
		t.Fatalf("the TARGET fixture never reached the screen, so this test is measuring "+
			"nothing:\n%s", got)
	}
	if !strings.Contains(got, markerHome) {
		t.Fatalf("the HOME fixture never reached the screen, so the half of this test that is "+
			"about C1 is measuring nothing:\n%s", got)
	}

	if r, found := rawForgingRune(got); found {
		t.Errorf("--dry-run rendered %q raw. A host path is not snug's to refuse, so the "+
			"renderer is the only guard it has, and this screen is the artifact a human reads "+
			"to decide whether to trust the sandbox:\n%s", r, got)
	}
	// The verbatim check, because rawForgingRune exempts '\n' and therefore
	// structurally cannot see a newline smuggled in through a directory name.
	for _, probe := range []string{"‮" + markerTarget, "1A"} {
		if strings.Contains(got, probe) {
			t.Errorf("--dry-run rendered the probe %q verbatim", probe)
		}
	}
}

// The same property for `snug profile show`'s "defined in" row (issue #65).
//
// p.Source is a path snug LISTED out of profiles.d rather than one it chose, so
// it is host text on a screen by the same argument. It sat four lines below the
// description loop, which was already escaping per line.
func TestProfileShowNeverRendersItsSourcePathRaw(t *testing.T) {
	const marker = "ECRUOS-DEGROF"

	// Driven through the real entry point with a real file, so Source is what
	// the loader put there rather than what a test wrote into the struct. The
	// FILENAME carries the override and the profile itself is VALID, which is
	// what distinguishes this from the unparseable-file sweep in
	// screensinks_test.go: that one renders the path out of an error, this one
	// renders it out of a profile that loaded perfectly.
	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/snug/profiles.d", 0o755); err != nil {
		t.Fatal(err)
	}
	path := dir + "/snug/profiles.d/tools‮" + marker + ".toml"
	if err := os.WriteFile(path, []byte("[profile.mytools]\ndescription = \"ok\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)

	got := captureStdout(t, func() { profileCmd([]string{"show", "mytools"}) })

	if !strings.Contains(got, marker) {
		t.Fatalf("the source fixture never reached the screen, so this test is measuring "+
			"nothing:\n%s", got)
	}
	if r, found := rawForgingRune(got); found {
		t.Errorf("profile show rendered %q raw in its \"defined in\" row:\n%s", r, got)
	}
	if strings.Contains(got, "‮") {
		t.Errorf("the source path reached the screen unescaped:\n%q", got)
	}
}
