package cli

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
	// after it. HOME carries pure C1 plus a raw CR instead - U+009B is CSI,
	// the single-character form of ESC-[, and "\r" completes a CSI-cursor-up
	// escape sequence into something a terminal would actually act on - so the
	// two rows exercise the two halves of IsForgingRune rather than one of
	// them twice.
	//
	// The two poisons are resolved SEPARATELY (two subtests), not combined
	// into one Context as an earlier version of this test did. Combined,
	// HOME's own control byte trips resolve.go's passwd-field format guard
	// (issue #612: BuiltinDefaults() selects @sys, which sets `nss = true`)
	// before Validate ever sees TARGET's bidi override - the guard returns
	// (nil, err), and there is no dry-run screen left to render AT ALL for
	// that Resolve call, combined or not. Splitting the two lets each poison
	// reach the refusal it actually produces: TARGET still reaches Validate's
	// refusal (p, err) and this test still asserts --dry-run never renders it
	// raw; HOME reaches the format guard's OWN refusal instead, and what is
	// asserted there is that the guard's message - the one thing a nil policy
	// leaves to print - escapes it exactly the same way.
	const markerTarget = "HTAP-A-YB-DEGROF"
	const markerHome = "FORGED-BY-A-HOME"

	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	regMap := map[policy.ProfileName]*policy.Profile(reg)

	t.Run("TARGET's bidi override reaches Validate and renders escaped", func(t *testing.T) {
		// NOT under /home/u: nested under a clean HOME, the SHARED block's
		// own "PERSISTS below" listing would render TARGET a second time
		// through a sink this test does not cover, and a real one would
		// fail the assertions below for a reason unrelated to the header
		// rows this test is about.
		target := "/srv/proj/w\u202e" + markerTarget
		ctx := policy.Context{
			Target: target,
			Home:   "/home/u",
			Shell:  "/usr/bin/bash", HostUserName: "u", HostGroupName: "u",
			Command: []string{"/bin/sh"},
		}
		env := newEnvFakeEnv()
		env.dirs[target] = true
		env.dirs["/home/u"] = true

		p, err := policy.Resolve(regMap, profile.BuiltinDefaults(), ctx, env)

		// THE POLICY IS REFUSED, AND THAT IS THE CASE UNDER TEST, not an
		// accident of the fixture. Since the round-3 sweep, Validate refuses a
		// forging rune in a GUEST path, and the target is bound at its own
		// path inside, so this selection cannot run. But Resolve's contract
		// returns the policy anyway and `snug --dry-run` RENDERS it - that is
		// the whole reproduction in issue #65, where the attacker's only move
		// is `mkdir`. A version of this test that stopped at the error would
		// assert the refusal, which is not the property this screen needs.
		if err != nil && p == nil {
			t.Fatalf("Resolve returned no policy to render: %v", err)
		}
		if err == nil {
			t.Fatal("the fixture was accepted; the refused-policy path this test exists for " +
				"was never reached, so it is measuring a different screen")
		}

		got := dryRunText(p, p.BwrapArgs(0, 0), config{}, nil)

		// The positive control: without it, a dry run that failed to render
		// TARGET at all would pass every assertion below.
		if !strings.Contains(got, markerTarget) {
			t.Fatalf("the TARGET fixture never reached the screen, so this test is measuring "+
				"nothing:\n%s", got)
		}
		if r, found := rawForgingRune(got); found {
			t.Errorf("--dry-run rendered %q raw. A host path is not snug's to refuse, so the "+
				"renderer is the only guard it has, and this screen is the artifact a human reads "+
				"to decide whether to trust the sandbox:\n%s", r, got)
		}
		if strings.Contains(got, "\u202e"+markerTarget) {
			t.Errorf("--dry-run rendered the probe %q verbatim", "\u202e"+markerTarget)
		}
	})

	t.Run("HOME's control byte reaches the passwd-field guard and refuses escaped", func(t *testing.T) {
		home := "/home/u\u009b1A\r" + markerHome
		ctx := policy.Context{
			Target: "/home/u/proj",
			Home:   home,
			Shell:  "/usr/bin/bash", HostUserName: "u", HostGroupName: "u",
			Command: []string{"/bin/sh"},
		}
		env := newEnvFakeEnv()
		env.dirs["/home/u/proj"] = true
		env.dirs[home] = true

		p, err := policy.Resolve(regMap, profile.BuiltinDefaults(), ctx, env)
		if err == nil {
			t.Fatal("the poisoned HOME was accepted; the format guard this half exists for " +
				"was never reached")
		}
		if p != nil {
			t.Fatalf("Resolve returned a policy despite an error; the format guard's own "+
				"contract is (nil, err), not (p, err): %v", err)
		}

		msg := err.Error()
		if !strings.Contains(msg, markerHome) {
			t.Fatalf("the HOME fixture never reached the refusal, so this test is measuring "+
				"nothing:\n%s", msg)
		}
		if r, found := rawForgingRune(msg); found {
			t.Errorf("the format guard's refusal rendered %q raw - this is the same sink issue "+
				"#65 closed for --dry-run, on the ONE message a nil policy leaves to print:\n%s",
				r, msg)
		}
		if strings.Contains(msg, "\u009b1A") {
			t.Errorf("the format guard's refusal rendered the probe %q verbatim:\n%s", "\u009b1A", msg)
		}
	})
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
	path := dir + "/snug/profiles.d/tools\u202e" + marker + ".toml"
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
	if strings.Contains(got, "\u202e") {
		t.Errorf("the source path reached the screen unescaped:\n%q", got)
	}
}
