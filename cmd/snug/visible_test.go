package main

import (
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// Every screen snug prints must escape the text it did not write, and this test
// asserts the SET of screens rather than one of them.
//
// That distinction is the whole finding. `visibleValue` was added to close a
// forged row in the ENVIRONMENT block, and it was applied at the three call
// sites in describeEnvironment and nowhere else — while `formatArgs` (which had
// no test at all), the FILESYSTEM loop and `snug profile show` rendered the same
// text verbatim. The commit that fixed the first one left the argv block four
// lines below it broken, reachable from a HOST value through @claude's shipped
// `inherit EDITOR` with no profile file involved:
//
//	EDITOR=$'vim\n  --ro-bind /home/u/.ssh /home/u/.ssh' snug --dry-run -p @claude .
//	  --setenv EDITOR vim
//	  --ro-bind /home/u/.ssh /home/u/.ssh      <- forged; no such mount in the policy
//
// The existing TestDryRunDropLineDoesNotRenderControlCharsVerbatim calls
// describeEnvironment DIRECTLY, so it structurally cannot observe any other
// sink — its own comment warns that a fix at one site would look identical, and
// that is exactly what happened. So this one drives the WHOLE screen and asks a
// question no per-site test can answer: does anything anywhere emit a raw
// control character?
//
// ESC and CR are the probes because legitimate output never contains either.
// Newline is excluded for the obvious reason.
func TestNoSnugScreenEmitsARawControlCharacter(t *testing.T) {
	const forged = "FORGED-BY-A-VALUE"

	// A host value carrying the escape sequence that erases the line above it,
	// reaching the policy through the same shipped `inherit` the live case used.
	env := newEnvFakeEnv()
	env.env["EDITOR"] = "vim\x1b[1A\r  ro     /etc/shadow   " + forged

	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "@claude")
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), env)
	if err != nil {
		t.Fatal(err)
	}

	got := captureStdout(t, func() { dryRun(p, p.BwrapArgs(0, 0), config{}, nil) })

	// The positive control, and it is load-bearing twice over: without it, a
	// dry-run that failed to render the value at all — or a fixture whose value
	// never reached the policy — would pass every assertion below.
	if !strings.Contains(got, forged) {
		t.Fatalf("the fixture value never reached the screen, so this test is measuring "+
			"nothing:\n%s", got)
	}
	if strings.ContainsAny(got, "\x1b\r") {
		t.Errorf("--dry-run emitted a raw ESC or CR. Some sink on this screen renders text "+
			"snug did not write, verbatim — find it and route it through visibleValue:\n%s",
			strings.ReplaceAll(got, "\x1b", "<ESC>"))
	}
	// …and it must be escaped in BOTH blocks, not just the one that had the
	// guard first. Two occurrences: the ENVIRONMENT row and the --setenv flag.
	if n := strings.Count(got, `\x1b`); n < 2 {
		t.Errorf("the escaped form appears %d time(s), want at least 2 — the ENVIRONMENT "+
			"block and the bwrap argv block both render this value, and the argv block is "+
			"the one that was missed", n)
	}
}

// The same sweep for `snug profile show`, which is upstream of every --dry-run:
// it is the screen someone reads to decide WHETHER to select a profile.
//
// The fixture puts the control characters in a path grant rather than in an
// environ value on purpose. ValidateEnvGrants now refuses a control character in
// an environ value at PARSE time, so that route can no longer reach this screen
// at all — but a path grant is only judged at RESOLVE time, against a target,
// and `profile show` deliberately runs without one. The renderer is what stands
// between the two.
func TestProfileShowEscapesEveryValue(t *testing.T) {
	const forged = "FORGED-BY-A-GRANT"

	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/snug/profiles.d", 0o755); err != nil {
		t.Fatal(err)
	}
	body := "[profile.forge]\n" +
		"description = \"harmless\"\n" +
		"ro = [\"/etc/hostname\", \"/a\\u001b[1A\\r  rw     /home/u   " + forged + "\"]\n"
	if err := os.WriteFile(dir+"/snug/profiles.d/forge.toml", []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)

	var code int
	got := captureStdout(t, func() { code = profileCmd([]string{"show", "forge"}) })
	if code != 0 {
		t.Fatalf("`profile show forge` exited %d:\n%s", code, got)
	}
	if !strings.Contains(got, forged) {
		t.Fatalf("the fixture grant never reached the screen:\n%s", got)
	}
	if strings.ContainsAny(got, "\x1b\r") {
		t.Errorf("`profile show` emitted a raw ESC or CR. Measured in a 110-column tmux pane "+
			"before this was fixed: the row above vanished from the terminal while `cat -v` "+
			"showed it there all along:\n%s", strings.ReplaceAll(got, "\x1b", "<ESC>"))
	}
}

// A control character in a GUEST path is refused outright, which is the other
// half of the FILESYSTEM finding: the renderer stops the row being forged, and
// this stops it being written.
//
// filepath.Clean leaves a newline alone, so the clean-path check next to this
// one passed it. The result rendered as two correctly-columned grant rows for a
// mount that did not exist — in the artifact CLAUDE.md calls the mechanism by
// which a human can trust snug.
func TestControlCharacterInAGuestPathIsRefused(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["forge"] = &policy.Profile{
		Name:  "forge",
		Tmpfs: []string{"/a\n  ro     /etc/shadow                      @sys"},
	}
	_, err = policy.Resolve(m, append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "forge"),
		envGoldenCtx(), newEnvFakeEnv())
	if err == nil {
		t.Fatal("a guest path containing a newline was accepted; --dry-run prints one grant " +
			"per line, so it renders as a second row for a grant nobody wrote")
	}
	if !strings.Contains(err.Error(), "control character") {
		t.Errorf("refused, but not for this reason — the message must name what is wrong so "+
			"the writer can see it, since the character is invisible in their editor: %v", err)
	}

	// The positive control: the identical grant without the control character is
	// accepted. Otherwise this test would pass on a resolver that refused every
	// tmpfs.
	m["forge"] = &policy.Profile{Name: "forge", Tmpfs: []string{"/a"}}
	if _, err := policy.Resolve(m, append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "forge"),
		envGoldenCtx(), newEnvFakeEnv()); err != nil {
		t.Errorf("the same grant without the control character was refused: %v", err)
	}
}

// captureStdout runs f with os.Stdout redirected to a temp file and returns what
// it wrote. dryRun and profileCmd both write to os.Stdout directly rather than
// taking a writer, and driving the REAL functions is the point — a test against
// an extracted helper would pass while the command printed something else.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	orig := os.Stdout
	tmp, err := os.CreateTemp(t.TempDir(), "stdout-")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = tmp
	f()
	os.Stdout = orig
	tmp.Close()

	b, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
