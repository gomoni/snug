package cli

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
//
// THE PROBE SET IS NOW C1 AS WELL, and the reason is that the guard was ASCII-
// only for a milestone while this test could not have noticed (redteam host
// round 2, F6). `visibleValue` triggered on `r < 0x20 || r == 0x7f`, so U+0085
// (NEL) and U+009B (CSI — the single-character form of ESC-[) passed every sink
// raw. Note the asymmetry that hid it, because it is why the fixture below
// carries a PURE-C1 value as well as a mixed one: mix one ASCII control into the
// same string and %q escapes the C1 characters too, so a mixed probe passes on a
// broken build. Latent rather than live here — tmux 3.7b does not interpret C1
// decoded from UTF-8, measured with `tmux capture-pane` — and live on a terminal
// in 8-bit C1 mode.
//
// The assertion is unicode.IsControl over the whole screen rather than a list of
// characters, for the same reason the test drives every sink rather than one:
// a set is checkable, an enumeration is a list someone has to remember to
// extend.
func TestNoSnugScreenEmitsARawControlCharacter(t *testing.T) {
	const forged = "FORGED-BY-A-VALUE"

	// A host value carrying the escape sequence that erases the line above it,
	// reaching the policy through the same shipped `inherit` the live case used.
	env := newEnvFakeEnv()
	env.env["EDITOR"] = "vim\x1b[1A\r  ro     /etc/shadow   " + forged
	// PURE C1, in a second variable, so that no ASCII control in the same value
	// can make %q escape these on snug's behalf. U+009B is CSI, so "\u009b1A"
	// is the 8-bit spelling of the cursor-up the value above writes as ESC-[,
	// and U+0085 (NEL) is a line break a C1-mode terminal acts on.
	// @claude inherits PAGER, so this arrives by exactly the route EDITOR does.
	env.env["PAGER"] = "less\u009b1A\u0085  ro     /etc/shadow   " + forged + "-C1"
	// AND THE BIDI SPELLING, in a third variable @claude inherits (redteam host
	// round 3, F2). U+202E is category Cf, not Cc, so the widening that closed C1
	// — unicode.IsControl — could not see it: at 8d17f85 this value reached the
	// ENVIRONMENT block AND the --setenv argv line raw, measured through `cat -v`.
	// It forges no row and erases none; it reverses the order the rest of the row
	// READS in, which is the same lie in the same artifact by another mechanism.
	// Note the marker is written backwards in the source: what a bidi-rendering
	// terminal shows after the override is "FORGED-BY-A-VALUE-RLO".
	env.env["VISUAL"] = "vi\u202eOLR-EULAV-A-YB-DEGROF"

	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	// AND THE INTERPRETED-PATH MARK (issues #169/#170, internal/policy's
	// PolicyInterpretedMarks). No BUILTIN grants a catalogued path
	// (TestNoBuiltinGrantsACredentialOrCommandTablePath, internal/profile), so
	// this sink is otherwise ABSENT from every fixture this sweep already
	// drives — and a sink nothing exercises is a sink this test cannot be said
	// to cover, the same gap TestAttachScreensAreCoveredByTheControlCharacterSweep
	// exists to close for describeAttach. A synthetic profile grants a real
	// catalogued row (/etc/gitconfig) so the mark actually renders.
	//
	// TestInterpretedMarksNeverInterpolateProfileText (internal/policy) already
	// proves the templates interpolate NO profile text at all, so nothing here
	// is expected to newly trip the sweep below — this fixture exists so that
	// claim is exercised on the REAL screen rather than only in isolation, and
	// so a future template change that DID start interpolating something would
	// be caught here rather than only in a dry run nobody wrote a test for.
	env.dirs["/host/gitconfig-src"] = true
	reg["forge-interpreted"] = &policy.Profile{
		Name: "forge-interpreted",
		RO:   []string{"/host/gitconfig-src:/etc/gitconfig"},
	}
	// @net is in the selection so describeNetwork renders its EGRESS arm and
	// the pasta argv below it — the two sinks the network fixture below aims
	// at. Without it both are absent and that half of the sweep measures
	// nothing.
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "@claude", "@net", "forge-interpreted")
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), env)
	if err != nil {
		t.Fatal(err)
	}

	// AND THE ENGINE VIEW BLOCK (issue #55, §7 item 12): a graft carries FOUR
	// renderable fields — Guest, Host, Why, From — and describeGrafts's own doc
	// comment says all four go through visibleValue, so this sweep must cover
	// them the same way it covers everything else, "asserting a set, not a
	// site." Installed by a RAW map assignment rather than through
	// Policy.Graft: Guest and Host are refused by Policy.Graft's own hygiene
	// check for exactly this class of rune (checkPathHygiene, graft.go — a
	// graft's Guest and Host get the SAME refusal a Mount's Guest does), so
	// this fixture is not a reachable production path today. It is still
	// worth asserting: TestOnlyGraftWritesGrafts pins Policy.Graft as the
	// ONLY writer of p.Grafts today, but the renderer must not depend on that
	// staying true forever — the same defence in depth every other block on
	// this screen gets, and the reason visibleValue exists at all rather than
	// "just don't let bad values in".
	p.Grafts = map[string]policy.Graft{
		"/mnt/probe": {
			Mount: policy.Mount{
				Guest: "/mnt/probe\x1b[1A\r  graft-rw  /etc/shadow    " + forged + "-GRAFT-GUEST",
				Host:  "/srv/host\u009b1A\u0085  graft-rw  /etc/shadow    " + forged + "-GRAFT-HOST-C1",
				Kind:  policy.KindGraft, Access: policy.AccessRW,
				From: []string{"(snug)\u202eOLR-" + forged + "-GRAFT-FROM"},
			},
			Why: "abuse\u202eOLR-" + forged + "-GRAFT-WHY",
		},
	}

	// AND THE NETWORK VALUES (redteam host round 4, F1). `address` and
	// `gateway` are profile-supplied scalars that reached TWO sinks raw: the
	// NETWORK block's address row, and the pasta argv printed a few lines
	// below it, which — unlike the bwrap argv beside it — was joined without
	// escaping. A round demonstrated a profile rewriting the `host loopback
	// UNREACHABLE` row from an `address` value while the sandbox ran normally,
	// because pasta's `-n` parser tolerates the trailing junk.
	//
	// Assigned RAW here for the same reason the graft fixture above is:
	// Policy.Validate now refuses this class of rune in both fields, so this
	// is not a reachable production path — and the renderer must not depend on
	// that staying true, which is the whole argument for visibleValue existing
	// alongside a refusal.
	p.Net.Address = "10.5.5.2/24\x1b[1A\r         host loopback   REACHABLE   " + forged + "-NET-ADDRESS"
	p.Net.Gateway = "10.5.5.1\u009b1A\u0085  " + forged + "-NET-GATEWAY-C1"

	got := captureStdout(t, func() { dryRun(p, p.BwrapArgs(0, 0), config{}, nil) })

	// POSITIVE CONTROL for the interpreted-path fixture: without this, the
	// grant above could have failed to resolve, or the mark could have failed
	// to fire, and the isForgingRune sweep below would still pass — on a
	// screen that never actually reached the sink it is meant to cover.
	if !strings.Contains(got, "COMMAND TABLE: git reads this") {
		t.Fatalf("the interpreted-path mark never reached the screen at all, so this half of the "+
			"sweep measures nothing:\n%s", got)
	}

	// POSITIVE CONTROLS for the network fixture, named separately so a failure
	// says which sink stopped rendering rather than "something is missing".
	// The address reaches BOTH the NETWORK block and the pasta argv; the
	// gateway reaches the pasta argv only, since the block does not print it.
	for _, want := range []string{forged + "-NET-ADDRESS", forged + "-NET-GATEWAY-C1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the network fixture's %q never reached the screen, so the NETWORK half "+
				"of this test measures nothing:\n%s", want, got)
		}
	}
	if n := strings.Count(got, forged+"-NET-ADDRESS"); n < 2 {
		t.Fatalf("the address fixture appears %d time(s), want at least 2 — the NETWORK block "+
			"and the pasta argv both render it, and the pasta argv is the one that was "+
			"unescaped:\n%s", n, got)
	}

	// POSITIVE CONTROLS for the graft fixture specifically: each of the four
	// fields actually reached the screen, in its escaped or unescaped form —
	// checked in full below by the whole-screen sweep, but named here so a
	// failure says WHICH field stopped reaching the block rather than just
	// "something is missing".
	for _, want := range []string{
		forged + "-GRAFT-GUEST", forged + "-GRAFT-HOST-C1", forged + "-GRAFT-FROM", forged + "-GRAFT-WHY",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("the graft fixture's %q never reached the screen, so the ENGINE VIEW half of "+
				"this test measures nothing:\n%s", want, got)
		}
	}

	// The positive control, and it is load-bearing twice over: without it, a
	// dry-run that failed to render the value at all — or a fixture whose value
	// never reached the policy — would pass every assertion below.
	if !strings.Contains(got, forged) {
		t.Fatalf("the fixture value never reached the screen, so this test is measuring "+
			"nothing:\n%s", got)
	}
	if !strings.Contains(got, forged+"-C1") {
		t.Fatalf("the pure-C1 fixture value never reached the screen, so the half of this test "+
			"that is about C1 is measuring nothing:\n%s", got)
	}
	// isForgingRune is the RENDERER'S OWN predicate, so this asserts the property
	// ("nothing on this screen can author a line") rather than a copy of a
	// character list that could drift away from it.
	if i := strings.IndexFunc(got, func(r rune) bool { return r != '\n' && isForgingRune(r) }); i >= 0 {
		t.Errorf("--dry-run emitted a raw control character (%q at byte %d). Some sink on this "+
			"screen renders text snug did not write, verbatim — find it and route it through "+
			"visibleValue:\n%s", []rune(got[i:])[0], i, strings.ReplaceAll(got, "\x1b", "<ESC>"))
	}
	// …and it must be escaped in BOTH blocks, not just the one that had the
	// guard first. Two occurrences: the ENVIRONMENT row and the --setenv flag.
	if n := strings.Count(got, `\x1b`); n < 2 {
		t.Errorf("the escaped form appears %d time(s), want at least 2 — the ENVIRONMENT "+
			"block and the bwrap argv block both render this value, and the argv block is "+
			"the one that was missed", n)
	}
	// The same assertion for the bidi spelling, and it is not implied by the
	// isForgingRune sweep above: that sweep would also pass if the whole VISUAL
	// row had silently vanished from the screen. Two occurrences, the same two
	// blocks.
	if n := strings.Count(got, `\u202e`); n < 2 {
		t.Errorf("the escaped form of U+202E appears %d time(s), want at least 2 — the "+
			"ENVIRONMENT block and the bwrap argv block both render this value. A "+
			"directional override reverses how the rest of the row reads, on any terminal, "+
			"pager, editor or review UI that implements the bidi algorithm", n)
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
	// The DESCRIPTION carries the pure-C1 probe and the path carries the ASCII
	// one, because that is exactly the shape the C1 gap was found in: `snug
	// profile list` rendering a description of "harmless\u009b1A\u00851G@sys",
	// which %q left alone because nothing else in the value was a control
	// character. checkEnvValue cannot reach either — neither is an environ value —
	// so the renderer is the only guard there is.
	// The third probe is the BIDI one, and it goes in a MOUNT PATH as well as in
	// the description, because a path is the sink the ENVIRONMENT-value guard
	// structurally cannot reach: checkEnvValue refuses a control character in an
	// environ value at parse time, and neither a description nor a `ro` entry is
	// one. Measured at 8d17f85: U+202E rendered raw here, in both.
	body := "[profile.forge]\n" +
		"description = \"harmless\\u009b1A\\u0085sneaky-" + forged + "-C1 \\u202eOLR-" + forged + "\"\n" +
		"ro = [\"/etc/hostname\", \"/a\\u001b[1A\\r  rw     /home/u   " + forged + "\",\n" +
		"      \"/opt/x\\u202eOLR-" + forged + "\"]\n"
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
	if !strings.Contains(got, forged+"-C1") {
		t.Fatalf("the C1 description never reached the screen, so half of this test measures "+
			"nothing:\n%s", got)
	}
	// The bidi probe, in both sinks: a description and a grant path. Escaped, so
	// what appears on the screen is the \u202e ESCAPE rather than the character.
	if n := strings.Count(got, `\u202e`); n < 2 {
		t.Fatalf("the escaped form of U+202E appears %d time(s), want 2 — one in the "+
			"description and one in the `ro` path. A directional override reverses how the "+
			"rest of the row reads, so a grant can display as a path it is not:\n%s", n, got)
	}
	if i := strings.IndexFunc(got, func(r rune) bool { return r != '\n' && isForgingRune(r) }); i >= 0 {
		t.Errorf("`profile show` emitted a raw control character (%q). Measured in a 110-column "+
			"tmux pane before this was fixed: the row above vanished from the terminal while "+
			"`cat -v` showed it there all along. The C1 half is the same defect one encoding "+
			"out — U+009B IS CSI, and it reached this screen raw for a milestone:\n%s",
			[]rune(got[i:])[0], strings.ReplaceAll(got, "\x1b", "<ESC>"))
	}
}

// TestAttachScreensAreCoveredByTheControlCharacterSweep is §13.7 test 29:
// "the existing TestNoSnugScreenEmitsARawControlCharacter must cover the new
// block and the new help text — check that it does, rather than assuming."
//
// dryRun already calls describeAttach unconditionally (dryrun.go), so the
// whole-screen sweep above already exercises it — this test exists so that
// fact is CHECKED, not assumed, and so a future describeAttach that starts
// interpolating something (a target path, say) is caught by the same
// isForgingRune sweep rather than silently exempted because nobody re-ran the
// coverage question. attachUsage's help text is static (no value is
// interpolated into it at all today), so there is nothing FOR the sweep to
// catch there yet — this test pins that fact directly rather than leaving it
// implicit, so it fails the moment the help text stops being static.
func TestAttachScreensAreCoveredByTheControlCharacterSweep(t *testing.T) {
	attachOut := captureFile(t, describeAttach)
	if attachOut == "" {
		t.Fatal("describeAttach produced no output at all, so the sweep in " +
			"TestNoSnugScreenEmitsARawControlCharacter cannot be said to cover it")
	}
	if i := strings.IndexFunc(attachOut, func(r rune) bool { return r != '\n' && isForgingRune(r) }); i >= 0 {
		t.Errorf("describeAttach emitted a raw control character (%q)", []rune(attachOut[i:])[0])
	}

	helpOut := captureStdout(t, attachUsage)
	if helpOut == "" {
		t.Fatal("attachUsage produced no output at all")
	}
	if i := strings.IndexFunc(helpOut, func(r rune) bool { return r != '\n' && isForgingRune(r) }); i >= 0 {
		t.Errorf("attach's help text emitted a raw control character (%q)", []rune(helpOut[i:])[0])
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

	// THE BIDI SPELLING, AND THIS ONE HAD NOT BEEN WIDENED AT ALL. When U+0085 and
	// U+009B were found reaching the screens, checkEnvValue and the renderer were
	// widened to unicode.IsControl; this refusal — the same rule, guarding the
	// same block of the same screen — kept its `r < 0x20 || r == 0x7f` trigger,
	// because its own test asserted its own spelling and passed. So a guest path
	// could carry a C1 character AND, one category out, a directional override
	// that makes the rendered row read as a different path. Both sites ask
	// policy.IsForgingRune now, which is why this loop can be written over the
	// spellings rather than over the sites.
	for _, probe := range []struct{ why, path string }{
		{"a C1 CSI", "/a\u009b1A  ro     /etc/shadow"},
		{"a directional override", "/opt/x\u202eOLR-DEGROF"},
	} {
		m["forge"] = &policy.Profile{Name: "forge", Tmpfs: []string{probe.path}}
		_, err := policy.Resolve(m, append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "forge"),
			envGoldenCtx(), newEnvFakeEnv())
		if err == nil {
			t.Errorf("a guest path containing %s was accepted", probe.why)
			continue
		}
		// The message must name the DAMAGE, and the two damages are different: a
		// control character forges or erases a row, an override reverses the one
		// it is in. A refusal that describes the wrong one leaves the author
		// looking for a character that is not there.
		if !strings.Contains(err.Error(), "control character") &&
			!strings.Contains(err.Error(), "directional formatting character") {
			t.Errorf("%s was refused, but the message names neither damage: %v", probe.why, err)
		}
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

// captureStdout runs f with BOTH standard streams redirected to a temp file and
// returns what it wrote. dryRun and profileCmd both write to os.Stdout directly
// rather than taking a writer, and driving the REAL functions is the point — a
// test against an extracted helper would pass while the command printed
// something else.
//
// IT CAPTURED ONE STREAM AND THE NAME OF THE TEST ABOVE CLAIMED ALL OF THEM.
// "No snug screen emits a raw control character" was asserted by a helper that
// redirected os.Stdout only, so every warning snug writes to stderr was outside
// the sweep by construction — and that is where the next raw sink was found:
// `snug: git config extracted: …` renders the host's gitconfig VALUES, from a
// call main makes before dryRun exists. The same gap shape as the ENVIRONMENT
// block being fixed while the argv block four lines below it was not, one stream
// over instead of one block over.
//
// Both streams go to ONE file rather than to two, deliberately: the property is
// about what a human sees in their terminal, where the two are interleaved, and
// a test that returned them separately would invite a caller to check one.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	tmp, err := os.CreateTemp(t.TempDir(), "screen-")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = tmp, tmp
	f()
	os.Stdout, os.Stderr = origOut, origErr
	tmp.Close()

	b, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
