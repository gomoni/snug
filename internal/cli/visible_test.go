package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
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
	// AND DEL, U+007F, ALONE IN A FOURTH VARIABLE (issue #333). It is a control
	// character, so policy.IsForgingRune has always answered true for it and the
	// screen has always escaped it — but the JSON half gated its own predicate at
	// `r >= 0x80` while the comment beside it argued `r >= 0x20`, and encoding/json
	// escapes nothing between the two except quote and backslash. DEL is the only
	// forging rune in that window, so it is the whole gap, and it reached the
	// document raw with `snug.lossy == false` beside it saying the document was
	// clean.
	//
	// PURE, and in a variable of its own, for the reason the C1 probe is: with an
	// ESC in the same value the human renderer escapes both and the mixed probe
	// passes on a build that can only see one of them. @claude inherits
	// ANTHROPIC_BASE_URL, so this arrives by the same shipped `inherit` route as
	// the three above.
	env.env["ANTHROPIC_BASE_URL"] = "https://api.example\x7f  ro     /etc/shadow   " + forged + "-DEL"

	// AND THE CONTAINERS BLOCK'S ENGINE SOURCE (a coverage gap the issue #417
	// round found): with neither variable set and no container profile selected,
	// describeContainers returns before describeEngineSource ever runs, so
	// its four value sinks (the two raw "binary %s"/"toolchain root %s"
	// echoes and the two "resolves to %s" lines) and its refusal sink
	// (describeEngineRefusal) passed the sweep below by never being reached,
	// not by being safe. @podman-socket plus these two turns the engine
	// block on so the sweep actually exercises it.
	env.env["SNUG_PODMAN"] = "/mnt/podman-bin\x1b[1A\r  ro     /etc/shadow   " + forged + "-PODMAN"
	env.env["SNUG_PODMAN_ROOT"] = "/mnt/podman-root\u009b1A\u0085  ro     /etc/shadow   " + forged + "-PODMAN-ROOT-C1"

	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	// @net is in the selection so describeNetwork renders its EGRESS arm and
	// the pasta argv below it — the two sinks the network fixture below aims
	// at. Without it both are absent and that half of the sweep measures
	// nothing.
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "@claude", "@net", "@podman-socket")
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
	// `gateway` used to be raw strings reaching TWO sinks unescaped: the
	// NETWORK block's address row, and the pasta argv printed a few lines
	// below it, which — unlike the bwrap argv beside it — was joined without
	// escaping. A round demonstrated a profile rewriting the `host loopback
	// UNREACHABLE` row from an `address` value while the sandbox ran normally,
	// because pasta's `-n` parser tolerates the trailing junk.
	//
	// netip typing (issue #165) closes that for PREFIXES structurally — a
	// forging rune cannot survive netip.ParsePrefix, so `p.Net.Address =
	// <raw string>` no longer even compiles — but NOT for a GATEWAY's ZONE
	// (J.2's correction): netip.ParseAddr accepts one and Addr.String()
	// re-emits it verbatim. Gateway6 carries the payload here for exactly
	// that reason; Address6 is set alongside it only so PastaArgs actually
	// renders the pair (addrPairs skips a family whose Address is invalid).
	p.Net.Address6 = netip.MustParsePrefix("fd00:5e79:1::2/64")
	p.Net.Gateway6 = netip.MustParseAddr("fe80::1%\x1b[1A\r         host loopback   REACHABLE   " + forged + "-NET-GATEWAY-ZONE")
	// dryRunText hardcodes a FRESH, empty envFakeEnv() — every other fixture
	// above reaches the screen through p itself (inherit bakes EDITOR, PAGER
	// and friends into p.Env at Resolve time), but the CONTAINERS block reads
	// $SNUG_PODMAN and $SNUG_PODMAN_ROOT off the Environ passed to dryRun
	// directly, so this capture has to reuse the SAME env the fixture above
	// set them on.
	var buf bytes.Buffer
	if err := dryRun(env, &buf, p, p.BwrapArgs(0, 0), config{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// POSITIVE CONTROL for the network fixture. The zoned gateway6 reaches the
	// pasta argv ONLY — the NETWORK block's routes row says "the gateway
	// above" without rendering the value itself (dryrun.go's describeNetwork),
	// so there is one sink here, not two, unlike the pre-netip version of
	// this fixture.
	if want := forged + "-NET-GATEWAY-ZONE"; !strings.Contains(got, want) {
		t.Fatalf("the network fixture's %q never reached the screen, so the NETWORK half "+
			"of this test measures nothing:\n%s", want, got)
	}

	// POSITIVE CONTROLS for the engine-source fixture: both $SNUG_PODMAN and
	// $SNUG_PODMAN_ROOT reached the CONTAINERS block, named so a failure says
	// which of the two stopped reaching describeEngineSource rather than just
	// "something is missing".
	for _, want := range []string{forged + "-PODMAN", forged + "-PODMAN-ROOT-C1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the engine-source fixture's %q never reached the screen, so the "+
				"CONTAINERS half of this test measures nothing:\n%s", want, got)
		}
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
	if !strings.Contains(got, forged+"-DEL") {
		t.Fatalf("the pure-DEL fixture value never reached the screen, so the half of this test "+
			"that is about U+007F is measuring nothing:\n%s", got)
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
	// And DEL. This one is about the JSON half below rather than about the
	// screen — the screen escaped U+007F from the beginning — but it is asserted
	// here too so a regression that stopped rendering the row at all is named
	// rather than showing up as a mysteriously clean document.
	if n := strings.Count(got, `\x7f`); n < 2 {
		t.Errorf("the escaped form of U+007F appears %d time(s), want at least 2 — the "+
			"ENVIRONMENT block and the bwrap argv block both render this value", n)
	}

	// AND THE MACHINE FORMAT, from the SAME fixture (issue #52). --dry-run has
	// two renderers now, and a sweep that covered one of them would be this
	// file's own recurring shape: a rule written once and applied to one of its
	// two halves.
	//
	// The document does NOT escape the way the screen does — it is a machine
	// format, so the value must stay the value (see lossyEncoder's doc
	// comment). What it does instead is spell the hazard as JSON's own
	// \uXXXX, which encoding/json already does for C0 and does NOT do for C1
	// or bidi. Same predicate, different spelling, same guarantee: nothing
	// raw reaches the artifact.
	var doc bytes.Buffer
	if err := dryRun(env, &doc, p, p.BwrapArgs(0, 0), config{json: true}, nil, nil); err != nil {
		t.Fatalf("dryRun --json: %v", err)
	}
	// POSITIVE CONTROL first: the poisoned values really did reach the
	// document, or "nothing raw" is a statement about an empty file.
	if !strings.Contains(doc.String(), forged) {
		t.Fatalf("the fixture value never reached the JSON document, so this half measures "+
			"nothing:\n%s", doc.String())
	}
	if !strings.Contains(doc.String(), forged+"-DEL") {
		t.Fatalf("the DEL fixture value never reached the JSON document, so the U+007F half "+
			"measures nothing:\n%s", doc.String())
	}
	if r, ok := rawForgingRune(doc.String()); ok {
		t.Errorf("the machine-readable dry run rendered %q raw. It is read in a golden diff, "+
			"through jq and in a review UI, so it answers to this sweep too", r)
	}
	if !strings.Contains(doc.String(), `\u202e`) {
		t.Error("the JSON document carries no \\u202e escape, so either the fixture's bidi " +
			"value stopped reaching it or the escape stopped being applied")
	}
	// And the DEL spelling, for the reason the bidi one is asserted separately:
	// the rawForgingRune sweep above also passes on a document the value stopped
	// reaching. `\u007f` is what the fix produces; a raw 0x7F byte is what shipped.
	if !strings.Contains(doc.String(), `\u007f`) {
		t.Error("the JSON document carries no \\u007f escape, so either the fixture's DEL " +
			"value stopped reaching it or the escape stopped being applied")
	}
	// AND THE DOCUMENT STILL PARSES, AND THE VALUE IS STILL THE VALUE. Both
	// halves are the mutation check for the bound this test moved. Widening it
	// is the direction that DESTROYS the document rather than hardening it —
	// escapeRawForgingRunes's own comment records a first draft that used
	// policy.IsForgingRune directly, rewrote MarshalIndent's structural newlines
	// to \u000a and produced something no decoder would read. So: drop the bound
	// to 0 and this Unmarshal goes red; raise it back to 0x80 and the \u007f
	// assertion above goes red. The two together pin the bound from both sides.
	//
	// The round trip is the second half of escapeRawForgingRunes's claim — that
	// it changes the SPELLING and not the value, which is why it does not set
	// snug.lossy. A decoder must hand back the DEL byte itself.
	var back struct {
		Environment []struct {
			Name    string `json:"name"`
			Entries []struct {
				Value string `json:"value"`
			} `json:"entries"`
		} `json:"environment"`
	}
	if err := json.Unmarshal(doc.Bytes(), &back); err != nil {
		t.Fatalf("the escaped document no longer parses: %v\n%s", err, doc.String())
	}
	var decoded string
	for _, v := range back.Environment {
		for _, e := range v.Entries {
			if strings.Contains(e.Value, forged+"-DEL") {
				decoded = e.Value
			}
		}
	}
	if decoded == "" {
		t.Fatalf("the DEL fixture value is not in the DECODED environment block, so the round "+
			"trip measures nothing:\n%s", doc.String())
	}
	if !strings.ContainsRune(decoded, 0x7f) {
		t.Errorf("the decoded value %q lost its U+007F. escapeRawForgingRunes spells a rune "+
			"in JSON's own \\uXXXX and must not change what a decoder gives back — that is "+
			"why it does not set snug.lossy", decoded)
	}
	// snug.lossy is the document's own claim that nothing was lost, and it is
	// the part that made #333 more than cosmetic: raw DEL travelled with
	// `"lossy": false` beside it. A valid-UTF-8 fixture must never set it.
	// Asserted as the PRESENCE of the false spelling, not the absence of the true
	// one: an absence assertion passes on a document that renamed the key.
	if !strings.Contains(doc.String(), `"lossy": false`) {
		t.Errorf("the JSON document does not carry `\"lossy\": false`. Every fixture value here "+
			"is valid UTF-8, so lossy must be false and present — lossy is about bytes no "+
			"string can carry, not about escaping:\n%s", doc.String())
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
	attachOut := captureFile(t, func(w io.Writer) {
		describeAttach(w, &policy.Policy{Target: "/home/u/proj"})
	})
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

// TestExplainScreenEmitsNoRawControlCharacter is the same sweep for the screen
// --explain renders (issue #541).
//
// It needs a fixture of its own rather than an arm on the dry-run sweep above,
// and the reason is the whole point of writing it: the two screens have
// DIFFERENT sinks. That fixture poisons environment variables, and --explain
// renders no environment block at all — an arm reusing it would sweep a screen
// the poison never reached and pass by measuring nothing, which is the failure
// this file exists to prevent. So the values go into the sinks --explain
// actually has: the two paths, the command, a writable mount's guest path and
// a declared door's name.
func TestExplainScreenEmitsNoRawControlCharacter(t *testing.T) {
	const forged = "FORGED-BY-A-VALUE"

	env := newEnvFakeEnv()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "@podman-socket")
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), env)
	if err != nil {
		t.Fatal(err)
	}

	// TARGET and HOME are HOST paths, and a host path is not snug's to refuse —
	// the attacker controls only a directory name, and `mkdir` is not a grant
	// (dryrun.go says the same about its own two rows). Rendering is the only
	// guard these have, on either screen.
	p.Target = "/tmp/proj\x1b[1A\r  writable   /etc/shadow   " + forged + "-TARGET"
	// PURE C1 in the second sink, so that no ASCII control in the same value
	// can make %q escape these on snug's behalf. U+009B is CSI, so the value
	// below carries the 8-bit spelling of the cursor-up above, and U+0085
	// (NEL) is a line break a C1-mode terminal acts on.
	p.Home = "/home/u\u009b1A\u0085  writable   /etc/shadow   " + forged + "-HOME-C1"
	// AND THE BIDI SPELLING. U+202E is category Cf, not Cc, so a widening that
	// stopped at unicode.IsControl could not see it. It forges no row and
	// erases none; it reverses the order the rest of the line READS in, which
	// is the same lie by another mechanism. The marker is written backwards in
	// the source: a bidi-rendering terminal shows "FORGED-BY-A-VALUE-RLO"
	// after the override.
	p.Command = []string{"sh\u202eOLR-EULAV-A-YB-DEGROF"}
	// DEL alone in a fourth sink (issue #333's rune), reaching the FILESYSTEM
	// block's writable list — the sink that has no equivalent on --dry-run,
	// because that screen renders every mount and this one renders only the
	// writable ones.
	p.Replace(policy.Mount{
		Guest:  "/srv/data\x7f  writable   /etc/shadow   " + forged + "-MOUNT-DEL",
		Kind:   policy.KindBind,
		Host:   "/srv/data",
		Access: policy.AccessRW,
		From:   []string{"@test"},
	})
	// And the door name, the one sink that is also an escape note.
	p.ListenNames = []string{"web\x1b[1A\r  " + forged + "-DOOR"}

	var buf bytes.Buffer
	if err := explain(env, &buf, p, p.BwrapArgs(0, 0), config{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	got := buf.String()

	// POSITIVE CONTROLS, named one by one so a failure says WHICH sink stopped
	// being reached rather than "something is missing". Without these, a screen
	// that rendered none of them would pass every assertion below.
	for _, want := range []string{
		forged + "-TARGET", forged + "-HOME-C1", forged + "-MOUNT-DEL", forged + "-DOOR",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("the fixture's %q never reached the --explain screen, so that sink is "+
				"measuring nothing:\n%s", want, got)
		}
	}
	// The bidi value's marker is reversed in the source, so it is asserted by
	// its ESCAPED spelling rather than by the forged marker: the sweep below
	// would also pass if the COMMAND line had silently vanished.
	if !strings.Contains(got, `\u202e`) {
		t.Fatalf("the COMMAND sink's bidi value never reached the screen escaped, so the "+
			"bidi half is measuring nothing:\n%s", got)
	}

	// isForgingRune is the RENDERER'S OWN predicate, so this asserts the
	// property ("nothing on this screen can author a line") rather than a copy
	// of a character list that could drift away from it.
	if i := strings.IndexFunc(got, func(r rune) bool { return r != '\n' && isForgingRune(r) }); i >= 0 {
		t.Errorf("--explain emitted a raw control character (%q at byte %d). Some sink on this "+
			"screen renders text snug did not write, verbatim — find it and route it through "+
			"visibleValue:\n%s", []rune(got[i:])[0], i, strings.ReplaceAll(got, "\x1b", "<ESC>"))
	}
}

// TestExplainSaysWhatIsNotThere pins the section that has no equivalent on
// --dry-run and is the reason the flag earns its code: --dry-run renders what
// IS, and on a deny-by-default model the absences leave no row, so a human
// cannot derive them by reading the grants. CLAUDE.md states the rule this
// implements — a missing capability is a feature to state plainly, not a gap
// to apologise for.
func TestExplainSaysWhatIsNotThere(t *testing.T) {
	env := newEnvFakeEnv()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		profile.BuiltinDefaults(), envGoldenCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := explain(env, &buf, p, p.BwrapArgs(0, 0), config{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		"No X11 and no Wayland",
		"No D-Bus",
		"No host loopback",
		"No ~/.ssh",
		"No root, no setuid",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("--explain no longer states %q. The stated absences ARE the feature:\n%s", want, got)
		}
	}
}
