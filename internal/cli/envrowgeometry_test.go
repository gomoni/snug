package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// ── the geometry of the ENVIRONMENT block ────────────────────────────────────
//
// Two properties, and only one of them is about legibility.
//
// A row of that block can carry three marks at once — `← unchecked` about the
// NAME, the annotation about what the tool DOES with the value, and
// `← not granted` about the VALUE as a path. Concatenated onto one line of a
// fixed-column table they produced, measured on this host before the fix:
//
//	277  GIT_CONFIG_KEY_0 …
//	272  NPM_CONFIG_SCRIPT_SHELL …
//	264  GIT_SSH …
//
// At 80 columns that is 3–4 unindented wrapped fragments inside a 20-row
// aligned table, with the verdict about that particular value landing at the
// end of the third fragment. --dry-run is the artifact a human reads to decide
// whether to trust a sandbox; a statement nobody can find in it is a statement
// snug did not really make.
//
// The second property is a security one and is the reason the marks are
// indented 21 rather than 19 — see TestNoEnvironmentLineCanBeMistakenForAMark.

// renderedEnvBlocks is every ENVIRONMENT block this suite can lay hands on: the
// committed goldens (which ARE describeEnvironment's output, byte for byte) plus
// two live renders. Both halves are here on purpose. The goldens cover every
// case anyone has thought worth pinning, including ones added later by someone
// who never reads this file; the live renders make the test exercise the
// renderer rather than a file that could in principle be stale.
func renderedEnvBlocks(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}

	paths, err := filepath.Glob(filepath.Join("testdata", "env.*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[p] = string(b)
	}
	// POSITIVE CONTROL for the sweep itself: if the glob ever stops matching,
	// every assertion below passes over an empty map.
	if len(out) < 4 {
		t.Fatalf("found %d ENVIRONMENT goldens, expected at least 4 — this sweep is "+
			"measuring almost nothing", len(out))
	}

	m := markJoinRegistry(t)
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "markjoin")
	p, err := policy.Resolve(m, sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	out["live:markjoin"] = captureFile(t, func(f *os.File) { describeEnvironment(f, p) })

	// A DROP LINE, which no committed golden happens to contain and which the
	// column rules below cannot be checked without: it is the other thing that
	// renders at column 19, and "a mark must not render where a drop line does"
	// is untestable against a corpus with no drop lines in it.
	drop := map[policy.ProfileName]*policy.Profile(mustBuiltins(t))
	drop["dropper"] = &policy.Profile{
		Name:    "dropper",
		Include: []policy.ProfileName{"@sys", "@home", "@cwd-rw"},
		Environ: policy.EnvGrants{Sanitise: []string{"PATH"}},
	}
	host := newEnvFakeEnv()
	// /usr/bin survives (@sys grants /usr); /tmp/attacker/bin is covered only by
	// snug's own /tmp tmpfs and is dropped with its reason named.
	host.env["PATH"] = "/usr/bin:/tmp/attacker/bin"
	dp, err := policy.Resolve(drop, append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...),
		"dropper"), envGoldenCtx(), host)
	if err != nil {
		t.Fatal(err)
	}
	out["live:dropper"] = captureFile(t, func(f *os.File) { describeEnvironment(f, dp) })
	return out
}

func mustBuiltins(t *testing.T) profile.Registry {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// TestNoDryRunEnvironmentLineIsWiderThanEightyColumns is the F5 regression, and
// N is 80 for a reason that is checkable rather than a matter of taste: it is
// the width every OTHER --dry-run block already respects. Measured on the
// committed goldens: the bwrap notes reach 78, the seccomp blocks 75, the
// topology blocks 81, and the syscall list is explicitly wrapped at 64
// (wrapList). The ENVIRONMENT block was the single outlier, at 264–277.
//
// The one thing allowed to exceed it is a single unbreakable TOKEN — a host
// path longer than the column. wrapMark breaks on spaces only, because a path
// cut in half is a lie about a path, and the second half of this test asserts
// that rather than leaving it to be discovered.
func TestNoDryRunEnvironmentLineIsWiderThanEightyColumns(t *testing.T) {
	const width = 80

	marks := 0
	for name, block := range renderedEnvBlocks(t) {
		for _, line := range strings.Split(block, "\n") {
			if strings.Contains(line, "←") {
				marks++
			}
			if w := utf8.RuneCountInString(line); w > width {
				// TWO EXEMPTIONS, both of the same kind: the overflow is DATA, not
				// snug's prose, and snug will not corrupt data to make a column.
				//
				// 1. A single unbreakable token — a host path longer than the
				//    budget. wrapMark breaks on spaces only.
				// 2. A drop line, which starts at column 19 with '(' and NAMES the
				//    host elements a filter removed, one line per reason. Its
				//    length is a property of the host's value (a PATH with six
				//    ungranted elements is a long line), and the deliberate choice
				//    there is that drops are named rather than counted. It is
				//    still one statement rather than three concatenated, which is
				//    what made the rows this test is named for unreadable.
				//    Wrapping it would need a continuation indent, and the only
				//    one available collides with the mark column — so it is left
				//    alone, on purpose, rather than half-fixed.
				if longestToken(line) > width-markIndent ||
					strings.HasPrefix(strings.TrimLeft(line, " "), "(") {
					continue
				}
				t.Errorf("%s: a %d-column line snug could have wrapped:\n%s\n"+
					"Every mark is its own line, wrapped to %d (dryrun.go's wrapMark). A row "+
					"this wide means something is being concatenated onto it again — which is "+
					"how the verdict about a VALUE ended up unreadable at the end of the third "+
					"wrapped fragment of a 277-column row.", name, w, line, width)
			}
		}
	}
	// POSITIVE CONTROL: the corpus actually contains marks. Without this the
	// width assertion passes trivially on a build that renders no mark at all —
	// which is the failure this whole area of the code exists to prevent.
	if marks == 0 {
		t.Fatal("not one mark in any rendered ENVIRONMENT block; the width rule was measured " +
			"against nothing")
	}
}

// TestWrapMarkNeverSplitsAToken is the other half of the width rule: a mark is
// wrapped, never truncated, and a token longer than the budget overflows rather
// than being cut. The tokens in these sentences are paths and command names.
func TestWrapMarkNeverSplitsAToken(t *testing.T) {
	long := "/var/lib/" + strings.Repeat("verylongdirectoryname/", 6) + "tool"
	got := wrapMark("  ← every process loads " + long + " before its own code")

	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, long) {
		t.Errorf("wrapMark split a %d-character token across lines:\n%s\nA path cut in half "+
			"is a lie about a path, and every sentence in this table names one", len(long), joined)
	}
	if len(got) < 2 {
		t.Fatalf("the fixture fitted on one line, so nothing was wrapped: %q", joined)
	}
	// The hanging indent is what makes a wrapped mark read as one statement
	// rather than as two.
	if !strings.HasPrefix(got[0], strings.Repeat(" ", markIndent)+"←") {
		t.Errorf("first fragment is not indented to the mark column: %q", got[0])
	}
	for _, frag := range got[1:] {
		if !strings.HasPrefix(frag, strings.Repeat(" ", markIndent+markWrapPad)) {
			t.Errorf("continuation fragment lost the hanging indent: %q", frag)
		}
	}
}

// TestNoEnvironmentLineCanBeMistakenForAMark is a SECURITY test, and it will
// read as pedantry to anyone who has not worked out why the indent is 21.
//
// The marks are snug's own words: `← not granted` is a verdict a human acts on.
// The values beside them are a PROFILE's words, and a profile is a file whose
// author snug does not vet (§1.4 — the author is trusted, the payload is not,
// and the screen is what a human uses to tell one grant from another). A value
// can contain `←`: visibleValue escapes control characters, and `←` is not one.
//
// So the two must be told apart by GEOMETRY, not by a glyph. Column 19 is taken
// — a continuation BAND of a list variable renders pad("",16), exactly 19
// spaces, and so does a drop line — which means a mark rendered there would be
// distinguishable from a value only by the arrow it starts with. At 21 no data
// line can reach the column, so:
//
//	2 spaces + non-space   a row carrying its own name
//	exactly 19 spaces      a continuation band, or a drop line
//	21 or more             snug's own mark, or the wrap of one
//
// Nothing renders at exactly 20. This is the rule the reader can rely on, and
// the rule a forged mark would have to break.
//
// THE INDENT IS COUNTED WITH unicode.IsSpace, NOT WITH " ", and that changed
// after a red team looked for the gap (host round 2, §4.1). Computing it as
// `len(line) - len(TrimLeft(line, " "))` counts ASCII spaces only, so a value
// beginning with U+00A0 or U+2003 would score an indent of 19 while PAINTING 21
// blank columns — a line that reads as snug's own mark and is classified as a
// data line. It is latent rather than live (see the sweep below for why nothing
// can currently get such a value onto a continuation line at all), and a latent
// hole in the test that is supposed to detect the hole is worth one line.
func TestNoEnvironmentLineCanBeMistakenForAMark(t *testing.T) {
	// The fixture has to contain all three shapes or the rule is asserted over
	// whatever happens to be there. Counted, then required, below.
	var bands, drops, markLines int

	for name, block := range renderedEnvBlocks(t) {
		for _, line := range strings.Split(block, "\n") {
			if line == "" || !strings.HasPrefix(line, "  ") {
				continue // the block heading
			}
			indent := visualIndent(line)
			switch {
			case indent == 2:
				// a row with its name in the label column
			case indent == 19:
				if strings.HasPrefix(trimIndent(line), "(") {
					drops++
				} else {
					bands++
				}
				if strings.HasPrefix(trimIndent(line), "←") {
					t.Errorf("%s: a mark rendered at column 19, where a continuation band and a "+
						"drop line also start:\n%s\nAt that column snug's own verdict and a "+
						"profile's value are told apart only by the arrow — and a value may "+
						"contain one", name, line)
				}
			case indent >= markIndent:
				markLines++
			default:
				t.Errorf("%s: a line at indent %d, which is neither a row (2), a continuation "+
					"band or drop line (19), nor a mark (%d+):\n%s\nThe three shapes are what "+
					"lets a reader — and rowFor — tell snug's words from a profile's",
					name, indent, markIndent, line)
			}
		}
	}
	if bands == 0 || drops == 0 || markLines == 0 {
		t.Fatalf("the corpus is missing one of the three shapes (bands=%d drops=%d marks=%d), "+
			"so the rule was checked against an incomplete screen", bands, drops, markLines)
	}
}

// TestAValueCannotForgeAMarkLine is the same rule from the attacker's side: a
// profile writes a PATH element that looks exactly like snug's own verdict, and
// the screen must still make clear which words are whose.
//
// It is a list element, because that is the only value that reaches a
// continuation line at all — a scalar always renders on the row that carries its
// name, where the columns give it away.
func TestAValueCannotForgeAMarkLine(t *testing.T) {
	m := map[policy.ProfileName]*policy.Profile(mustBuiltins(t))
	m["forge"] = &policy.Profile{
		Name:    "forge",
		Include: []policy.ProfileName{"@sys", "@home", "@cwd-rw"},
		// Absolute (a relative element is refused outright), GRANTED (the
		// coupling rule refuses a path the profile does not bring — which is why
		// the forgery has to live under the fixture $HOME rather than anywhere
		// convenient), and spelled without a space so elementValue does not quote
		// it. That is the most mark-shaped value a profile can actually get onto
		// the screen.
		Environ: policy.EnvGrants{Merge: map[string][]string{"PATH": {"{home}/←not-granted"}}},
	}
	p, err := policy.Resolve(m, append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...),
		"forge"), envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	got := captureFile(t, func(f *os.File) { describeEnvironment(f, p) })

	if !strings.Contains(got, "←not-granted") {
		t.Fatalf("the forged value never reached the screen, so this test measures nothing:\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if !strings.Contains(line, "←not-granted") {
			continue
		}
		indent := visualIndent(line)
		if indent >= markIndent {
			t.Errorf("a profile's value rendered at the mark column:\n%q\nAt indent %d it is "+
				"indistinguishable from a sentence snug wrote", line, indent)
		}
	}
}

// visualIndent and trimIndent count and strip EVERY kind of space, not only
// U+0020.
//
// The rule this file enforces is about COLUMNS a reader sees, and U+00A0 (no-break
// space) and U+2003 (em space) paint one each while `strings.TrimLeft(s, " ")`
// leaves them in place. So a value beginning with one would be classified as a
// data line at indent 19 while occupying the mark column — the forgery this test
// exists to catch, wearing the one costume the test could not see. Found by a red
// team as a latent hole in the TEST rather than in the renderer (host round 2,
// §4.1), and it stays latent only because of the structural property asserted in
// internal/policy's TestEveryMergeableListIsPathValued.
func visualIndent(line string) int {
	return len(line) - len(trimIndent(line))
}

func trimIndent(line string) string {
	return strings.TrimLeftFunc(line, unicode.IsSpace)
}

// longestToken is the width of the longest space-delimited token on a line,
// counted in runes — what wrapMark could not have broken.
func longestToken(line string) int {
	max := 0
	for _, tok := range strings.Fields(line) {
		if w := utf8.RuneCountInString(tok); w > max {
			max = w
		}
	}
	return max
}
