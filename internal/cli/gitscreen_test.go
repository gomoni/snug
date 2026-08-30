package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// THE GIT EXTRACTION BAND IS A SCREEN, AND IT IS ON THE STREAM THE SWEEP DID NOT
// CAPTURE.
//
// TestNoSnugScreenEmitsARawControlCharacter drives dryRun and, until this
// change, captured os.Stdout alone. Everything this band prints goes to STDERR,
// from `hostGitValues`, which main calls BEFORE a Policy exists to dry-run — so
// the sweep whose name says "no snug screen" could not have seen any of it, and
// `gitValuesLine`'s own doc comment said it rendered "for --dry-run", which sent
// the next reader to look in exactly the place that was already green. Found by
// review, not by the sweep. That is the ENVIRONMENT-block-fixed-argv-block-left-
// broken shape, one STREAM over instead of one block over.
//
// WHAT THIS TEST IS, and why it is not a list of four call sites: it poisons
// every HOST INPUT the band reads and then asserts the property over everything
// the band PRINTS. A message added to this band later renders one of those
// inputs or it renders nothing interesting, so a new raw sink fails here without
// anyone remembering to extend a list.
//
// The four channels, all of them host-controlled and none of them refusable:
//
//   - a whitelisted VALUE in the host's gitconfig     -> `git config extracted:`
//   - a FILE PATH reached through include.path        -> `dropping git … from …`
//   - the same, through includeIf "onbranch:"         -> `ignoring an includeIf …`
//   - git's OWN stderr, when it refuses a file        -> `git refused to parse …`
//
// The last two are worth naming precisely: the PATH is chosen by a VALUE in the
// host's config, so "it is only a filename" is not a defence — a config that
// includes ./<crafted name>/x picks the text snug prints.
func TestTheGitExtractionBandNeverRendersHostTextRaw(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		// A skip is a test that did not run, so say what stops it rather than
		// leaving a silent green. `make gate` runs on a host with git.
		t.Skip("git is not installed, so the extraction band cannot be driven at all")
	}
	// U+202E reverses the rest of the rendered line; U+009B is CSI, the
	// single-character form of ESC-[. Both are invisible in the fixture, which is
	// why the marker text is spelled backwards: on a bidi-rendering terminal the
	// value below reads as "…-RLO".
	const rlo, csi = "\u202e", "\u009b"
	const marker = "OLR-DEGROF"

	root := t.TempDir()
	// A DIRECTORY whose NAME carries the override, so every message naming a file
	// under it renders host text. A host config reaches this by one include.path
	// line; snug has no say in what it is called.
	dir := filepath.Join(root, "conf"+rlo+marker)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "proj")
	if err := os.MkdirAll(filepath.Join(target, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	sel := []policy.ProfileName{"@git-ro"}

	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The whole screen, both streams, from the REAL function main calls.
	run := func(global string) string {
		t.Setenv("GIT_CONFIG_GLOBAL", global)
		return captureStdout(t, func() {
			// A collector writing to os.Stderr, built INSIDE the capture:
			// captureStdout swaps the stream around this closure, and a notes
			// built outside would hold the real one. verbose, because the
			// `git config extracted:` line this test sweeps is an aside.
			_, err := hostGitValues(reg, sel, root, target, newNotes(os.Stderr, true), true)
			if err != nil {
				// dryRun=true, so hostGitValues prints and returns nil; anything
				// else would mean this test is measuring a different path.
				t.Errorf("hostGitValues returned an error instead of printing it: %v", err)
			}
		})
	}
	check := func(what, screen string, want ...string) {
		t.Helper()
		// POSITIVE CONTROLS FIRST. Without them a band that printed nothing at
		// all — a fixture git no longer parses, a message deleted — passes every
		// assertion below, which is the failure mode this project has already
		// shipped once.
		for _, w := range want {
			if !strings.Contains(screen, w) {
				t.Fatalf("%s: the screen does not carry %q, so this case measures "+
					"nothing:\n%s", what, w, screen)
			}
		}
		if i := strings.IndexFunc(screen, func(r rune) bool {
			return r != '\n' && policy.IsForgingRune(r)
		}); i >= 0 {
			t.Errorf("%s: a raw forging rune (%q) reached the screen. Something in the "+
				"git band renders host text verbatim — route it through "+
				"policy.VisibleText:\n%q", what, []rune(screen[i:])[0], screen)
		}
		// The rune sweep has to exempt '\n' (these messages are legitimately
		// several lines), so it structurally cannot see a NEWLINE smuggled in
		// through host text. The escaped form of the poisoned name is what proves
		// the value went through VisibleText rather than merely containing no
		// rune the sweep looks at.
		if strings.Contains(screen, rlo) || strings.Contains(screen, csi) {
			t.Errorf("%s: host text reached the screen unescaped:\n%q", what, screen)
		}
	}

	// ── the VALUE channel, plus both messages that name an included FILE ─────
	inc := filepath.Join(dir, "inc.gitconfig")
	write(inc, "[user]\n\temail = drop\u0001me@example.invalid\n"+
		"[includeIf \"onbranch:main\"]\n\tpath = "+inc+"\n")
	global := filepath.Join(root, "gitconfig")
	write(global, "[user]\n\tname = Some"+rlo+marker+" One"+csi+"1A\n"+
		"[include]\n\tpath = "+inc+"\n")

	check("the value and the two file messages", run(global),
		"git config extracted:",
		"dropping git user.email from",
		"ignoring an `includeIf")

	// ── git's OWN stderr, which snug quotes back verbatim ────────────────────
	//
	// A separate run because this one ABORTS the extraction: a file git refuses
	// to parse is invariant 5's case, not a value to skip.
	bad := filepath.Join(dir, "bad.gitconfig")
	write(bad, "[user\nthis is not a git config\n")
	write(global, "[user]\n\tname = Plain Name\n[include]\n\tpath = "+bad+"\n")

	check("git's own error text", run(global), "git refused to parse")

	// THE CONTROL, and it is what keeps the fix from being "escape everything":
	// an ordinary config renders its values as themselves, accents included. A
	// band that %q'd every line would pass every assertion above while making the
	// verbose output unreadable.
	plain := filepath.Join(root, "plain.gitconfig")
	write(plain, "[user]\n\tname = Ada Lovelace\n\temail = ada@example.invalid\n")
	screen := run(plain)
	if !strings.Contains(screen, "user.name=Ada Lovelace") {
		t.Errorf("an ordinary value was not rendered as itself, which makes the verbose "+
			"line harder to read than the problem it reports:\n%s", screen)
	}
}
