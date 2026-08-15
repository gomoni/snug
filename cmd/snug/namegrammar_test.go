package main

import (
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// T8. The sink half of the include-target grammar (internal/profile's
// TestIncludeTargetMustBeALegalName): after that change no FILE can produce an
// include this ugly, so proving the renderer is still safe means constructing
// the registry directly rather than going through parse — a bug elsewhere (or
// a future caller of Registry that skips parse) must not turn back into a
// forged row on this screen.
//
// "root" is a legal, known profile; its one include is not in the registry at
// all, so printTree recurses into the "(unknown)" branch — the site
// TestNoSnugScreenEmitsARawControlCharacter's own sweep does not reach, since
// that test drives dryRun/describeEnvironment rather than `snug profile tree`.
func TestProfileTreeDoesNotRenderAnUnknownIncludeVerbatim(t *testing.T) {
	const forged = "FORGED-BY-AN-INCLUDE"
	reg := profile.Registry{
		"root": &policy.Profile{Name: "root", Include: []string{"a\x1b[1A\r" + forged}},
	}

	got := captureStdout(t, func() {
		printTree(reg, "root", "", "", map[string]bool{})
	})

	// The positive control: without it, a tree walk that silently dropped the
	// unknown include (printed nothing at all) would pass the ESC/CR check
	// below for measuring nothing.
	if !strings.Contains(got, forged) {
		t.Fatalf("the fixture include never reached the screen, so this test measures nothing:\n%s", got)
	}
	if strings.ContainsAny(got, "\x1b\r") {
		t.Errorf("printTree rendered an unknown include's name with a raw ESC or CR, forging a "+
			"row on the tree:\n%s", strings.ReplaceAll(got, "\x1b", "<ESC>"))
	}
}

// T9. The three dryrun.go sites: the PROFILES line, the "+ ... pulled in by
// include" line, and pathAnnotation's "via ..." — the site whose absence let
// the live defect stand (this whole file is the regression the driver's task
// description names).
//
// Two malicious names, injected directly into the registry after
// internal/profile.checkName/checkRef have already been proven to refuse
// them at parse time — the same "no file could produce this, so prove the
// downstream renderer independently" shape as T8, mirroring
// TestControlCharacterInAGuestPathIsRefused above.
func TestDryRunDoesNotRenderAProfileNameVerbatim(t *testing.T) {
	const forgedSelected = "FORGED-SELECTED-PROFILE"
	const forgedImplied = "FORGED-IMPLIED-PROFILE"
	malSelected := "sel\x1b[1A\r" + forgedSelected
	malImplied := "inc\x1b[1A\r" + forgedImplied

	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]*policy.Profile(reg)
	// "carrier" pulls in malImplied by INCLUDE, so it is never in p.Selected —
	// only in p.Implied(), which is the second site. malSelected is picked
	// directly, hitting the PROFILES line, and it grants a tmpfs at an
	// ANCESTOR of $HOME so that mountedAt's covering mount for HOME has
	// Guest ("/home") != path ("/home/u"), which is pathAnnotation's "via ..."
	// branch — the third site.
	m["carrier"] = &policy.Profile{Name: "carrier", Include: []string{malImplied}}
	m[malSelected] = &policy.Profile{Name: malSelected, Tmpfs: []string{"/home"}}
	m[malImplied] = &policy.Profile{Name: malImplied}

	// @sys and @parent-ro (not @cwd-rw, which includes @home and would mount
	// $HOME itself — making it the DEEPEST covering mount and defeating the
	// point of malSelected's ancestor grant) round the selection out to one
	// Validate actually admits, so this test stays about the three dryrun.go
	// sites and does not also exercise the unescaped Validate-refusal message
	// dryRun prints at the bottom of a REFUSED run — a fourth, real gap this
	// fixture found by accident and which is reported separately rather than
	// silently dodged.
	sel := []string{"@sys", "@parent-ro", malSelected, "carrier"}
	p, resolveErr := policy.Resolve(m, sel, envGoldenCtx(), newEnvFakeEnv())
	if resolveErr != nil {
		t.Fatalf("Resolve refused this selection: %v", resolveErr)
	}

	// Positive controls: the fixtures actually reach the fields this test
	// exists to cover, before asking whether the SCREEN forged anything.
	selectedOK := false
	for _, n := range p.Selected {
		if n == malSelected {
			selectedOK = true
		}
	}
	if !selectedOK {
		t.Fatalf("malSelected is not in p.Selected: %v", p.Selected)
	}
	impliedOK := false
	for _, n := range p.Implied() {
		if n == malImplied {
			impliedOK = true
		}
	}
	if !impliedOK {
		t.Fatalf("malImplied is not in p.Implied(): %v", p.Implied())
	}

	got := captureStdout(t, func() { dryRun(p, p.BwrapArgs(0, 0), config{}, resolveErr) })

	if !strings.Contains(got, forgedSelected) {
		t.Fatalf("the selected profile's marker never reached the screen, so the PROFILES site "+
			"was never exercised:\n%s", got)
	}
	if !strings.Contains(got, forgedImplied) {
		t.Fatalf("the implied profile's marker never reached the screen, so the \"pulled in by "+
			"include\" site was never exercised:\n%s", got)
	}
	if strings.ContainsAny(got, "\x1b\r") {
		t.Errorf("--dry-run rendered a profile name with a raw ESC or CR:\n%s",
			strings.ReplaceAll(got, "\x1b", "<ESC>"))
	}
}

// printTree has THREE printing branches, and the first pass of issue #20
// guarded two of them: the "(unknown)" branch T8 covers, and the normal branch
// below it. The diamond branch — reached when `include` composes as a set and
// the same profile is arrived at twice — sat between them rendering `name`
// raw.
//
// A registry key cannot carry a control character now that checkName is an
// allowlist, so this is defence in depth and not a live hole. That is the part
// worth keeping: it was missed precisely BECAUSE nothing could reach it, in
// the change whose own subject is that a rule must not be applied to one of
// its halves. Found by reading the function, not by escaping through it.
//
// a→b, a→c, b→d, c→d: d is arrived at twice and the second visit takes the
// diamond branch.
func TestProfileTreeEscapesADiamondInclude(t *testing.T) {
	const forged = "FORGED-BY-A-DIAMOND"
	dup := "d\x1b[1A\r" + forged
	reg := profile.Registry{
		"a": &policy.Profile{Name: "a", Include: []string{"b", "c"}},
		"b": &policy.Profile{Name: "b", Include: []string{dup}},
		"c": &policy.Profile{Name: "c", Include: []string{dup}},
		dup: &policy.Profile{Name: dup},
	}

	got := captureStdout(t, func() {
		printTree(reg, "a", "", "", map[string]bool{})
	})

	// Two positive controls, because this test can pass vacuously in two
	// different ways. First: the walk must actually reach the name.
	if !strings.Contains(got, forged) {
		t.Fatalf("the fixture never reached the screen, so this test measures nothing:\n%s", got)
	}
	// Second, and the one that matters: it must reach the DIAMOND branch. Without
	// this, a walk that visited the duplicate only once would exercise the
	// already-guarded normal branch and report success for the wrong site.
	if !strings.Contains(got, "(already included above)") {
		t.Fatalf("the fixture never took the diamond branch, so the guard under test was "+
			"never executed:\n%s", got)
	}
	if strings.ContainsAny(got, "\x1b\r") {
		t.Errorf("printTree rendered a diamond include's name with a raw ESC or CR:\n%s",
			strings.ReplaceAll(got, "\x1b", "<ESC>"))
	}
}

// A profile DESCRIPTION is attacker-supplied and, unlike a name, deliberately
// unvalidated: it is prose, and refusing punctuation in prose would be absurd.
// So the visibleValue guard on `snug profile list` is load-bearing in
// production rather than defence in depth — and deleting it turned NO test
// red. That is the pasta.avx2 shape caught in advance: a guard whose removal
// nothing notices is a guard that will eventually be removed.
//
// Goes through a real file and a real profile.Load, because a description
// reaching this screen unescaped is exactly what a hostile profiles.d does.
func TestProfileListEscapesADescription(t *testing.T) {
	const forged = "FORGED-BY-A-DESCRIPTION"
	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/snug/profiles.d", 0o755); err != nil {
		t.Fatal(err)
	}
	body := "[profile.forge]\n" +
		"description = \"harmless\\u001b[1A\\r" + forged + "\"\n" +
		"ro = [\"/etc/hostname\"]\n"
	if err := os.WriteFile(dir+"/snug/profiles.d/forge.toml", []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)

	var code int
	got := captureStdout(t, func() { code = profileCmd([]string{"list"}) })
	if code != 0 {
		t.Fatalf("`profile list` exited %d:\n%s", code, got)
	}
	if !strings.Contains(got, forged) {
		t.Fatalf("the fixture description never reached the screen:\n%s", got)
	}
	if strings.ContainsAny(got, "\x1b\r") {
		t.Errorf("`snug profile list` emitted a raw ESC or CR from a profile description, "+
			"forging a row on the one screen whose job is to say what profiles exist:\n%s",
			strings.ReplaceAll(got, "\x1b", "<ESC>"))
	}
}
