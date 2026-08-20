package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

// ── issue #179: a target directly in $HOME ─────────────────────────────────
//
// `mkdir ~/proj && snug ~/proj` was refused by the default selection with
//
//	conflict at /home/u: tmpfs (from @home) vs bind (from @parent-ro)
//
// correct — there is no join between a tmpfs and a bind — and useless: it named
// two profiles, no working command, and did not say the problem was WHERE the
// target sits. `~/myproject` is an extremely common layout.
//
// The maintainer's call is to refuse the layout outright rather than name the
// narrow selection that works, so a project directly in an ephemeral directory
// is one answer instead of a fork somebody guesses at. Note what that means and
// what the message says out loud: a selection without @parent-ro DOES resolve.
// It used to be reachable only alongside a lethal alternative; #220 closed that,
// so this is a usability rule now, not a security one.
//
// THREE THINGS MEASURED BEFORE THIS WAS WRITTEN, each of which would have made a
// naive version wrong:
//
//  1. @home provides FIVE tmpfs paths — {home} and the four XDG directories — so
//     `~/.cache/build` produces the identical conflict at a different path. A
//     rule keyed on p.Home would have been wrong on day one.
//  2. snug's own /tmp is a tmpfs too, and `snug /tmp/x` is ordinary: `mktemp -d`
//     targets are how VERIFY.md and the whole integration suite build theirs.
//     Only tmpfs paths rooted at $HOME count.
//  3. When the target IS one of those five (`snug ~`), NO builtin selection
//     works — @cwd-rw includes @home, so a bind of the target and the tmpfs
//     collide however you select. That case needs its own sentence, because
//     "select differently" there is advice nobody can follow.

func ephemeralCtx(target string) Context {
	c := testCtx()
	c.Target = target
	return c
}

// envWith adds each path AND ITS ANCESTORS to the shared fixture rather than
// editing it. The ancestors are not padding: @parent-ro grants {target_parent}
// and Validate refuses a grant of a directory that does not exist, so a fixture
// naming only the target fails on the parent instead of on the rule under test —
// which is a test failing for the wrong reason, and looks identical to the rule
// being broken.
//
// Added here rather than to newFakeEnv() because these are this test's fixtures;
// the shared one carries a comment explaining why each of ITS entries exists.
func envWith(paths ...string) *fakeEnv {
	e := newFakeEnv()
	for _, p := range paths {
		for d := p; d != "/" && d != "."; d = filepath.Dir(d) {
			e.dirs[d] = true
		}
	}
	return e
}

func TestATargetDirectlyInAnEphemeralDirectoryIsRefused(t *testing.T) {
	reg := testRegistry()
	for _, tc := range []struct{ target, ephemeral, why string }{
		{"/home/u/proj", "/home/u", "the filed case: directly in $HOME"},
		{"/home/u/.cache/build", "/home/u/.cache", "an XDG child — the reason this is not keyed on p.Home"},
		{"/home/u/.config/nvim", "/home/u/.config", "a genuinely plausible target"},
	} {
		_, err := Resolve(reg, testDefaults, ephemeralCtx(tc.target), envWith(tc.target, tc.ephemeral))
		if err == nil {
			t.Errorf("ACCEPTED %s — %s", tc.target, tc.why)
			continue
		}
		got := err.Error()
		if strings.Contains(got, "conflict at") {
			t.Errorf("%s still reports the raw kind conflict rather than the positional "+
				"refusal. The check must run BEFORE the fold, or `join` speaks first and the "+
				"message #179 was filed about is what the user sees:\n%s", tc.target, got)
		}
		for _, want := range []string{
			"refusing to sandbox",
			tc.ephemeral,       // WHICH directory is ephemeral, not just that one is
			"Move the project", // the fix, named
			"mv ",              // an actual command, not a description of one
		} {
			if !strings.Contains(got, want) {
				t.Errorf("the refusal for %s does not contain %q:\n%s", tc.target, want, got)
			}
		}
	}
}

// The ruling in one test: the selection that RESOLVES is refused too, and the
// message says so rather than implying no working selection exists.
func TestTheSafeSelectionIsRefusedToo(t *testing.T) {
	reg := testRegistry()
	_, err := Resolve(reg, []ProfileName{"@sys", "@home", "@cwd-rw"}, ephemeralCtx("/home/u/proj"), newFakeEnv())
	if err == nil {
		t.Fatal("`--no-defaults -p @sys -p @home -p @cwd-rw ~/proj` was accepted. It resolves " +
			"cleanly, and the maintainer's ruling on #179 is that it is refused anyway: a " +
			"project directly in an ephemeral directory is the wrong thing to sandbox")
	}
	if !strings.Contains(err.Error(), "does resolve") {
		t.Errorf("the refusal hides the fact that a selection without @parent-ro works. A "+
			"message that conceals a true option is the kind of thing this repo files issues "+
			"about:\n%v", err)
	}
}

// The target IS the ephemeral directory. Different sentence, because there is no
// selection to point at.
func TestATargetThatIsItselfEphemeralGetsTheOtherSentence(t *testing.T) {
	reg := testRegistry()
	_, err := Resolve(reg, testDefaults, ephemeralCtx("/home/u"), newFakeEnv())
	if err == nil {
		t.Fatal("`snug ~` was accepted")
	}
	got := err.Error()
	if !strings.Contains(got, "No selection sandboxes this path") {
		t.Errorf("the target IS the tmpfs, so no selection works — measured. The message must "+
			"not send the user off to try one:\n%s", got)
	}
	if strings.Contains(got, "Move the project one level down") {
		t.Errorf("told the user to move a project when the target is their home directory:\n%s", got)
	}
}

// POSITIVE CONTROLS. A rule that refused everything would satisfy all of the
// above and make snug useless.
func TestTheEphemeralTargetRuleIsNarrow(t *testing.T) {
	reg := testRegistry()
	for _, tc := range []struct{ target, why string }{
		{"/home/u/proj/sub", "one level down — the layout the refusal tells people to move to"},
		{"/home/u/src/deep/project", "deeper still"},
		{"/tmp/build", "snug's own /tmp is a tmpfs, and mktemp -d targets are how the suite works"},
		{"/tmp/build/sub", "and one below it"},
	} {
		if _, err := Resolve(reg, testDefaults, ephemeralCtx(tc.target), envWith(tc.target)); err != nil {
			t.Errorf("REFUSED %s — %s\n%v", tc.target, tc.why, err)
		}
	}
}

// TWO HALVES OF ONE RULE, and this project has a standing complaint about
// exactly that shape. The pre-fold check in Resolve exists because `join` would
// otherwise speak first; Validate carries the same rule over resolved mounts, for
// a policy built without going through Resolve. If they ever disagree, one of
// them is a rule that does not fire.
func TestBothHalvesOfTheEphemeralRuleAgree(t *testing.T) {
	for _, tc := range []struct {
		target string
		want   bool
	}{
		{"/home/u/proj", true},
		{"/home/u", true},
		{"/home/u/.cache/x", true},
		{"/home/u/proj/sub", false},
		{"/tmp/x", false},
	} {
		// The Validate half, over a hand-built policy carrying the same tmpfs
		// set @home grants.
		p := &Policy{
			Target: tc.target,
			Home:   "/home/u",
			Mounts: map[string]Mount{},
		}
		for _, g := range []string{"/home/u", "/home/u/.cache", "/home/u/.config", "/tmp"} {
			p.Mounts[g] = Mount{Kind: KindTmpfs, Guest: g, Access: AccessRW, From: []string{"@home"}}
		}
		validateRefused := p.rejectTargetInAnEphemeralDirectory() != nil
		if validateRefused != tc.want {
			t.Errorf("Validate half: %s refused=%v, want %v", tc.target, validateRefused, tc.want)
		}

		// The Resolve half, over the real registry.
		_, err := Resolve(testRegistry(), testDefaults, ephemeralCtx(tc.target), envWith(tc.target))
		resolveRefused := err != nil
		if resolveRefused != tc.want {
			t.Errorf("Resolve half: %s refused=%v, want %v (%v)", tc.target, resolveRefused, tc.want, err)
		}
	}
}

// The home-rooted restriction, exercised where it is actually load-bearing.
//
// Found by mutation: dropping `covers(home, g)` from the PRE-FOLD half changed
// no test. The reason is worth writing down — snug's own /tmp tmpfs is installed
// by yieldTo() AFTER the fold, so it is never a profile GRANT and the pre-fold
// scan never sees it. The /tmp control covers the Validate half, where /tmp does
// appear in Mounts, and covered nothing here.
//
// What the restriction actually protects is a profile that makes some path
// outside $HOME ephemeral. Without it, a target inside such a path would be
// refused with a message about the home directory, which is both wrong and
// confusing.
func TestOnlyEphemeralDirectoriesRootedAtHomeRefuseATarget(t *testing.T) {
	reg := testRegistry()
	reg["scratch"] = &Profile{
		Name:  "scratch",
		Tmpfs: []string{"/scratch"},
		RW:    []string{"{target}"},
	}
	sel := []ProfileName{"@sys", "scratch"}
	env := envWith("/scratch/proj")

	if _, err := Resolve(reg, sel, ephemeralCtx("/scratch/proj"), env); err != nil {
		t.Errorf("REFUSED a target inside a tmpfs that is NOT rooted at $HOME:\n%v\n"+
			"Only $HOME-rooted ephemeral directories refuse a target. snug's own /tmp is a "+
			"tmpfs and `snug /tmp/x` must keep working, which is the same rule seen from the "+
			"other side", err)
	}
}
