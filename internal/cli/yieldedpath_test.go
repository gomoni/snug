package cli

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// ── issue #223: a profile can take over /tmp and nothing said so ────────────
//
// yieldTo() installs snug's own mount only if nothing already claims that guest
// path. That is deliberate — it is how a profile hands a host directory to the
// sandbox as its /tmp. What is not deliberate
// is @parent-ro reaching /tmp by accident of where the target sits: `snug
// /tmp/proj` makes the target's parent /tmp, so the private tmpfs never lands and
// the sandbox runs with the HOST's /tmp read-only, $TMPDIR pointing into it, no
// refusal and nothing on screen.
//
// Two things stop being true for that run, and the first is a documented count.
// CLAUDE.md says the writable surface is EIGHT paths with /tmp among them; here
// it is seven, and nothing said the guarantee changed. That is invariant 5's
// subject exactly.
//
// SAID RATHER THAN REFUSED, deliberately: `snug /tmp/x` is ordinary — `mktemp -d`
// targets are how VERIFY.md and the whole integration suite build theirs — so a
// refusal would break snug's own workflow unless it could tell "the yield was
// asked for" from "the yield happened by accident", and this layer cannot.
//
// WHY THIS IS NOT A GOLDEN. The change moved no golden at all, because every
// dry-run fixture in this package uses a synthetic target that is not under /tmp.
// A golden nobody's fixture exercises proves nothing about the row it renders —
// the same gap issue #59 turned up in NOT GRANTED.

// renderFilesystem builds a policy with one mount at guest and returns the
// FILESYSTEM block. authored mirrors what yieldTo() sets on snug's own mounts.
func renderFilesystem(t *testing.T, guest string, kind policy.Kind, access policy.Access, authored bool, from string) string {
	t.Helper()
	p := &policy.Policy{
		Target: "/home/u/proj",
		Home:   "/home/u",
		Mounts: map[string]policy.Mount{
			guest: {
				Kind: kind, Guest: guest, Host: guest,
				Access: access, Authored: authored, From: []string{from},
			},
		},
	}
	return dryRunText(p, p.BwrapArgs(0, 0), config{}, nil)
}

func TestDryRunSaysWhenAProfileTookOverSnugsOwnTmp(t *testing.T) {
	got := renderFilesystem(t, "/tmp", policy.KindBind, policy.AccessRO, false, "@parent-ro")

	for _, want := range []struct{ text, why string }{
		{"HOST's /tmp", "the fact: it is not snug's private one"},
		{"never landed", "why — the tmpfs snug would have installed did not"},
		{"$TMPDIR points inside it", "the practical consequence, and the one that breaks builds"},
		{"READ-ONLY", "this row is a ro bind, so the tmpdir is read-only too"},
	} {
		if !strings.Contains(got, want.text) {
			t.Errorf("the /tmp row does not say %q — %s\n%s", want.text, want.why, got)
		}
	}
}

// A rw takeover — a profile binding a host directory at /tmp — is a deliberate
// profile doing its job. It still gets the "this is the host's" note, because
// that is true and worth knowing, but not the read-only warning, which would be
// false.
func TestAWritableTakeoverIsNotCalledReadOnly(t *testing.T) {
	got := renderFilesystem(t, "/tmp", policy.KindBind, policy.AccessRW, false, "sharedtmp")
	if !strings.Contains(got, "HOST's /tmp") {
		t.Errorf("a writable takeover still replaces snug's private tmpfs and must say so:\n%s", got)
	}
	if strings.Contains(got, "READ-ONLY") {
		t.Errorf("a rw bind was described as READ-ONLY, which is simply false:\n%s", got)
	}
}

// THE POSITIVE CONTROL, and the one that makes the test above mean anything.
// snug's own tmpfs at /tmp must render with no mark at all — otherwise every
// ordinary run carries a warning, and a warning on every run is one nobody reads.
func TestSnugsOwnTmpCarriesNoMark(t *testing.T) {
	got := renderFilesystem(t, "/tmp", policy.KindTmpfs, policy.AccessRW, true, "(snug)")
	for _, unwanted := range []string{"HOST's /tmp", "never landed", "READ-ONLY"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("snug's OWN /tmp was marked as a takeover (%q). The mark keys on "+
				"Mount.Authored, which yieldTo() sets; if that stopped being set, every "+
				"default run now carries this warning:\n%s", unwanted, got)
		}
	}
}

// /proc and /dev go through the same yieldTo() and have the same blind spot.
// Asserting the set rather than the site, per CLAUDE.md.
func TestTheOtherYieldablePathsAreCoveredToo(t *testing.T) {
	for _, guest := range []string{"/proc", "/dev"} {
		got := renderFilesystem(t, guest, policy.KindBind, policy.AccessRO, false, "@probe")
		if !strings.Contains(got, "a profile claimed "+guest) {
			t.Errorf("a profile took over %s and the screen did not say so. yieldTo() treats "+
				"/proc, /dev and /tmp identically, so a mark for one of the three and not the "+
				"others is the 'rule applied to one of its halves' shape:\n%s", guest, got)
		}
	}
}

// An ordinary row must not gain a mark. Without this, a mark that fired on
// everything would satisfy every assertion above.
func TestAnUnrelatedRowIsNotMarked(t *testing.T) {
	got := renderFilesystem(t, "/usr", policy.KindBind, policy.AccessRO, false, "@sys")
	for _, unwanted := range []string{"HOST's /tmp", "a profile claimed"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("an ordinary /usr row was marked (%q):\n%s", unwanted, got)
		}
	}
}

// countReadOnlyAndWritable mirrors explainFilesystem's own counting rule
// (KindData excluded, everything else split by Access) so the test below
// reads the same fact --explain would print, without depending on the exact
// sentence around it.
func countReadOnlyAndWritable(p *policy.Policy) (ro, rw int) {
	for _, m := range p.SortedMounts() {
		switch {
		case m.Kind == policy.KindData:
			continue
		case m.Access == policy.AccessRW:
			rw++
		default:
			ro++
		}
	}
	return ro, rw
}

// TestTheTmpTakeoverCostsOneWritablePath is issue #223's guarantee stated as a
// DELTA rather than as absolute counts, which is what the comment on this
// file's own countReadOnlyAndWritable warns a golden cannot do: every
// dry-run fixture in this package targets a synthetic path outside /tmp, so a
// golden here would need its OWN fixture, and the moment that fixture's
// ancestry changed depth (issue #553's anchor mounts) the pinned numbers would
// go stale while every existing golden stayed green. Absolute counts are
// exactly the shape CLAUDE.md's own "eight paths" claim went stale in.
//
// The fact this fails if it stops holding: @parent-ro on a target whose
// PARENT is /tmp displaces snug's own private tmpfs at /tmp with the host's
// real one, read-only (issue #223) — so the run ends up with one FEWER
// writable path and one MORE read-only path than the identical target
// resolved without the profile, never zero, and never any other number.
func TestTheTmpTakeoverCostsOneWritablePath(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	env := newEnvFakeEnv()
	env.dirs["/tmp"] = true
	env.dirs["/tmp/proj"] = true
	ctx := policy.Context{
		Target: "/tmp/proj", Home: "/home/u", Shell: "/usr/bin/bash", Command: []string{"/bin/sh"},
	}

	without, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		[]policy.ProfileName{"@sys", "@home", "@target-rw"}, ctx, env)
	if err != nil {
		t.Fatalf("Resolve(without @parent-ro): %v", err)
	}
	with, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		[]policy.ProfileName{"@sys", "@home", "@target-rw", "@parent-ro"}, ctx, env)
	if err != nil {
		t.Fatalf("Resolve(with @parent-ro): %v", err)
	}

	// CONTROL: an ordinary target (this package's own fixture home, nowhere
	// near /tmp) gets no mark and no takeover at all — @parent-ro granting a
	// parent that is NOT /tmp must not move these counts, or the delta below
	// would be measuring "a profile was added", not "the target's parent
	// happens to be /tmp".
	ordinaryCtx := envGoldenCtx()
	ordinary, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		[]policy.ProfileName{"@sys", "@home", "@target-rw"}, ordinaryCtx, newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(ordinary target): %v", err)
	}
	if m, ok := ordinary.Mounts["/tmp"]; !ok || m.Kind != policy.KindTmpfs || !m.Authored {
		t.Fatalf("control: an ordinary target's /tmp is not snug's own authored tmpfs (%+v, ok=%v) — "+
			"this fixture no longer shows the state the takeover is a departure FROM", m, ok)
	}

	roWithout, rwWithout := countReadOnlyAndWritable(without)
	roWith, rwWith := countReadOnlyAndWritable(with)

	if got, want := roWith-roWithout, 1; got != want {
		t.Errorf("read-only count moved by %d granting @parent-ro on a /tmp target, want %d "+
			"(without=%d, with=%d)", got, want, roWithout, roWith)
	}
	if got, want := rwWith-rwWithout, -1; got != want {
		t.Errorf("writable count moved by %d granting @parent-ro on a /tmp target, want %d "+
			"(without=%d, with=%d)", got, want, rwWithout, rwWith)
	}
}
