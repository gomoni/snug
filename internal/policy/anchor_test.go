package policy

import (
	"reflect"
	"strings"
	"testing"
)

// ── InstallAnchors, issue #553 ───────────────────────────────────────────────
//
// See anchor.go's own doc comment for the rule and the reason each condition
// exists; these tests pin it rather than re-derive it.

// TestAnAncestorCoveredByATmpfsIsAnchored is the shipped shape #553 is about:
// a bare `snug ~/proj/sub` leaves the target's parent as a plain name in
// @home's tmpfs, and this is what makes it a mount root instead.
func TestAnAncestorCoveredByATmpfsIsAnchored(t *testing.T) {
	p := mustResolveDefaults(t) // testCtx: target /home/u/proj/sub

	m, ok := p.Mounts["/home/u/proj"]
	if !ok {
		t.Fatal("no mount at all at the target's parent; the default selection must anchor it")
	}
	if m.Kind != KindTmpfs {
		t.Errorf("Kind = %v, want KindTmpfs", m.Kind)
	}
	if !m.Anchor {
		t.Error("Anchor = false")
	}
	if !m.Authored {
		t.Error("Authored = false — an anchor is snug's own write, like the generated identity files")
	}
	if len(m.From) != 1 || m.From[0] != anchorFrom {
		t.Errorf("From = %v, want [%q]", m.From, anchorFrom)
	}
}

// TestNoAnchorWhereTheAncestorIsAlreadyAMount: `-p @parent-ro` binds the
// target's parent itself, so it is already a mount root by the time
// InstallAnchors runs and must be left exactly as the profile granted it.
func TestNoAnchorWhereTheAncestorIsAlreadyAMount(t *testing.T) {
	p := mustResolve(t, withParentRo()...)

	m, ok := p.Mounts["/home/u/proj"]
	if !ok {
		t.Fatal("no mount at the target's parent at all")
	}
	if m.Anchor {
		t.Error("the parent is marked Anchor even though @parent-ro grants a real bind there")
	}
	if m.Kind != KindBind || m.Access != AccessRO {
		t.Errorf("the @parent-ro bind was altered: Kind=%v Access=%v", m.Kind, m.Access)
	}
}

// TestNoAnchorUnderAReadWriteBind is the masking guard, and it fails if
// condition 3 is ever "simplified" to payloadWritable (the predicate
// CheckEngineBindSource uses one file over): an anchor is Authored, so
// rejectMasking never sees it, and an empty tmpfs stacked on a real,
// read-write host directory would hide every entry in it that no profile
// separately granted — invariant 1's subtraction, made to look like a mount
// nobody chose. A tmpfs cover has nothing underneath by construction, which is
// why only THAT cover may be anchored over.
func TestNoAnchorUnderAReadWriteBind(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		"/data":          {Guest: "/data", Kind: KindBind, Host: "/data", Access: AccessRW},
		"/data/proj/sub": {Guest: "/data/proj/sub", Kind: KindBind, Host: "/data/proj/sub", Access: AccessRW},
	}}
	p.InstallAnchors()

	if m, ok := p.Mounts["/data/proj"]; ok {
		t.Fatalf("an anchor (or anything else) was installed at /data/proj, which a read-write "+
			"bind of /data already covers — that would hide every entry under it a profile did "+
			"not separately grant: %+v", m)
	}
}

// The read-only half of the same guard: a tmpfs stacked on a read-only host
// directory hides its content just the same, and there is no writability
// exception that makes hiding safe.
func TestNoAnchorUnderAReadOnlyBind(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		"/data":          {Guest: "/data", Kind: KindBind, Host: "/data", Access: AccessRO},
		"/data/proj/sub": {Guest: "/data/proj/sub", Kind: KindBind, Host: "/data/proj/sub", Access: AccessRO},
	}}
	p.InstallAnchors()

	if m, ok := p.Mounts["/data/proj"]; ok {
		t.Fatalf("an anchor was installed at /data/proj under a read-only bind: %+v", m)
	}
}

// TestNoAnchorAtOrUnderSnugsOwnPaths asserts over the snugsOwn map generally,
// not just StagedBinDir: a hostile-shaped cover — a hypothetical future Kind,
// or simply a tmpfs standing in for the root here — must never anchor at or
// under SnugDir, because a WRITABLE directory at StagedBinDir is issue #22's
// hole arrived at from a new side (anchor.go's own reasoning). The exact
// mount that would trigger it does not exist in any shipped selection today,
// which is exactly why this is checked directly against a hand-built mount
// set rather than left to whatever Resolve happens to produce.
func TestNoAnchorAtOrUnderSnugsOwnPaths(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		// Stands in for a tmpfs covering the root — the shape that would
		// satisfy every OTHER condition InstallAnchors checks (proper
		// ancestor of a mount, not itself a mount, cover is a tmpfs) for
		// both SnugDir and StagedBinDir, exactly as it would for any other
		// path under an ordinary tmpfs.
		"/": {Guest: "/", Kind: KindTmpfs, Access: AccessRW},
		// Nested two levels under SnugDir, so the candidate ancestors are
		// SnugDir itself (StagedBinDir's parent) and StagedBinDir — the
		// second exercises snugsOwnCovered (the candidate covers a snugsOwn
		// key exactly), the first exercises snugsOwnAncestorOf (the
		// candidate is a proper ancestor of one, never equal).
		StagedBinDir + "/extra": {Guest: StagedBinDir + "/extra", Kind: KindBind, Host: "/host/extra", Access: AccessRO},
		// POSITIVE CONTROL, same cover, a path with nothing to do with
		// snug's own namespace: proves this fixture DOES produce anchors in
		// general, so the absence of one under /snug is the guard firing
		// and not an artefact of a fixture that anchors nothing at all.
		"/other/deep/thing": {Guest: "/other/deep/thing", Kind: KindBind, Host: "/host/thing", Access: AccessRO},
	}}
	p.InstallAnchors()

	if m, ok := p.Mounts["/other/deep"]; !ok || !m.Anchor {
		t.Fatalf("control: no anchor at /other/deep, which the same tmpfs cover as /snug/bin " +
			"should anchor — without this the assertions below prove nothing")
	}

	for guest, m := range p.Mounts {
		if !m.Anchor {
			continue
		}
		if _, _, ok := snugsOwnCovered(guest); ok {
			t.Errorf("anchor installed at %s, which snug's own namespace covers", guest)
		}
		if _, _, ok := snugsOwnAncestorOf(guest); ok {
			t.Errorf("anchor installed at %s, which is inside snug's own namespace", guest)
		}
	}
	if m, ok := p.Mounts[SnugDir]; ok && m.Anchor {
		t.Errorf("an anchor was installed AT %s itself", SnugDir)
	}
	if m, ok := p.Mounts[StagedBinDir]; ok && m.Anchor {
		t.Errorf("an anchor was installed AT %s itself", StagedBinDir)
	}
}

// TestNoAnchorAtASymlinkAncestor: ANY kind at a candidate path counts as
// "already taken", symlinks included — a symlink is not a mountpoint bwrap
// can overmount, and doing so would mask whatever the symlink's author
// granted (anchor.go's own comment on the loop). The assertion is that the
// symlink survives untouched, not merely that no NEW anchor row appears.
func TestNoAnchorAtASymlinkAncestor(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		"/home/u/link":      {Guest: "/home/u/link", Kind: KindSymlink, Host: "elsewhere"},
		"/home/u/link/deep": {Guest: "/home/u/link/deep", Kind: KindBind, Host: "/host/deep", Access: AccessRW},
	}}
	p.InstallAnchors()

	m, ok := p.Mounts["/home/u/link"]
	if !ok {
		t.Fatal("the symlink mount disappeared")
	}
	if m.Kind != KindSymlink || m.Anchor {
		t.Errorf("the symlink at /home/u/link was overmounted: %+v", m)
	}
}

// TestEveryGrantIsStillVisibleUnderAnAnchor: a sibling grant deeper than an
// anchor keeps its own Host and Access, and SortedMounts emits the anchor
// strictly before everything it covers — invariant 1's ordering guarantee,
// stated for the one mount kind snug installs after every profile grant.
func TestEveryGrantIsStillVisibleUnderAnAnchor(t *testing.T) {
	reg := testRegistry()
	reg["sibling"] = &Profile{Name: "sibling", RO: []string{"{home}/src/other"}}
	sel := append(append([]ProfileName{}, testDefaults...), "sibling")
	ctx := ephemeralCtx("/home/u/src/proj/sub")
	env := envWith("/home/u/src/proj/sub", "/home/u/src/other")

	p, err := Resolve(reg, sel, ctx, env)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for _, anc := range []string{"/home/u/src", "/home/u/src/proj"} {
		if m, ok := p.Mounts[anc]; !ok || !m.Anchor {
			t.Fatalf("control: expected an anchor at %s; got %+v (ok=%v)", anc, m, ok)
		}
	}
	sibling, ok := p.Mounts["/home/u/src/other"]
	if !ok {
		t.Fatal("the sibling grant is gone")
	}
	if sibling.Kind != KindBind || sibling.Access != AccessRO || sibling.Host != "/home/u/src/other" {
		t.Errorf("the sibling grant changed shape under the anchor: %+v", sibling)
	}

	sorted := p.SortedMounts()
	index := map[string]int{}
	for i, m := range sorted {
		index[m.Guest] = i
	}
	for _, m := range sorted {
		if !m.Anchor {
			continue
		}
		for guest, i := range index {
			if guest == m.Guest {
				continue
			}
			if covers(m.Guest, guest) && i < index[m.Guest] {
				t.Errorf("anchor %s sorts AFTER %s, which it covers — bwrap would shadow it",
					m.Guest, guest)
			}
		}
	}
}

// TestInstallAnchorsIsIdempotent: internal/cli/main.go calls it a second time
// after its own post-Resolve mounts, and the whole point is that this is an
// addition, never a change to what Resolve already installed.
func TestInstallAnchorsIsIdempotent(t *testing.T) {
	p := mustResolveDefaults(t)

	before := make(map[string]Mount, len(p.Mounts))
	for k, v := range p.Mounts {
		before[k] = v
	}

	p.InstallAnchors()

	if !reflect.DeepEqual(before, p.Mounts) {
		t.Errorf("a second InstallAnchors call changed the mount set\nbefore: %+v\nafter:  %+v",
			before, p.Mounts)
	}
	for guest, m := range p.Mounts {
		if !m.Anchor {
			continue
		}
		for _, f := range m.From {
			if strings.HasPrefix(f, "replaces:") {
				t.Errorf("anchor at %s carries a replaces: entry (%q) — nothing should ever be "+
					"displaced to install one, so Replace's displacement branch must be "+
					"unreachable from here", guest, f)
			}
		}
	}
}

// TestAHomeRootedTargetStillResolves is the regression test for the
// Validate.rejectTargetInAnEphemeralDirectory edit: without the Anchor
// exemption, the anchor InstallAnchors puts at the target's own parent would
// equal that rule's "parent" on every default run, and a target two or more
// levels under $HOME would stop resolving at all.
func TestAHomeRootedTargetStillResolves(t *testing.T) {
	p, err := Resolve(testRegistry(), testDefaults, ephemeralCtx("/home/u/src/proj/sub"), envWith("/home/u/src/proj/sub"))
	if err != nil {
		t.Fatalf("`snug ~/src/proj/sub` was refused: %v", err)
	}
	if m, ok := p.Mounts["/home/u/src/proj"]; !ok || !m.Anchor {
		t.Fatalf("control: expected an anchor at the target's parent; got %+v (ok=%v)", m, ok)
	}

	// #179 still refuses a target directly in $HOME, or $HOME itself: these
	// are the two cases TestATargetDirectlyInAnEphemeralDirectoryIsRefused and
	// TestATargetThatIsItselfEphemeralGetsTheOtherSentence pin already; kept
	// here too, alongside the case anchors newly unblock, so a reader of this
	// file sees the whole boundary in one place.
	if _, err := Resolve(testRegistry(), testDefaults, ephemeralCtx("/home/u/proj"), envWith("/home/u/proj")); err == nil {
		t.Error("`snug ~/proj` was accepted")
	}
	if _, err := Resolve(testRegistry(), testDefaults, ephemeralCtx("/home/u"), envWith("/home/u")); err == nil {
		t.Error("`snug ~` was accepted")
	}
}

// TestAnchorsNeverChangeAShadowSlotVerdict: an anchor's own guest path was
// already covered by a tmpfs before InstallAnchors ran (that cover is
// condition 3), so IsShadowSlot's answer at that path — and at everything
// beneath it — must be identical whether or not the anchor mount exists,
// literally rather than merely in argument: types.go's comment on the Anchor
// field promises every existing switch keeps giving the tmpfs answer.
func TestAnchorsNeverChangeAShadowSlotVerdict(t *testing.T) {
	withAnchors := mustResolveDefaults(t)

	withoutAnchors := &Policy{Mounts: map[string]Mount{}}
	anchors := 0
	for g, m := range withAnchors.Mounts {
		if m.Anchor {
			anchors++
			continue
		}
		withoutAnchors.Mounts[g] = m
	}
	if anchors == 0 {
		t.Fatal("control: the default selection installed no anchor at all; this test proves nothing")
	}

	for g := range withAnchors.Mounts {
		got, want := withAnchors.IsShadowSlot(g), withoutAnchors.IsShadowSlot(g)
		if got != want {
			t.Errorf("IsShadowSlot(%s) = %v with anchors installed, %v without", g, got, want)
		}
	}
}

// TestAnchorsDoNotChangeTheResolvedEnvironment compares two selections that
// differ in exactly one respect — whether the target's parent is snug's own
// anchor or @parent-ro's real bind of it — and carry no other Environ claim
// between them, so any difference in p.Env would be an anchor changing what
// the sandbox's environment says, which InstallAnchors runs late enough to
// avoid: it is the LAST write in Resolve before the environment is built.
func TestAnchorsDoNotChangeTheResolvedEnvironment(t *testing.T) {
	withAnchor := mustResolveDefaults(t)
	if m, ok := withAnchor.Mounts["/home/u/proj"]; !ok || !m.Anchor {
		t.Fatalf("control: expected an anchor at /home/u/proj; got %+v (ok=%v)", m, ok)
	}

	withRealBind := mustResolve(t, withParentRo()...)
	if m, ok := withRealBind.Mounts["/home/u/proj"]; !ok || m.Anchor {
		t.Fatalf("control: expected a real, non-anchor bind at /home/u/proj under @parent-ro; "+
			"got %+v (ok=%v)", m, ok)
	}

	// SNUG_PROFILES is excluded before comparing: it HONESTLY differs between
	// these two selections (one names @parent-ro, the other does not), and
	// that is a fact about the selection the user typed, not about anchoring.
	// Comparing it here would make this test fail for a reason that has
	// nothing to do with InstallAnchors.
	a := cloneEnvWithout(withAnchor.Env, "SNUG_PROFILES")
	b := cloneEnvWithout(withRealBind.Env, "SNUG_PROFILES")
	if !reflect.DeepEqual(a, b) {
		t.Errorf("the resolved environment differs depending on whether the target's parent is "+
			"an anchor or a real bind\nwith anchor:    %+v\nwith real bind: %+v", a, b)
	}
}

// cloneEnvWithout is TestAnchorsDoNotChangeTheResolvedEnvironment's own
// helper: a shallow copy of an Env map with one key dropped, so the caller's
// original is never mutated out from under it.
func cloneEnvWithout(env map[string]EnvVar, drop string) map[string]EnvVar {
	out := make(map[string]EnvVar, len(env))
	for k, v := range env {
		if k == drop {
			continue
		}
		out[k] = v
	}
	return out
}

// ── The anchored-source rule (enginebind.go), with anchors in the mount set ──

// TestAnAnchorAnchorsAnEngineBindSource is the ergonomic payoff #553 fixes:
// CheckEngineBindSource's case 2 used to fire at the target's own parent on
// this exact layout (a name in a writable tmpfs, not itself a mount root),
// and the anchor there removes that — case 3 then decides, and it is
// satisfied (see enginebind.go's "Anchors satisfy case 3" section).
func TestAnAnchorAnchorsAnEngineBindSource(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		"/home/u":          {Guest: "/home/u", Kind: KindTmpfs, Access: AccessRW},
		"/home/u/src/proj": {Guest: "/home/u/src/proj", Kind: KindBind, Host: "/home/u/src/proj", Access: AccessRW},
	}}
	p.InstallAnchors()

	if m, ok := p.Mounts["/home/u/src"]; !ok || !m.Anchor {
		t.Fatalf("control: expected an anchor at /home/u/src; got %+v (ok=%v)", m, ok)
	}

	if err := p.CheckEngineBindSource("/home/u/src/proj"); err != nil {
		t.Errorf("CheckEngineBindSource(/home/u/src/proj) = %v, want nil now that /home/u/src "+
			"is anchored", err)
	}
}

// TestASourceInsideTheTargetIsStillRefused: the anchor covers the target's
// OWN ancestor chain, never the inside of the target itself — the target is a
// read-write bind, so a plain name inside it is exactly M2's #284 primitive
// and must still refuse.
func TestASourceInsideTheTargetIsStillRefused(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		"/home/u":          {Guest: "/home/u", Kind: KindTmpfs, Access: AccessRW},
		"/home/u/src/proj": {Guest: "/home/u/src/proj", Kind: KindBind, Host: "/home/u/src/proj", Access: AccessRW},
	}}
	p.InstallAnchors()

	err := p.CheckEngineBindSource("/home/u/src/proj/inside")
	if err == nil {
		t.Fatal("CheckEngineBindSource(/home/u/src/proj/inside) = nil, want a refusal — nothing " +
			"inside the target may ever be forwarded")
	}
	if !strings.Contains(err.Error(), "inside") {
		t.Errorf("refusal does not name the offending component:\n%v", err)
	}
}

// TestASourceUnderAReadWriteBoundAncestorIsStillRefused is the residual
// anchor.go states rather than papers over: a read-write bind of a tree
// containing the target is NOT anchored over (the masking guard), so its
// child that IS a mount root is still reachable from the OTHER route the rw
// bind itself offers — case 3, rwBindCovers — exactly as before #553. No
// anchor is installed here at all, and CheckEngineBindSource must still
// refuse with case 3's message, not go silent because InstallAnchors ran.
func TestASourceUnderAReadWriteBoundAncestorIsStillRefused(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		"/data":      {Guest: "/data", Kind: KindBind, Host: "/data", Access: AccessRW},
		"/data/proj": {Guest: "/data/proj", Kind: KindBind, Host: "/data/proj", Access: AccessRW},
	}}
	p.InstallAnchors()

	if _, ok := p.Mounts["/data"]; !ok {
		t.Fatal("fixture broken: /data itself is missing")
	}

	err := p.CheckEngineBindSource("/data/proj")
	if err == nil {
		t.Fatal("CheckEngineBindSource(/data/proj) = nil, want the case-3 refusal")
	}
	for _, want := range []string{"/data", "read-write bind", "#284"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not contain %q:\n%v", want, err)
		}
	}
}
