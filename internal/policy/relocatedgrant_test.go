package policy

import (
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"testing"
)

// A GRANT'S GUEST PATH IS WHERE IT LANDS — AND NOWHERE ELSE (issue #588).
//
// bwrap resolves a mount's destination component by component, INSIDE the
// sandbox, against whatever a covering bind already supplies there. A host
// symlink inside a bound tree therefore diverts the mountpoint to wherever the
// SANDBOX has the link's text, which can be another profile's grant. Before
// this rule, that divergence was invisible: the content is still reachable at
// the guest path a profile named (the same link chain a process would
// follow), so --dry-run's FILESYSTEM row is not false about the guest path —
// it is silent about the LANDING, which is where the mountpoint really goes
// and whatever grant supplies that path controls what ends up there. MEASURED
// (issue #588, bubblewrap 0.12.0): a second profile's translating cover, with
// a host symlink inside it, landed a `--ro-bind` on top of an earlier
// profile's `rw` grant — exit 0, no refusal, and the ACCESS a first profile
// had granted changed with no line of --dry-run naming it.
//
// rejectMasking (validate.go) is unchanged by this fix and now correct rather
// than accidentally correct: after rejectRelocatedGrant runs, m.Guest IS the
// landing for every mount it compares, so its lexical comparison of guest
// paths is the landing comparison.

// twoOf is testDefaults plus extra names, for the fixtures below that need
// the default OS runtime and target as well as the neutral, unrelated grants
// under test.
func twoOf(names ...ProfileName) []ProfileName {
	return append(append([]ProfileName{}, testDefaults...), names...)
}

// relocationRegistry is testRegistry() plus the two profiles the ticket's own
// reproduction uses: victim grants rw on a plain directory, evil grants ro on
// a translating cover PLUS a second mount whose host source is a subdirectory
// of victim's own tree — the shape a host symlink inside the cover can steer
// onto.
func relocationRegistry() map[ProfileName]*Profile {
	reg := testRegistry()
	reg["victim"] = &Profile{Name: "victim", RW: []string{"/w"}}
	reg["evil"] = &Profile{Name: "evil",
		RO: []string{"/cover:/G", "/w/mnt:/G/sub/mnt"}}
	return reg
}

// relocationEnv is newFakeEnv() plus the host directories the two profiles
// above grant, and the host symlink that steers evil's second mount onto
// victim's tree: $cover/sub -> $w, exactly the ticket's own reproduction.
func relocationEnv() *fakeEnv {
	env := newFakeEnv()
	env.dirs["/w"] = true
	env.dirs["/w/mnt"] = true
	env.dirs["/cover"] = true
	env.links["/cover/sub"] = "/w"
	return env
}

// ── golden-refusal producers (issue #588) ───────────────────────────────────
//
// Five rows, one per refusal arm: a mount that lands on another profile's
// grant, one that lands nowhere any grant covers, an Lstat error partway
// through the walk, the link-budget bound, and the after-me ordering refusal.
// Each is built once here and reused by TestGoldenRefusals's table
// (refusals_test.go) — the house convention every other refusal in that file
// follows — and by a focused Test* below where §8 names one.

// refusalRelocatedOntoAnotherGrant is item 1: the ticket's exact reproduction.
// Resolve validates internally (resolve.go), so its own returned error IS the
// refusal — there is no separate policy to hand to Validate a second time.
func refusalRelocatedOntoAnotherGrant(t testing.TB) error {
	_, err := Resolve(relocationRegistry(), twoOf("victim", "evil"), testCtx(), relocationEnv())
	return err
}

// refusalRelocatedOntoNothing is item 2's fixture: base.toml's own documented
// shape (base.toml:37), a host /etc/ssl/certs -> ../../var/lib/ca-certificates/pem
// discovered two components below one profile's cover while resolving another
// profile's grant, landing nowhere any mount covers.
func refusalRelocatedOntoNothing(t testing.TB) error {
	p := resolveDefaults(t)
	p.Mounts["/etc/ssl"] = Mount{
		Guest: "/etc/ssl", Host: "/etc/ssl", Kind: KindBind, Access: AccessRO,
		From: []string{"alpha"},
	}
	p.Mounts["/etc/ssl/certs/extra.pem"] = Mount{
		Guest: "/etc/ssl/certs/extra.pem", Host: "/etc/ssl/certs/extra.pem",
		Kind: KindBind, Access: AccessRO, From: []string{"beta"},
	}
	env := newFakeEnv()
	env.links["/etc/ssl/certs"] = "../../var/lib/ca-certificates/pem"
	return p.Validate(env)
}

// refusalRelocatedLstatError is the fail-closed arm: an intermediate
// component the walk cannot examine (EACCES, not ErrNotExist) must refuse
// rather than be treated as "not there yet" — "I cannot tell where this
// lands" and "it lands outside the grant" have to give the same answer.
func refusalRelocatedLstatError(t testing.TB) error {
	p := resolveDefaults(t)
	p.Mounts["/K"] = Mount{Guest: "/K", Host: "/hostK", Kind: KindBind, Access: AccessRO,
		From: []string{"cover"}}
	p.Mounts["/K/d/x"] = Mount{Guest: "/K/d/x", Host: "/irrelevant", Kind: KindBind, Access: AccessRO,
		From: []string{"grantee"}}
	env := newFakeEnv()
	env.statErrs["/hostK/d"] = &fs.PathError{Op: "lstat", Path: "/hostK/d", Err: syscall.EACCES}
	return p.Validate(env)
}

// refusalRelocatedLinkBudgetExceeded is item 6's fixture: two host symlinks
// pointing at each other, so the walk cannot terminate by exhausting
// positions to look at and has to give up after maxGeneratedDestLinks steps.
func refusalRelocatedLinkBudgetExceeded(t testing.TB) error {
	p := resolveDefaults(t)
	p.Mounts["/K"] = Mount{Guest: "/K", Host: "/hostK", Kind: KindBind, Access: AccessRO,
		From: []string{"cover"}}
	p.Mounts["/K/a/x"] = Mount{Guest: "/K/a/x", Host: "/irrelevant", Kind: KindBind, Access: AccessRO,
		From: []string{"grantee"}}
	env := newFakeEnv()
	env.links["/hostK/a"] = "b"
	env.links["/hostK/b"] = "a"
	return p.Validate(env)
}

// refusalRelocatedAfterMe is §4's worked case: a link jump lands the walk
// DEEPER than the mount being judged, at a position whose covering mount ties
// on depth and sorts lexically AFTER it (SortedMounts' own comparator) — so
// that mount does not exist yet when bwrap creates the mountpoint being
// judged, and answering from it would be a guess. m.Guest = /G/a/b (depth 3),
// /G/a a host symlink landing at /home/u/x (depth 3, so it TIES rather than
// being an ancestor), and "/home/u/x" > "/G/a/b" lexically.
func refusalRelocatedAfterMe(t testing.TB) error {
	p := resolveDefaults(t)
	p.Mounts["/G"] = Mount{Guest: "/G", Host: "/hostG", Kind: KindBind, Access: AccessRO,
		From: []string{"cover"}}
	p.Mounts["/home/u/x"] = Mount{Guest: "/home/u/x", Kind: KindTmpfs, Access: AccessRW,
		From: []string{"other"}}
	p.Mounts["/G/a/b"] = Mount{Guest: "/G/a/b", Host: "/irrelevant", Kind: KindBind, Access: AccessRO,
		From: []string{"grantee"}}
	env := newFakeEnv()
	env.links["/hostG/a"] = "/home/u/x"
	return p.Validate(env)
}

// ── §8 items 1-3: the ticket's own reproduction ─────────────────────────────

// TestGrantLandingOnAnotherProfilesGrantIsRefused is the ticket's exact
// reproduction (issue #588): victim grants rw on /w; evil grants ro on a
// cover at /G (host /cover) and, separately, on /w/mnt at /G/sub/mnt. bwrap
// resolves /G/sub/mnt's destination inside the sandbox, where /G/sub is the
// cover's host symlink to /w — so the mountpoint it actually creates is
// /w/mnt, inside victim's own grant, not /G/sub/mnt. Before this rule
// Validate accepted the policy and victim's rw became ro with no refusal.
func TestGrantLandingOnAnotherProfilesGrantIsRefused(t *testing.T) {
	if err := refusalRelocatedOntoAnotherGrant(t); err == nil {
		t.Fatal("accepted a policy where evil's cover steers a mount onto victim's own grant " +
			"through a host symlink — the mountpoint bwrap actually creates is inside victim's " +
			"tree, at a path named by no line of --dry-run (issue #588)")
	}
}

// TestRelocationRefusalNamesTheLandingAndTheLink is the "errors name the fix"
// half: the refusal must carry both profiles' names, the guest-side location
// of the symlink that diverted the walk, the link's own unresolved text, and
// where the mountpoint really lands. Because the cover is untranslated (host
// == guest), the rendered "host path carrying the link" and the link's guest
// path are the same string, so a single substring check covers both.
func TestRelocationRefusalNamesTheLandingAndTheLink(t *testing.T) {
	err := refusalRelocatedOntoNothing(t)
	if err == nil {
		t.Fatal("accepted a grant two components below a cover whose intermediate directory is " +
			"a host symlink out of it")
	}
	for _, want := range []string{
		"alpha",                                  // owns the cover carrying the symlink
		"beta",                                   // owns the mount that lands elsewhere
		"/etc/ssl/certs",                         // the symlink's own guest-side location
		"../../var/lib/ca-certificates/pem",      // the link's own, unresolved text
		"/var/lib/ca-certificates/pem/extra.pem", // where the mountpoint really lands
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q:\n%v", want, err)
		}
	}
}

// TestRelocationRefusalIsOrderIndependent asserts the structural half of
// invariant 1 by construction: Validate reads p.Mounts as a SET, so which
// profile was selected first must not change the verdict or its wording.
// Composition turning an accepted grant into a refusal (adding evil is what
// creates the divergence) is a refusal, not a silent subtraction — the same
// shape every masking refusal already has — and that refusal has to read the
// same regardless of selection order.
func TestRelocationRefusalIsOrderIndependent(t *testing.T) {
	env := relocationEnv()
	reg := relocationRegistry()

	// Resolve validates internally (resolve.go), so its own returned error IS
	// the refusal for each ordering.
	_, err1 := Resolve(reg, twoOf("victim", "evil"), testCtx(), env)
	_, err2 := Resolve(reg, twoOf("evil", "victim"), testCtx(), env)

	if err1 == nil || err2 == nil {
		t.Fatalf("fixture: expected both orderings to be refused, got %v and %v", err1, err2)
	}
	if err1.Error() != err2.Error() {
		t.Errorf("selection order changed the refusal:\n[victim,evil] = %v\n[evil,victim] = %v",
			err1, err2)
	}
}

// ── §8 item 4: the chain arm ─────────────────────────────────────────────────

// TestRelocationWalkFollowsAChainOfHostSymlinks pins the "re-examine the same
// position after every jump" arm of guestLanding: a landing can itself be a
// host symlink, and following only the FIRST one is the exact bug
// followToDestination's own step() comment records (measured there with
// bwrap alone) — the walk remapped to the first link's landing and moved on
// without ever reading a link AT that landing. Two hops: /hc/l1 -> "l2"
// (relative, stays under the cover), /hc/l2 -> "/final/place" (absolute,
// leaves it entirely). A single-hop walk would report a landing under
// /C/l2/x; the correct one is under /final/place/x.
func TestRelocationWalkFollowsAChainOfHostSymlinks(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		"/C": {Guest: "/C", Host: "/hc", Kind: KindBind, Access: AccessRO, From: []string{"cover"}},
	}}
	m := Mount{Guest: "/C/l1/x", Host: "/irrelevant", Kind: KindBind, Access: AccessRO,
		From: []string{"grantee"}}

	env := newFakeEnv()
	env.links["/hc/l1"] = "l2"
	env.links["/hc/l2"] = "/final/place"

	landing, via, text, err := p.guestLanding(env, m)
	if err != nil {
		t.Fatalf("guestLanding: %v", err)
	}
	if landing != "/final/place/x" {
		t.Errorf("landing = %q, want /final/place/x — a walk that follows only the first hop "+
			"would stop at /C/l2/x instead", landing)
	}
	if via != "/C/l1" || text != "l2" {
		t.Errorf("via, text = %q, %q — want the FIRST link's own position and text (/C/l1, l2)",
			via, text)
	}
}

// ── §8 item 5: the anti-drift test ──────────────────────────────────────────

// TestLinkLandingAgreesWithFollowToDestination replaces folding the two walks
// together: linkLanding is the one piece of namespace logic followToDestination
// (the generated-file walk, #580) and guestLanding (this rule, #588) share, and
// a fix to one must not silently diverge from the other's answer for the same
// destination.
//
// The fixture is a destination reached through an IN-GRANT link — a host
// symlink whose landing stays inside the same cover, which is the shape
// neither walk refuses. guestLanding answers in GUEST terms; mapped back
// through the cover's host translation, it must equal followToDestination's
// own HOST answer for the identical mount.
func TestLinkLandingAgreesWithFollowToDestination(t *testing.T) {
	p := &Policy{Mounts: map[string]Mount{
		"/K": {Guest: "/K", Host: "/hostK", Kind: KindBind, Access: AccessRO, From: []string{"cover"}},
	}}
	m := Mount{Guest: "/K/d/gen.conf", Kind: KindData, Access: AccessRO, From: []string{"(snug)"}}

	env := newFakeEnv()
	env.links["/hostK/d"] = "inner" // in-grant: /hostK/inner
	env.dirs["/hostK/inner"] = true
	env.files["/hostK/inner/gen.conf"] = true

	landing, _, _, err := p.guestLanding(env, m)
	if err != nil {
		t.Fatalf("guestLanding: %v", err)
	}
	mappedBack := "/hostK" + strings.TrimPrefix(landing, "/K")

	outer := p.Mounts["/K"]
	hostDest, parentExists, err := p.followToDestination(env, m, outer, "/K", "/hostK")
	if err != nil {
		t.Fatalf("followToDestination: %v", err)
	}
	if !parentExists {
		t.Fatalf("fixture: followToDestination reports the parent absent, so its hostDest is not " +
			"the settled answer this test compares against")
	}
	if mappedBack != hostDest {
		t.Errorf("guestLanding's landing (%s), mapped back through the cover, is %s; "+
			"followToDestination's own answer for the identical mount is %s — the two walks "+
			"have drifted on the namespace rule they are meant to share", landing, mappedBack, hostDest)
	}
}

// ── §8 item 6: the bound ─────────────────────────────────────────────────────

// TestRelocationWalkIsBounded is the cycle case: two host symlinks pointing
// at each other, so the walk cannot terminate by exhausting positions to look
// at. It has to give up after maxGeneratedDestLinks steps (the same bound
// followToDestination already uses) rather than hang.
func TestRelocationWalkIsBounded(t *testing.T) {
	err := refusalRelocatedLinkBudgetExceeded(t)
	if err == nil {
		t.Fatal("a cycle of host symlinks was followed forever instead of being refused")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d", maxGeneratedDestLinks)) ||
		!strings.Contains(err.Error(), "refuses rather than guess") {
		t.Errorf("refusal does not name the step bound or refuse rather than guess: %v", err)
	}
}

// ── §8 item 7: negatives — none of these may refuse ─────────────────────────
//
// Each is a real, unremarkable shape, and a version of this rule that refused
// any of them would be refusing the common case rather than the attack.

// TestTargetRWOverParentROIsNotRelocated is §6's own worked negative:
// target-rw's grant sits exactly ONE component below parent-ro's, which is
// the final component and is never followed — no Lstat is even performed, so
// this is safe structurally rather than by luck of the fixture.
func TestTargetRWOverParentROIsNotRelocated(t *testing.T) {
	p := mustResolve(t, withParentRo()...)
	if err := p.Validate(newFakeEnv()); err != nil {
		t.Fatalf("refused the shipped target-rw-over-parent-ro shape: %v", err)
	}
}

// TestGrantInsideATmpfsCoverIsNotRelocated pins 2(c): a tmpfs has no host
// content, so nothing under one can be a host symlink and the walk never
// touches Lstat for a component covered by one. nested-bin's grant sits
// inside @home's own tmpfs, exactly like @claude's shipped shape.
func TestGrantInsideATmpfsCoverIsNotRelocated(t *testing.T) {
	p := mustResolve(t, twoOf("nested-bin")...)
	if err := p.Validate(newFakeEnv()); err != nil {
		t.Fatalf("refused a grant nested inside a tmpfs cover, which has no host content to "+
			"divert through: %v", err)
	}
}

// TestAbsentIntermediateComponentIsNotARefusal is the fixture that would
// otherwise redden sanitise.bwrap.txt: envy's grant of /opt/tools/bin sits two
// components below @sys's /opt cover, and the fake host's /opt/tools —
// deliberately absent (resolve_test.go's dirs map) — must answer
// fs.ErrNotExist rather than a refusal. "Not created yet" and "diverted
// elsewhere" are different facts, and treating the first as the second would
// refuse every default run on a host whose optional directory tree is simply
// shallower than a profile's grant.
func TestAbsentIntermediateComponentIsNotARefusal(t *testing.T) {
	// Resolve validates internally (resolve.go), so a refusal over the absent
	// /opt/tools would surface right here.
	if _, err := Resolve(testRegistry(), sanitiseProbeSelection(), testCtx(), sanitiseProbeEnv()); err != nil {
		t.Fatalf("refused the sanitise-C fixture over an absent intermediate directory "+
			"(/opt/tools): %v", err)
	}
}

// TestStagedBinaryUnderSnugBinIsNotRelocated: @claude's staged binary lands
// under StagedBinDir, which is a skeleton `--dir` bwrap creates, never a
// mount — so nothing covers it and the walk finds no host content to divert
// through, the same reasoning 2(c) gives for a tmpfs.
func TestStagedBinaryUnderSnugBinIsNotRelocated(t *testing.T) {
	p := mustResolveDefaults(t)
	p.Mounts[StagedBinDir+"/claude"] = Mount{
		Guest: StagedBinDir + "/claude", Host: "/home/u/.local/bin/claude",
		Kind: KindBind, Access: AccessRO, From: []string{"@claude"},
	}
	if err := p.Validate(newFakeEnv()); err != nil {
		t.Fatalf("refused a staged binary under snug's own StagedBinDir skeleton: %v", err)
	}
}

// TestGeneratedFilesAreUnaffectedByTheRelocationRule: an Authored mount is
// snug's own writing, judged by rejectGeneratedOntoHost's own walk instead
// (its doc comment says so, and that rule's own containment arm already
// covers this exact shape). rejectRelocatedGrant skips it outright — called
// directly, rather than through Validate, to isolate that THIS rule
// specifically has nothing to say about a generated file, independent of what
// the other rule would do with the identical fixture.
func TestGeneratedFilesAreUnaffectedByTheRelocationRule(t *testing.T) {
	p := mustResolveDefaults(t)
	bind(p, "/srv/app", "/srv/app", AccessRO)
	generated(p, "/srv/app/deep/gen.conf", AccessRO)

	if err := p.rejectRelocatedGrant(newFakeEnv()); err != nil {
		t.Fatalf("the relocation rule judged an Authored (generated) mount, which is not its "+
			"business: %v", err)
	}
}

// ── the round on this change: two arms the constructed cases did not reach ──

// TestRelocationWalkRefusesACoverEmittedAfterTheMountItSupplies is the step-(c)
// half of the after-me rule. refusalRelocatedAfterMe above covers step (b), an
// EXACT mount at the position the walk jumped to; this is the other way a
// later mount can be consulted — the walk lands somewhere no mount occupies
// exactly, and the mount that would SUPPLY the host content there is emitted
// after the one being judged.
//
// It is not a case anything could be shown to exploit: in every shape the
// round on this change could build, the landing already differed from m.Guest
// and the policy was refused anyway. The arm is what makes that a property of
// the walk rather than a coincidence of the cases somebody thought of — bwrap
// has not created that cover when it creates this mountpoint, so its host
// content describes a sandbox that does not exist at that moment.
//
// /G/a/b is depth 3; the cover at /home/u/q ties on depth and sorts after it
// lexically, which is SortedMounts' own comparator and so bwrap's emission
// order.
func TestRelocationWalkRefusesACoverEmittedAfterTheMountItSupplies(t *testing.T) {
	p := resolveDefaults(t)
	p.Mounts["/G"] = Mount{Guest: "/G", Host: "/hostG", Kind: KindBind, Access: AccessRO,
		From: []string{"cover"}}
	p.Mounts["/home/u/q"] = Mount{Guest: "/home/u/q", Host: "/hostQ", Kind: KindBind, Access: AccessRO,
		From: []string{"later"}}
	p.Mounts["/G/a/b"] = Mount{Guest: "/G/a/b", Host: "/irrelevant", Kind: KindBind, Access: AccessRO,
		From: []string{"grantee"}}
	env := newFakeEnv()
	env.links["/hostG/a"] = "/home/u/q/z"

	err := p.Validate(env)
	if err == nil {
		t.Fatal("a walk whose landing is supplied by a mount emitted AFTER the one being judged\n" +
			"was accepted. bwrap has not created that cover yet, so whatever the walk read\n" +
			"through it describes a sandbox that does not exist at that moment.")
	}
	for _, want := range []string{"emitted AFTER this one", "later", "/home/u/q/z"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not contain %q, so it does not say which mount\n"+
				"would have supplied the position or where the walk had reached:\n%v", want, err)
		}
	}
}

// TestRelocationOntoAnEphemeralTmpfsSaysSoRatherThanClaimingADowngrade is
// about what the refusal SAYS, which is the half "errors name the fix" is for.
//
// The downgrade sentence carries issue #588's own measurement — a second
// profile's rw grant served read-only. That measurement is false when the
// landing is inside a tmpfs: a tmpfs exposes nothing, dies with the sandbox,
// and no access changes. The refusal is still right (the grant takes effect at
// a path no profile named), so the arm must be distinguishable by its text,
// not by its verdict — a refusal that quotes a measurement its own policy does
// not carry is the shape the "never write a measurement you did not read" rule
// exists to refuse.
func TestRelocationOntoAnEphemeralTmpfsSaysSoRatherThanClaimingADowngrade(t *testing.T) {
	p := resolveDefaults(t)
	p.Mounts["/G"] = Mount{Guest: "/G", Host: "/hostG", Kind: KindBind, Access: AccessRO,
		From: []string{"cover"}}
	p.Mounts["/G/a/b"] = Mount{Guest: "/G/a/b", Host: "/irrelevant", Kind: KindBind, Access: AccessRO,
		From: []string{"grantee"}}
	env := newFakeEnv()
	env.links["/hostG/a"] = "/home/u/scratch"

	err := p.Validate(env)
	if err == nil {
		t.Fatal("a grant landing inside the ephemeral $HOME tmpfs was accepted; it takes effect\n" +
			"at a path no profile named and nothing in --dry-run says so")
	}
	if !strings.Contains(err.Error(), "ephemeral tmpfs") {
		t.Errorf("the refusal does not say the landing is an ephemeral tmpfs:\n%v", err)
	}
	if strings.Contains(err.Error(), "became read-only") {
		t.Errorf("the refusal quotes issue #588's rw-to-ro measurement for a landing inside a\n"+
			"tmpfs, where nothing is shadowed and no access changes:\n%v", err)
	}
}
