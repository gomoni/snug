package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// ── §7 item 1 (the model half) ───────────────────────────────────────────────
//
// TestNoProfileCanAuthorAGraft here is the STRUCTURAL half: Profile, the parsed
// form of a [profile.NAME] table, has no field whose type can express a Graft
// — no field named Graft, no []Graft, no map[...]Graft — so there is no
// assignment ANYWHERE Resolve could reach that writes one. The parse-time half
// (DisallowUnknownFields refusing an unrelated unknown key) already exists and
// is not what this checks; this is the type-system guard that stands behind
// it. internal/policy cannot import internal/profile (resolve_test.go's own
// testRegistry doc comment says why), so the RUNTIME half — resolving every
// REAL builtin and checking p.Grafts is empty — lives in internal/cli under
// the same test name.
func TestNoProfileCanAuthorAGraft(t *testing.T) {
	rt := reflect.TypeOf(Profile{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if typeMentionsGraft(f.Type) {
			t.Errorf("Profile.%s has type %s, which can express a Graft — a TOML key could then "+
				"author one, and no profile may ever author a graft (issue #55)", f.Name, f.Type)
		}
	}

	// The runtime half, over the widest combination THIS package's fake
	// registry can resolve — the default selection. If Resolve ever grew a
	// path from a Profile field into p.Grafts, this is the fold that would
	// have to carry it. The structural check above is what actually prevents
	// it; this is the fact a reader can see MOVE if it broke.
	p := mustResolveDefaults(t)
	if len(p.Grafts) != 0 {
		t.Errorf("a default Resolve produced %d grafts; nothing in Resolve authors one", len(p.Grafts))
	}
}

// typeMentionsGraft reports whether t is Graft, or a pointer/slice/array/map
// that could eventually hold one.
func typeMentionsGraft(t reflect.Type) bool {
	if t.Name() == "Graft" {
		return true
	}
	switch t.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array:
		return typeMentionsGraft(t.Elem())
	case reflect.Map:
		return typeMentionsGraft(t.Key()) || typeMentionsGraft(t.Elem())
	}
	return false
}

// ── §7 item 2 ─────────────────────────────────────────────────────────────────

// graftWriteRE matches an ASSIGNMENT into a Grafts map — `X.Grafts[k] = v` —
// and not a read: `p.Grafts[k]` alone (no trailing `=`), a range over the map,
// or a comparison (`==`, excluded by the trailing `[^=]`).
//
// This is Go's regexp package (RE2), not a shell invocation of grep(1) — the
// `|` inside a pattern here is never the "grep 'a|b' without -E matches a
// literal pipe" trap CLAUDE.md warns about, because that trap is specific to
// the grep BINARY's basic-regex mode. This pattern has no `|` at all, but the
// positive control below still proves it can see a violation, for the same
// reason every sweep in this codebase carries one: a pattern that matched
// nothing would pass by finding exactly the one real hit and look identical to
// "the sweep works".
var graftWriteRE = regexp.MustCompile(`\.Grafts\[[^]]*\]\s*=[^=]`)

// TestOnlyGraftWritesGrafts is the same device as TestPolicyHasNoRestrictionOperation
// (resolve_test.go) and TestTopologyIsDerivedNotSettable (topology_test.go): an
// invariant with a single writer is checkable by finding it, not by trusting
// the doc comment that claims it. Policy.Graft is meant to be the ONLY place in
// the tree that ever assigns into p.Grafts — issue #55's own writer discipline,
// the same device as Policy.Replace for p.Mounts and deriveTopology for
// p.Topology — and this sweep asserts that by finding every assignment,
// package-tree-wide, not just within internal/policy: p.Grafts is an exported
// field, and a future Tier C (#125) writer could just as easily land in
// internal/cli or internal/stage.
func TestOnlyGraftWritesGrafts(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	var hits []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		text := string(src)
		for _, loc := range graftWriteRE.FindAllStringIndex(text, -1) {
			line := 1 + strings.Count(text[:loc[0]], "\n")
			rel, _ := filepath.Rel(root, path)
			hits = append(hits, fmt.Sprintf("%s:%d", filepath.ToSlash(rel), line))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(hits) != 1 {
		t.Fatalf("found %d assignment(s) into a .Grafts map under internal/, want exactly 1 "+
			"(policy/graft.go's Policy.Graft): %v", len(hits), hits)
	}
	if !strings.HasPrefix(hits[0], "policy/graft.go:") {
		t.Errorf("the one writer is at %s, not policy/graft.go — Policy.Graft is meant to be the "+
			"only writer of p.Grafts, and that is where it lives", hits[0])
	}

	// POSITIVE CONTROL: the pattern can actually tell a write from a read and
	// from a comparison. Exercised on an in-memory fixture rather than by
	// planting a second writer in the tree, because a check that can only be
	// proven by temporarily breaking the invariant it guards is not one this
	// suite should run by default.
	fixture := "func evil(p *Policy) { p.Grafts[\"x\"] = Graft{} }\n" +
		"// a read: _ = p.Grafts[\"y\"]\n" +
		"// a comparison: ok := a == p.Grafts[\"z\"]\n" +
		"for _, g := range p.Grafts { _ = g }\n"
	if got := graftWriteRE.FindAllString(fixture, -1); len(got) != 1 {
		t.Fatalf("control: the pattern found %d writes in a fixture with exactly one real "+
			"assignment, one read, one comparison and one range — it is not discriminating a "+
			"write from the rest: %v", len(got), got)
	}
}

// ── shared fixtures for the G1-G5 tests below ────────────────────────────────

// rawGraft returns a structurally-valid Graft at an arbitrary absolute guest,
// with no attempt to satisfy G3 or G4 — usable only where the rule under test
// fires BEFORE those two are ever reached (checkGraft's order is G5's
// structural checks, then path hygiene, then G1, G2, G3, G4 in that order), so
// G1's own table and G3's own negative cases can name any guest they like
// without first building a policy that would make it exist.
func rawGraft(guest string) Graft {
	return Graft{
		Mount: Mount{
			Guest: guest, Host: "/opt", Kind: KindGraft, Access: AccessRO,
			From: []string{"(snug)"},
		},
		Why: "test abuse sentence: a hostile process inside the sandbox can use this to test",
	}
}

// resolveDefaults resolves the default profile selection against this
// package's fake registry — the same fixture mustResolveDefaults(*testing.T)
// uses, spelled to take testing.TB so the refusal helpers below (which are
// shared between a focused Test* function and TestGoldenRefusals's table, and
// so are typed testing.TB like every other helper in refusals_test.go) can
// call it too.
func resolveDefaults(t testing.TB) *Policy {
	t.Helper()
	p, err := Resolve(testRegistry(), testDefaults, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("fixture: the default profile selection failed to resolve: %v", err)
	}
	return p
}

// validGraft returns a Graft the default profile selection ACCEPTS: Guest and
// Host both strictly inside the writable target, so it passes G1 (nowhere
// near snug's own paths), G3 (inside the target's AccessRW grant — the third,
// approximating disjunct of existsInSandbox) and G4 (the target's own Host
// tree is visible, since the sandbox's own grant of it is AccessRW).
//
// Every refusal test below starts here and changes exactly ONE field, so a
// refusal it produces is attributable to the ONE rule under test rather than
// to an unrelated fixture mistake. See TestValidGraftFixtureIsAccepted, the
// shared positive control every one of those tests depends on meaning
// something.
func validGraft(p *Policy, suffix string) Graft {
	target := p.Mounts[p.Target]
	return Graft{
		Mount: Mount{
			Guest: p.Target + "/" + suffix,
			Host:  target.Host + "/" + suffix,
			Kind:  KindGraft, Access: AccessRO,
			From: []string{"(snug)"},
		},
		Why: "a hostile process inside the sandbox can use this to reach the host's project tree " +
			"outside the exact target it was given",
	}
}

// TestValidGraftFixtureIsAccepted is the shared positive control named above.
func TestValidGraftFixtureIsAccepted(t *testing.T) {
	p := mustResolveDefaults(t)
	if err := p.Graft(validGraft(p, "control")); err != nil {
		t.Fatalf("control: the shared valid-graft fixture was refused, so every refusal test built "+
			"from it by changing one field cannot be trusted to be refusing for the reason it "+
			"claims: %v", err)
	}
}

// ── §7 item 3 ─────────────────────────────────────────────────────────────────

// refusalGraftCoversStagedBinDir is G1: a graft may not cover one of snug's
// own paths, in EITHER namespace — the same rule Validate's mount-level check
// applies, asked of a graft's Guest with the trap named in graft.go's own doc
// comment: validate.go's mount-level version reads `ours && !m.Authored`, and
// every graft is Authored by construction, so copying that clause here makes
// this check a PERMANENT NO-OP. Nothing legitimately covers StagedBinDir in
// ANY namespace, so unlike the mount-level check there is no analogous
// exemption to carry over — checkGraft's G1 deliberately does not have one.
func refusalGraftCoversStagedBinDir(t testing.TB, guest string) error {
	p := resolveDefaults(t)
	return p.Graft(rawGraft(guest))
}

// TestGraftCoveringStagedBinDirIsRefused is the test the trap above exists
// for. If `&& !g.Authored` (or any spelling of it) is ever added to G1 in
// graft.go, every one of these subtests goes from refusing to accepting,
// because Policy.Graft sets Authored unconditionally three lines before
// checkGraft ever runs. Mutation-checked: reverting this file's comment is not
// enough on its own — see the report for how this was verified by actually
// adding the clause and watching this fail.
func TestGraftCoveringStagedBinDirIsRefused(t *testing.T) {
	for _, guest := range []string{"/", "/run", "/run/snug", StagedBinDir, "/proc", "/dev"} {
		t.Run(guest, func(t *testing.T) {
			err := refusalGraftCoversStagedBinDir(t, guest)
			if err == nil {
				t.Fatalf("a graft at %s was accepted; it covers one of snug's own paths, in a "+
					"namespace this check must refuse it in exactly as it would in the sandbox's",
					guest)
			}
			at, _, ours := snugsOwnCovered(guest)
			if !ours {
				t.Fatalf("fixture bug: %s does not cover any of snug's own paths at all — this "+
					"case is not testing G1", guest)
			}
			// "is snug's" is G1's OWN wording (both of its branches — one
			// reads "%s is snug's own:", the other wraps across a line as
			// "...is snug's\n       own:", so "is snug's" is the longest
			// substring common to both) and G3's message does not contain it
			// at all (G3 refuses with "nothing in this policy creates that
			// directory" instead). Required specifically so this assertion
			// cannot be satisfied by a DIFFERENT rule firing for a different
			// reason. Without it, the StagedBinDir-exact subtest still
			// "passes" if `&& !g.Authored` is reintroduced into G1: G1 stops
			// firing, but G3 then refuses the same guest anyway (nothing
			// creates /run/snug/bin either), producing a non-nil error that
			// also names the guest — a false pass, caught only by requiring
			// G1's own wording. Measured by reverting this exact clause into
			// graft.go and re-running this test: five of six subtests failed
			// outright, and the sixth (StagedBinDir exact) passed for the
			// wrong reason until this line was added.
			for _, want := range []string{guest, at, "cannot graft", "is snug's"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

// ── §7 item 4 ─────────────────────────────────────────────────────────────────

// TestGraftInsideStagedBinDirStillLegal mirrors
// TestGrantInsideStagedBinDirStillLegal (refusals_test.go): G1's predicate is
// a path-ANCESTOR test, so a graft strictly INSIDE StagedBinDir — landing on
// the very same Guest an existing staged bind already occupies, the shape a
// Tier C graft "onto a writable grant" would actually take — must stay legal.
// If snugsOwnCovered ever starts refusing this, G1 has gone from
// ancestor-aware to over-broad.
func TestGraftInsideStagedBinDirStillLegal(t *testing.T) {
	base := mustResolveDefaults(t)
	p := *base
	p.Mounts = make(map[string]Mount, len(base.Mounts)+1)
	for k, v := range base.Mounts {
		p.Mounts[k] = v
	}
	// The existing bind this graft lands "onto" — G3's disjunct 1 (it is
	// itself a mountpoint), and its Host doubles as G4's positive case (the
	// graft's own Host matches this bind's Host exactly).
	p.Mounts[StagedBinDir+"/mytool"] = Mount{
		Guest: StagedBinDir + "/mytool", Host: "/opt/mytool", Kind: KindBind, Access: AccessRO,
	}

	g := Graft{
		Mount: Mount{
			Guest: StagedBinDir + "/mytool", Host: "/opt/mytool",
			Kind: KindGraft, Access: AccessRO, From: []string{"(snug)"},
		},
		Why: "test abuse sentence",
	}
	if err := p.Graft(g); err != nil {
		t.Fatalf("control: a graft strictly inside %s must stay legal: %v", StagedBinDir, err)
	}
}

// ── §7 item 5 — the control the issue exists for ─────────────────────────────

// TestEngineViewIsShadowSlotSeesAGraft is the positive control issue #55
// demands (spec §4, §7 item 5). It hand-builds a Policy — bypassing
// Policy.Graft entirely, so the SUBJECT here is IsShadowSlot/EngineView, not
// the refusal machinery — installs an AccessRW graft at /run, and asserts
// EngineView().IsShadowSlot(StagedBinDir) is true.
//
// THE SECOND HALF IS NOT DECORATION. Written in the style
// internal/cli/shadowslot_test.go's own TestShadowSlotPredicateFiresOnAWritableHomeDirectory
// used for exactly this reason: a predicate that answered true for every guest
// path would pass the first half and mean nothing. So this also asks the
// IDENTICAL View — same Mounts, no graft applied — and requires false: the
// verdict has to hinge on the graft's presence, not on StagedBinDir being
// asked about at all. And it asks the SANDBOX's own view of the very same
// Policy and requires false there too, which is the fact issue #55 is
// actually about: a graft is invisible to the payload's own namespace by
// construction, and only EngineView can ever see it.
func TestEngineViewIsShadowSlotSeesAGraft(t *testing.T) {
	mounts := map[string]Mount{
		"/usr": {Guest: "/usr", Kind: KindBind, Access: AccessRO},
	}
	p := &Policy{Mounts: mounts}

	// WITHOUT the graft: neither view may say StagedBinDir is a shadow slot.
	if (View{Mounts: mounts}).IsShadowSlot(StagedBinDir) {
		t.Fatal("control: IsShadowSlot(StagedBinDir) = true with NO graft installed at all — the " +
			"predicate below would then be unfalsifiable, exactly the defect " +
			"shadowslot_test.go documents about its own earlier version")
	}
	if p.SandboxView().IsShadowSlot(StagedBinDir) {
		t.Fatal("control: the SANDBOX's own view must never see a graft")
	}

	p.Grafts = map[string]Graft{
		"/run": {
			Mount: Mount{Guest: "/run", Kind: KindGraft, Access: AccessRW, From: []string{"(snug)"}},
			Why:   "test",
		},
	}

	// THE CLAIM. /run is not itself StagedBinDir, but it is StagedBinDir's
	// ancestor, and the graft's writability makes the whole subtree it covers
	// writable in the ENGINE's derived view — the /run-graft-covers-/run/snug/bin
	// shape issue #55 is named for.
	ev, ok := p.EngineView()
	if !ok {
		t.Fatal("EngineView() ok=false with a graft present")
	}
	if !ev.IsShadowSlot(StagedBinDir) {
		t.Fatal("EngineView().IsShadowSlot(StagedBinDir) = false with an AccessRW graft at /run — " +
			"a graft is a Mount like any other once it is in the engine's view, and this is the " +
			"exact hole issue #55 reports: neither Validate nor IsShadowSlot could see one")
	}

	// The payload's OWN view is still blind to it, even now that the graft
	// exists — this is the fact that makes "the engine's view is derived from
	// the sandbox's, never the other way, and never the same map" true rather
	// than aspirational.
	if p.SandboxView().IsShadowSlot(StagedBinDir) {
		t.Fatal("the SANDBOX's own view answered true once a graft existed — a graft must never " +
			"reach the payload's mount namespace, in the model or at runtime")
	}
}

// ── §7 item 6 ─────────────────────────────────────────────────────────────────

// TestGraftSourceMustBeVisibleToTheSandbox is G4. Negative: a graft whose Host
// is $XDG_RUNTIME_DIR's real path — the ssh-agent, D-Bus, Wayland and the
// host's rootless podman socket reach ENGINE-NETNS.md §5.1 measured through a
// /run graft — is refused, because no grant in the default profile selection
// exposes it. Positive control: a graft whose Host sits inside an AccessRW
// grant (the target) is accepted.
// refusalGraftSourceNotVisible is also used as a TestGoldenRefusals row.
func refusalGraftSourceNotVisible(t testing.TB) error {
	p := resolveDefaults(t)
	bad := validGraft(p, "xdg")
	bad.Host = "/run/user/1000"
	return p.Graft(bad)
}

func TestGraftSourceMustBeVisibleToTheSandbox(t *testing.T) {
	p := mustResolveDefaults(t)

	err := refusalGraftSourceNotVisible(t)
	if err == nil {
		t.Fatal("a graft whose Host is /run/user/1000 (ssh-agent, D-Bus, Wayland, the host's " +
			"rootless podman socket — ENGINE-NETNS.md §5.1) was accepted; no grant in this " +
			"policy exposes it, so no graft may reach it either")
	}
	for _, want := range []string{"/run/user/1000", "does not expose this host path"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	// POSITIVE CONTROL, same Policy: TestValidGraftFixtureIsAccepted already
	// proves this shape is accepted; repeated here as g4's own control so this
	// file's G4 test does not depend on reading another one to mean anything.
	if err := p.Graft(validGraft(p, "inside-target")); err != nil {
		t.Fatalf("control: a graft whose Host sits inside an AccessRW grant must be accepted: %v", err)
	}
}

// ── §7 item 7 ─────────────────────────────────────────────────────────────────

// refusalGraftDestinationDoesNotExist is G3, checked against the two negative
// rows ENGINE-NETNS.md §5.1 measured: /etc/containers and /var/tmp both fail
// move_mount's implicit mkdir with EROFS on the read-only sandbox root,
// because nothing in the default profile selection creates either directory
// inside the sandbox (the real @sys binds fourteen individual /etc entries and
// never /etc itself).
func refusalGraftDestinationDoesNotExist(t testing.TB, guest string) error {
	p := resolveDefaults(t)
	return p.Graft(rawGraft(guest))
}

func TestGraftDestinationMustExist(t *testing.T) {
	for _, guest := range []string{"/etc/containers", "/var/tmp"} {
		t.Run(guest, func(t *testing.T) {
			err := refusalGraftDestinationDoesNotExist(t, guest)
			if err == nil {
				t.Fatalf("a graft at %s was accepted; nothing in the default selection creates that "+
					"directory inside the sandbox, and move_mount's implicit mkdir fails EROFS on "+
					"the read-only sandbox root (measured, ENGINE-NETNS.md §5.1)", guest)
			}
			for _, want := range []string{guest, "EROFS"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}

	// POSITIVE CONTROL: a destination inside a writable grant passes G3.
	p := mustResolveDefaults(t)
	if err := p.Graft(validGraft(p, "inside")); err != nil {
		t.Fatalf("control: a graft destination inside a writable grant must pass G3: %v", err)
	}
}

// ── §7 item 9 ─────────────────────────────────────────────────────────────────

// TestGraftNeverReachesBwrapArgs is the mechanical form of the claim §9 and
// §10 both make: a graft is unreachable from the bwrap argv, so a moved
// .bwrap.txt golden means a graft reached the payload's namespace. Three
// parts: the argv itself never names a graft's Guest or Host; a KindGraft
// hand-placed into p.Mounts (never through Policy.Graft, which cannot produce
// one there) is refused by Validate; and — bypassing Validate on purpose,
// because what is under test here IS what happens if that refusal is ever
// removed or skipped — BwrapFlags panics rather than silently omitting or
// emitting the mount, closing the exact "--seccomp after bwrap's --" shape
// CLAUDE.md warns about.
func TestGraftNeverReachesBwrapArgs(t *testing.T) {
	base := mustResolveDefaults(t)
	p := *base
	p.Mounts = make(map[string]Mount, len(base.Mounts))
	for k, v := range base.Mounts {
		p.Mounts[k] = v
	}

	g := validGraft(&p, "argv-probe")
	if err := p.Graft(g); err != nil {
		t.Fatalf("fixture: a valid graft was rejected: %v", err)
	}

	args := p.BwrapFlags(1000, 1000, func(string) int { return 9 })
	for _, a := range args {
		if a == g.Guest {
			t.Errorf("bwrap argv contains the graft's Guest (%s) — a graft must never reach the "+
				"payload's mount namespace", g.Guest)
		}
		if a == g.Host {
			t.Errorf("bwrap argv contains the graft's Host (%s)", g.Host)
		}
	}

	// A hand-placed KindGraft in p.Mounts — Validate must refuse it.
	leaking := *base
	leaking.Mounts = make(map[string]Mount, len(base.Mounts)+1)
	for k, v := range base.Mounts {
		leaking.Mounts[k] = v
	}
	leaking.Mounts["/mnt/leak"] = Mount{
		Guest: "/mnt/leak", Host: "/host/leak", Kind: KindGraft, Access: AccessRW,
		From: []string{"(snug)"},
	}
	err := leaking.Validate(newFakeEnv())
	if err == nil {
		t.Fatal("a KindGraft mount hand-placed in p.Mounts was accepted by Validate")
	}
	if !strings.Contains(err.Error(), "KindGraft in p.Mounts") {
		t.Errorf("unexpected message: %v", err)
	}

	// The default arm, exercised DIRECTLY against BwrapFlags — skipping
	// Validate on purpose, since this is the one place in this file allowed to:
	// the claim under test is what happens if Validate's refusal above is ever
	// bypassed, and the answer must be "fails loudly", never "silently omitted
	// or emitted as a real bind".
	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("BwrapFlags over a policy with a KindGraft in p.Mounts did not panic — a " +
					"future Kind reaching this switch with no case would be silently OMITTED from " +
					"the argv instead, the exact shape CLAUDE.md warns about")
			}
			if !strings.Contains(fmt.Sprint(r), "unhandled Kind") {
				t.Errorf("panic message %v does not say \"unhandled Kind\"", r)
			}
		}()
		leaking.BwrapFlags(1000, 1000, func(string) int { return 9 })
	}()
}

// ── §7 item 10 ────────────────────────────────────────────────────────────────

// TestGraftCarriesAnAbuseSentence is G5's Why check, plus a sweep of every
// CALL to Policy.Graft in the shipped (non-test) source tree, asserting each
// one constructs its Graft literal with a non-empty Why. Today the sweep finds
// nothing to complain about, because nothing in the shipped code path calls
// Policy.Graft at all — Tier C (#125) has not landed, the same fact
// TestOnlyGraftWritesGrafts confirms a different way. Written now so the day a
// graft IS authored, this sweep is already watching rather than being bolted
// on after the fact.
// refusalGraftEmptyWhy is also used as a TestGoldenRefusals row
// (refusals_test.go), which is why it is split out rather than inlined below.
func refusalGraftEmptyWhy(t testing.TB) error {
	p := resolveDefaults(t)
	g := validGraft(p, "why-probe")
	g.Why = ""
	return p.Graft(g)
}

func TestGraftCarriesAnAbuseSentence(t *testing.T) {
	err := refusalGraftEmptyWhy(t)
	if err == nil {
		t.Fatal("a graft with an empty Why was accepted; every graft is the abuse sentence's only " +
			"home, since no profile authors one for a TOML comment to sit beside it")
	} else if !strings.Contains(err.Error(), "Why is empty") {
		t.Errorf("error %q does not name the empty Why", err)
	}

	// POSITIVE CONTROL for the refusal above — TestValidGraftFixtureIsAccepted
	// already proves validGraft's own Why is accepted; nothing further needed
	// here beyond that shared control.

	sites := graftCallSitesWithoutWhy(t)
	for _, s := range sites {
		t.Errorf("%s", s)
	}
	if len(sites) == 0 {
		t.Log("no policy.Graft call sites found under internal/ with a missing or empty Why " +
			"(expected: Tier C, issue #125, has not landed — see the positive control below, " +
			"which proves this walk can actually see a violation)")
	}

	// POSITIVE CONTROL for the sweep: fed an in-memory fixture with a call
	// that omits Why, it must flag it — otherwise the zero found above proves
	// nothing about the real tree either.
	bad := "func evil(p *policy.Policy) error {\n" +
		"\treturn p.Graft(policy.Graft{Mount: policy.Mount{Guest: \"/x\"}})\n" +
		"}\n"
	if got := graftLiteralsWithoutWhy("control.go", bad); len(got) != 1 {
		t.Fatalf("control: the sweep's own checker did not flag a Graft{} call whose literal omits "+
			"Why — it would pass on any real omission too: %v", got)
	}
	good := "func fine(p *policy.Policy) error {\n" +
		"\treturn p.Graft(policy.Graft{Mount: policy.Mount{Guest: \"/x\"}, Why: \"because\"})\n" +
		"}\n"
	if got := graftLiteralsWithoutWhy("control.go", good); len(got) != 0 {
		t.Fatalf("control: the sweep flagged a Graft{} call whose literal DOES set a non-empty "+
			"Why: %v", got)
	}
}

// graftWhyCallRE finds a call to (something).Graft( — the method, not the
// type. Deliberately loose (it does not require the receiver to be a
// *Policy): the point of this sweep is "can I see a Why beside this call",
// and a stricter match would need full type information this package-local
// text scan does not have.
var graftWhyCallRE = regexp.MustCompile(`\.Graft\(`)

// graftWhyRE looks for a non-empty Why field inside the TEXT of one call's
// argument list.
var graftWhyRE = regexp.MustCompile(`Why:\s*"[^"]+"`)

// graftLiteralsWithoutWhy scans src for every `.Graft(...)` call and returns
// one line per call whose argument text does not contain a non-empty `Why:
// "..."`. Matching on the TEXT between the call's own parens, via bracket
// counting, rather than on an AST: this file's other sweeps use go/ast where
// the shape under test is a table (envnotesource_test.go); a single-method
// call site is simple enough that a text scan is the more readable choice,
// and the positive control above is what keeps that choice honest.
func graftLiteralsWithoutWhy(filename, src string) []string {
	var bad []string
	for _, loc := range graftWhyCallRE.FindAllStringIndex(src, -1) {
		depth := 1
		i := loc[1]
		for ; i < len(src) && depth > 0; i++ {
			switch src[i] {
			case '(':
				depth++
			case ')':
				depth--
			}
		}
		call := src[loc[0]:i]
		if !graftWhyRE.MatchString(call) {
			line := 1 + strings.Count(src[:loc[0]], "\n")
			bad = append(bad, fmt.Sprintf("%s:%d: call to .Graft(...) has no literal, non-empty "+
				"Why field visible in its argument text: %s", filename, line, strings.TrimSpace(call)))
		}
	}
	return bad
}

// graftCallSitesWithoutWhy runs graftLiteralsWithoutWhy over every non-test
// .go file under internal/.
func graftCallSitesWithoutWhy(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..", "internal")
	var bad []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		bad = append(bad, graftLiteralsWithoutWhy(path, string(src))...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return bad
}

// ── §7 item 11 ────────────────────────────────────────────────────────────────

func TestGraftAccessIsROorRW(t *testing.T) {
	p := mustResolveDefaults(t)
	g := validGraft(p, "access-probe")
	g.Access = AccessNone
	err := p.Graft(g)
	if err == nil {
		t.Fatal("a graft with Access=none (neither ro nor rw) was accepted; Access is a " +
			"REQUIREMENT enforced by mount_setattr before move_mount, and \"none\" describes " +
			"nothing the stage can build")
	}
	if !strings.Contains(err.Error(), "must be ro or rw") {
		t.Errorf("error %q does not say Access must be ro or rw", err)
	}
}

// refusalGraftOptional is also used as a TestGoldenRefusals row.
func refusalGraftOptional(t testing.TB) error {
	p := resolveDefaults(t)
	g := validGraft(p, "optional-probe")
	g.Optional = true
	return p.Graft(g)
}

func TestGraftMayNotBeOptional(t *testing.T) {
	err := refusalGraftOptional(t)
	if err == nil {
		t.Fatal("a graft with Optional=true was accepted; -try semantics mean \"silently do " +
			"less\", and under Tier C the derived view IS the enforcement boundary — a graft " +
			"that silently did not happen is a different confinement from the one --dry-run " +
			"described")
	}
	if !strings.Contains(err.Error(), "Optional is not permitted") {
		t.Errorf("error %q does not say Optional is not permitted", err)
	}
}

func TestGraftFromNamesNoProfile(t *testing.T) {
	p := mustResolveDefaults(t)
	g := validGraft(p, "from-probe")
	g.From = []string{"@sys"}
	err := p.Graft(g)
	if err == nil {
		t.Fatal("a graft whose From names @sys (a resolved profile) was accepted; no profile may " +
			"ever author a graft, and a From naming one means the caller copied provenance from a " +
			"Mount instead of writing the graft's own")
	}
	for _, want := range []string{"@sys", "No profile may author a graft"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

// TestGraftMayNotCoverAnotherGraft is G2. Not itemised by number in the
// spec's §7 list, but required by §9's golden table ("graft-covers-graft"):
// checkGraft's own doc comment explains why the EXACT-same-Guest case is
// checked by Policy.Graft's map lookup rather than here, so this test is
// deliberately about two DIFFERENT guests in an ancestor relationship, which
// only checkGraft's G2 loop can see.
// refusalGraftCoversGraft is also used as a TestGoldenRefusals row: it installs
// the inner graft for real, then attempts an outer one covering it.
func refusalGraftCoversGraft(t testing.TB) error {
	p := resolveDefaults(t)
	inner := validGraft(p, "nest/child")
	if err := p.Graft(inner); err != nil {
		t.Fatalf("fixture: the inner graft was refused: %v", err)
	}
	return p.Graft(validGraft(p, "nest"))
}

func TestGraftMayNotCoverAnotherGraft(t *testing.T) {
	p := mustResolveDefaults(t)
	inner := validGraft(p, "nest/child")
	outer := validGraft(p, "nest")

	if err := p.Graft(inner); err != nil {
		t.Fatalf("fixture: the inner graft was refused: %v", err)
	}
	err := p.Graft(outer)
	if err == nil {
		t.Fatal("a graft at an ancestor of an existing graft was accepted; it would take the " +
			"descendant's destination with it in the engine's mount namespace")
	}
	for _, want := range []string{outer.Guest, inner.Guest, "CONTAIN"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	// The reverse order: outer first, then inner — the OTHER branch of G2's
	// loop.
	q := mustResolveDefaults(t)
	if err := q.Graft(validGraft(q, "nest2")); err != nil {
		t.Fatalf("fixture: the outer graft was refused: %v", err)
	}
	err = q.Graft(validGraft(q, "nest2/child"))
	if err == nil {
		t.Fatal("a graft at a descendant of an existing graft was accepted")
	}
	if !strings.Contains(err.Error(), "CONTAINS") {
		t.Errorf("error %q does not say CONTAINS", err)
	}
}
