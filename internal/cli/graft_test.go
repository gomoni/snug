package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestNoProfileCanAuthorAGraft is the RUNTIME half of issue #55 §7 item 1, run
// against every REAL builtin. internal/policy cannot import internal/profile
// (see resolve_test.go's own testRegistry comment for why), so this package —
// which already imports both to drive profile.Builtins() against
// policy.Resolve — is the only one that can. See the STRUCTURAL half of the
// same name in internal/policy/graft_test.go: Profile has no field capable of
// expressing a Graft, so this loop is expected to find nothing, on every
// selection that resolves at all. Same shape as
// TestNoBuiltinPutsAWritableDirectoryOnPATH (shadowslot_test.go).
func TestNoProfileCanAuthorAGraft(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	names := make([]policy.ProfileName, 0, len(reg))
	for name := range reg {
		names = append(names, name)
	}
	slices.Sort(names)

	checked := 0
	for _, name := range names {
		sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), name)
		p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
		if err != nil {
			t.Logf("skipped %s: %v", name, err)
			continue
		}
		checked++
		if len(p.Grafts) != 0 {
			t.Errorf("builtin %s produced %d graft(s); no profile may ever author one (issue #55)",
				name, len(p.Grafts))
		}
	}

	if checked < len(names)/2 {
		t.Fatalf("only %d of %d builtins resolved on the fake host; the sweep is not covering "+
			"enough to mean anything", checked, len(names))
	}
}

// twoValidGrafts installs two grafts a real resolved default-selection Policy
// accepts — both strictly inside the writable target — and returns them for
// assertion. Mirrors internal/policy/graft_test.go's validGraft, spelled
// against a REAL Resolve() so the fixture this file's tests exercise cannot
// silently diverge from the one policy's own tests use.
func twoValidGrafts(t *testing.T, p *policy.Policy) []policy.Graft {
	t.Helper()
	target := p.Mounts[p.Target]
	var out []policy.Graft
	for _, suffix := range []string{"graft-one", "graft-two"} {
		g := policy.Graft{
			Mount: policy.Mount{
				Guest: p.Target + "/" + suffix,
				Host:  target.Host + "/" + suffix,
				Kind:  policy.KindGraft, Access: policy.AccessRW,
				From: []string{"(snug)"},
			},
			Why: "test abuse sentence for " + suffix,
		}
		if err := p.Graft(newEnvFakeEnv(), g); err != nil {
			t.Fatalf("fixture: a valid graft (%s) was rejected: %v", suffix, err)
		}
		out = append(out, g)
	}
	return out
}

// TestGraftIsNotInTheFilesystemBlock is §7 item 8. The FILESYSTEM block's own
// header says "every line is a grant" of the PAYLOAD's view; a graft row there
// would assert the payload can see the host's container store, which is false
// — the same class of lie, facing the other way, ENGINE-NETNS.md §5.1's /run
// finding is about. Zero graft rows in FILESYSTEM, exactly two (one per graft)
// in ENGINE VIEW.
func TestGraftIsNotInTheFilesystemBlock(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), profile.BuiltinDefaults(),
		envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	grafts := twoValidGrafts(t, p)

	got := captureStdout(t, func() { dryRun(p, p.BwrapArgs(0, 0), config{}, nil) })

	fsBlock := blockBetween(t, got, "FILESYSTEM", "NOT GRANTED")
	engineBlock := blockBetween(t, got, "ENGINE VIEW", "FILESYSTEM")

	// POSITIVE CONTROLS, first: the fixture actually reached the screen at
	// all, in the block this test claims to be checking. Without these, "zero
	// graft rows in FILESYSTEM" would also be true of a screen that rendered
	// nothing.
	for _, g := range grafts {
		if !strings.Contains(engineBlock, g.Guest) {
			t.Fatalf("fixture: graft %s never reached the ENGINE VIEW block:\n%s", g.Guest, engineBlock)
		}
	}
	if n := strings.Count(engineBlock, "graft-rw"); n != len(grafts) {
		t.Errorf("ENGINE VIEW block has %d graft-rw row(s), want %d:\n%s", n, len(grafts), engineBlock)
	}

	// THE CLAIM: FILESYSTEM never names a graft's kind column, guest, or host.
	if strings.Contains(fsBlock, "graft-ro") || strings.Contains(fsBlock, "graft-rw") {
		t.Errorf("FILESYSTEM block renders a graft-kind row — a graft is not a grant of the "+
			"payload's view and must never appear there:\n%s", fsBlock)
	}
	for _, g := range grafts {
		if strings.Contains(fsBlock, g.Guest) {
			t.Errorf("FILESYSTEM block names the graft's Guest (%s) — the payload cannot see "+
				"this path:\n%s", g.Guest, fsBlock)
		}
		if strings.Contains(fsBlock, g.Host) {
			t.Errorf("FILESYSTEM block names the graft's Host (%s)", g.Host)
		}
	}
}

// blockBetween returns the screen text starting at the line containing start
// and ending just before the line containing end, both of which must appear
// exactly once after the FIRST occurrence of start — used here because
// "FILESYSTEM" also appears in the ENGINE VIEW block's own explanatory prose
// ("a property of the engine TOPOLOGY... before FILESYSTEM" does not, but
// other blocks' comments about FILESYSTEM might in a future edit), so this
// slices by the screen's own section headers rather than by a bare substring
// search that could match prose instead of a header.
func blockBetween(t *testing.T, screen, start, end string) string {
	t.Helper()
	si := strings.Index(screen, "\n"+start)
	if si < 0 {
		si = strings.Index(screen, start)
	}
	if si < 0 {
		t.Fatalf("section %q not found on screen:\n%s", start, screen)
	}
	rest := screen[si+1:]
	ei := strings.Index(rest, end)
	if ei < 0 {
		t.Fatalf("section %q not found after %q on screen:\n%s", end, start, screen)
	}
	return rest[:ei]
}

// TestGoldenEngineView is the golden ENGINE VIEW block, §9: new, built from a
// HAND fixture (two grafts) because no shipping topology produces one at all
// — TestGraftIsNotInTheFilesystemBlock above proves the same fixture renders
// correctly; this file pins the exact bytes a human reviews.
func TestGoldenEngineView(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), profile.BuiltinDefaults(),
		envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}

	target := p.Mounts[p.Target]
	// One shared env for every graft below, so the planted link (for the
	// third graft) is visible to exactly the call it is meant to affect and
	// nothing else — a fresh newEnvFakeEnv() per call, as this fixture used
	// to build, would work just as well for the first two, but a single
	// shared env is what makes it obvious the third graft's divergence is a
	// property of ITS OWN Host, not of some other env accidentally reused.
	env := newEnvFakeEnv()

	// One RO, one RW, so the golden pins both kind-column spellings.
	if err := p.Graft(env, policy.Graft{
		Mount: policy.Mount{
			Guest: p.Target + "/ro-graft", Host: target.Host + "/ro-src",
			Kind: policy.KindGraft, Access: policy.AccessRO,
			From: []string{"(snug)"},
		},
		Why: "a container given a read-only bind of this can still enumerate everything under " +
			"the host tree it names, even though it cannot write to it",
	}); err != nil {
		t.Fatalf("fixture: RO graft rejected: %v", err)
	}
	if err := p.Graft(env, policy.Graft{
		Mount: policy.Mount{
			Guest: p.Target + "/rw-graft", Host: target.Host + "/rw-src",
			Kind: policy.KindGraft, Access: policy.AccessRW,
			From: []string{"(snug)"},
		},
		Why: "a container that is given a bind of this writes to the host tree directly, so a " +
			"file it creates is visible to every later process that reads the same host path",
	}); err != nil {
		t.Fatalf("fixture: RW graft rejected: %v", err)
	}

	// A THIRD graft (issue #55, finding F6) whose source is a SYMLINK the
	// payload planted inside the writable target, resolving to a host path
	// the sandbox's own @sys grant already exposes (/usr) — so it survives
	// G4, and the golden pins the "asked" + "resolved:" rows that only fire
	// when resolution actually changed something.
	env.links[target.Host+"/elsewhere-link"] = "/usr"
	if err := p.Graft(env, policy.Graft{
		Mount: policy.Mount{
			Guest: p.Target + "/elsewhere-graft", Host: target.Host + "/elsewhere-link",
			Kind: policy.KindGraft, Access: policy.AccessRO,
			From: []string{"(snug)"},
		},
		Why: "a container given this graft reads the host tree a symlink the payload planted " +
			"resolves to, not the literal path snug's own code named",
	}); err != nil {
		t.Fatalf("fixture: the diverging (symlink) graft was rejected: %v", err)
	}

	got := captureFile(t, func(f *os.File) { describeGrafts(f, p) })

	path := filepath.Join("testdata", "engineview.tierc.txt")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/cli -update)", err)
	}
	if got != string(want) {
		t.Errorf("the ENGINE VIEW block changed — this is what a human reads to learn what a "+
			"Tier C graft would expose to the container engine, and nothing to the payload.\n"+
			"--- got\n%s\n--- want\n%s", got, want)
	}
}

// TestGraftRendersASourceThatResolvedElsewhere is issue #55's F6 decision,
// §7's last row: the golden fixture above added a THIRD graft whose source
// diverges (a symlink resolving elsewhere); this test asserts what that
// addition is FOR, independent of the byte-exact golden comparison — the
// "asked" and "resolved:" rows render for the diverging graft, and NEITHER
// of the other two (whose Host was never a symlink) renders either row.
func TestGraftRendersASourceThatResolvedElsewhere(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), profile.BuiltinDefaults(),
		envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	target := p.Mounts[p.Target]
	env := newEnvFakeEnv()

	// A graft whose Host is NOT a symlink — HostAsked stays empty.
	plain := policy.Graft{Mount: policy.Mount{
		Guest: p.Target + "/plain-graft", Host: target.Host + "/plain-src",
		Kind: policy.KindGraft, Access: policy.AccessRO, From: []string{"(snug)"},
	}, Why: "test abuse sentence for the plain graft"}
	if err := p.Graft(env, plain); err != nil {
		t.Fatalf("fixture: the plain graft was rejected: %v", err)
	}

	// A graft whose Host IS a symlink, resolving to a host path the sandbox's
	// own @sys grant exposes (/usr) — HostAsked is set.
	env.links[target.Host+"/diverges-link"] = "/usr"
	diverging := policy.Graft{Mount: policy.Mount{
		Guest: p.Target + "/diverging-graft", Host: target.Host + "/diverges-link",
		Kind: policy.KindGraft, Access: policy.AccessRO, From: []string{"(snug)"},
	}, Why: "test abuse sentence for the diverging graft"}
	if err := p.Graft(env, diverging); err != nil {
		t.Fatalf("fixture: the diverging graft was rejected: %v", err)
	}
	stored := p.Grafts[diverging.Guest]
	if stored.HostAsked == "" {
		t.Fatalf("fixture: the diverging graft's stored HostAsked is empty — the render this test " +
			"checks never fires unless resolution actually changed something")
	}

	got := captureFile(t, func(f *os.File) { describeGrafts(f, p) })

	// Split into each graft's own rendered block, the same technique
	// TestEngineOwnedHostPathsAreOnTheScreen uses.
	idxPlain := strings.Index(got, plain.Guest)
	idxDiverging := strings.Index(got, diverging.Guest)
	if idxPlain < 0 || idxDiverging < 0 {
		t.Fatalf("fixture: one of the two grafts never reached the screen at all:\n%s", got)
	}
	var plainBlock, divergingBlock string
	if idxPlain < idxDiverging {
		plainBlock, divergingBlock = got[idxPlain:idxDiverging], got[idxDiverging:]
	} else {
		divergingBlock, plainBlock = got[idxDiverging:idxPlain], got[idxPlain:]
	}

	for _, want := range []string{"asked " + stored.HostAsked, "resolved:"} {
		if !strings.Contains(divergingBlock, want) {
			t.Errorf("the diverging graft's own block does not contain %q:\n%s", want, divergingBlock)
		}
	}
	// POSITIVE CONTROL: the plain graft's block, whose HostAsked is empty,
	// must render NEITHER row — otherwise the condition guarding them could
	// be unconditionally true and this golden would still look plausible.
	for _, unwanted := range []string{"asked ", "resolved:"} {
		if strings.Contains(plainBlock, unwanted) {
			t.Errorf("the PLAIN graft's block (HostAsked empty) renders %q, which must be "+
				"conditional on HostAsked actually being set:\n%s", unwanted, plainBlock)
		}
	}
}

// §9's negative claim — internal/cli/testdata/topology.podman-*.txt must NOT
// move, because Tier B makes no grafts — is NOT re-asserted by a new test
// here. TestGoldenTopology (topologygolden_test.go) already regenerates and
// diffs exactly those files on every run, unmodified by this change; a green
// run of it after this file lands IS the check. A second, hand-rolled
// re-implementation of that comparison would be a second copy of "what does
// this golden say", the shape CLAUDE.md warns is how a rule and its check
// drift apart, for no assertion this file does not already get for free.
func TestGraftAddsNoGoldenSurfaceToTopology(t *testing.T) {
	// describeGrafts on a Policy with zero Grafts prints nothing — the one
	// fact that makes "topology.podman-*.txt do not move" true, asserted
	// directly rather than only implied by a diff staying empty elsewhere.
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	sel := []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Grafts) != 0 {
		t.Fatalf("a podman-socket selection resolved with %d graft(s); Tier B must make none", len(p.Grafts))
	}
	if got := captureFile(t, func(f *os.File) { describeGrafts(f, p) }); got != "" {
		t.Errorf("describeGrafts printed %q for a policy with zero grafts — the ENGINE VIEW block "+
			"must be silent whenever len(p.Grafts) == 0, or topology.podman-*.txt would start "+
			"moving the day dryRun's block order or spacing changes", got)
	}
}

// ── issue #55, finding F4 ─────────────────────────────────────────────────────

// TestGraftDestinationNoteMatchesTheDestination is the regression test for
// F4. describeGrafts used to print ONE fixed sentence for every graft's
// destination — "created on the sandbox's own root tmpfs … empty …
// unwritable once / is remounted read-only" — which is false for the
// destination shape G3's third disjunct actually permits (inside a writable
// grant), and that is the exact shape the committed golden
// (engineview.tierc.txt) itself pins. The fix decides the note PER GRAFT from
// the sandbox's own view (graftDestinationNote); this test asserts the
// decision, not merely that SOME text renders.
func TestGraftDestinationNoteMatchesTheDestination(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), profile.BuiltinDefaults(),
		envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}

	// THE CLAIM: a destination inside a WRITABLE bind (G3's third disjunct —
	// the target itself, and the exact shape engineview.tierc.txt's own
	// golden fixture uses) must not get the fixed root-tmpfs/empty/unwritable
	// sentence, because none of those three claims is true of it.
	writable := policy.Graft{Mount: policy.Mount{
		Guest: p.Target + "/writable-dest", Host: p.Mounts[p.Target].Host + "/writable-src",
		Kind: policy.KindGraft, Access: policy.AccessRO, From: []string{"(snug)"},
	}}
	note := graftDestinationNote(p, writable)
	for _, forbidden := range []string{"root tmpfs", "empty,", "unwritable"} {
		if strings.Contains(note, forbidden) {
			t.Errorf("the note for a destination inside a WRITABLE grant still claims %q — false "+
				"for this shape (issue #55, finding F4): %s", forbidden, note)
		}
	}
	if !strings.Contains(note, "HOST") {
		t.Errorf("the note for a destination inside a writable BIND does not say a write reaches "+
			"the HOST: %s", note)
	}

	// POSITIVE CONTROL: a destination with NOTHING in the sandbox's own view
	// covering it (or any of its ancestors) — G3's first/second disjunct, an
	// auto-created directory sitting on the bare root tmpfs — DOES get the
	// fixed sentence. Without this, "the note never claims root
	// tmpfs/empty/unwritable" would be trivially true of a function that
	// never renders that sentence at all.
	bare := policy.Graft{Mount: policy.Mount{
		Guest: "/totally-uncovered-directory", Host: p.Mounts[p.Target].Host,
		Kind: policy.KindGraft, Access: policy.AccessRO,
	}}
	if _, ok := p.SandboxView().CoveringMount(bare.Guest); ok {
		t.Fatalf("fixture: %s is covered by something in the default policy — pick a different "+
			"guest for the bare-tmpfs control", bare.Guest)
	}
	bareNote := graftDestinationNote(p, bare)
	if !strings.Contains(bareNote, "root tmpfs") {
		t.Errorf("control: an UNCOVERED destination must still get the fixed root-tmpfs sentence: %s", bareNote)
	}
}

// ── issue #55, finding F2 (screen half) ───────────────────────────────────────

// TestEngineOwnedHostPathsAreOnTheScreen is F2's screen assertion: a graft
// that passes G4 ONLY through EngineOwnedHostPaths — not through the
// sandbox's own HostPathVisible — must render that provenance explicitly, and
// the enumerated set of engine-owned paths must appear too. Before
// OwnEngineHostPath existed, nothing on --dry-run said why such a graft was
// legal at all: the screen is the mechanism by which a human is meant to
// trust snug, and a host path snug declares its own by fiat is exactly the
// kind of thing that screen owes a line to.
func TestEngineOwnedHostPathsAreOnTheScreen(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), profile.BuiltinDefaults(),
		envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	env := newEnvFakeEnv()

	// The host's ssh-agent/session D-Bus/Wayland/rootless-podman-socket
	// directory — no grant in the default selection exposes it, so this
	// graft can pass G4 ONLY through EngineOwnedHostPaths.
	owned := "/run/user/1000"
	if err := p.OwnEngineHostPath(env, owned); err != nil {
		t.Fatalf("fixture: OwnEngineHostPath refused a hygienic path: %v", err)
	}
	ownedGraft := policy.Graft{Mount: policy.Mount{
		Guest: p.Target + "/owned", Host: owned, Kind: policy.KindGraft, Access: policy.AccessRO,
		From: []string{"(snug)"},
	}, Why: "test abuse sentence for the owned graft"}
	if err := p.Graft(env, ownedGraft); err != nil {
		t.Fatalf("fixture: a graft sourced from an engine-owned path was refused: %v", err)
	}

	// A SECOND graft, visible only through the sandbox's own grant (the
	// target itself) — never touching EngineOwnedHostPaths at all. This is
	// the control that the "owned:" line is conditional, not printed for
	// every graft regardless of provenance.
	visibleGraft := policy.Graft{Mount: policy.Mount{
		Guest: p.Target + "/visible", Host: p.Mounts[p.Target].Host + "/visible",
		Kind: policy.KindGraft, Access: policy.AccessRO, From: []string{"(snug)"},
	}, Why: "test abuse sentence for the visible graft"}
	if err := p.Graft(env, visibleGraft); err != nil {
		t.Fatalf("fixture: a graft sourced from a sandbox-visible path was refused: %v", err)
	}

	got := captureFile(t, func(f *os.File) { describeGrafts(f, p) })

	// POSITIVE CONTROLS: both grafts actually reached the screen.
	idxOwned := strings.Index(got, ownedGraft.Guest)
	idxVisible := strings.Index(got, visibleGraft.Guest)
	if idxOwned < 0 {
		t.Fatalf("fixture: the owned graft's Guest never reached the screen at all:\n%s", got)
	}
	if idxVisible < 0 {
		t.Fatalf("fixture: the visible graft's Guest never reached the screen at all:\n%s", got)
	}

	// THE CLAIM: the engine-owned host paths summary section names the path.
	if !strings.Contains(got, "engine-owned host paths") {
		t.Errorf("the ENGINE VIEW block never rendered the 'engine-owned host paths' summary "+
			"section at all:\n%s", got)
	}
	if !strings.Contains(got, owned) {
		t.Errorf("the ENGINE VIEW block does not name %s anywhere:\n%s", owned, got)
	}

	// Split into each graft's own rendered block ("owned" sorts before
	// "visible" alphabetically, so the owned graft's block is the text
	// between the two Guest occurrences).
	var ownedBlock, visibleBlock string
	if idxOwned < idxVisible {
		ownedBlock, visibleBlock = got[idxOwned:idxVisible], got[idxVisible:]
	} else {
		visibleBlock, ownedBlock = got[idxVisible:idxOwned], got[idxOwned:]
	}

	if !strings.Contains(ownedBlock, "owned:") {
		t.Errorf("the owned graft's own block does not carry the per-graft 'owned:' provenance "+
			"line:\n%s", ownedBlock)
	}
	// POSITIVE CONTROL for the split above: the visible graft's block must
	// NOT carry an "owned:" line — the rendering is conditional on
	// HostPathVisible, not printed unconditionally for every graft.
	if strings.Contains(visibleBlock, "owned:") {
		t.Errorf("the VISIBLE graft's block carries an 'owned:' line — it is visible through the "+
			"sandbox's own grant, not through EngineOwnedHostPaths, so this line must be conditional "+
			"per-graft rather than printed for everything:\n%s", visibleBlock)
	}
}
