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
	// One RO, one RW, so the golden pins both kind-column spellings.
	if err := p.Graft(newEnvFakeEnv(), policy.Graft{
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
	if err := p.Graft(newEnvFakeEnv(), policy.Graft{
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
