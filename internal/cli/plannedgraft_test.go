package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
)

// The fixture environment for the planned-paths golden. Both are visibly not
// real directories and are outside the fixture's target (/home/u/proj/sub) and
// home (/home/u), so a reader cannot mistake a row here for one of the
// payload's own grants, and nothing here can collide with a path envGoldenCtx
// already names.
const (
	plannedDataHome = "/xdg-data"
	plannedTmpDir   = "/tmpdir"
)

// TestGoldenEngineViewPlannedPaths is the golden for the four HOST-TREE grafts
// — store, runroot, sock, conf — built from the real engine.PlannedPaths, on
// the same @sys @cwd-rw @podman-socket selection every other engine-view
// fixture in this package uses.
//
// # WHAT WAS MISSING, AND WHY IT MATTERED
//
// engineview.enginemounts.txt pins the engine's OWN four mounts (/proc,
// /sys/fs/cgroup, /var/tmp, /run — installEngineViewGrafts) and
// engineview.tierc.txt pins the host-tree RENDER path from a hand-built
// fixture with invented paths. Neither ran engine.PlannedPaths. So the rows a
// human reads to learn that the container image store is READ-WRITE, PERSISTS
// across runs and is SHARED with every other sandbox on the same target
// directory had no golden at all — the highest-value hand-over a container run
// makes, pinned nowhere (issues #252, #364).
//
// # WHY THERE IS NO INJECTABLE TAG IN PRODUCTION CODE
//
// The obstacle to this golden was always stated as a constraint on
// engine.PlannedPaths: it keys this run's directory on
// fmt.Sprintf("snug-%d-%d", os.Getuid(), os.Getpid()), so a naive golden
// embeds a live pid and fails on its second run and on every other machine.
// The remedy proposed alongside it was a settable tag. That remedy was
// REJECTED, and the reasoning is worth carrying because it is a rule and not a
// preference:
//
//   - A tag seam does not even achieve the goal. os.Getuid() enters a SECOND
//     time, through the runroot's own name (fmt.Sprintf("snug-engines-%d-%s",
//     os.Getuid(), key) in planPaths). Fixing the tag alone leaves the output
//     host-dependent and leaves this golden unwritable.
//   - Making the UID injectable is worse than cosmetic. The runroot lives
//     under world-writable /tmp, and engineKey's own doc comment names what
//     actually protects it: "that guarantee is VerifyOwnedAndPrivate's uid+mode
//     check". That check compares against os.Getuid() and would keep doing so,
//     so a seam bypasses no ownership check — what it breaks is the AGREEMENT
//     between the name and the owner. Two processes with different uids could
//     be steered to one runroot name, and the collision is then settled by
//     whoever created the directory first, with the loser refused by
//     VerifyOwnedAndPrivate. That is a name that no longer means what it says.
//   - planPaths is the SOLE author of "which host directory is this run's
//     own", and internal/engine's TestEngineCreatedPathsMatchPlannedPaths pins
//     engine.New's created directories to it. A settable tag is a second way
//     for two live runs to claim one socket directory.
//
// The asymmetry that makes the test-side answer legitimate rather than a
// dodge: TWO of the four host-dependent inputs are ALREADY injectable through
// the environment — dataHomeDir() reads $XDG_DATA_HOME and os.TempDir()
// re-reads $TMPDIR on every call, so t.Setenv reaches both. The remaining two
// are the process's IDENTITY. Identity can never be anything but the real
// value in production, so a seam there makes no production behaviour testable
// that is not already — it only makes one breakable. Normalising identity in
// the test is the honest description of what is going on; instrumenting the
// subject would not be.
//
// # WHAT THE NORMALISATION MUST PRESERVE
//
// The uid and pid digits carry exactly one piece of security content: WHICH
// paths are per-run and which are per-target-and-persistent. So the
// substitution is structure-preserving and uses two DISTINGUISHABLE
// placeholders, and it deliberately leaves the engineKey hash alone — that
// value is internal/targetkey.Hash(pol.Target), the full untruncated sha256
// hex digest (issue #308's key-length ruling: engineKey used to truncate to
// 16 hex chars, a lossy transform a reader could not detect from the name
// alone), identical on every machine, and it is the evidence that the store
// and the runroot are keyed on the TARGET.
//
// Read the golden and the distinction is on its face: the key hash appears in
// the store and runroot rows and NOT in sock/conf; snug-UID-PID appears in
// sock/conf and NOT in store/runroot; the store sits under $XDG_DATA_HOME and
// the other three under $TMPDIR.
//
// FORBIDDEN, and stated here because both shortcuts look reasonable: a digit
// regexp ([0-9]+ also eats the key hash, and any number inside an abuse
// sentence), and a single blanket <host> placeholder. Either destroys the
// per-run/per-target evidence, which is the only thing the digits ever carried.
// replacePlannedIdentity replaces two COMPOSED tokens — text only the running
// process's own identity can have produced.
//
// # WHAT THIS STILL DOES NOT COVER
//
// The TOOLCHAIN graft has no golden on any path, because the preflight that
// answers it does not run under --dry-run at all (GraftPathsInto returns
// before it whenever p.EngineToolchainRoot is empty, which this test asserts).
// And a WHOLE-SCREEN podman golden remains impossible for the same identity
// reason this test works around, so this covers the describeGrafts block
// alone — the one-block-one-golden convention this package uses throughout.
func TestGoldenEngineViewPlannedPaths(t *testing.T) {
	// No t.Parallel: t.Setenv forbids it, and the two variables below are
	// what make this test's output the same on every machine.
	t.Setenv("XDG_DATA_HOME", plannedDataHome)
	t.Setenv("TMPDIR", plannedTmpDir)

	p := engineViewPolicy(t)

	// A dry run knows no toolchain, and GraftPathsInto records a FIFTH graft
	// when it does. Asserting it here rather than only counting to four below
	// separates "the count is right" from "the count is right for the reason
	// this test claims" — and if a toolchain ever does reach this path, the
	// failure names the cause instead of leaving a mysterious fifth row to be
	// absorbed by a -update run.
	if p.EngineToolchainRoot != "" {
		t.Fatalf("the fixture policy carries EngineToolchainRoot %q; --dry-run runs no preflight, "+
			"so this must be empty and the graft count below must be four",
			p.EngineToolchainRoot)
	}

	paths, err := engine.PlannedPaths(p)
	if err != nil {
		t.Fatalf("engine.PlannedPaths: %v", err)
	}
	if err := engine.GraftPathsInto(newEnvFakeEnv(), p, paths); err != nil {
		t.Fatalf("engine.GraftPathsInto: %v", err)
	}

	// THE STRUCTURE IS ASSERTED FROM p.Grafts, NOT FROM THE RENDERED TEXT, and
	// that split is the point: the golden holds the literals a human reviews,
	// this table holds the facts a -update run must not be able to absorb. A
	// golden is only ever as strong as whoever read the regeneration, so the
	// store silently becoming read-only — or the conf directory becoming
	// writable, which would let a talked-into engine rewrite the storage,
	// registry and signature policy it was started under — has to fail on an
	// assertion someone must delete on purpose.
	want := []struct {
		guest  string
		host   string
		access policy.Access
	}{
		{policy.EngineStoreGuest, paths.Store, policy.AccessRW},
		{policy.EngineRunrootGuest, paths.Runroot, policy.AccessRW},
		{policy.EngineSockGuest, paths.SockDir, policy.AccessRW},
		{policy.EngineConfGuest, paths.ConfDir, policy.AccessRO},
	}

	if len(p.Grafts) != len(want) {
		guests := make([]string, 0, len(p.Grafts))
		for g := range p.Grafts {
			guests = append(guests, g)
		}
		t.Fatalf("GraftPathsInto recorded %d graft(s) (%v), want exactly %d — a golden compared "+
			"against the wrong number of rows proves nothing about any of them",
			len(p.Grafts), guests, len(want))
	}

	for _, w := range want {
		gr, ok := p.Grafts[w.guest]
		if !ok {
			t.Errorf("no graft at %s", w.guest)
			continue
		}
		if gr.Host != w.host {
			t.Errorf("the graft at %s is sourced from %q, but PlannedPaths computed %q — the "+
				"screen would then name a host directory the run does not use",
				w.guest, gr.Host, w.host)
		}
		if gr.Access != w.access {
			t.Errorf("the graft at %s is %v, want %v", w.guest, gr.Access, w.access)
		}
		if gr.Why == "" {
			t.Errorf("the graft at %s has no abuse sentence", w.guest)
		}
	}

	raw := captureFile(t, func(f io.Writer) { describeGrafts(f, p) })

	// BOTH SUBSTITUTIONS MUST FIRE, asserted on the raw screen before either
	// runs. The failure is not pedantry: if PlannedPaths stops embedding uid
	// or pid, this test must stop silently comparing unnormalised bytes and
	// say so — because at that point the golden can be made EXACT, the
	// residual named in dryrun.go's describeGrafts comment is closed, and both
	// of those are decisions to take deliberately rather than side effects of
	// a green run. It is also the positive control on the render itself: a
	// describeGrafts that printed nothing would carry neither token.
	for _, sub := range plannedIdentitySubs() {
		if !strings.Contains(raw, sub.from) {
			t.Fatalf("the rendered block contains no %q, so that substitution is a no-op and the "+
				"golden below would be comparing unnormalised bytes. If engine.planPaths no "+
				"longer composes that token, the golden can be made exact and this "+
				"normalisation should go — do that deliberately, do not delete the check:\n%s",
				sub.from, raw)
		}
	}
	got := replacePlannedIdentity(raw)

	// Every host path reaches the screen, checked AFTER normalisation and
	// through the same substitution — so this also proves the two tokens
	// covered every path, not merely that each fired somewhere.
	for _, w := range want {
		if !strings.Contains(got, replacePlannedIdentity(w.host)) {
			t.Errorf("the rendered block never names %s's host source %q:\n%s",
				w.guest, w.host, got)
		}
	}

	// describeGrafts dropping the Why lines would otherwise still match a
	// regenerated golden, and the abuse sentence is the one thing on this
	// block a reader cannot reconstruct from the paths.
	if n := strings.Count(got, "abuse:"); n != len(want) {
		t.Errorf("the rendered block carries %d abuse sentence(s), want %d:\n%s", n, len(want), got)
	}

	path := filepath.Join("testdata", "engineview.planned.txt")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	wantGolden, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/cli -update)", err)
	}
	if got != string(wantGolden) {
		t.Errorf("the ENGINE VIEW block for the engine's HOST-TREE grafts changed — this is what "+
			"a human reads to learn that the container image store is writable, persistent and "+
			"shared across every run of the same target directory.\n--- got\n%s\n--- want\n%s",
			got, wantGolden)
	}
}

// TestBuildReportJudgesTheToolchainRootWithoutRecordingIt is --dry-run's own
// version of the assertion just above (TestGoldenEngineViewPlannedPaths's
// EngineToolchainRoot check): JudgeEngineToolchain, buildReport's caller,
// records nothing, so a cleared $SNUG_PODMAN_ROOT on the fake host must leave
// EngineToolchainRoot empty after a full buildReport. --dry-run becoming a
// second writer of a write-once field is exactly what would make the run and
// the screen able to disagree about which root is recorded.
func TestBuildReportJudgesTheToolchainRootWithoutRecordingIt(t *testing.T) {
	p := engineViewPolicy(t)
	env := newEnvFakeEnv()
	env.env["SNUG_PODMAN_ROOT"] = "/home/u/secrets-tools" // clean, ungranted, cleared
	env.dirs["/home/u/secrets-tools"] = true

	_ = buildReport(env, p, nil, config{}, nil, func() engine.SignaturePolicySummary {
		return engine.SignaturePolicySummary{}
	})

	if p.EngineToolchainRoot != "" {
		t.Errorf("buildReport left EngineToolchainRoot = %q; --dry-run must judge without "+
			"recording", p.EngineToolchainRoot)
	}
}

// plannedIdentitySubs are the two tokens engine.planPaths composes from THIS
// process's own identity, with the placeholder each is replaced by.
//
// Two composed tokens, never a digit regexp and never one blanket <host>
// placeholder: see the FORBIDDEN paragraph on the test above for why the
// distinction between them is the only security content the digits carry.
func plannedIdentitySubs() []struct{ from, to string } {
	return []struct{ from, to string }{
		// This run's own directory: sock and conf live under it.
		{fmt.Sprintf("snug-%d-%d", os.Getuid(), os.Getpid()), "snug-UID-PID"},
		// The runroot's parent, which carries the uid a SECOND time — the
		// reason a tag seam alone could never have produced this golden. The
		// trailing dash keeps the full-hex engineKey that follows it intact.
		{fmt.Sprintf("snug-engines-%d-", os.Getuid()), "snug-engines-UID-"},
	}
}

// replacePlannedIdentity applies plannedIdentitySubs and nothing else. It does
// not assert that either fired: it is called on single host paths too, and no
// one path carries both tokens. The caller asserts, once, against the whole
// rendered block.
func replacePlannedIdentity(s string) string {
	for _, sub := range plannedIdentitySubs() {
		s = strings.ReplaceAll(s, sub.from, sub.to)
	}
	return s
}
