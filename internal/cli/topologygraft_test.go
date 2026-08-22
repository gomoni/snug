package cli

import (
	"io"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestTopologyBlockDoesNotDependOnGrafts turns a CONVENTION into a property
// with a name (issue #364, specified there and not written until now; issue
// #33 is the tracker for named-but-unwritten tests).
//
// The convention: the TOPOLOGY block is narrow on purpose. describeTopology
// renders the namespace topology and nothing else, so topology.podman-*.txt
// carry no graft rows even though a real `snug --dry-run -p @podman-socket`
// prints a whole ENGINE VIEW block below them — startContainers calls
// installEngineViewGrafts BEFORE its --dry-run branch (container.go, #125
// §9.2), so p.Grafts is populated on every container run. The ENGINE VIEW
// artifact lives in engineview.enginemounts.txt, which is the one-block-one-
// golden convention this package uses throughout: FILESYSTEM in
// filesystem.defaults.txt, ENVIRONMENT in env.podman-socket.txt.
//
// WHY THAT CONVENTION NEEDS A TEST RATHER THAN A COMMENT. It held by accident
// of two independent facts — describeTopology happens not to read p.Grafts,
// and topologygolden_test.go happens to capture that one function — and
// NOTHING FAILED if either changed. The comment that used to explain the empty
// goldens was itself false for a tier and was the reason nobody looked (#364);
// replacing false prose with true prose leaves the same gap, one revision
// later.
//
// AND THE FAILURE MODE IS A FLAKE, NOT A MESSAGE, which is what makes it worth
// a test of its own. engine.PlannedPaths keys this run's runroot on
// fmt.Sprintf("snug-%d-%d", os.Getuid(), os.Getpid()) (internal/engine/paths.go).
// So the first symptom of someone rendering graft-derived text in the TOPOLOGY
// block is a golden that embeds a live pid, passes on the run that regenerated
// it, and fails on its second run and on every other machine. A developer
// meeting that sees a mysterious golden diff, not a sentence naming the rule
// they broke. This test names it.
//
// It deliberately does NOT assert that describeTopology's output is any
// particular text — TestGoldenTopology owns that. What it asserts is the
// weaker, structural thing the goldens depend on: whatever that block prints,
// it prints the same bytes whether or not this policy carries grafts.
func TestTopologyBlockDoesNotDependOnGrafts(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	// The same selection topologygolden_test.go's "podman-offline" case uses,
	// and it must stay that way: this test is about the fixture behind THAT
	// golden, so a different selection would be checking a property of some
	// other policy. @podman-socket is what makes p.Podman != PodmanOff and so
	// what makes describeTopology render the engine line group at all — the
	// only branch where a graft row could plausibly be added by mistake.
	sel := []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel,
		envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}

	before := captureFile(t, func(f io.Writer) { describeTopology(f, p) })

	// POSITIVE CONTROL, part one: the block really renders something. A
	// describeTopology that printed nothing would satisfy the byte-identity
	// assertion below trivially, in both directions.
	if before == "" {
		t.Fatal("describeTopology printed nothing, so the byte-identity assertion below " +
			"would hold for a block that renders no text at all")
	}

	if err := installEngineViewGrafts(newEnvFakeEnv(), p); err != nil {
		t.Fatalf("installEngineViewGrafts: %v", err)
	}

	// POSITIVE CONTROL, part two, and it is THE one this test cannot do
	// without: grafts were really installed. Without it, "the output did not
	// change when grafts were added" passes on a policy where no graft was
	// ever added — the vacuous shape this repo keeps rediscovering, most
	// recently as #344's matcher that named a string nothing carried.
	//
	// The count is FOUR, and it is asserted as a number rather than as
	// non-emptiness on purpose: installEngineViewGrafts makes four p.Graft
	// calls (/proc, /sys/fs/cgroup, /var/tmp, /run), and its own doc comment
	// said THREE in four places for as long as /var/tmp had existed (#364).
	// A count in prose is a copy of state held in the calls; a count in a test
	// is a copy that fails loudly when the state moves, which is the point.
	// If a fifth graft is added here, this line is SUPPOSED to fail: update it
	// deliberately, and check the new graft did not bring a per-run path into
	// a block that is rendered into a golden.
	const wantGrafts = 4
	if got := len(p.Grafts); got != wantGrafts {
		t.Fatalf("installEngineViewGrafts left %d grafts on the policy, want %d — this "+
			"test's whole assertion is that adding grafts does not move the TOPOLOGY "+
			"block, so a policy with the wrong number of them proves nothing either way",
			got, wantGrafts)
	}

	after := captureFile(t, func(f io.Writer) { describeTopology(f, p) })

	if before != after {
		t.Errorf("the TOPOLOGY block changed when grafts were installed.\n"+
			"       That block is captured ALONE by topologygolden_test.go, so its goldens\n"+
			"       (topology.podman-*.txt) are built from a policy with NO grafts. If this\n"+
			"       block now renders graft-derived text, those goldens are narrower than\n"+
			"       the screen — and worse, engine.PlannedPaths keys the runroot on\n"+
			"       snug-<uid>-<pid>, so a regenerated golden would embed a live pid and\n"+
			"       fail on its second run and on every other machine.\n"+
			"       The ENGINE VIEW block is where graft rows belong; its golden is\n"+
			"       engineview.enginemounts.txt (issue #364).\n"+
			"before:\n%s\nafter:\n%s", before, after)
	}
}
