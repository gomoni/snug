package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestTopologyProcessesMatchRunStagedsPredicates is the regression for issue
// #154 §A: --dry-run's TOPOLOGY block named pasta on an offline
// @podman-socket run that starts none, omitted the container engine that run
// does start, and printed 4 for a `@net -p @podman-socket` run that starts
// five. The count was a hand-written sentence per arm; Tier B (issue #63)
// added a fourth long-lived process and neither sentence was revisited.
//
// TestGoldenTopology already shows the rendered block, and a golden diff is
// how a human reviews a change to it. It cannot fail for the RIGHT reason on
// its own, though: a golden regenerated from wrong code is green, which is
// exactly how the wrong count survived a reviewed golden for a milestone. So
// this test states the rule independently of both the golden files and
// longLivedProcesses' own implementation:
//
//	pasta  appears IFF p.Net.Mode == policy.NetEgress
//	engine appears IFF p.Podman != policy.PodmanOff
//	stage  appears IFF p.Topology.NeedsStage()
//	snug and bwrap appear always
//
// Those are the predicates internal/sandbox/exec.go's runStaged actually
// branches on. The point is not that the number is 4 or 5 today — it is that
// the number cannot drift from the predicates without failing here.
func TestTopologyProcessesMatchRunStagedsPredicates(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sel  []policy.ProfileName
	}{
		{"isolated", []policy.ProfileName{"@sys", "@cwd-rw"}},
		{"egress", []policy.ProfileName{"@sys", "@cwd-rw", "@net"}},
		{"podman-offline", []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}},
		{"podman-egress", []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket", "@net"}},
		{"podman-build-offline", []policy.ProfileName{"@sys", "@cwd-rw", "@podman-build"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), tc.sel, envGoldenCtx(), newEnvFakeEnv())
			if err != nil {
				t.Fatalf("Resolve(%v): %v", tc.sel, err)
			}

			names := map[string]bool{}
			for _, pr := range longLivedProcesses(p) {
				if names[pr.name] {
					t.Errorf("%q listed twice — the count would double-count it", pr.name)
				}
				if pr.role == "" {
					t.Errorf("%q has no role; the list answers \"which\", not only \"how many\"", pr.name)
				}
				names[pr.name] = true
			}

			want := map[string]bool{
				"snug":       true,
				"bwrap":      true,
				"stage (P1)": p.Topology.NeedsStage(),
				"pasta":      p.Net.Mode == policy.NetEgress,
				"engine":     p.Podman != policy.PodmanOff,
			}
			for name, expected := range want {
				if names[name] != expected {
					t.Errorf("process %q: present=%v, want %v (netmode=%v podman=%v needsStage=%v)",
						name, names[name], expected, p.Net.Mode, p.Podman, p.Topology.NeedsStage())
				}
			}

			// The positive control this test would be worthless without: a
			// case asserting "pasta is absent" passes just as well on a
			// longLivedProcesses that returns nothing at all. At least one
			// case must therefore have every optional process present, and
			// this is the assertion that fails if the table above ever loses
			// it.
			if tc.name == "podman-egress" && !(names["pasta"] && names["engine"] && names["stage (P1)"]) {
				t.Errorf("the all-processes case is missing one: %v — every other case's "+
					"absence assertion is unverified without it", names)
			}
		})
	}
}

// TestTopologyProcessCountMatchesTheListItPrints guards the seam between the
// derived list and the rendered block: the number on the "processes" line and
// the number on the __innetns footnote must both be len(procs), not a literal
// that happens to agree today.
func TestTopologyProcessCountMatchesTheListItPrints(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	sel := []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket", "@net"}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}

	procs := longLivedProcesses(p)
	if len(procs) != 5 {
		t.Fatalf("expected snug+stage+pasta+engine+bwrap = 5 for %v, got %d: %v", sel, len(procs), procs)
	}

	got := captureFile(t, func(f io.Writer) { describeTopology(f, p) })

	// Every listed process is named in the block, and the count agrees.
	if !strings.Contains(got, "processes       5 —") {
		t.Errorf("the processes line does not carry the derived count 5:\n%s", got)
	}
	if !strings.Contains(got, "so it is not one of the 5.)") {
		t.Errorf("the __innetns footnote does not carry the derived count 5:\n%s", got)
	}
	for _, pr := range procs {
		if !strings.Contains(got, pr.name) {
			t.Errorf("process %q is counted but never named in the block:\n%s", pr.name, got)
		}
	}
	// The line this replaced claimed pasta unconditionally on every staged
	// run. Nothing may reintroduce a process name that is not in the list.
	if strings.Count(got, "pasta") != 1 {
		t.Errorf("pasta should be named exactly once, by the list:\n%s", got)
	}
}
