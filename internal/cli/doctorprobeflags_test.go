package cli

import (
	"slices"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestDoctorProbeIsNotWeakerThanTheSandbox is the regression for issue #159.
//
// doctor's output is a claim that snug will run on this host. A probe that
// demands LESS of the kernel than the run demands produces a false green —
// invariant 5's silent downgrade arriving through a diagnostic instead of
// through the sandbox. That is issue #98: probeBase passed --unshare-all, bwrap
// decoded it to its own -try spellings, an exhausted user.max_user_namespaces
// made bwrap skip the unshare and exit 0, and doctor printed a green tick for a
// host where every run would die.
//
// #98's fix re-typed the strict list into probeBase. That closed the instance
// and left the defect: a hand-typed copy checked by nothing, forty lines below
// a comment in the same file saying a probe must call the real code path rather
// than re-type it. #159 made probeBase read policy.Topology.UnshareFlags; this
// test is what keeps it reading it.
//
// It compares against NetnsSandbox deliberately, and that choice is the
// assertion: NetnsSandbox demands the MOST of the kernel of the three
// topologies. The stage asks bwrap for fewer namespaces (the stage already made
// the netns), so a host passing this probe satisfies both.
func TestDoctorProbeIsNotWeakerThanTheSandbox(t *testing.T) {
	want := policy.Topology{Netns: policy.NetnsSandbox}.UnshareFlags()

	// POSITIVE CONTROL, and it is mandatory rather than tidy: the loop below
	// is vacuous if the authority returns nothing, and "the probe is not weaker
	// than an empty set" is exactly the shape of assertion that let #98 ship.
	// Six is the count as of #24 — user, ipc, pid, uts, cgroup-try, net — and
	// this is a floor, not a golden: adding a namespace should not fail here,
	// losing one should.
	if len(want) < 6 {
		t.Fatalf("the authority returned %d flags (%v); every assertion below is vacuous",
			len(want), want)
	}

	got := probeBase()
	for _, flag := range want {
		if !slices.Contains(got, flag) {
			t.Errorf("the real sandbox asks bwrap for %s and doctor's probe does not, so a "+
				"host that fails on %s is reported as able to run snug.\n  probe:     %v\n  sandbox:   %v",
				flag, flag, got, want)
		}
	}

	// The two spellings that made the probe weaker in the first place. Neither
	// can come back through a well-meaning edit without failing here.
	for _, forbidden := range []string{"--unshare-all", "--unshare-user-try"} {
		if slices.Contains(got, forbidden) {
			t.Errorf("doctor's probe passes %s, which exits 0 having created no namespace when "+
				"the kernel refuses it (issue #98): %v", forbidden, got)
		}
	}
}
