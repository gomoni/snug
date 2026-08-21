package policy

import (
	"sort"
	"testing"
)

// closurePaths is what the four mounts are, read back from the code that
// installs them rather than typed again here: a literal list in the test would
// pass while the shipped set drifted.
func closurePaths(p *Policy) []string {
	var got []string
	for guest := range p.Mounts {
		if IsProcfsClosurePath(guest) {
			got = append(got, guest)
		}
	}
	sort.Strings(got)
	return got
}

// TestProcfsClosuresApplyToAnOrdinaryRun is the positive half, and it comes
// first because everything below it is "…except here": an ordinary sandbox
// gets snug's own empty files over the host's kernel config and keyring, and
// a read-only /proc/sys.
func TestProcfsClosuresApplyToAnOrdinaryRun(t *testing.T) {
	p := mustResolve(t, "@sys", "@cwd-rw")

	got := closurePaths(p)
	if len(got) == 0 {
		t.Fatalf("an ordinary run has none of the procfs closures — every assertion about the "+
			"engine exemption below would then be about a set that is empty anyway: %v", got)
	}
	for _, guest := range got {
		m := p.Mounts[guest]
		if !m.Authored {
			t.Errorf("%s is not Authored, so rejectMasking would judge it as a profile's grant "+
				"and a profile could mount over it", guest)
		}
		if m.Access != AccessRO {
			t.Errorf("%s is %s; every closure is read-only — a writable one would be a path the "+
				"payload can put its own content at", guest, m.Access)
		}
	}
	t.Logf("ordinary run closes: %v", got)
}

// TestProcfsClosuresAreSkippedForAnEngineRun pins the exception's SHAPE, which
// is the half that decides how much it costs (issue #29).
//
// The maintainer accepted the exemption with its cost stated: a run that starts
// a container engine keeps the host's procfs values, because the kernel refuses
// the engine its own procfs otherwise. What must NOT follow is either of the
// two adjacent things a reader might assume:
//
//   - that having a container profile installed weakens every run. It does not.
//     The guard keys on the RESOLVED Podman mode, so a selection that does not
//     ask for an engine keeps its closures even when the profile exists in the
//     registry and could have been selected.
//   - that the exemption removes anything else. It removes exactly the four
//     closures; every other mount is identical between the two policies.
//
// Both are asserted, because "scoped" is a claim about what does not change.
func TestProcfsClosuresAreSkippedForAnEngineRun(t *testing.T) {
	ordinary := mustResolve(t, "@sys", "@cwd-rw")
	engine := mustResolve(t, "@sys", "@cwd-rw", "@podman-socket")

	if got := closurePaths(engine); len(got) != 0 {
		t.Errorf("an engine run still installs %v. The kernel refuses the engine a fresh procfs "+
			"while any mount covers part of one it can see, so this run would fail with "+
			"`__inengine: mounting a fresh /proc … operation not permitted`", got)
	}
	if !ProcfsClosuresSkipped(engine) || ProcfsClosuresSkipped(ordinary) {
		t.Errorf("ProcfsClosuresSkipped disagrees with what was installed (engine=%v, ordinary=%v) "+
			"— --dry-run's disclosure reads that same function, so the screen would be wrong "+
			"rather than merely inconsistent",
			ProcfsClosuresSkipped(engine), ProcfsClosuresSkipped(ordinary))
	}

	// SCOPE, half one: installed is not selected. testRegistry() carries
	// @podman-socket throughout, and `ordinary` above never named it.
	if _, ok := testRegistry()["@podman-socket"]; !ok {
		t.Fatal("this registry has no container profile, so the scoping assertion below is " +
			"vacuous — it is asserting that an absent profile changed nothing")
	}
	if got := closurePaths(ordinary); len(got) == 0 {
		t.Error("a selection that does not name a container profile lost its closures anyway: " +
			"the exemption is keyed on the profile EXISTING rather than on this run asking " +
			"for an engine, which weakens every run on the host instead of this one")
	}

	// SCOPE, half two: nothing else moved. A guard that also dropped some
	// unrelated mount would pass every assertion above.
	for guest, was := range ordinary.Mounts {
		if IsProcfsClosurePath(guest) {
			continue
		}
		now, ok := engine.Mounts[guest]
		if !ok {
			t.Errorf("the engine run is missing %s, which is not one of the closures — the "+
				"exemption removed more than it is allowed to", guest)
			continue
		}
		if now.Access < was.Access {
			t.Errorf("the engine run weakened %s from %s to %s, which the exemption does not "+
				"cover", guest, was.Access, now.Access)
		}
	}
}

// TestProcfsClosureExemptionIsOneCondition guards the drift this exemption is
// most likely to suffer: two places deciding "does this run get the closures".
//
// installProcfsReplacements applies it and --dry-run discloses it, and if those
// ever answer differently the screen becomes a lie in the reassuring direction
// — a run that says the closures are applied while they are not. One predicate
// is what makes that impossible, so the predicate's agreement with the
// installed set is checked here for every Podman mode rather than for the one
// a test happened to pick.
func TestProcfsClosureExemptionIsOneCondition(t *testing.T) {
	for _, tc := range []struct {
		name string
		sel  []ProfileName
	}{
		{"no engine", []ProfileName{"@sys", "@cwd-rw"}},
		{"engine", []ProfileName{"@sys", "@cwd-rw", "@podman-socket"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := mustResolve(t, tc.sel...)
			installed := len(closurePaths(p)) > 0
			if installed == ProcfsClosuresSkipped(p) {
				t.Errorf("ProcfsClosuresSkipped says %v while the policy has %d closure mount(s) "+
					"— the predicate and the installer disagree",
					ProcfsClosuresSkipped(p), len(closurePaths(p)))
			}
		})
	}
}
