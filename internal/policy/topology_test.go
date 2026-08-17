package policy

import (
	"strings"
	"testing"
)

// The lattice laws, per field, in the shape of TestNetModeJoinsPermissiveWard —
// Topology.Join must be commutative, associative and idempotent, because
// resolution folds profiles in sorted order and must not depend on that order.
func TestTopologyJoinIsMonotoneAndCommutative(t *testing.T) {
	netnsVals := []NetnsOwner{NetnsSandbox, NetnsStage, NetnsHost}
	subuidVals := []SubuidMode{SubuidNone, SubuidFull}
	attachVals := []AttachMode{AttachNone, AttachPayloads}

	for _, a := range netnsVals {
		for _, b := range netnsVals {
			if got, want := a.Join(b), b.Join(a); got != want {
				t.Errorf("NetnsOwner.Join not commutative: %s.Join(%s)=%s, %s.Join(%s)=%s",
					a, b, got, b, a, want)
			}
			if got := a.Join(b); got < a || got < b {
				t.Errorf("NetnsOwner.Join(%s,%s)=%s is not >= both operands", a, b, got)
			}
		}
	}
	for _, a := range subuidVals {
		for _, b := range subuidVals {
			if got, want := a.Join(b), b.Join(a); got != want {
				t.Errorf("SubuidMode.Join not commutative: %s.Join(%s)=%s, %s.Join(%s)=%s",
					a, b, got, b, a, want)
			}
		}
	}
	for _, a := range attachVals {
		for _, b := range attachVals {
			if got, want := a.Join(b), b.Join(a); got != want {
				t.Errorf("AttachMode.Join not commutative: %s.Join(%s)=%s, %s.Join(%s)=%s",
					a, b, got, b, a, want)
			}
		}
	}

	// Topology.Join itself, field by field, and idempotent (resolve([a,a]) ==
	// resolve([a]) depends on this at the whole-Policy level; this is the
	// narrower claim about the field alone).
	x := Topology{Netns: NetnsStage, Subuid: SubuidFull, Attach: AttachPayloads}
	y := Topology{Netns: NetnsSandbox, Subuid: SubuidNone, Attach: AttachNone}
	if got, want := x.Join(y), y.Join(x); got != want {
		t.Errorf("Topology.Join not commutative: %v vs %v", got, want)
	}
	if got := x.Join(x); got != x {
		t.Errorf("Topology.Join not idempotent: %v.Join(itself) = %v", x, got)
	}
}

// TestResolveIsMonotone compares Access per EXISTING Guest key and will not
// catch a Topology regression — Topology is a scalar on Policy, not a Mount.
// This is the field's own monotonicity test: over every single-profile addition
// in the fake registry that resolves at all, adding a profile must never LOWER
// any of Topology's three fields relative to the base selection.
func TestAddingAProfileNeverLowersATopologyField(t *testing.T) {
	base := []ProfileName{"@sys", "@cwd-rw"}
	basePol := mustResolve(t, base...)

	for name := range testRegistry() {
		with, err := Resolve(testRegistry(), append(append([]ProfileName{}, base...), name), testCtx(), newFakeEnv())
		if err != nil {
			continue // a conflict is a symmetric error, not a tightening
		}
		if with.Topology.Netns < basePol.Topology.Netns {
			t.Errorf("adding %q LOWERED Topology.Netns from %s to %s",
				name, basePol.Topology.Netns, with.Topology.Netns)
		}
		if with.Topology.Subuid < basePol.Topology.Subuid {
			t.Errorf("adding %q LOWERED Topology.Subuid from %s to %s",
				name, basePol.Topology.Subuid, with.Topology.Subuid)
		}
		if with.Topology.Attach < basePol.Topology.Attach {
			t.Errorf("adding %q LOWERED Topology.Attach from %s to %s",
				name, basePol.Topology.Attach, with.Topology.Attach)
		}
	}
}

// No Profile field, no TOML key and no CLI flag may produce a Topology — the
// same device as TestPolicyHasNoRestrictionOperation: checkable by finding
// none.
//
// The literal below is UNKEYED, and that is the entire mechanism. The first
// version of this test used a keyed literal and claimed "if any of them were
// named Topology this line would not compile" — false, because a keyed literal
// compiles perfectly well with fields missing. It was verified fake by adding a
// `Topology Topology` field to Profile and watching internal/policy,
// internal/profile and internal/cli all stay green. An unkeyed literal must supply
// every field in order, so adding one anywhere breaks this build.
//
// Profile is only HALF the surface. TOML decodes into internal/profile's
// rawProfile, not into Profile, and internal/policy cannot import
// internal/profile without a cycle — so the other half of this check lives in
// TestNoTOMLKeyProducesATopology over there. Neither may be deleted as a
// duplicate of the other.
func TestTopologyIsDerivedNotSettable(t *testing.T) {
	_ = Profile{
		"x", "", nil, // Name, Description, Include
		nil, nil, nil, nil, // RO, RW, Tmpfs, Symlink
		nil,       // Optional
		"", false, // Network, DNS
		nil,       // Publish
		"", "", 0, // Address, Gateway, MTU
		"",          // Podman
		"",          // Git
		nil,         // Identity
		EnvGrants{}, // Environ
		"", false,   // Source, Trusted
	}
}

func TestValidateRefusesAnInconsistentTopology(t *testing.T) {
	p := mustResolve(t, "@sys", "@cwd-rw")
	p.Topology.Netns = NetnsHost // p.Net.Mode is still NetIsolated/NetEgress-derived
	err := p.Validate(newFakeEnv())
	if err == nil {
		t.Fatal("Validate accepted a Topology inconsistent with Net.Mode/Podman")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error %q does not explain the mismatch", err)
	}
}

// Phase 1 delegates no subuids, for ANY PodmanMode including PodmanBuild — the
// engine still runs on the host, so a delegated range would be a capability
// with no consumer (SUPERVISOR-DESIGN.md §3.6). This is the device that
// makes Phase 3 raising it a conscious edit: change this test on purpose, or
// the change was not conscious.
func TestPhase1DelegatesNoSubuids(t *testing.T) {
	for _, pm := range []PodmanMode{PodmanOff, PodmanSocket, PodmanBuild} {
		for _, n := range []NetMode{NetIsolated, NetEgress, NetHost} {
			if got := deriveTopology(n, pm).Subuid; got != SubuidNone {
				t.Errorf("deriveTopology(%s, %s).Subuid = %s, want none — "+
					"Phase 1 has no subuid consumer yet", n, pm, got)
			}
		}
	}
}

func TestNeedsStageIsFalseForOfflineAndHost(t *testing.T) {
	if deriveTopology(NetIsolated, PodmanOff).NeedsStage() {
		t.Error("NetIsolated should not need a stage")
	}
	if deriveTopology(NetHost, PodmanOff).NeedsStage() {
		t.Error("NetHost should not need a stage — it inherits the host's own netns")
	}
	// NetEgress needs a stage as of Commit B (deriveTopology's doc comment):
	// bwrap can no longer create N itself and stay the only process in the
	// tree, because the netns move (SUPERVISOR-DESIGN.md §1) has to
	// happen in a process that outlives bwrap's own clone. Before Commit B
	// this assertion read the opposite way — NetEgress NOT needing a stage —
	// and existed precisely so that commit's diff to deriveTopology would show
	// up as a failing test, not just a golden diff. It did; this is that
	// change, made deliberately.
	if !deriveTopology(NetEgress, PodmanOff).NeedsStage() {
		t.Error("NetEgress should need a stage now that deriveTopology has Commit B's shape")
	}
}

// canon() must mention the field, so TestResolveIsCommutative and
// TestResolveIsIdempotent cannot silently stop covering it — the same failure
// mode the "pasta.avx2" bullet in CLAUDE.md describes for a different field.
func TestCanonCoversTopology(t *testing.T) {
	p := mustResolveDefaults(t)
	if !strings.Contains(canon(p), "topology ") {
		t.Fatal("canon() does not render Topology; TestResolveIsCommutative cannot cover it")
	}
}
