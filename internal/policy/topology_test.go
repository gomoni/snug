package policy

import (
	"strings"
	"testing"
)

// TestResolveIsMonotone compares Access per EXISTING Guest key and will not
// catch a Topology regression — Topology is a scalar on Policy, not a Mount.
// This is the field's own monotonicity test: over every single-profile addition
// in the fake registry that resolves at all, adding a profile must never LOWER
// either of Topology's fields relative to the base selection.
//
// It is now the ONLY monotonicity check for Topology. The lattice-law test that
// used to sit above it went with Topology.Join, NetnsOwner.Join and
// SubuidMode.Join, none of which had a caller outside that test — a law about
// dead code, proved while the live path went partly unwalked.
//
// Two BASES, and that is the half the deletion made load-bearing. With only an
// isolated base, every addition that raises the netns owner raises it from
// NetnsSandbox, so the NetnsStage -> NetnsHost edge was never taken: the
// registry had no `network = "host"` fixture either, so nothing in this package
// had ever resolved one. `netty-host` and the egress base are what walk it.
func TestAddingAProfileNeverLowersATopologyField(t *testing.T) {
	bases := map[string][]ProfileName{
		"isolated": {"@sys", "@cwd-rw"},
		// Starts at NetnsStage, so adding a host-network profile takes the
		// stage -> host edge, and adding an isolated one must not walk back
		// down it.
		"egress": {"@sys", "@cwd-rw", "netty"},
	}

	// Coverage, asserted rather than assumed: a base that stopped resolving to
	// NetnsStage, or a fixture that stopped granting host network, would leave
	// this test passing over a strictly smaller set of edges and say nothing.
	// This is the same shape as a positive control — the test must prove it
	// went where it claims to go.
	seen := map[string]bool{}

	for baseName, base := range bases {
		basePol := mustResolve(t, base...)
		for name := range testRegistry() {
			with, err := Resolve(testRegistry(), append(append([]ProfileName{}, base...), name), testCtx(), newFakeEnv())
			if err != nil {
				continue // a conflict is a symmetric error, not a tightening
			}
			if with.Topology.Netns < basePol.Topology.Netns {
				t.Errorf("on the %s base, adding %q LOWERED Topology.Netns from %s to %s",
					baseName, name, basePol.Topology.Netns, with.Topology.Netns)
			}
			if with.Topology.Subuid < basePol.Topology.Subuid {
				t.Errorf("on the %s base, adding %q LOWERED Topology.Subuid from %s to %s",
					baseName, name, basePol.Topology.Subuid, with.Topology.Subuid)
			}
			if basePol.Topology.Netns != with.Topology.Netns {
				seen[basePol.Topology.Netns.String()+"->"+with.Topology.Netns.String()] = true
			}
		}
	}

	for _, edge := range []string{"sandbox->stage", "sandbox->host", "stage->host"} {
		if !seen[edge] {
			t.Errorf("PRECONDITION: no profile addition took the %s edge, so this test did "+
				"not exercise it. Edges walked: %v. Either a base no longer resolves where "+
				"this test expects, or the fixture that grants that network mode is gone",
				edge, sortedKeys(seen))
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
