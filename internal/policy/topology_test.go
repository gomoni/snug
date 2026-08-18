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
			// Subuid edge, tracked the same way — issue #63, Tier B added the
			// SubuidNone->SubuidFull rise (a container engine needs the full
			// delegated range even offline). Without this, a bug that stopped
			// @podman-socket raising Subuid could pass silently: the LOWERED
			// check above only fires on a DECREASE, and nothing else in this
			// test asserted the rise ever happens at all.
			if basePol.Topology.Subuid != with.Topology.Subuid {
				seen["subuid:"+basePol.Topology.Subuid.String()+"->"+with.Topology.Subuid.String()] = true
			}
		}
	}

	for _, edge := range []string{"sandbox->stage", "sandbox->host", "stage->host", "subuid:none->full"} {
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

// TestPodmanDelegatesFullSubuid replaces TestPhase1DelegatesNoSubuids, which
// asserted the OPPOSITE — SubuidNone for every PodmanMode — specifically so
// that raising it would be a conscious edit forced by a failing test, not a
// silent side effect of adding a case to deriveTopology (its own message said
// so). Issue #63, Tier B is that conscious edit: a container engine's storage
// needs the full delegated subuid range to chown across without ever
// touching a host uid it was not given, whether or not the run has egress.
func TestPodmanDelegatesFullSubuid(t *testing.T) {
	for _, pm := range []PodmanMode{PodmanSocket, PodmanBuild} {
		for _, n := range []NetMode{NetIsolated, NetEgress, NetHost} {
			if got := deriveTopology(n, pm).Subuid; got != SubuidFull {
				t.Errorf("deriveTopology(%s, %s).Subuid = %s, want full — "+
					"a container engine always needs the full delegated range", n, pm, got)
			}
		}
	}
	// Positive control: PodmanOff must NOT raise Subuid, on any NetMode — so
	// this test can distinguish "podman raises it" from "everything raises it".
	for _, n := range []NetMode{NetIsolated, NetEgress, NetHost} {
		if got := deriveTopology(n, PodmanOff).Subuid; got != SubuidNone {
			t.Errorf("deriveTopology(%s, PodmanOff).Subuid = %s, want none", n, got)
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
	// An OFFLINE container run also needs a stage now (issue #63, Tier B): the
	// engine needs a stage to own its U even when Net.Mode never leaves
	// NetnsSandbox on its own — deriveTopology raises Netns to NetnsStage
	// itself once pm != PodmanOff. This is the assertion that would have
	// caught a NeedsStage that checked only Netns and not Subuid.
	if !deriveTopology(NetIsolated, PodmanSocket).NeedsStage() {
		t.Error("an offline container run should still need a stage — the engine needs U+N")
	}
}

// TestPodmanSelectsAStage pins deriveTopology's podman branch directly:
// selecting a container engine raises BOTH Netns (to at least NetnsStage) and
// Subuid (to SubuidFull), even with no egress. Positive control in the same
// test: PodmanOff must leave an offline topology completely unchanged, so a
// bug that made deriveTopology raise everything regardless of pm cannot pass.
func TestPodmanSelectsAStage(t *testing.T) {
	for _, pm := range []PodmanMode{PodmanSocket, PodmanBuild} {
		got := deriveTopology(NetIsolated, pm)
		if got.Netns != NetnsStage {
			t.Errorf("deriveTopology(NetIsolated, %s).Netns = %s, want stage", pm, got.Netns)
		}
		if got.Subuid != SubuidFull {
			t.Errorf("deriveTopology(NetIsolated, %s).Subuid = %s, want full", pm, got.Subuid)
		}
		if !got.NeedsStage() {
			t.Errorf("deriveTopology(NetIsolated, %s).NeedsStage() = false, want true", pm)
		}
	}

	// Positive control: an offline non-podman selection is untouched.
	off := deriveTopology(NetIsolated, PodmanOff)
	if off.Netns != NetnsSandbox || off.Subuid != SubuidNone || off.NeedsStage() {
		t.Errorf("deriveTopology(NetIsolated, PodmanOff) = %+v, want the unraised floor — "+
			"the podman branch must not fire for PodmanOff", off)
	}

	// The --i-know @net-host + podman edge: NetnsHost is preserved (the engine
	// inherits the host netns there), but Subuid still rises to SubuidFull and
	// NeedsStage is still true, because the stage owns U regardless of which
	// netns the engine joins.
	hostPodman := deriveTopology(NetHost, PodmanSocket)
	if hostPodman.Netns != NetnsHost {
		t.Errorf("deriveTopology(NetHost, PodmanSocket).Netns = %s, want host (preserved, not lowered)", hostPodman.Netns)
	}
	if hostPodman.Subuid != SubuidFull || !hostPodman.NeedsStage() {
		t.Errorf("deriveTopology(NetHost, PodmanSocket) = %+v, want Subuid=full and NeedsStage=true", hostPodman)
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
