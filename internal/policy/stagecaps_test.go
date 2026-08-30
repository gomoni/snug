package policy

import "testing"

// TestStageCapDropIsExactlyTheStandingGate pins the single entry issue #61's
// settlement measured as case G, mirroring TestEngineCapBoundingIsTheMeasuredTwelve's
// own shape for the other constant this package exports a fixed capability
// list from. Growing the list — case G measured ONE capability as the gate
// that works, not a family of them — must be a reviewed diff, not a silent
// append.
func TestStageCapDropIsExactlyTheStandingGate(t *testing.T) {
	if len(StageCapDrop) != 1 {
		t.Fatalf("StageCapDrop has %d entries, want 1: %v", len(StageCapDrop), StageCapDrop)
	}
	if StageCapDrop[0] != "CAP_SYS_PTRACE" {
		t.Errorf("StageCapDrop[0] = %q, want CAP_SYS_PTRACE", StageCapDrop[0])
	}
}

// TestStageCapDropAndEngineCapBoundingAreDisjoint is the coupling guard
// stagecaps.go's own doc comment names: P1's bounding set is the CEILING the
// engine's own capset(2) call is computed against (the engine's clone carries
// no CLONE_NEWUSER), so a capability named in BOTH lists would have
// dropFromBounding remove it from P1 and then have the engine's own
// dropCapsToExactly ask to KEEP it — a permitted set outside the bounding set,
// which capset(2) refuses. This fails at `go test`, on a laptop with no
// namespace privilege at all, rather than mid-run on a real engine's launch.
func TestStageCapDropAndEngineCapBoundingAreDisjoint(t *testing.T) {
	dropped := map[string]bool{}
	for _, name := range StageCapDrop {
		dropped[name] = true
	}
	for _, name := range EngineCapBounding {
		if dropped[name] {
			t.Errorf("%s is in both StageCapDrop and EngineCapBounding: the engine's own "+
				"capset(2) would ask to keep a capability P1 already removed from its own "+
				"bounding set, which the kernel refuses", name)
		}
	}
}
