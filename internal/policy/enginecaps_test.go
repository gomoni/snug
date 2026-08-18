package policy

import "testing"

// TestEngineCapBoundingExcludesTheStandingGate pins the two caps that must
// never appear, for two different reasons: CAP_SYS_PTRACE is the standing
// gate against a peer-in-U read (CLAUDE.md, M6); CAP_NET_ADMIN is the
// maintainer's settled decision that a compromised engine must not be able
// to reconfigure the shared network namespace N. Either reappearing is a
// widening that must show up here AND in the topology.podman-*.txt goldens.
func TestEngineCapBoundingExcludesTheStandingGate(t *testing.T) {
	for _, forbidden := range []string{"CAP_SYS_PTRACE", "CAP_NET_ADMIN"} {
		for _, c := range EngineCapBounding {
			if c == forbidden {
				t.Fatalf("EngineCapBounding contains %s, which must never be granted to the engine", forbidden)
			}
		}
	}
}

// TestEngineCapBoundingIsTheMeasuredTwelve pins the exact measured floor
// (host-bridge, M-CAP) so a change to the count is a conscious, reviewed
// edit rather than an accidental append or a "tightened" false floor.
func TestEngineCapBoundingIsTheMeasuredTwelve(t *testing.T) {
	want := map[string]bool{
		"CAP_SYS_ADMIN": true, "CAP_SYS_CHROOT": true, "CAP_CHOWN": true,
		"CAP_DAC_OVERRIDE": true, "CAP_FOWNER": true, "CAP_FSETID": true,
		"CAP_SETUID": true, "CAP_SETGID": true, "CAP_SETPCAP": true,
		"CAP_SETFCAP": true, "CAP_KILL": true, "CAP_NET_BIND_SERVICE": true,
	}
	if len(EngineCapBounding) != len(want) {
		t.Fatalf("EngineCapBounding has %d entries, want %d: %v", len(EngineCapBounding), len(want), EngineCapBounding)
	}
	seen := map[string]bool{}
	for _, c := range EngineCapBounding {
		if seen[c] {
			t.Errorf("EngineCapBounding contains %s twice", c)
		}
		seen[c] = true
		if !want[c] {
			t.Errorf("EngineCapBounding contains unexpected %s", c)
		}
	}
	for c := range want {
		if !seen[c] {
			t.Errorf("EngineCapBounding is missing %s", c)
		}
	}
}
