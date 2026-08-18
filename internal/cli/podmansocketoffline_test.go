package cli

import (
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestPodmanSocketDoesNotImplyEgress is the structural half of the closing
// act of issue #63, Tier B: resolving @podman-socket alone must be offline —
// NetIsolated, with @net not in the resolved include closure — now that the
// engine runs in the sandbox's OWN network namespace and no longer needs
// `include = ["net"]` to tell the truth about egress.
//
// Positive control, same test: @podman-socket -p @net still resolves to
// NetEgress, so this test can tell "offline" apart from "resolution broke" —
// a bug that made Resolve ignore @net entirely would otherwise pass the
// negative half for the wrong reason.
func TestPodmanSocketDoesNotImplyEgress(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	regMap := map[policy.ProfileName]*policy.Profile(reg)

	off, err := policy.Resolve(regMap, []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(@podman-socket): %v", err)
	}
	if off.Net.Mode != policy.NetIsolated {
		t.Errorf("@podman-socket alone resolved Net.Mode = %s, want NetIsolated (offline)", off.Net.Mode)
	}
	for _, name := range off.Profiles {
		if name == "@net" || name == "@net-anon" || name == "@net-host" {
			t.Errorf("@podman-socket alone pulled in %s — it must not include any network profile", name)
		}
	}

	// Positive control.
	with, err := policy.Resolve(regMap, []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket", "@net"}, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(@podman-socket, @net): %v", err)
	}
	if with.Net.Mode != policy.NetEgress {
		t.Errorf("@podman-socket + @net resolved Net.Mode = %s, want NetEgress — "+
			"otherwise this test cannot tell offline apart from a broken resolver", with.Net.Mode)
	}
}
