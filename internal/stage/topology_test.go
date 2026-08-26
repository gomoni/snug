package stage

import (
	"os"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestStartRefusesEveryTopologyFieldItDoesNotImplement is issue #25: before
// this, Config carried Netns alone and the stage hardcoded its single-uid map
// independently, so `subuid none` in --dry-run was true by COINCIDENCE. Nothing
// connected the screen to the code — a deriveTopology that began returning
// SubuidFull would have changed what a human reads and nothing else, which is
// invariant 6 failing in the one artifact by which snug can be trusted at all.
//
// The check is not "does Start read the field"; a field can be read and
// ignored. It is that a topology the stage cannot build is REFUSED, loudly,
// naming what to do about it — invariant 5.
//
// Issue #63, Tier B taught Start to delegate a full subuid range (subuid.go),
// so SubuidFull moved from "refused" to "implemented, same as SubuidNone" —
// this test's own subtests moved with it, per its original comment's promise
// ("Phase 3 is where this stops being an error... a deliberate edit here").
// What is refused now is a Subuid value NEITHER of the two named constants
// names — the only way to construct one is a raw conversion, which is exactly
// what makes the refusal a genuine "this package does not implement X" rather
// than a stand-in for a value nothing produces today.
//
// Nothing here starts a working stage. Every case is refused before Start
// creates a socketpair, and the over-large Sandbox slice gives the
// implemented-Subuid cases a harmless downstream failure (the fd budget) to
// land on instead.
func TestStartRefusesEveryTopologyFieldItDoesNotImplement(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	oversized := make([]*os.File, maxPassthrough+1)
	for i := range oversized {
		oversized[i] = devNull
	}

	t.Run("an unimplemented Subuid value is refused", func(t *testing.T) {
		_, err := Start(Config{
			Topology: policy.Topology{Netns: policy.NetnsStage, Subuid: policy.SubuidMode(99)},
			Sandbox:  oversized,
		})
		if err == nil {
			t.Fatal("Start accepted a Subuid value neither SubuidNone nor SubuidFull names")
		}
		if !strings.Contains(err.Error(), "Subuid") {
			t.Errorf("Start refused, but not for the subuid reason — so this test would pass "+
				"on a build where the subuid check had been deleted and something else "+
				"failed first:\n%v", err)
		}
	})

	// Both IMPLEMENTED Subuid values must get PAST the subuid gate and fail
	// for the SAME downstream reason (the fd budget, from the oversized
	// Sandbox slice) — proving the gate above discriminates on the value
	// rather than refusing SubuidFull outright the way it used to.
	for _, sub := range []policy.SubuidMode{policy.SubuidNone, policy.SubuidFull} {
		t.Run("Subuid="+sub.String()+" gets past the subuid check", func(t *testing.T) {
			_, err := Start(Config{
				Topology: policy.Topology{Netns: policy.NetnsStage, Subuid: sub},
				Sandbox:  oversized,
			})
			if err == nil {
				t.Fatal("PRECONDITION: the over-large Sandbox slice was accepted, so this control " +
					"is not landing where it was aimed")
			}
			if strings.Contains(err.Error(), "Subuid") {
				t.Errorf("Subuid=%s was refused for a subuid reason — it should be implemented:\n%v", sub, err)
			}
			if !strings.Contains(err.Error(), "fdNetnsN") {
				t.Errorf("PRECONDITION: expected the fd-budget refusal, got:\n%v", err)
			}
		})
	}

	t.Run("a netns owner the stage does not own is refused", func(t *testing.T) {
		for _, owner := range []policy.NetnsOwner{policy.NetnsSandbox} {
			_, err := Start(Config{Topology: policy.Topology{Netns: owner}})
			if err == nil {
				t.Errorf("Start accepted Netns=%s — only the stage topology has a stage", owner)
				continue
			}
			if !strings.Contains(err.Error(), "NetnsStage") {
				t.Errorf("the refusal for Netns=%s does not name what was expected:\n%v", owner, err)
			}
		}
	})
}
