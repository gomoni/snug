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
// Nothing here starts a stage. Both cases are refused before Start creates a
// socketpair, and the over-large Sandbox slice gives the positive control a
// harmless downstream failure to land on.
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

	t.Run("a delegated subuid range is refused", func(t *testing.T) {
		_, err := Start(Config{
			Topology: policy.Topology{Netns: policy.NetnsStage, Subuid: policy.SubuidFull},
			Sandbox:  oversized,
		})
		if err == nil {
			t.Fatal("Start accepted a Topology asking for a delegated subuid range, which it " +
				"does not implement: the clone maps exactly one uid. A policy would then " +
				"believe a delegation that never happened")
		}
		if !strings.Contains(err.Error(), "Subuid") {
			t.Errorf("Start refused, but not for the subuid reason — so this test would pass "+
				"on a build where the subuid check had been deleted and something else "+
				"failed first:\n%v", err)
		}
		// "Errors name the fix": whoever hits this is the person about to
		// teach the stage to delegate.
		if !strings.Contains(err.Error(), "deriveTopology") {
			t.Errorf("the refusal does not name deriveTopology, so it does not say where the "+
				"value came from or what to change:\n%v", err)
		}
	})

	// The positive control, and the whole test rests on it: an otherwise
	// IDENTICAL Config that differs only in Subuid must fail for the other
	// reason. Without this, a Start that refused everything unconditionally —
	// or one whose subuid message had leaked into an unrelated error — would
	// pass the case above perfectly.
	t.Run("positive control: the same Config with no delegation gets past the subuid check", func(t *testing.T) {
		_, err := Start(Config{
			Topology: policy.Topology{Netns: policy.NetnsStage, Subuid: policy.SubuidNone},
			Sandbox:  oversized,
		})
		if err == nil {
			t.Fatal("PRECONDITION: the over-large Sandbox slice was accepted, so this control " +
				"is not landing where it was aimed")
		}
		if strings.Contains(err.Error(), "Subuid") {
			t.Errorf("a Config with Subuid=none was still refused for a subuid reason, so the "+
				"check above fires regardless of the value it claims to be reading:\n%v", err)
		}
		if !strings.Contains(err.Error(), "fdNetnsN") {
			t.Errorf("PRECONDITION: expected the fd-budget refusal, got:\n%v", err)
		}
	})

	t.Run("a netns owner the stage does not own is refused", func(t *testing.T) {
		for _, owner := range []policy.NetnsOwner{policy.NetnsSandbox, policy.NetnsHost} {
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
