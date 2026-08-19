package dockerproxy

import (
	"strings"
	"testing"
)

// TestEveryRefusedFieldExplainsItself: a refusal a user meets is the only
// explanation they get, and CLAUDE.md's rule is that errors name the fix. A
// field on the reject-list with no reason refuses with a bare "not permitted".
func TestEveryRefusedFieldExplainsItself(t *testing.T) {
	for _, k := range refusedHostConfig {
		reason, ok := refusalReason[k]
		if !ok {
			t.Errorf("HostConfig.%s is refused with no reason; the user gets \"not permitted\" and nothing else", k)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("HostConfig.%s has an empty reason", k)
		}
	}
	// The inverse, so a field deleted from the reject-list does not leave an
	// orphan reason behind to be read as though it still applied.
	for k := range refusalReason {
		found := false
		for _, r := range refusedHostConfig {
			if r == k {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("refusalReason has an entry for %q, which is not on refusedHostConfig — "+
				"a reason for a refusal that no longer happens", k)
		}
	}
}

// TestNoRefusalReasonDescribesTheHostSideEngine is the regression for issue
// #154 §B.
//
// Before Tier B (issue #63) the container engine ran on the host, so "the
// sandbox cannot reach it" was the honest reason for refusing PortBindings.
// The engine now runs inside the sandbox's own network namespace, and the
// sentence survived the move: it told a user that a published port lands
// somewhere unreachable and creates a host-visible surface, when the truth is
// that a container already shares the sandbox's netns and the engine holds no
// CAP_NET_ADMIN to publish anything at all. Nothing caught it, because the
// create-refusal table asserts only the "X is not permitted" prefix and never
// the reason — so the reason was untested prose next to tested code.
//
// This checks the CLASS rather than the one string: no refusal may explain
// itself by placing the engine, or a container, on the far side of a boundary
// that Tier B removed. It is deliberately a phrase blocklist with a positive
// control below, not a golden of the current wording — the point is to catch a
// stale MODEL, not to freeze the prose.
func TestNoRefusalReasonDescribesTheHostSideEngine(t *testing.T) {
	// Each phrase encodes "the engine is somewhere the sandbox is not".
	stale := []string{
		"the sandbox cannot reach",
		"engine's side of the world",
		"host-visible surface",
		"outside this sandbox's own",
	}

	for field, reason := range refusalReason {
		lower := strings.ToLower(reason)
		for _, phrase := range stale {
			if strings.Contains(lower, strings.ToLower(phrase)) {
				t.Errorf("HostConfig.%s's refusal reason contains %q, which describes the "+
					"pre-Tier-B world where the engine ran on the host (issue #63, #154).\n"+
					"reason: %s", field, phrase, reason)
			}
		}
	}

	// POSITIVE CONTROL. Without this the test above passes on an empty map,
	// on a map whose reasons are all "", and on a build where refusalReason
	// was renamed out from under it — every one of which reads as "no stale
	// model found".
	if len(refusalReason) < 10 {
		t.Fatalf("refusalReason has only %d entries; the sweep above proves nothing", len(refusalReason))
	}
	poisoned := map[string]string{"Test": "published ports land where the sandbox cannot reach them"}
	hits := 0
	for _, reason := range poisoned {
		for _, phrase := range stale {
			if strings.Contains(strings.ToLower(reason), strings.ToLower(phrase)) {
				hits++
			}
		}
	}
	if hits == 0 {
		t.Error("the phrase list no longer matches the exact sentence this test was written " +
			"against, so it would not have caught the original defect")
	}
}

// TestPortRefusalsNameTheRealMechanism pins the replacement, not just the
// absence of the old one: a reader who hits this refusal must learn WHY
// publishing is meaningless here, or they will go looking for a flag that
// turns it on. There is none, and there cannot be one without granting the
// engine CAP_NET_ADMIN.
func TestPortRefusalsNameTheRealMechanism(t *testing.T) {
	for _, field := range []string{"PortBindings", "PublishAllPorts"} {
		reason, ok := refusalReason[field]
		if !ok {
			t.Fatalf("HostConfig.%s has no refusal reason at all", field)
		}
		if !strings.Contains(reason, "network namespace") {
			t.Errorf("HostConfig.%s's reason does not say the container shares this sandbox's "+
				"network namespace, which is the whole reason publishing is moot:\n%s", field, reason)
		}
	}
	// Only PortBindings claims the capability half: PublishAllPorts is
	// refused for the simpler reason and does not need to repeat it.
	if !strings.Contains(refusalReason["PortBindings"], "CAP_NET_ADMIN") {
		t.Errorf("HostConfig.PortBindings' reason does not name CAP_NET_ADMIN, so a reader "+
			"cannot tell whether publishing is forbidden by snug or impossible for the "+
			"engine — it is both, and the second is the one that cannot be relaxed:\n%s",
			refusalReason["PortBindings"])
	}
}
