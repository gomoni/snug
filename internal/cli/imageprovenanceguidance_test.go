package cli

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestTheInjectedGuidanceNamesTheImageProvenanceRules is the third site rule
// applied to issues #137 and #142: a fact that changes what an agent should do
// belongs in the file the agent reads, not only in --dry-run and a comment.
//
// Both consequences produce errors that look like breakage — a short name that
// resolves nowhere, a registry that refuses to authenticate — and an agent
// that has not been told will spend turns "fixing" them, which for the second
// one means trying to log in with credentials it should never be given.
//
// The negative arm is not a formality: the section must be absent when no
// engine is selected, or the guidance would describe a capability the run does
// not have, which is the same defect as claiming one it does.
func TestTheInjectedGuidanceNamesTheImageProvenanceRules(t *testing.T) {
	withEngine := string(claudeGuidance(resolveFor(t,
		[]policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude", "@podman-socket"})))
	for _, want := range []string{"docker.io", "no registry credentials"} {
		if !strings.Contains(strings.ToLower(withEngine), strings.ToLower(want)) {
			t.Errorf("the injected guidance never says %q, so an agent meets an unresolvable "+
				"short name or an auth failure with no idea it is the design:\n%s", want, withEngine)
		}
	}

	withoutEngine := string(claudeGuidance(resolveFor(t,
		[]policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude"})))
	if strings.Contains(withoutEngine, "## Containers") {
		t.Errorf("the injected guidance has a Containers section on a run with no engine:\n%s",
			withoutEngine)
	}
}
