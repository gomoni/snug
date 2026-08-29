package cli

// enginetarget.go installs the target graft: the always-on host-tree half of
// issue #376.
//
// WHY IT IS ITS OWN FILE. engineview.go's own header divides its four grafts
// from the host-tree ones by MECHANISM — those are mount(2) calls the stage
// makes for itself, this is an open_tree(2) clone of a host directory. It is
// not in internal/engine/paths.go either: the path here is p.Target, which
// internal/policy already resolved and judged, and this file needs to know
// nothing of engine.Paths.

import (
	"fmt"

	"github.com/gomoni/snug/internal/policy"
)

// installEngineTargetGraft records the target graft in p.Grafts, when
// EngineTargetGraft says there is one to install.
//
// Called from startContainers BEFORE its --dry-run branch, for the reason
// installEngineViewGrafts is: the ENGINE VIEW block renders from p.Grafts, and
// a --dry-run rendering fewer mounts than the run performs is issue #252
// again. ok == false is the ordinary case — no capability lost, see
// EngineTargetGraft's own doc comment — and installs nothing.
func installEngineTargetGraft(env policy.Environ, p *policy.Policy) error {
	guest, access, ok := p.EngineTargetGraft()
	if !ok {
		return nil
	}
	readable := "read-only"
	if access == policy.AccessRW {
		readable = "READ-WRITE"
	}
	if err := p.Graft(env, policy.Graft{
		Mount: policy.Mount{
			Guest: guest, Host: p.Target,
			Kind: policy.KindGraft, Access: access, From: []string{"(snug)"},
		},
		Why: "bind the sandbox's own target directory into a container of its OWN choosing — " +
			"its own image, its own command, running as root in this run's user namespace and " +
			"in the ENGINE's network namespace rather than the sandbox's — at " + readable +
			" access, because that is what the sandbox itself already has at the target. The " +
			"graft is a fixed root: the container proxy forwards only this directory, exact " +
			"match, and never a tail of the payload's own naming underneath it",
	}); err != nil {
		return fmt.Errorf("grafting the container engine's view of the target: %w", err)
	}
	return nil
}
