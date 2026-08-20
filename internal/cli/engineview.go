package cli

// engineview.go installs the grafts that describe the ENGINE's own mount
// namespace — the mounts __inengine makes for itself, which until now existed
// only as three mount(2) calls in internal/stage with nothing in the model
// naming them.
//
// WHY THIS FILE EXISTS. Issue #125 said it about two of them: "/proc and
// /sys/fs/cgroup as engine-view mounts that must be modelled in p.Grafts too —
// an unmodelled mount in the derived view is precisely #55's shape one layer
// further on." The /run tmpfs arrived after that sentence was written and is a
// THIRD, and the worst of the three to leave unmodelled because it is the only
// one that is WRITABLE, which is the exact ingredient #55 is about. Unmodelled
// means: --dry-run cannot render it, Validate cannot judge it, and
// IsShadowSlot cannot see it — three questions that all answer "there is
// nothing there" about a mount that is really there.
//
// WHAT IT DOES NOT DO, and the honesty this file owes. It does not install the
// four HOST-tree grafts (the container store, the runroot, the socket
// directory, the config directory): those are open_tree(2) clones the stage
// cannot make until the derived view exists, and modelling a graft that no run
// performs would be the "documented but not implemented" shape this repo keeps
// naming. The three here are different — the stage makes all three mount(2)
// calls TODAY, in the engine's own mount namespace, on every container run —
// so modelling them describes what already happens rather than what is planned.
//
// WHY THE THREE CALLS ARE WRITTEN OUT rather than looped over a table, which
// was the first attempt: TestGraftCarriesAnAbuseSentence sweeps every
// policy.Graft call site under internal/ and requires a LITERAL, non-empty Why
// in the argument text. A table defeats it — the sweep sees `Why: g.why` and
// cannot tell an abuse sentence from an empty string — and the rule is right:
// the working agreement's "write the abuse sentence first" is about the
// sentence sitting where the grant is made, not one indirection away.

import (
	"fmt"

	"github.com/gomoni/snug/internal/policy"
)

// installEngineViewGrafts records the engine's own mounts in p.Grafts.
//
// Called from startContainers BEFORE its --dry-run branch, deliberately: the
// ENGINE VIEW block is how a human learns what the engine's namespace holds,
// and a --dry-run that renders fewer mounts than the run performs is exactly
// the gap this closes. It is only ever called for a run that has an engine,
// which the caller checks — the caller is the one that already knows p.Podman.
//
// Every failure is FATAL to the run and none is expected: these three grafts
// are constants, judged against a policy that has already resolved, so a
// refusal here means a rule changed underneath them (a destination that stopped
// existing in the sandbox's view, a Kind that left graftKindRules) and the
// honest response is to say so rather than to start an engine whose view the
// model no longer describes.
//
// The order matches the order __inengine performs the mounts, so a reader
// comparing the two reads them in one direction. Nothing depends on it:
// Policy.Graft is keyed by Guest and G2 refuses any overlap between two.
func installEngineViewGrafts(env policy.Environ, p *policy.Policy) error {
	if err := p.Graft(env, policy.Graft{
		Mount: policy.Mount{
			Guest:  "/proc",
			Kind:   policy.KindProc,
			Access: policy.AccessRW,
			From:   []string{"(snug)"},
		},
		Why: "read the process table of the engine's own pid namespace — which is what a " +
			"container engine legitimately needs, and is why this is a FRESH procfs rather " +
			"than the host's: without it the engine would carry the stage's copy of the HOST " +
			"/proc, and every host process's cmdline, environ and fd table with it",
	}); err != nil {
		return fmt.Errorf("recording the engine's own /proc: %w", err)
	}

	if err := p.Graft(env, policy.Graft{
		Mount: policy.Mount{
			Guest:  "/sys/fs/cgroup",
			Kind:   policy.KindCgroup2,
			Access: policy.AccessRW,
			From:   []string{"(snug)"},
		},
		Why: "write cgroup controller files for the containers it starts — a fresh cgroup2 " +
			"rooted at the engine's OWN cgroup namespace, so what it can write is the " +
			"delegated subtree and not the host's cgroup tree, which is what the inherited " +
			"mount would still have been rooted at",
	}); err != nil {
		return fmt.Errorf("recording the engine's own /sys/fs/cgroup: %w", err)
	}

	if err := p.Graft(env, policy.Graft{
		Mount: policy.Mount{
			Guest:  "/run",
			Kind:   policy.KindTmpfs,
			Access: policy.AccessRW,
			From:   []string{"(snug)"},
		},
		Why: "write anything it likes into a tmpfs that dies with the run — podman needs " +
			"/run/libpod writable and does not self-mount one when it reads itself as " +
			"root-like (the full delegated subuid range), and the sandbox's own /run is a " +
			"directory on the read-only root. Nothing of the HOST's /run is in it: this is a " +
			"fresh, empty filesystem, not a graft of anything",
	}); err != nil {
		return fmt.Errorf("recording the engine's own /run: %w", err)
	}
	return nil
}
