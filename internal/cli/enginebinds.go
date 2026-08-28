package cli

// enginebinds.go installs one graft per `engine_binds` entry the selected
// profiles declared: the host-tree half of issue #376.
//
// WHY IT IS ITS OWN FILE. engineview.go installs the mounts the STAGE makes for
// itself — a fresh procfs, a fresh cgroup2, two empty tmpfs — and says so in
// its own header, which is why a fifth call could not simply go in there:
// these are open_tree(2) clones of HOST directories, the mechanism
// internal/engine/paths.go uses for the store, the runroot and the run
// directory. It is not in paths.go either, because the paths here are not
// snug's own artefacts: they come from p.EngineBinds, which internal/policy
// resolved, and this file needs to know nothing about a host path at all.

import (
	"fmt"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// installEngineBindGrafts records this run's declared engine binds in p.Grafts.
//
// Called from startContainers BEFORE its --dry-run branch, for the reason
// installEngineViewGrafts is: the ENGINE VIEW block is where a human reads what
// the engine's namespace holds, and #376's own standard is that "a mount the
// payload asked for is a mount a human should be able to see before it exists".
// Only ever called for a run with an engine — Resolve refuses `engine_binds`
// with p.Podman == PodmanOff outright, so an engine-less run has none of these
// to install and the caller's own check is not the only thing standing between
// a declaration and silence.
//
// Every failure is FATAL. The judgement here is G1–G5 exactly as any other
// graft gets it, and each of these already passed the narrower question Resolve
// asked (is this path visible to the sandbox, at what access, is its base name
// unique) — so a refusal means a rule this pass does not model, and starting an
// engine whose view the model does not describe is invariant 5's failure.
//
// THE TOCTOU IS ABSENT, NOT NARROWED, and this is the load-bearing fact of Fork
// A rather than a reassurance. A declared source is frequently INSIDE the
// target, which is payload-writable — that is the whole point, it is the case
// the anchored-source rule refuses — so the question "who can rewrite this name
// between the judgement and the openat2" has to have an answer. On any run with
// an engine, bwrap parks the payload behind --block-fd until after the engine
// has started (internal/sandbox/exec.go's release, non-nil iff EngineSpec !=
// nil; internal/stage/gate.go). So when __inengine walks a declared source,
// THIS run's payload has never executed. The residual actors are the two
// checkGraft's own G4 comment names — a PREVIOUS run's payload, because the
// target and /tmp under @tmp-shared both persist, and another same-uid host
// process, which is outside the threat model — and what closes the first is
// openat2's RESOLVE_NO_SYMLINKS in the stage, refusing a symlink at any depth
// with no fallback to the path form.
func installEngineBindGrafts(env policy.Environ, p *policy.Policy) error {
	for _, b := range p.EngineBinds {
		access := "read-only"
		if b.Access == policy.AccessRW {
			access = "READ-WRITE"
		}
		if err := p.Graft(env, policy.Graft{
			Mount: policy.Mount{
				Guest: b.Guest, Host: b.Host,
				Kind: policy.KindGraft, Access: b.Access, From: []string{"(snug)"},
			},
			// A literal opener, because TestGraftCarriesAnAbuseSentence reads
			// the argument TEXT of every Policy.Graft call under the module
			// root and wants to see a non-empty Why there — a Why built
			// entirely out of variables defeats that sweep, and the sweep is
			// right: the abuse sentence belongs where the grant is made.
			Why: "bind this host tree into a container of its OWN choosing — its own image, its " +
				"own command, running as root in this run's user namespace and in the ENGINE's " +
				"network namespace rather than the sandbox's — at " + access + " access, because " +
				"that is what the sandbox itself has at " + b.Host + ". Declared by " +
				strings.Join(b.From, "+") + " with engine_binds, which is why the payload cannot " +
				"choose the path: only this root is forwarded, and never with a tail of the " +
				"payload's own",
		}); err != nil {
			return fmt.Errorf("grafting the declared engine bind %s: %w", b.Host, err)
		}
	}
	return nil
}
