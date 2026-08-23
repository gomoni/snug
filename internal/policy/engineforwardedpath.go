package policy

import (
	"fmt"
	"path/filepath"
)

// CheckEngineForwardedPath reports whether a path STRING is safe to hand the
// container engine — whether the NAME, resolved inside the ENGINE's derived
// mount namespace, reaches the same host tree the SANDBOX's own mount set puts
// at that name. nil means the name is a FIXED POINT of the host<->guest
// correspondence and forwarding it verbatim asks the engine for the thing this
// sandbox just judged.
//
// # Two spaces, two questions (issue #371)
//
// It is the guest-space half of a pair whose host-space half is
// HostPathVisible, and the two are NOT interchangeable. HostPathVisible answers
// "may the client have this HOST path" by walking Mount.Host. The engine then
// resolves the forwarded STRING against Mount.Guest — plus this run's grafts,
// which exist only in its derived view. Every mount whose Host and Guest differ
// makes those two questions have different answers, and divergent mounts are a
// first-class feature of the profile language rather than a future hazard:
// splitSpec (resolve.go) parses "host:guest" for every ro/rw entry, @tmp-shared
// ships `rw = ["{host_tmpdir}:/tmp"]`, and @claude ships
// `"{home}/.local/bin/claude:/snug/bin/claude"` — divergent BY RULE, because
// the shadow-slot rule requires it and it can never be normalised away.
//
// So the coincidence Host == Guest, which the whole forwarding path used to
// lean on, is not merely unasserted: IT IS ALREADY FALSE. What is actually true
// is narrower and was never written down — for any name the filter accepts, the
// deepest-by-Host projection equals the sandbox's own deepest-by-Guest
// resolution — and it holds because of rejectMasking's RULE 2 (validate.go: a
// bind nested inside a bind may only re-bind H/rel, so a divergent bind can
// never sit in guest space underneath a Host == Guest one) plus the refusal of
// any bind covering $HOME (issue #220). Load-bearing, narrower than anyone
// stated, and enforced in a different file for a different reason: the worst of
// the three states, and the reason this function exists rather than a test
// asserting the coincidence.
//
// # What this is NOT: EngineGuestPath
//
// EngineGuestPath answers "where does the engine see this host CONTENT",
// matching GRAFTS by Graft.Host. That is the right question for snug's own
// wiring — internal/engine asks it about paths SNUG owns, to write them into
// the engine's argv, environment and generated configuration — and the wrong
// one here, twice over:
//
//   - a graft lands at its Guest, never at its Host, so a graft whose Host
//     covers the name says nothing about what the NAME means; and
//   - its first arm answers "visible, at /snug/engine/store" for exactly the
//     engine-owned host paths HostPathVisible refuses, which is the hole issue
//     #251 closed.
//
// Asked about a payload-supplied string it also over-refuses: a
// $SNUG_PODMAN_ROOT that sits inside one of the sandbox's own grants is
// reachable in the engine's view BOTH at its own name (the sandbox's mount,
// inherited) and at /snug/engine/toolchain (the graft), and EngineGuestPath's
// graft arm wins unconditionally — there is no depth comparison between the two
// arms — so it names the graft and the caller refuses a bind that was correct
// to forward.
//
// # The rule, in guest space and nothing else
//
// Let B be the deepest non-symlink mount whose Guest covers name — the same
// "deepest cover decides" rule the rest of the resolver uses. nil iff ALL of:
//
//   - B exists. No cover is the sandbox's own read-only root tmpfs: the engine
//     finds nothing at that name at all.
//   - B.Kind == KindBind. A tmpfs, /dev, procfs or generated KindData cover
//     means the engine finds a filesystem SNUG created for this run at that
//     name, not the host tree the caller asked about.
//   - B.Host == B.Guest. This is the fixed-point clause: the host tree under
//     the name is the host path spelled the same way, so forwarding the name
//     unchanged asks for what was judged.
//   - No Graft's Guest covers name. A graft is a different tree installed on
//     top of the sandbox's view in the engine's derived one (ENGINE-NETNS.md
//     §5.1), so a name underneath it does not mean what this sandbox judged.
//
// # Refuse, never translate
//
// The obvious alternative — map the name into guest space and forward the
// mapped string — is rejected on purpose. If the client's string and the
// engine's string differ, the client asked for something snug cannot honour,
// and substituting a different path is snug authoring a request nobody made:
// invariant 5 pointing the other way, and the checkBuildVolume mistake of issue
// #304 with the sign flipped. Nothing is converted here, so nothing can be
// converted wrongly.
//
// Purely lexical, like HostPathVisible, EngineGuestPath and
// CheckEngineBindSource beside it: no filesystem, no Environ, so it runs
// unprivileged in CI. Callers owe it a path already put through
// ResolveExistingHostPath, and must forward THAT path rather than the one they
// asked about.
func (p *Policy) CheckEngineForwardedPath(name string) error {
	name = filepath.Clean(name)

	for _, g := range p.Grafts {
		if covers(g.Guest, name) {
			return fmt.Errorf("%s cannot be forwarded to the container engine:\n"+
				"       it is inside %s, which is one of snug's own grafts in the engine's derived\n"+
				"       view (issue #371) — the engine sees different content there than this sandbox\n"+
				"       does, so the name cannot mean what this check just judged.\n"+
				"       Fix: name a path outside %s.",
				name, g.Guest, g.Guest)
		}
	}

	b, ok := deepestNonSymlinkCover(p.Mounts, name)
	if !ok {
		return fmt.Errorf("%s cannot be forwarded to the container engine:\n"+
			"       no mount of this sandbox covers that name, so in the engine's view — which is\n"+
			"       DERIVED from this sandbox's — it resolves on the read-only root tmpfs and reaches\n"+
			"       nothing at all (issue #371). The engine resolves the string it is given inside its\n"+
			"       OWN namespace, not on the host.\n"+
			"       Fix: name a path a read-only or read-write bind exposes at its own spelling.",
			name)
	}

	if b.Kind != KindBind {
		return fmt.Errorf("%s cannot be forwarded to the container engine:\n"+
			"       at that name the engine's view holds %s (%s), a filesystem snug created for this\n"+
			"       run, not the host tree this check judged (issue #371).\n"+
			"       Fix: name a path a read-only or read-write bind exposes at its own spelling.",
			name, b.Guest, b.Kind)
	}

	if b.Host != b.Guest {
		return fmt.Errorf("%s cannot be forwarded to the container engine:\n"+
			"       this sandbox reaches %s at %s, so the engine resolving the string %q finds a\n"+
			"       different tree (issue #371). snug refuses rather than rewriting your request into\n"+
			"       one you did not make.\n"+
			"       Fix: grant the path with a single spelling (ro = [%q]) rather than as host:guest.",
			name, b.Host, b.Guest, name, b.Host)
	}

	return nil
}
