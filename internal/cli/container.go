package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gomoni/snug/internal/dockerproxy"
	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/stage"
)

// containerSocketGuest is where the sandbox sees the proxy. A fixed path snug
// chooses, never one a profile names.
const containerSocketGuest = policy.ContainerSocketGuest

// containerAudit is the proxy's -v channel, and it is the ONE place text written
// by the PAYLOAD becomes a line on the host user's terminal.
//
// Everything the proxy audits is derived from a request the sandbox made:
// `container create: …`, `refused: …`, `build: <summary>`, and — the sharp one —
// `mount source %s resolves to %s` (internal/dockerproxy/create.go), where the
// source is a string the payload chose. Every other screen in snug renders HOST
// text; this one renders the untrusted side's, so a payload that wants a human
// to misread the audit line is the whole threat model rather than an edge case.
//
// THE ESCAPE IS AT THE SINK, NOT AT THE CALL SITES, and that is deliberate:
// dockerproxy has a dozen audit calls today and will have more, they live in
// another package, and a rule that has to be remembered at each of them is the
// rule this project has now failed to apply four times in a row. Here it is one
// function, so a message added upstream is escaped the day it is added — and
// dockerproxy stays free to build whatever string it likes, because the boundary
// where that string becomes a SCREEN is here.
//
// One line per call, so whole-string escaping (VisibleText) is right: an audit
// message has no legitimate newline in it.
func containerAudit(verbose bool) func(string) {
	if !verbose {
		return func(string) {}
	}
	return func(msg string) {
		fmt.Fprintln(os.Stderr, "snug: containers: "+policy.VisibleText(msg))
	}
}

// containerRun is everything startContainers hands back: the cleanup its
// caller must defer, plus what sandbox.Run needs to know about this run's
// engine.
//
// A struct rather than a longer return list. Five positional values was
// already at the limit of what a caller can read without counting commas, and
// the sixth (excludeFromTeardown, issue #113) is the kind of thing that gets
// wired to the wrong slot exactly once and then silently protects nothing.
// Every field is optional: the zero value is a run with no containers, which
// is why the error paths return it directly.
type containerRun struct {
	cleanup       func()
	spec          *stage.EngineSpec
	onEngineReady func() error
	onPayloadExit func()

	// excludeFromTeardown is the container reaper's host pid — see
	// sandbox.Options.ExcludeFromTeardown and issue #113. Empty on every path
	// that did not arm a reaper.
	excludeFromTeardown []int
}

// startContainers wires up a per-sandbox engine behind a filtering proxy.
//
// The engine is now EAGER (issue #63, Tier B — ENGINE-WIRING.md §1): it is
// forked by the stage, in this sandbox's OWN network namespace, before the
// payload exists, not lazily on the proxy's first request. This function
// itself starts nothing beyond the proxy's listening socket; the fork
// happens inside sandbox.Run, driven by the engineSpec/onEngineReady/
// onPayloadExit values this function returns, wired into sandbox.Options by
// the caller (internal/cli/main.go). That split is what keeps
// internal/sandbox from importing internal/engine (layering: sandbox is
// lower-level) — the ONE seam issue #63 needed and TIER-B.md/
// ENGINE-WIRING.md both flagged and settled: a hook, not a proxy-routed
// `podman stop`.
//
// Preflight (P1, P2, P3, P5, P6 — see containerpreflight.go) runs here,
// BEFORE anything is created, and refuses cleanly rather than letting a
// real run reach stage.Start or __inengine with a host this tier cannot
// deliver on. P4 (a throwaway overlay+MS_PRIVATE probe under a fresh
// userns) is NOT implemented as a separate host-side probe — see that
// file's own doc comment for why, and what covers it instead (__inengine's
// own mount call, which still refuses loudly, just one step later than the
// design's own probe would).
func startContainers(pol *policy.Policy, verbose, dryRun bool) (containerRun, error) {
	if pol.Podman == policy.PodmanOff {
		return containerRun{cleanup: func() {}}, nil
	}

	// @net-host + a container profile (ENGINE-WIRING.md §4's flagged edge,
	// settled by the maintainer: REFUSE, do not build a second, host-netns
	// engine shape). deriveTopology keeps Netns=NetnsHost for @net-host (the
	// `<` guard preserves it) while still raising Subuid to SubuidFull, so
	// NeedsStage() is true — but stage.Start refuses any Netns != NetnsStage
	// outright, and there is no N descriptor for a host-netns engine to
	// setns into in the first place. Left unhandled, this combination would
	// reach stage.Start as a crash rather than a clean refusal; caught here,
	// before a single namespace exists.
	//
	// @net-host is already the --i-know escape hatch for "a process with a
	// different filesystem view, sharing the host's own network" (CLAUDE.md,
	// invariant 5's "no silent downgrade" is what makes that an explicit
	// flag rather than a default). A container engine confined to THIS
	// sandbox's own N is a different, and incompatible, contract: there is
	// no sandbox network namespace for it to join.
	if pol.Net.Mode == policy.NetHost {
		return containerRun{}, fmt.Errorf("@net-host and a container profile " +
			"(@podman-socket/@podman-build) cannot be combined: the container engine (issue #63, " +
			"Tier B) must be confined to THIS SANDBOX's own network namespace, and @net-host shares " +
			"the HOST's instead — there is no sandbox network namespace for the engine to join.\n" +
			"      Fix: drop @net-host (use '@net' if the sandbox itself needs egress), or drop " +
			"the container profile.")
	}

	if dryRun {
		// --dry-run's own promise is "having started nothing" (CLAUDE.md).
		// Binding the proxy's LISTENING socket is not starting the engine —
		// no upstream connection is ever dialled, no request is ever
		// forwarded, and sandbox.Run (where the eager fork lives) is never
		// called on this path — so it is safe here exactly as it always
		// was, and it is what lets --dry-run's MOUNTS section show the real
		// bound path. Preflight itself is NOT run for --dry-run: none of its
		// probes are needed to render a resolved policy, and running them
		// (a real /etc/subuid read, a real cgroup write probe) would be
		// host I/O a debugging command has no business doing.
		return startContainersScreen(pol, verbose)
	}

	pf, err := runContainerPreflight()
	if err != nil {
		return containerRun{}, err
	}

	warnAboutPodmanClient()

	// P7 said the engine's own /etc/resolv.conf cannot be replaced on this
	// host. Said HERE, before anything starts, rather than left to
	// __inengine's own backstop warning several seconds later — and said
	// precisely: this is the engine's resolver, not a container's, which the
	// generated containers.conf decides without needing any mount at all
	// (issue #126). Not a refusal: nothing leaks, so refusing would be
	// refusing over lost ergonomics.
	var probeUnavailable *probeUnavailableError
	if err := pf.ResolvConfBind; err != nil && !errors.As(err, &probeUnavailable) {
		fmt.Fprintf(os.Stderr, "snug: this host cannot bind a file over /etc/resolv.conf, so the "+
			"container engine will keep the host's own resolver configuration.\n"+
			"      Containers are NOT affected: their DNS comes from snug's generated "+
			"containers.conf.\n"+
			"      What is affected is the ENGINE's own name resolution: offline, it will try "+
			"the host's resolvers and time out slowly instead of failing fast.\n"+
			"      Probe said: %v\n"+
			"      Common cause: /etc/resolv.conf is itself a bind mount over a deleted inode "+
			"(issue #128); restarting the container or VM snug runs in repairs it.\n", err)
	}

	// P8: snug now authors the signature policy the engine reads, and on a
	// host that had configured a stricter one that is a DOWNGRADE. Invariant
	// 5 forbids doing it silently, so it is said here, before anything
	// starts, and it names the file it is talking about.
	if n := pf.SignaturePolicy; n != nil {
		fmt.Fprint(os.Stderr, n.String())
	}

	eng, err := engine.New(pol.Profiles, pol.Target)
	if err != nil {
		return containerRun{}, err
	}

	// pol.Net, the resolved network policy itself — not a rendering of it.
	// The engine needs the same DNS decision twice over, once as an
	// /etc/resolv.conf and once as three containers.conf keys, and handing it
	// the policy lets each renderer read the values directly. Handing it the
	// rendered resolv.conf bytes instead (which is what this did) forced the
	// second renderer to parse them back, making a generated file the author
	// of a fact the policy owns — invariant 6, "one Policy, one author"
	// (issues #126, #132).
	// HOME is deliberately NOT passed. The engine gets a home of its own,
	// written by Spec: the host user's carries podman's registries.conf and
	// policy.json (issue #137) and the host's own registry credentials
	// (issue #142), none of which the resolved Policy authored.
	// baseEnv carries nothing of the host's own environment, PATH included
	// (issue #125): Spec pins PATH itself, and see its doc comment for why
	// os.Getenv("PATH") is not a value this call site is trusted to supply.
	spec, err := eng.Spec(pf.Podman, nil, pf.CgroupsDisabled, pol.Net)
	if err != nil {
		return containerRun{}, err
	}

	// Armed NOW, before sandbox.Run has even created the stage — this is
	// what covers a snug killed during the stage's own startup window
	// (creating U+N, waiting for the network), before the engine has been
	// forked at all. It needs only this run's socket path, already fixed on
	// the Engine by New; it does not need the engine's socket to exist yet,
	// still less the podman binary (issue #167 removed the reaper's own
	// host-side `podman stop`, so it no longer needs one at all).
	if err := eng.ArmReaper(); err != nil {
		return containerRun{}, err
	}

	dir, err := runtimeDir()
	if err != nil {
		return containerRun{}, err
	}
	sock := filepath.Join(dir, "podman.sock")

	audit := containerAudit(verbose)

	// ensureEngine is nil: the engine is EAGER now, forked and confirmed
	// (its socket exists) well before StartSandbox ever forks the payload —
	// by construction, no request can reach this proxy before that has
	// already succeeded, so there is nothing left for the proxy itself to
	// ensure.
	p, err := dockerproxy.New(pol, eng.Socket(), sock, eng.RunLabel(), audit, nil)
	if err != nil {
		return containerRun{}, err
	}
	go p.Serve()

	// Provenance is "(containers)", not "(identity)". BindSocket used to
	// hard-code the latter, so the container socket — a completely
	// different hole, opened by @podman-socket — read in --dry-run as
	// though the ssh identity machinery had granted it.
	pol.BindSocket(sock, containerSocketGuest, "(containers)")
	containerEnv(pol)

	return containerRun{
		cleanup:       func() { p.Close(); eng.Stop() },
		spec:          &spec,
		onEngineReady: eng.DialLifeline,
		onPayloadExit: eng.Stop,
		// The reaper is the one helper snug starts that is MEANT to outlive
		// it, so it is the one thing the signalled-teardown sweep must not
		// SIGKILL (issue #113). Its pid is already fixed: ArmReaper ran above,
		// before sandbox.Run has created anything at all.
		excludeFromTeardown: eng.ReaperPIDs(),
	}, nil
}

// startContainersScreen is the --dry-run path: it binds the proxy's real
// listening socket (so --dry-run's MOUNTS section shows the real bound
// path, exactly as before Tier B) and stops there. No engine, no preflight,
// no store directory — nothing sandbox.Run will ever be asked to fork.
func startContainersScreen(pol *policy.Policy, verbose bool) (containerRun, error) {
	dir, err := runtimeDir()
	if err != nil {
		return containerRun{}, err
	}
	sock := filepath.Join(dir, "podman.sock")
	audit := containerAudit(verbose)

	p, err := dockerproxy.New(pol, "", sock, "", audit, nil)
	if err != nil {
		return containerRun{}, err
	}
	go p.Serve()

	pol.BindSocket(sock, containerSocketGuest, "(containers)")
	containerEnv(pol)

	return containerRun{cleanup: func() { p.Close() }}, nil
}

// containerEnv points the client at the proxy. A function of its own so it can
// be exercised without starting an engine: these three names are half of the
// post-Resolve writers, and those are the dangerous half of the ownership set —
// a profile allowed to write DOCKER_HOST = "ssh://you@host/..." would make the
// client exec ssh (§1.1, §3.2).
func containerEnv(pol *policy.Policy) {
	// podman's own CLI reads CONTAINER_HOST; DOCKER_HOST is set too so anything
	// speaking the compat API finds the same proxy. snug targets podman.
	pol.AuthorEnv("CONTAINER_HOST", "unix://"+containerSocketGuest)
	pol.AuthorEnv("DOCKER_HOST", "unix://"+containerSocketGuest)
	// DOCKER_BUILDKIT=0 is a TIGHTENING, not a convenience: with BuildKit on
	// (docker's own default), `docker build` never POSTs to /build at all — it
	// tries to boot a moby/buildkit builder CONTAINER instead, and negotiates
	// build options over a buildkit session the /build query-string filter in
	// internal/dockerproxy never inspects. Forcing the classic path is what
	// makes `docker build` go through the one endpoint snug actually filters.
	//
	// It is also attacker-overridable: the payload can set
	// DOCKER_BUILDKIT=1 itself and boot a buildkit builder (its `create` is
	// still filtered), then negotiate `RUN --mount=type=bind,...` over the
	// buildkit session — a channel the /build filter cannot see. So this
	// default is not the only backstop; it narrows the common case, and the
	// buildkit session itself is not something snug filters at all.
	//
	// (The caller already returned when pol.Podman == PodmanOff, so setting it
	// unconditionally here is correct, not merely convenient.)
	pol.AuthorEnv("DOCKER_BUILDKIT", "0")
}
