package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gomoni/snug/internal/dockerproxy"
	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
)

// containerSocketGuest is where the sandbox sees the proxy. A fixed path snug
// chooses, never one a profile names.
const containerSocketGuest = "/run/snug/podman.sock"

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

// startContainers wires up a per-sandbox engine behind a filtering proxy.
//
// The engine is NOT started here — it starts lazily on the first request that
// reaches the proxy, so selecting the profile and never using it costs nothing.
func startContainers(pol *policy.Policy, verbose bool) (cleanup func(), err error) {
	if pol.Podman == policy.PodmanOff {
		return func() {}, nil
	}

	// TEMPORARY, issue #63 Tier B: deriveTopology now correctly DEMANDS a stage
	// with the full delegated subuid range and the engine's own capability
	// bounding set (policy.EngineCapBounding) whenever a container profile is
	// selected — internal/stage/stage.go's Start CAN satisfy that demand today.
	// What it does NOT yet do is actually FORK PODMAN INTO THAT STAGE'S
	// namespaces: internal/engine.Engine.Start below still execs podman as a
	// PLAIN HOST PROCESS, on the host's own network namespace, unrelated to the
	// stage entirely.
	//
	// That gap is invisible everywhere except here: --dry-run's TOPOLOGY and
	// CONTAINERS blocks (internal/cli/dryrun.go) and @podman-socket's own
	// description now both say "offline unless @net is selected" and describe
	// an engine confined to the sandbox's own netns with a 12-cap bounding set
	// — none of which the RUNNING engine below actually delivers yet. Silently
	// proceeding here would be exactly the finding this ticket exists to close
	// (ENGINE-NETNS.md §0), now wearing more confident language on the trust
	// screen. Invariant 5 — no silent downgrade — is the reason for this
	// refusal rather than a warning: a user who believes "offline" because the
	// screen says so is worse off than one who is told plainly that this build
	// cannot deliver it yet.
	//
	// Closing this requires a host-bridge decision this ticket's implementation
	// pass did not settle: how a long-lived engine child is launched through
	// the stage's existing one-shot, single-request control protocol
	// (internal/stage/serve.go) without either serialising it behind bwrap's
	// own lifecycle or opening the concurrent-request redesign that decision
	// needs. Remove this refusal only once internal/engine (or its
	// replacement) actually forks podman through the stage, into N, with its
	// mount namespace and policy.EngineCapBounding applied — and drop this
	// comment along with it. (pol.Podman != policy.PodmanOff is guaranteed at
	// this point by the early return above.)
	return nil, fmt.Errorf("container engine support is incomplete on this build (issue #63, " +
		"Tier B): the policy layer now correctly demands the container engine run inside this " +
		"sandbox's own network namespace, but the engine is not yet wired to actually start " +
		"there — it would still run on the HOST's network, silently contradicting what " +
		"--dry-run says about egress. Refusing rather than handing the sandbox an engine " +
		"whose guarantee this build cannot keep. See internal/cli/container.go for what is " +
		"missing")
}

// startContainersHostNetwork is the pre-Tier-B implementation, kept intact
// and UNREACHABLE (called from nowhere) rather than deleted: it is exactly
// what startContainers should resume doing, minus the host-network engine
// launch, once internal/engine forks podman through the stage instead of
// exec'ing it as a plain host process. Deleting it would make the follow-up
// a rewrite from scratch instead of a diff against a known-working shape.
//
//lint:ignore U1000 intentionally unreferenced — see the comment above
func startContainersHostNetwork(pol *policy.Policy, verbose bool) (cleanup func(), err error) {
	warnAboutPodmanClient()

	eng, err := engine.New(pol.Profiles, pol.Target)
	if err != nil {
		return nil, err
	}

	dir, err := runtimeDir()
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "podman.sock")

	audit := containerAudit(verbose)

	p, err := dockerproxy.New(pol, eng.Socket(), sock, eng.RunLabel(), audit, eng.Start)
	if err != nil {
		return nil, err
	}
	go p.Serve()

	// Provenance is "(containers)", not "(identity)". BindSocket used to hard-code
	// the latter, so the container socket — a completely different hole, opened by
	// @podman-socket — read in --dry-run as though the ssh identity machinery had
	// granted it. A trust artifact that misattributes a grant is worse than one
	// that omits it.
	pol.BindSocket(sock, containerSocketGuest, "(containers)")
	containerEnv(pol)

	return func() { p.Close(); eng.Stop() }, nil
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
