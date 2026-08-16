package main

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
