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

	audit := func(string) {}
	if verbose {
		audit = func(msg string) { fmt.Fprintln(os.Stderr, "snug: containers: "+msg) }
	}

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
	// podman's own CLI reads CONTAINER_HOST; DOCKER_HOST is set too so anything
	// speaking the compat API finds the same proxy. snug targets podman.
	pol.Env["CONTAINER_HOST"] = "unix://" + containerSocketGuest
	pol.Env["DOCKER_HOST"] = "unix://" + containerSocketGuest
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
	// (This function already returned above when pol.Podman == PodmanOff, so
	// setting it unconditionally here is correct, not merely convenient.)
	pol.Env["DOCKER_BUILDKIT"] = "0"

	return func() { p.Close(); eng.Stop() }, nil
}
