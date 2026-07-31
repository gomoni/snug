package main

import (
	"fmt"
	"os"
	"path/filepath"

	"snug/internal/dockerproxy"
	"snug/internal/engine"
	"snug/internal/policy"
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

	p, err := dockerproxy.New(pol, eng.Socket(), sock, audit, eng.Start)
	if err != nil {
		return nil, err
	}
	go p.Serve()

	pol.BindSocket(sock, containerSocketGuest)
	// podman's own CLI reads CONTAINER_HOST; DOCKER_HOST is set too so anything
	// speaking the compat API finds the same proxy. snug targets podman.
	pol.Env["CONTAINER_HOST"] = "unix://" + containerSocketGuest
	pol.Env["DOCKER_HOST"] = "unix://" + containerSocketGuest

	return func() { p.Close(); eng.Stop() }, nil
}
