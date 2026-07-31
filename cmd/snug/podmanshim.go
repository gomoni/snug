package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// podmanClientUsable reports whether a podman binary would actually work INSIDE
// a sandbox, and why not when it would not.
//
// The case this exists for: inside distrobox, /usr/bin/podman is a symlink to
// distrobox-host-exec — a shim that forwards the call to the real podman on the
// host via host-spawn. From the sandbox that forwarding cannot work (no bus, no
// host socket), and podman's own diagnostic is the memorably unhelpful
//
//	You must run  podman inside a container!
//
// which names neither distrobox nor the shim, and reads like a snug bug. snug
// knows exactly what happened, so it should say so.
//
// snug's own engine still works in this situation — it runs on snug's side of
// the fence, where the shim resolves. Only the CLIENT inside the sandbox is
// broken, which is why this is a warning rather than a refusal.
func podmanClientUsable() (ok bool, detail string) {
	path, err := exec.LookPath("podman")
	if err != nil {
		return false, "podman is not installed"
	}

	resolved := path
	if r, err := filepath.EvalSymlinks(path); err == nil {
		resolved = r
	}
	if strings.Contains(filepath.Base(resolved), "host-exec") ||
		strings.Contains(resolved, "distrobox") {
		return false, fmt.Sprintf("%s is a distrobox shim (%s) that forwards to the host",
			path, resolved)
	}

	// A shell script wrapper is the other common shape. A real podman is an ELF
	// binary; anything starting with #! is forwarding somewhere.
	if f, err := os.Open(resolved); err == nil {
		defer f.Close()
		var magic [2]byte
		if n, _ := f.Read(magic[:]); n == 2 && magic[0] == '#' && magic[1] == '!' {
			return false, fmt.Sprintf("%s is a shell wrapper, not the podman binary", resolved)
		}
	}
	return true, ""
}

// warnAboutPodmanClient prints the explanation once, when the profile that needs
// it is selected. Not fatal: the engine and the filtering proxy both work, and a
// caller driving the API directly is unaffected.
//
// # Why snug does not stage a working `podman` on PATH instead
//
// It could. $HOME inside the sandbox is a writable tmpfs snug owns, so a
// generated `~/.local/bin/podman` bound read-only, with that directory first on
// PATH, is purely ADDITIVE — it adds a file to a tmpfs snug already controls and
// never overmounts /usr/bin/podman, so it does not touch the masking rule. The
// mechanism is fine. The idea is not, for four reasons, in order of weight:
//
//  1. It would be a lie about which CLI you are running. The only thing the
//     shim could re-exec is `docker`, and the two CLIs diverge immediately
//     outside run/ps/images: --pod, --userns, --cgroups, system/generate/kube/
//     machine. Every one of those would fail with an error that names DOCKER,
//     from a command the human typed as `podman`. Today's failure is at least
//     attributed correctly.
//  2. It would not even fix `podman run` here, which is the whole point of
//     wanting it. The docker CLI always sends HostConfig.LogConfig, and the
//     proxy refuses that field (it is a host-file-write primitive). So
//     `podman run` would fail with a message about podman's k8s-file log
//     driver, produced by docker, from a shim pretending to be podman. Three
//     layers of misattribution for one error.
//  3. The real fault is on the host, and it has a host fix: this container HAS
//     podman 5.8.3 installed, and distrobox replaced the binary with its
//     symlink — `rpm -V podman` reports `....L....  /usr/bin/podman`. Papering
//     over that inside the sandbox hides a thing the human can actually repair.
//  4. It is a compatibility layer between two moving CLIs, shipped as generated
//     content snug would have to keep correct for ever, in exchange for
//     spelling one command differently.
//
// So: say what is wrong, say what does work, and say what to do about it.
func warnAboutPodmanClient() {
	ok, detail := podmanClientUsable()
	if ok {
		return
	}
	fmt.Fprintf(os.Stderr,
		"snug: the podman CLI will not work inside this sandbox — %s.\n"+
			"      snug's own engine and filtering proxy are fine; it is the client binary\n"+
			"      that cannot reach the host from inside. podman's own error for this is\n"+
			"      \"You must run podman inside a container!\", which names neither cause.\n"+
			"\n"+
			"      What does work, in the sandbox, unchanged:\n"+
			"        - the API at $CONTAINER_HOST / $DOCKER_HOST (both point at the proxy)\n"+
			"        - any docker-compatible client, e.g. `docker`, if one is installed\n"+
			"\n"+
			"      snug deliberately does NOT stage a `podman` that re-execs `docker`:\n"+
			"      the two CLIs diverge past run/ps/images, so it would answer half your\n"+
			"      commands with errors naming a tool you did not run. To get the real\n"+
			"      thing back, install a genuine podman binary in this container — the\n"+
			"      package is usually already there and only the binary was replaced\n"+
			"      (check with `rpm -V podman` or your distro's equivalent).\n", detail)
}
