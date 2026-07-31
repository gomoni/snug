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
			"      The API is still reachable at $CONTAINER_HOST.\n", detail)
}
