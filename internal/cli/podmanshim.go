package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// hostEscapeShims is the trigger list for STAGING a replacement stub — see
// CONTAINER-CLIENT.md §8. The property that predicts breakage is resolving
// to one of these named host-escape helpers, NOT "is a symlink": ordinary
// symlinks (/bin -> usr/bin, vi -> vim) are common and resolve perfectly
// well inside a sandbox. Detecting "is a symlink" would stage a stub over
// half of /usr/bin; detecting this short, named list does not.
var hostEscapeShims = map[string]bool{
	"distrobox-host-exec": true,
	"host-spawn":          true,
	"flatpak-spawn":       true,
}

// DetectHostShim resolves name on $PATH and reports it as a policy.HostShim
// only when it resolves to a host-escape helper.
//
// EXPORTED for one caller outside this package: test/integration's engine
// gate, which must refuse a shim rather than refuse the host's own podman
// (issue #393). It is exported instead of copied because the alternative is
// two spellings of one security predicate, and the copy is the one nobody
// updates when hostEscapeShims grows — issue #396's fix landed on THIS
// function, and a second copy in the test tree would have missed it. The map
// stays unexported: callers ask the question, they do not read the list.
//
// This is deliberately narrower than podmanClientUsable's "#!" heuristic
// below, which stays exactly where it is and is used for the WARNING only —
// a wrong warning costs a sentence, a wrong stage costs a stub standing in
// for a binary that might have worked. Symlinks are ordinary; the "#!" test
// catches wrapper scripts of every shape, most of which are not host-escape
// helpers at all.
func DetectHostShim(name string) (policy.HostShim, bool) {
	path, err := exec.LookPath(name)
	if err != nil {
		return policy.HostShim{}, false
	}
	resolved := path
	if r, err := filepath.EvalSymlinks(path); err == nil {
		resolved = r
	}
	if !hostEscapeShims[filepath.Base(resolved)] {
		return policy.HostShim{}, false
	}
	return policy.HostShim{Name: name, Path: path, Resolved: resolved}, true
}

// detectHostShims runs snug's PATH-resolution detector for every command
// that might need a replacement stub. Today that is podman only; adding
// another command means adding a name here, not a new mechanism.
func detectHostShims() []policy.HostShim {
	var out []policy.HostShim
	if s, ok := DetectHostShim("podman"); ok {
		out = append(out, s)
	}
	return out
}

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
	//
	// HOSTREAD-EXEMPT: resolved comes from exec.LookPath("podman") on this
	// user's own $PATH, the same trust boundary as the shell that set it — a
	// hostile PATH entry can already run arbitrary code as this user, so a
	// FIFO here blocking this one doctor check is not a new capability. Not
	// hostread.Optional: the cap that guards against an oversized read would
	// reject a real multi-MB podman binary before this ever reaches the
	// two-byte magic check below.
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
// # Why the staged replacement is a dispatcher, not a translator
//
// snug now DOES stage a `podman` on PATH when it resolves to a host-escape
// shim (podmanstub.go, CONTAINER-CLIENT.md §6-§8) — reversing the standing
// refusal this comment used to argue for. It forwards a fixed, compiled-in
// allowlist of docker subcommands to `docker`, byte for byte, and refuses
// everything else BY NAME; it never rewrites a flag or otherwise translates.
// Three of the original four reasons against staging one still hold, now as
// costs of that choice rather than reasons not to make it:
//
//  1. It is not a lie about which CLI is running only because the stub says so
//     on every refusal path: the two CLIs diverge immediately outside
//     run/ps/images (--pod, --userns, --cgroups, system/generate/kube/
//     machine), and each of those is refused by name instead of silently
//     mistranslated.
//  2. The real fault is on the host, and it has a host fix: this container HAS
//     podman 5.8.3 installed, and distrobox replaced the binary with its
//     symlink — `rpm -V podman` reports `....L....  /usr/bin/podman`. The stub
//     does not hide that; its refusal messages name it.
//  3. It is a compatibility layer between two moving CLIs — the allowlist in
//     podmanstub.go tracks docker's command set, not podman's, and has to
//     stay honest as both change.
//
// The remaining reason from the original four — "it would not even fix
// `podman run`, because the proxy refuses HostConfig.LogConfig" — is DELETED
// rather than kept for history, because it is now measurably false:
// `isDefaultLogConfig` (internal/dockerproxy/create.go) was added because the
// denylist it replaced "refused every `docker run` there has ever been
// through this proxy", and `docker run --rm alpine echo` works today. See
// CONTAINER-CLIENT.md §5.
func warnAboutPodmanClient() {
	ok, detail := podmanClientUsable()
	if !ok {
		_, staged := DetectHostShim("podman")
		fmt.Fprintf(os.Stderr,
			"snug: the podman CLI will not work inside this sandbox — %s.\n"+
				"      snug's own engine and filtering proxy are fine; it is the client binary\n"+
				"      that cannot reach the host from inside. podman's own error for this is\n"+
				"      \"You must run podman inside a container!\", which names neither cause.\n"+
				"\n"+
				"      What does work, in the sandbox, unchanged:\n"+
				"        - the API at $CONTAINER_HOST / $DOCKER_HOST (both point at the proxy)\n"+
				"        - any docker-compatible client, e.g. `docker`, if one is installed\n", detail)
		if staged {
			fmt.Fprint(os.Stderr,
				"\n"+
					"      snug staged a `podman` on PATH ahead of this one: a dispatcher that\n"+
					"      forwards a fixed set of docker subcommands to `docker`, byte for byte,\n"+
					"      and refuses the rest by name — see the COMMANDS block in\n"+
					"      `snug --dry-run`. /usr/bin/podman is untouched and still reachable by\n"+
					"      its absolute path; this file is read-only and only comes first on PATH.\n"+
					"      It is not podman — the two CLIs diverge past run/ps/images — but `run`,\n"+
					"      `pull`, `ps`, `images` and the rest of docker's command set now work.\n")
		} else {
			fmt.Fprint(os.Stderr,
				"\n"+
					"      snug did not stage a replacement here: this is not one of the host-escape\n"+
					"      helpers it covers (distrobox-host-exec, host-spawn, flatpak-spawn). To get\n"+
					"      a real podman back, install a genuine binary in this container — check\n"+
					"      with `rpm -V podman` or your distro's equivalent.\n")
		}
		return
	}

	// podman resolves to a genuine binary, and it STILL cannot `run` or `pull`
	// here: podman's own CLI speaks the libpod-native API against
	// $CONTAINER_HOST, and snug refuses a libpod request that changes state
	// unless its own filter has read it — the filter reads the docker-compat
	// schema, and a libpod body is a different shape it cannot inspect
	// (internal/dockerproxy). "body-bearing" is what this said until issue #340
	// inverted the gate from a denylist of segments to `libpodExamined`; the
	// test is now "not GET or HEAD, and not examined", which also covers the
	// DELETE routes the old wording never named. `ps`, `images` and `info` are
	// read-only libpod routes and answer truthfully; `run` and `pull` do not.
	//
	// `podman build` DOES work and the message says so, because omitting it read
	// as "podman cannot build here" to the one person who selected the profile
	// for building. POST /libpod/build is the single state-changing libpod route
	// the filter has read — libpodExamined is isBuild — and it is filterable by
	// the SAME code as /build because a build's parameters travel in the query
	// string, not in a body (handleBuild starts at r.URL.Query()). MEASURED:
	// `podman build -t probe:1 .` pulled alpine:3.20, ran its RUN step and
	// committed localhost/probe:1 through this proxy. See CONTAINER-CLIENT.md §3
	// and issue #459 for whether the libpod split should survive at all.
	fmt.Fprint(os.Stderr,
		"snug: podman here is genuine, but `run` and `pull` will not work through this\n"+
			"      sandbox's proxy — podman's CLI speaks the libpod-native API, and snug\n"+
			"      refuses a libpod request that changes state unless its own filter has read\n"+
			"      it (it filters the docker-compat schema only). Working: `podman build`,\n"+
			"      and the read-only routes `podman ps`, `podman images`, `podman info`.\n"+
			"      For `run` and `pull`, use `docker` instead. Issue #459.\n")
}
