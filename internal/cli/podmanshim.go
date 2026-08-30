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
// The RESOLVED path is returned as well as the verdict: `snug doctor` prints
// it beside the tick the way it prints bwrap's and pasta's, and it was already
// computed here. Two callers asking the PATH separately would be two answers
// to "which podman", which is the question the shim arms below exist to get
// right.
func podmanClientUsable() (ok bool, path, detail string) {
	found, err := exec.LookPath("podman")
	if err != nil {
		return false, "", "podman is not installed"
	}
	path = found

	resolved := path
	if r, err := filepath.EvalSymlinks(path); err == nil {
		resolved = r
	}
	if strings.Contains(filepath.Base(resolved), "host-exec") ||
		strings.Contains(resolved, "distrobox") {
		return false, resolved, fmt.Sprintf("%s is a distrobox shim (%s) that forwards to the host",
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
			return false, resolved, fmt.Sprintf("%s is a shell wrapper, not the podman binary", resolved)
		}
	}
	return true, resolved, ""
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
func warnAboutPodmanClient(n *notes) {
	ok, _, detail := podmanClientUsable()
	if !ok {
		_, staged := DetectHostShim("podman")
		// Built into ONE string and emitted as ONE note, rather than the
		// three consecutive writes this used to be: a note is the unit the
		// collector gates and renders, and three notes would let -v or the
		// NOTES block interleave a blank line into the middle of a single
		// paragraph of English.
		msg := fmt.Sprintf(
			"snug: the podman CLI will not work inside this sandbox — %s.\n"+
				"      snug's own engine and filtering proxy are fine; it is the client binary\n"+
				"      that cannot reach the host from inside. podman's own error for this is\n"+
				"      \"You must run podman inside a container!\", which names neither cause.\n"+
				"\n"+
				"      What does work, in the sandbox, unchanged:\n"+
				"        - the API at $CONTAINER_HOST / $DOCKER_HOST (both point at the proxy)\n"+
				"        - any docker-compatible client, e.g. `docker`, if one is installed\n", detail)
		if staged {
			msg += "\n" +
				"      snug staged a `podman` on PATH ahead of this one: a dispatcher that\n" +
				"      forwards a fixed set of docker subcommands to `docker`, byte for byte,\n" +
				"      and refuses the rest by name — see the COMMANDS block in\n" +
				"      `snug --dry-run`. /usr/bin/podman is untouched and still reachable by\n" +
				"      its absolute path; this file is read-only and only comes first on PATH.\n" +
				"      It is not podman — the two CLIs diverge past run/ps/images — but `run`,\n" +
				"      `pull`, `ps`, `images` and the rest of docker's command set now work.\n"
		} else {
			msg += "\n" +
				"      snug did not stage a replacement here: this is not one of the host-escape\n" +
				"      helpers it covers (distrobox-host-exec, host-spawn, flatpak-spawn). To get\n" +
				"      a real podman back, install a genuine binary in this container — check\n" +
				"      with `rpm -V podman` or your distro's equivalent.\n"
		}
		n.aside("%s", msg)
		return
	}

	// podman resolves to a genuine binary. podman's own CLI speaks the
	// libpod-native API against $CONTAINER_HOST, and snug refuses a libpod
	// request that changes state unless its own filter has read it — the
	// test is "not GET or HEAD, and not examined" (libpodExamined).
	//
	// The whole `podman run -d` chain is read now: build and pull (query
	// string), containers/create (the SpecGenerator body), the lifecycle
	// verbs and removal. FOREGROUND `podman run` is the one that still
	// stops, and it stops for a REASON rather than an omission: it posts
	// `attach` before start, as a HIJACK, and admitting that route is a
	// decision about the libpod attach stream (issues #465/#508) that the
	// maintainer has ruled stays unmade. `docker run` is unaffected; it
	// never speaks this API.
	n.aside(
		"snug: podman here is genuine. `podman build`, `pull`, `run -d`, `stop`, `kill`,\n" +
			"      `restart`, `pause`, `unpause`, `wait`, `rm` and the volume verbs all work\n" +
			"      through this sandbox's proxy end to end. FOREGROUND `podman run` (without\n" +
			"      -d) is the exception: it opens an attach stream this proxy does not frame,\n" +
			"      and is refused there. Use `podman run -d` and `podman logs`, or `docker`,\n" +
			"      which is unaffected.\n")
}
