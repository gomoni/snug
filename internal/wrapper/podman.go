package wrapper

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/gomoni/snug/internal/policy"
)

// exitStub is what every refusal of the podman stub exits with: podman's own
// code for an error in podman itself, as opposed to the container's.
const exitStub = 125

// dockerSubcommands is the allowlist the stub forwards to docker
// byte-for-byte. It allowlists the tool it DELEGATES to rather than the one it
// impersonates: docker's command set is stable across releases, podman's grows
// every one, and a too-small denylist would let docker answer "unknown
// command" in a voice that is not the stub's — the failure mode
// internal/cli/podmanshim.go's standing refusal was written against.
var dockerSubcommands = []string{
	"attach", "build", "builder", "commit", "compose", "config", "container",
	"context", "cp", "create", "diff", "events", "exec", "export", "history",
	"image", "images", "import", "info", "inspect", "kill", "load", "login",
	"logout", "logs", "manifest", "network", "node", "pause", "plugin",
	"port", "ps", "pull", "push", "rename", "restart", "rm", "rmi", "run",
	"save", "search", "secret", "service", "stack", "start", "stats", "stop",
	"swarm", "system", "tag", "top", "trust", "unpause", "update", "version",
	"volume", "wait",
}

// podmanOnlySubcommands names subcommands that exist only in podman's CLI, so
// refusing them on the docker path gets a specific reason instead of the
// generic one. Not exhaustive, and does not need to be: the allowlist above is
// what refuses, this map only makes the common cases legible.
var podmanOnlySubcommands = map[string]string{
	"pod":      "pods are a podman-only grouping; docker has no equivalent command",
	"kube":     "generating or playing Kubernetes YAML is podman-only; docker has no equivalent command",
	"generate": "it produces podman-specific output (systemd units, Kubernetes YAML); docker has no equivalent command",
	"machine":  "it manages podman's own VM-backed engine, not the one this sandbox uses",
	"unshare":  "it enters podman's own user namespace, which has no docker equivalent and no meaning inside this sandbox",
	"farm":     "build farms are podman-only; docker has no equivalent command",
}

// connectionShapingFlags select a different engine, connection or storage than
// the one this sandbox was given. podman accepts them anywhere in argv, so the
// whole of it is scanned, on both client paths.
var connectionShapingFlags = []string{
	"--remote", "--url", "--connection", "--root", "--runroot", "--runtime",
}

// IsPodmanStub reports whether this process is the podman stub: invoked by the
// name podman (a shell's PATH search passes the bare word, an absolute exec
// the full path) AND executing the image bound at policy.WrapperGuest. The
// second half is what keeps a host snug installed or copied as `podman` the
// CLI: outside a sandbox nothing is at that path, and exe is wherever snug is.
func IsPodmanStub(argv0, exe string) bool {
	return filepath.Base(argv0) == "podman" && exe == policy.WrapperGuest
}

// Podman is the stub at policy.StagedBinDir/podman, staged when podman on the
// host resolves to a helper that forwards outside the sandbox. It hands args to
// the first client in policy.PodmanStubClients found on path: docker through
// the allowlist above, podman-remote verbatim, since it is podman's own CLI.
// Either reaches the engine through $CONTAINER_HOST or $DOCKER_HOST, which snug
// set and the stub never touches; the container proxy is what decides, so
// nothing here is a boundary. It returns only on refusal or failure.
func Podman(args []string, path string, stderr io.Writer) int {
	client, bin := podmanClient(path)
	if bin == "" {
		fmt.Fprintf(stderr, "snug: stub -- podman cannot run inside this sandbox: the podman on this\n"+
			"      host's PATH resolves to a helper that forwards commands outside the\n"+
			"      sandbox rather than running them, and no %s is\n"+
			"      installed here to use instead. Install one, or drive the API directly\n"+
			"      at $CONTAINER_HOST.\n", strings.Join(quoted(policy.PodmanStubClients), " or "))
		return exitStub
	}

	for _, a := range args {
		for _, f := range connectionShapingFlags {
			if a == f || strings.HasPrefix(a, f+"=") {
				fmt.Fprintf(stderr, "snug: stub refuses '%s' -- it selects a different engine, connection or\n"+
					"      storage than the one this sandbox was given. Run '%s %s' directly if\n"+
					"      that is really what you want.\n", a, client, strings.Join(args, " "))
				return exitStub
			}
		}
	}

	if client == "docker" {
		cmd := ""
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				cmd = a
				break
			}
		}
		switch reason, podmanOnly := podmanOnlySubcommands[cmd]; {
		case cmd == "":
			fmt.Fprintf(stderr, "snug: stub -- no subcommand given. Run 'docker' directly, or see the COMMANDS\n"+
				"      block in 'snug --dry-run' for what this stub forwards.\n")
			return exitStub
		case podmanOnly:
			fmt.Fprintf(stderr, "snug: stub refuses 'podman %s' -- %s.\n", cmd, reason)
			return exitStub
		case !slices.Contains(dockerSubcommands, cmd):
			fmt.Fprintf(stderr, "snug: stub refuses 'podman %s' -- it is not one of the docker subcommands\n"+
				"      this stub forwards. Run 'docker %s' directly if you mean it.\n", cmd, cmd)
			return exitStub
		}
	}

	err := syscall.Exec(bin, append([]string{client}, args...), os.Environ())
	fmt.Fprintf(stderr, "snug: stub -- %s: %v\n", bin, err)
	if errors.Is(err, syscall.ENOENT) {
		return exitNotFound
	}
	return exitCannotRun
}

// podmanClient finds the first of policy.PodmanStubClients on path, every
// directory searched for docker before any for podman-remote. It skips
// policy.StagedBinDir, where the stub itself lives, and every relative entry: a
// relative entry resolves against the working directory, which is the target,
// and the client the stub picks would then be a file the repo ships.
func podmanClient(path string) (name, bin string) {
	for _, name := range policy.PodmanStubClients {
		for _, dir := range filepath.SplitList(path) {
			if !filepath.IsAbs(dir) || filepath.Clean(dir) == policy.StagedBinDir {
				continue
			}
			p := filepath.Join(dir, name)
			// HOSTREAD-EXEMPT: runs inside the sandbox, never on the host.
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && syscall.Access(p, 1) == nil {
				return name, p
			}
		}
	}
	return "", ""
}

func quoted(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = "'" + n + "'"
	}
	return out
}
