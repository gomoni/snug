package policy

import (
	"fmt"
	"sort"
	"strings"
)

// PodmanStubDir is where snug stages the dispatcher when podman resolves to
// a host-escape shim on this host. Under /run/snug, alongside the container
// proxy socket — both are snug's own, both unwritable from inside once
// --remount-ro / has run (constraint 1, CONTAINER-CLIENT.md §8: measured —
// /run/snug/bin refuses `touch` and `echo >` with EROFS), and both gone with
// the sandbox.
const PodmanStubDir = "/run/snug/bin"

// podmanStubDelim is the heredoc delimiter the script's one host-derived
// string — the detected shim's resolved path — is wrapped in. A quoted
// heredoc (<<'DELIM') stops the shell expanding anything inside it, however
// odd the path looks, which is the whole point of using one. That is not
// enough on its own: a path containing a LINE equal to the delimiter would
// still terminate the heredoc early and hand the remaining lines to the
// shell as commands, so podmanStubScript refuses to stage rather than risk
// it — see its doc comment.
const podmanStubDelim = "SNUG_TEXT_END"

// dockerSubcommands is the compiled-in allowlist the stub forwards
// byte-for-byte. It allowlists the tool it DELEGATES to (docker) rather than
// the one it impersonates (podman): docker's command set is stable across
// releases, podman's grows every one, and a too-small denylist would let
// podman answer "unknown command" in the stub's own voice — the failure mode
// podmanshim.go's standing refusal was written against. See
// CONTAINER-CLIENT.md §8.
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

// podmanOnlySubcommands names subcommands that exist ONLY in podman's CLI —
// there is no docker command to forward them to — so refusing them gets a
// one-sentence, specific reason instead of the generic "not one of the
// subcommands this stub forwards" message. Not exhaustive: podman's command
// set grows every release, which is exactly why the stub is an ALLOWLIST
// over docker's side rather than an attempt to enumerate podman's — this map
// only makes the common cases legible, the "otherwise" branch still catches
// everything else.
var podmanOnlySubcommands = map[string]string{
	"pod":      "pods are a podman-only grouping; docker has no equivalent command",
	"kube":     "generating or playing Kubernetes YAML is podman-only; docker has no equivalent command",
	"generate": "it produces podman-specific output (systemd units, Kubernetes YAML); docker has no equivalent command",
	"machine":  "it manages podman's own VM-backed engine, not the one this sandbox uses",
	"unshare":  "it enters podman's own user namespace, which has no docker equivalent and no meaning inside this sandbox",
	"farm":     "build farms are podman-only; docker has no equivalent command",
}

// connectionShapingFlags select a different engine, connection or storage
// than the one this sandbox was given. podman accepts them in any position
// in argv, so the stub scans the whole thing rather than just $1. Named
// explicitly, from CONTAINER-CLIENT.md §8.
var connectionShapingFlags = []string{
	"--remote", "--url", "--connection", "--root", "--runroot", "--runtime",
}

// podmanStubScript generates the dispatcher staged at PodmanStubDir/podman.
// It is a pure function of the detected shim — no filesystem, no exec — so
// Resolve can call it directly and stay pure itself.
//
// The shim's resolved path is the ONLY host-derived text in the script, and
// it is interpolated ONLY inside a quoted heredoc (<<'SNUG_TEXT_END'), which
// stops the shell expanding anything inside it — a `$(...)` or backtick in
// the path is printed literally, not run. That is not sufficient by itself:
// a path containing a line equal to the delimiter would still terminate the
// heredoc early and hand the rest of the script to the shell as commands, so
// staging is refused outright — fail closed, per invariant 5 — rather than
// risk it.
func podmanStubScript(shim HostShim) (string, error) {
	if strings.Contains(shim.Resolved, "\n") {
		return "", fmt.Errorf("cannot stage the podman stub: the detected shim path %q contains "+
			"a newline; refusing rather than risk it breaking out of the script's heredoc", shim.Resolved)
	}
	if shim.Resolved == podmanStubDelim {
		return "", fmt.Errorf("cannot stage the podman stub: the detected shim path %q equals "+
			"the heredoc delimiter %q; refusing rather than risk it terminating the heredoc early",
			shim.Resolved, podmanStubDelim)
	}

	var flagCases strings.Builder
	for i, f := range connectionShapingFlags {
		if i > 0 {
			flagCases.WriteString("|")
		}
		fmt.Fprintf(&flagCases, "%s|%s=*", f, f)
	}

	var cmdCases strings.Builder
	cmdCases.WriteString(strings.Join(dockerSubcommands, "|"))

	podmanOnlyNames := make([]string, 0, len(podmanOnlySubcommands))
	for name := range podmanOnlySubcommands {
		podmanOnlyNames = append(podmanOnlyNames, name)
	}
	sort.Strings(podmanOnlyNames)
	var podmanOnlyCases strings.Builder
	for _, name := range podmanOnlyNames {
		fmt.Fprintf(&podmanOnlyCases, "  %s)\n"+
			"    echo \"snug: stub refuses 'podman %s' -- %s.\" >&2\n"+
			"    exit 125\n"+
			"    ;;\n", name, name, podmanOnlySubcommands[name])
	}

	return fmt.Sprintf(podmanStubTemplate,
		flagCases.String(), shim.Resolved, cmdCases.String(), podmanOnlyCases.String()), nil
}

// podmanStubTemplate is the dispatcher's body. Four %s slots, IN THE ORDER
// THEY APPEAR: the connection-shaping flag patterns, the detected shim's
// resolved path (inside the one quoted heredoc — see podmanStubScript's doc
// comment), the docker subcommand allowlist, and the podman-only refusal
// cases.
const podmanStubTemplate = `#!/bin/sh
# snug: this file is a STUB standing in for /usr/bin/podman, INSIDE THIS
# SANDBOX ONLY. It is not podman. It is a dispatcher: it forwards a fixed
# allowlist of docker subcommands to the real 'docker' CLI, byte-for-byte,
# and refuses everything else by name. It never sets DOCKER_HOST or -H --
# whatever snug already put in the environment is what docker inherits.
#
# Why this exists: the podman on this host's PATH resolves to a shim that
# forwards commands outside the sandbox and cannot work from inside one.
# /usr/bin/podman is untouched and still reachable by its absolute path;
# this file only comes first on PATH. See CONTAINER-CLIENT.md section 8.
#
# This file and the directory it lives in are read-only from inside the
# sandbox -- generated and owned by snug, not by anything running here.

# Flags that select a different engine, connection or storage than the one
# this sandbox was given. Refused wherever they appear in argv, by name,
# before the subcommand is even looked at.
for _snug_arg in "$@"; do
  case "$_snug_arg" in
    %s)
      echo "snug: stub refuses '$_snug_arg' -- it selects a different engine, connection or" >&2
      echo "      storage than the one this sandbox was given. Run 'docker $*' directly if" >&2
      echo "      that is really what you want." >&2
      exit 125
      ;;
  esac
done

_snug_cmd=""
for _snug_arg in "$@"; do
  case "$_snug_arg" in
    -*) continue ;;
    *) _snug_cmd="$_snug_arg"; break ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  cat <<'SNUG_TEXT_END' >&2
snug: stub -- podman cannot run inside this sandbox: the podman on this
      host's PATH resolves to %s, a helper that forwards commands
      outside the sandbox rather than running them, and no docker-compatible
      client is installed here to use instead. Install 'docker', or drive
      the API directly at $CONTAINER_HOST.
SNUG_TEXT_END
  exit 125
fi

case "$_snug_cmd" in
  %s)
    exec docker "$@"
    ;;
%s  "")
    echo "snug: stub -- no subcommand given. Run 'docker' directly, or see the COMMANDS" >&2
    echo "      block in 'snug --dry-run' for what this stub forwards." >&2
    exit 125
    ;;
  *)
    echo "snug: stub refuses 'podman $_snug_cmd' -- it is not one of the docker subcommands" >&2
    echo "      this stub forwards. Run 'docker $_snug_cmd' directly if you mean it." >&2
    exit 125
    ;;
esac
`
