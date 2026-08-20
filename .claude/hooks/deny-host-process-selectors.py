#!/usr/bin/env python3
"""PreToolUse hook: refuse Bash commands that choose their target by MATCHING
instead of by naming it.

WHY THIS EXISTS (issue #197). Its sibling, deny-host-credential-paths.py, needs
two things before it refuses: a destructive verb and a mention of a protected
path. Both incidents this hook exists for had neither.

    pkill -x bwrap
    podman system reset

No path, no `rm`, and on this host both are catastrophic. Flatpak runs every
desktop application under `bwrap`, so the first closes the browser, the mail
client and the terminal emulator the session is running inside. The second
destroys the rootless-podman distrobox this project is developed in — the same
container the agent issuing the command is running in.

Neither is a sandbox escape and neither is snug's fault. They are ordinary host
commands issued at the user's own uid, by an agent that has a shell because
every agent in this repository has one.

DESIGN NOTES, each one a decision rather than an accident:

* DENY THE SELECTOR, NOT THE SIGNAL. `kill 12345` is the correct form and stays
  allowed, as does `kill "$P"` after `P=$!`. A guard that refused killing
  outright would push people into working around it, and a worked-around guard
  protects nothing. What is refused is choosing the target by pattern —
  `pkill`, `killall`, `kill $(pgrep …)`, `… | xargs kill` — because that is the
  step at which a process nobody started enters the target set.

* A HOOK CANNOT TELL WHICH CONTAINERS A SESSION CREATED, so it does not
  pretend to. The unscoped podman/docker forms — `--all`, every `prune`,
  `system reset`, `machine` — are refused outright, and named single-container
  operations are left alone. `podman ps -a` and `podman images -a` are reads and
  are not touched: the `-a` rule applies only behind a destructive subcommand.

* A PAYLOAD INSIDE A SANDBOX IS EXEMPT, and this is the one place where "it is
  inside" IS a safety property. The sibling hook is careful to say it is not,
  and for mounts that is right — a policy granting rw over ~/.ssh is inside and
  lethal. Processes are different in kind: snug always gives the sandbox its own
  pid namespace (`PidMode=host` is refused outright, issue #145), so a payload
  cannot signal a host pid whatever the policy says. test/integration's
  `pkill -9 -x sleep` probe asserts exactly that, and is committed work this
  hook must not block. So a `snug <dir> -- <payload>` segment is skipped whole.

* IT MATCHES TEXT, NOT INTENT, AND SAYS SO. A determined command can evade it.
  That is acceptable: this guards against a MISTAKE, not against a hostile
  agent — a hostile agent has a shell either way, and the answer to that is not
  to run one.

* IT ERRS TOWARDS ALLOWING ON ITS OWN FAILURE. A hook that crashes and blocks
  every Bash call makes the session unusable, which gets it deleted. A parse
  failure falls back to a crude word search for the two spellings that have
  actually happened here.
"""

import json
import os
import re
import shlex
import sys

# Verbs that pick their victims by name or pattern. There is no flag that makes
# any of these scoped: `pkill -x` is exact-name-matching, which is precisely the
# spelling that killed 17 Flatpak processes.
SELECTOR_KILLERS = {"pkill", "killall", "killall5"}

# Commands whose whole job is to turn a pattern into a pid list. Seeing one
# inside a `kill` argument is what makes that kill a selector kill; running one
# on its own is a read and is left alone.
PID_FINDERS = re.compile(r"\b(pgrep|pidof|ps)\b")

# Container subcommands that destroy. `ps`, `images`, `inspect` and `logs` are
# deliberately absent: `-a` on a read means "show me everything".
CONTAINER_DESTRUCTIVE = {"kill", "stop", "rm", "rmi", "restart", "pause", "unpause"}

# Wrappers that stand in front of the real command without changing what it does.
TRANSPARENT = {"sudo", "doas", "nohup", "nice", "ionice", "stdbuf", "command", "exec", "time", "env"}

# The flags that mean "everything you can find", in the spellings a shell accepts.
ALL_FLAG = re.compile(r"^(--all(=true)?|-[a-zA-Z]*a[a-zA-Z]*)$")


def split_top_level(text):
    """Split on shell operators, respecting quotes, `$(…)` and backticks.

    Not a shell parser and not trying to be. It exists so that
    `snug /tmp/t -- sh -c 'pkill x'; pkill -x bwrap` is two segments — the
    exemption must cover the payload and must NOT cover what follows it.
    """
    out, cur = [], []
    quote = None
    depth = 0
    i = 0
    while i < len(text):
        c = text[i]
        if quote:
            cur.append(c)
            if c == quote:
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < len(text):
            cur.append(c)
            cur.append(text[i + 1])
            i += 2
            continue
        if c in "'\"`":
            quote = c
            cur.append(c)
            i += 1
            continue
        if text[i:i + 2] == "$(":
            depth += 1
            cur.append("$(")
            i += 2
            continue
        if c == ")" and depth > 0:
            depth -= 1
            cur.append(c)
            i += 1
            continue
        if depth == 0:
            if text[i:i + 2] in ("&&", "||"):
                out.append("".join(cur))
                cur = []
                i += 2
                continue
            if c in ";|&\n":
                out.append("".join(cur))
                cur = []
                i += 1
                continue
        cur.append(c)
        i += 1
    out.append("".join(cur))
    return [s.strip() for s in out if s.strip()]


def words(segment):
    try:
        return shlex.split(segment, comments=False, posix=True)
    except ValueError:
        return segment.split()


def is_snug_invocation(argv):
    """A snug run with a payload after `--`. The payload runs in the sandbox's
    own pid namespace and cannot reach a host pid, so it is not this hook's
    business."""
    if not argv or "--" not in argv:
        return False
    head = argv[:argv.index("--")]
    if not head:
        return False
    if os.path.basename(head[0]) == "snug":
        return True
    # `go run ./cmd/snug <dir> -- <payload>` is the same thing spelled longer.
    return any(w.rstrip("/").endswith("cmd/snug") for w in head)


def strip_wrappers(argv):
    """Peel env assignments and transparent wrappers off the front.

    Returns (argv, via_xargs). `xargs` is called out rather than merely peeled:
    a kill reached through xargs took its pids from a stream, which is a
    selector by construction however the stream was produced.
    """
    via_xargs = False
    i = 0
    while i < len(argv):
        w = argv[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w):
            i += 1
            continue
        if w == "--":
            # `env -- pkill x` and `sudo -- pkill x`. The end-of-options marker
            # is not a command, and leaving it in place made argv[0] `--`, which
            # matched no rule at all.
            i += 1
            continue
        base = os.path.basename(w)
        if base in TRANSPARENT:
            i += 1
            continue
        if base == "timeout":
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                i += 1
            i += 1  # the duration
            continue
        if base == "xargs":
            via_xargs = True
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                # -n, -P, -I, -d and -a take a value; the rest are switches.
                takes_value = argv[i] in ("-n", "-P", "-I", "-d", "-a", "-s", "-L", "-E")
                i += 1
                if takes_value and i < len(argv):
                    i += 1
            continue
        break
    return argv[i:], via_xargs


def nested(argv):
    """The command strings a shell wrapper is asked to run: `sh -c '<here>'`."""
    out = []
    for i, w in enumerate(argv):
        if re.match(r"^-[a-z]*c$", w) and i + 1 < len(argv):
            out.append(argv[i + 1])
    return out


def subcommands(argv):
    """The non-flag words after a container engine's name, in order."""
    out = []
    skip_value = {"--url", "--connection", "--runtime", "--root", "--runroot",
                  "--storage-driver", "--log-level", "--identity", "--remote",
                  "--context", "--host", "-H", "-c", "--config"}
    i = 1
    while i < len(argv):
        w = argv[i]
        if w in skip_value:
            i += 2
            continue
        if w.startswith("-"):
            i += 1
            continue
        out.append(w)
        i += 1
    return out


def check(segment):
    """A refusal headline for this one segment, or None."""
    argv = words(segment)
    if not argv:
        return None
    if is_snug_invocation(argv):
        return None

    argv, via_xargs = strip_wrappers(argv)
    if not argv:
        return None
    base = os.path.basename(argv[0])

    if base in SELECTOR_KILLERS:
        return f"`{base}` chooses its targets by matching a name, not by naming a process"

    if base == "kill":
        if via_xargs:
            return "a `kill` fed from a pipe takes whatever the pipe found, which is a selector"
        if PID_FINDERS.search(segment) and ("$(" in segment or "`" in segment):
            return "this `kill` takes its pids from a pattern search rather than from a pid you recorded"

    if base in ("podman", "docker"):
        chain = subcommands(argv)
        if not chain:
            return None
        if "prune" in chain:
            return f"`{base} {' '.join(chain)}` is unscoped by construction — it names no container"
        if chain[:2] == ["system", "reset"]:
            return f"`{base} system reset` destroys every container, image and volume on this host"
        if chain[0] == "machine":
            return f"`{base} machine {' '.join(chain[1:])}` operates on the engine itself, not on one container"
        if chain[0] in CONTAINER_DESTRUCTIVE:
            for w in argv[1:]:
                if ALL_FLAG.match(w):
                    return f"`{base} {chain[0]} {w}` reaches containers this session never created"

    if base == "systemctl":
        for w in subcommands(argv):
            if w in ("stop", "kill"):
                return f"`systemctl {w}` stops a unit this session did not start"

    if base == "loginctl":
        for w in subcommands(argv):
            if re.match(r"^(terminate|kill)-(user|session|seat)$", w):
                return f"`loginctl {w}` ends the user's login session, and everything in it"

    return None


def verdict(command):
    for segment in split_top_level(command):
        argv = words(segment)
        if is_snug_invocation(argv):
            continue
        found = check(segment)
        if found:
            return found
        for inner in nested(argv):
            for sub in split_top_level(inner):
                found = check(sub)
                if found:
                    return found
    return None


def deny(headline, command):
    reason = (
        f"Refused: {headline}.\n"
        "\n"
        "On this host `bwrap` is what Flatpak runs every desktop application under, and the\n"
        "development environment is itself a rootless-podman distrobox. So `pkill -x bwrap`\n"
        "closes the user's browser, mail client and terminal with no chance to save, and a\n"
        "podman command with `--all` or `system reset` destroys the container this session is\n"
        "running inside. Neither is a sandbox escape and neither is snug's fault — they are\n"
        "ordinary host commands issued at the user's own uid.\n"
        "\n"
        "It has happened twice: 2026-08-13 (18 Flatpaks killed, reported at the time as\n"
        "successful cleanup — the probe ran one sandbox at a time and could never have left\n"
        "18) and again 2026-08-19 (issues #197, #185).\n"
        "\n"
        "The fix, and `kill <numeric-pid>` is not what is being refused here:\n"
        "  * Capture the pid when you start something — `P=$!` in a shell, `cmd.Process.Pid`\n"
        "    in Go — and signal exactly that: `kill \"$P\"`.\n"
        "  * To reach a whole TREE, walk /proc ancestry from your own pid and signal only\n"
        "    what descends from a process you started. `descendantsOf` in\n"
        "    test/integration/stage_test.go already does exactly this; copy it.\n"
        "  * For a container, name it: `podman rm <name>`, never `--all`.\n"
        "  * If you find yourself wanting to match by name, you have lost track of a pid.\n"
        "    Go and find it rather than widening the target.\n"
        "\n"
        "A payload running INSIDE a sandbox is exempt and needs no workaround: snug always\n"
        "gives it its own pid namespace, so `snug <dir> -- sh -c '<payload>'` is allowed\n"
        "through unread.\n"
        "\n"
        "This hook has no override, on purpose: an override is a thing an agent talks itself\n"
        "into. If it really has to run on the host, a human has to do it.\n"
        f"\ncommand: {command.strip()[:400]}"
    )
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def main():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
        command = payload.get("tool_input", {}).get("command", "")
    except Exception:
        # The crude read, for a shape this hook did not expect. Only the two
        # spellings that have actually happened on this host.
        if re.search(r"\b(pkill|killall)\b", raw) or re.search(r"system\s+reset", raw):
            deny("this input names a selector-matched kill or a container-engine reset", raw)
        sys.exit(0)

    if not isinstance(command, str) or not command:
        sys.exit(0)
    headline = verdict(command)
    if headline:
        deny(headline, command)
    sys.exit(0)


if __name__ == "__main__":
    main()
