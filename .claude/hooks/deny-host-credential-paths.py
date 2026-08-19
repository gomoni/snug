#!/usr/bin/env python3
"""PreToolUse hook: refuse destructive Bash aimed at the HOST's credential and
configuration paths.

WHY THIS EXISTS (issues #185, #186). Agents working on snug run on the host, and
for almost all of them that is the ordinary and correct mode — they edit files,
run `go test`, drive git. Nothing here treats a host shell as a mistake.

What no task in this repository requires is DESTROYING the host's credential and
configuration paths. That is the whole rule: not "be careful where you are", but
"these paths are not yours to overwrite, wherever you think you are".

bin/blast-radius is the check an agent can RUN before a destructive payload, and
it answers a different question — is anything worth losing reachable from here.
This layer does not depend on an agent choosing to run anything, which is the
point: the incident is precisely a run nobody stopped to check.

DESIGN NOTES, each one a decision rather than an accident:

* A DENY LIST OF PATHS, not a ban on `rm`. Ordinary work in this repo deletes
  files constantly — build outputs, worktrees, scratchpad fixtures — and a hook
  that blocks all deletion is one somebody switches off within the hour. What is
  protected is the small set of host paths that are expensive and irreplaceable.

* THE SANDBOX VERIFIER IS DELIBERATELY NOT CONSULTED HERE. This hook's answer
  must not depend on a check that can itself fail open. It refuses the same way
  whether or not a sandbox is running.

* IT MATCHES TEXT, NOT INTENT, AND SAYS SO. A determined command can evade it
  (a variable holding the path, base64, a here-doc). That is acceptable: this
  guards against a MISTAKE, not against a hostile agent — a hostile agent has a
  shell either way, and the answer to that is not to run one.

* IT ERRS TOWARDS ALLOWING ON ITS OWN FAILURE, with one exception. A hook that
  crashes and blocks every Bash call makes the session unusable, which gets it
  deleted. So a parse failure falls back to a crude substring check over the raw
  input and allows anything that does not mention a protected path.
"""

import json
import os
import re
import sys

# The paths worth an interruption. Everything here is either a credential store
# or a command table that runs on the HOST, outside anything snug confines.
PROTECTED_RELATIVE = [
    ".claude",       # settings.json, CLAUDE.md, hooks, the credential file, the transcript archive
    ".ssh",          # private keys
    ".gnupg",        # private keys
    ".aws",          # cloud keys
    ".config",       # a credential dump and a persistence vector in one (CLAUDE.md)
    ".local/share",  # keyrings, and the claude bundle
]

# Verbs that destroy or replace. `mv` is here because moving a directory away is
# indistinguishable from deleting it from the caller's point of view.
DESTRUCTIVE = re.compile(
    # The boundary class carries the quote characters deliberately. Without them
    # `sh -c "rm -rf ~/.claude"` did not match at all — the verb sits directly
    # behind a double quote, which is the ordinary spelling of a payload string
    # and therefore exactly the shape this hook exists for.
    r"""(^|[|;&("']|\s)(rm|rmdir|shred|srm|unlink|truncate|dd|mv|mkfs\.\w+)\s""",
    re.IGNORECASE,
)
# Redirections that clobber, and the sweeps that delete without naming a verb
# first. `>` is one character and carries the same consequence as `rm`.
CLOBBER = re.compile(r"(>{1,2}\s*\S)|(--delete\b)|(-delete\b)|(-exec\s+rm\b)")


def home():
    return os.path.expanduser("~").rstrip("/")


def protected_paths():
    """(path, whole_tree) pairs.

    $HOME itself is protected only as an EXACT target — `rm -rf ~` — and
    explicitly not as a prefix. Treating it as a tree would silently protect
    everything under it, including this repository, which lives in $HOME on the
    machine where the incident happened. A hook that refuses `rm -rf
    $HOME/projects/x/build` is one somebody switches off, and a switched-off
    hook protects nothing. Found by mutation: deleting `.claude` from the list
    below changed no test, because the bare-home entry was quietly covering
    every child.
    """
    h = home()
    return [(h + "/" + rel, True) for rel in PROTECTED_RELATIVE] + [(h, False)]


def normalise(command):
    """Expand the spellings that mean the same directory, so the match is on the
    path rather than on how it was typed. This is not a shell parser and is not
    trying to be: it closes the ordinary spellings, which is what a mistake uses.
    """
    h = home()
    out = command
    for var in ("${HOME}", "$HOME", "~"):
        out = out.replace(var, h)
    return re.sub(r"/{2,}", "/", out)


def mentions(command, path, whole_tree):
    """True when command names path — or, for a whole_tree path, anything inside
    it. The boundary check stops /home/u/.config matching a mention of
    /home/u/.configured."""
    ends = ("", " ", '"', "'", ";", "&", "|", ")", "\n", "\t", "*")
    idx = 0
    while True:
        idx = command.find(path, idx)
        if idx == -1:
            return False
        after = command[idx + len(path): idx + len(path) + 1]
        if after in ends or (whole_tree and after == "/"):
            return True
        # A trailing slash on an exact target is still that target: `rm -rf ~/`.
        if not whole_tree and after == "/" and command[idx + len(path) + 1: idx + len(path) + 2] in ends:
            return True
        idx += 1


# The ONE exemption, and it is the form the agent files mandate: the guard and
# the destructive command in a single invocation, guard first.
#
#     snug <dir> -- sh -c 'blast-radius && rm -rf "$HOME/.config"'
#
# Exempting it is not a loophole, it is the point — the hook has to leave the
# sanctioned pattern usable or the instruction and the enforcement contradict
# each other. Note it does NOT exempt a bare `snug … -- sh -c 'rm -rf …'`: being
# inside a sandbox says nothing about what that sandbox's policy hands over, and
# a run whose grants reach the host's ~/.ssh is inside and lethal.
GUARDED = re.compile(r"blast-radius[^\n]{0,40}?&&")


def verdict(command):
    """Return a refusal reason, or None to allow."""
    text = normalise(command)
    hit = DESTRUCTIVE.search(text) or CLOBBER.search(text)
    if not hit:
        return None
    guard = GUARDED.search(text)
    if guard and guard.start() < hit.start():
        return None
    for path, whole_tree in protected_paths():
        if mentions(text, path, whole_tree):
            return path
    return None


def deny(path, command):
    reason = (
        f"Refused: this command destroys or overwrites {path}, which belongs to the host.\n"
        "\n"
        "Working on the host is normal here and is not the problem. Overwriting the host's\n"
        "credentials, its shell and tool configuration, or its transcript archive is — no task\n"
        "in this repository requires it, and the recovery from the last one ran on exactly\n"
        "those files (issues #185, #186).\n"
        "\n"
        "If this was meant to run INSIDE a sandbox: pin HOME to a scratch directory first,\n"
        "and guard the payload in the SAME invocation —\n"
        "    snug <dir> -- sh -c 'blast-radius && <the destructive command>'\n"
        "never as two steps. Note that being inside a sandbox is not the safety property:\n"
        "a sandbox whose policy grants rw over ~/.ssh is inside and lethal, which is why the\n"
        "guard asks what is REACHABLE rather than where you are standing.\n"
        "\n"
        "If it really was meant to run on the host, a human has to do it. This hook has no\n"
        "override, on purpose: an override is a thing an agent talks itself into.\n"
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
        # Fall back to the crude read rather than blocking the session on a
        # shape this hook did not expect.
        for path, _ in protected_paths():
            if path in raw and (DESTRUCTIVE.search(raw) or CLOBBER.search(raw)):
                deny(path, raw)
        sys.exit(0)

    if not isinstance(command, str) or not command:
        sys.exit(0)
    path = verdict(command)
    if path:
        deny(path, command)
    sys.exit(0)


if __name__ == "__main__":
    main()
