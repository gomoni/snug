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

WHAT THIS MATCHES, AND WHY IT CHANGED (issue #199). The first version required a
destructive-looking token and a protected path to appear *anywhere in the same
string*, with no requirement that they belonged to each other. That refused five
pieces of harmless work in one morning across two sessions — a commit message, an
issue body, an issue comment and two edits to a gitignored plan file — while zero
destructive commands were attempted in that window. Every one of them was text
*about* destruction: this repository writes about destroying things constantly,
because that is what the incidents were.

So it now matches only where a command can actually appear. A destructive token
inside a CARRIED ARGUMENT — a `--comment` body, a `-m` message, an `echo` string,
a here-document — was never a command and is not graded. `sh -c '…'` IS a command
position and is descended into, which is the half that must not regress: the
spelling that started #185 was a payload string.

That distinction is the whole fix. It does not answer the larger question #199
raises, and must not be read as having answered it — see below.

DESIGN NOTES, each one a decision rather than an accident:

* A DENY LIST OF PATHS, not a ban on `rm`. Ordinary work in this repo deletes
  files constantly — build outputs, worktrees, scratchpad fixtures — and a hook
  that blocks all deletion is one somebody switches off within the hour. What is
  protected is the small set of host paths that are expensive and irreplaceable.

* THE SANDBOX VERIFIER IS DELIBERATELY NOT CONSULTED HERE. This hook's answer
  must not depend on a check that can itself fail open. It refuses the same way
  whether or not a sandbox is running.

* IT MATCHES TEXT, NOT INTENT, AND SAYS SO — AND IT IS NARROWER THAN ITS OWN
  REFUSAL READS. A command assembled from a variable, a file or an interpreter's
  stdin never reaches the argv this hook grades, and neither does the same
  operation performed through a non-Bash tool, because the hook is registered for
  Bash alone. `--body-file` is the everyday example. Whether that makes this a
  SPEED BUMP against the literal mistake or a BOUNDARY that belongs somewhere
  else entirely is an open maintainer decision recorded on #199. It is not
  settled here, and narrowing the false positives did not settle it.

* IT ERRS TOWARDS ALLOWING ON ITS OWN FAILURE, with one exception. A hook that
  crashes and blocks every Bash call makes the session unusable, which gets it
  deleted. So a parse failure falls back to a crude substring check over the raw
  input and allows anything that does not mention a protected path.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shellcmd import (  # noqa: E402
    nested_payloads,
    redirect_targets,
    split_top_level,
    strip_heredoc_bodies,
    strip_wrappers,
    words,
)

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
DESTRUCTIVE = {"rm", "rmdir", "shred", "srm", "unlink", "truncate", "dd", "mv"}
MKFS = re.compile(r"^mkfs\.\w+$")

# `find` destroys without naming a verb in command position.
FIND_DESTROYS = ("-delete", "-exec", "-execdir")


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


def path_hit(token):
    """The protected path this ARGUMENT names, or None.

    Graded per token rather than by searching the line, which is the whole of
    #199: `/home/u/.claude` as an operand of `rm` is a target; the same text
    inside a commit message is a citation.
    """
    t = token
    m = re.match(r"^[A-Za-z_][A-Za-z0-9_]*=(.*)$", t)  # dd of=…, and friends
    if m:
        t = m.group(1)
    t = t.rstrip("/") or "/"
    for path, whole_tree in protected_paths():
        if t == path:
            return path
        if whole_tree and t.startswith(path + "/"):
            return path
    return None


def grade(argv):
    """The protected path this one command destroys, or None."""
    argv, _ = strip_wrappers(argv)
    if not argv:
        return None

    # A clobbering redirect is the one way a path dies with no destructive verb
    # anywhere in the command. `echo x > ~/.config/f` must stay refused; a `>`
    # inside a quoted message must not be read as one, which is what tokenising
    # first buys.
    for target in redirect_targets(argv):
        hit = path_hit(target)
        if hit:
            return hit

    base = os.path.basename(argv[0])
    operands = argv[1:]

    if base in DESTRUCTIVE or MKFS.match(base):
        for operand in operands:
            hit = path_hit(operand)
            if hit:
                return hit

    if base == "find" and any(flag in operands for flag in FIND_DESTROYS):
        for operand in operands:
            hit = path_hit(operand)
            if hit:
                return hit

    return None


# The ONE exemption, and it is the form the agent files mandate: the guard and
# the destructive command in a single invocation, guard first.
#
#     snug <dir> -- sh -c 'blast-radius && rm -rf "$HOME/.config"'
#
# Exempting it is not a loophole, it is the point — the hook has to leave the
# sanctioned pattern usable or the instruction and the enforcement contradict
# each other. Note it does NOT exempt a bare `snug … -- sh -c 'rm -rf …'`: being
# inside a sandbox says nothing about what that sandbox's policy hands over, and
# a run whose grants reach the host's key material is inside and lethal.
GUARDED = re.compile(r"blast-radius[^\n]{0,40}?&&")


def scan(text):
    """Walk every command position in text and return the first refusal."""
    guard = GUARDED.search(text)
    guard_end = guard.end() if guard else None

    for offset, segment in split_top_level(text):
        if guard_end is not None and offset >= guard_end:
            # Everything after `blast-radius &&` in this string is the guarded
            # payload, which is the sanctioned form.
            continue
        argv = words(segment)
        hit = grade(argv)
        if hit:
            return hit
        for payload in nested_payloads(argv):
            hit = scan(payload)
            if hit:
                return hit
    return None


def verdict(command):
    """Return a refusal reason, or None to allow."""
    return scan(normalise(strip_heredoc_bodies(command)))


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
        "a sandbox whose policy grants write access over the host's key material is inside\n"
        "and lethal, which is why the guard asks what is REACHABLE rather than where you are\n"
        "standing.\n"
        "\n"
        "If it really was meant to run on the host, a human has to do it. This hook has no\n"
        "override, on purpose: an override is a thing an agent talks itself into.\n"
        "\n"
        "If you were WRITING ABOUT a destructive command rather than running one, that is\n"
        "not supposed to be refused any more (issue #199). Report it rather than rewording\n"
        "until the matcher stops seeing it — normalising that workaround is what makes the\n"
        "guard worthless.\n"
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
        hit = verdict(raw)
        if hit:
            deny(hit, raw)
        sys.exit(0)

    if not isinstance(command, str) or not command:
        sys.exit(0)
    path = verdict(command)
    if path:
        deny(path, command)
    sys.exit(0)


if __name__ == "__main__":
    main()
