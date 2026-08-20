"""Where a command can actually appear in a shell string.

Shared by the two PreToolUse hooks. Both of them need the same answer to the
same question — *is this text a command, or is it an argument being carried?* —
and both of them got it wrong in opposite directions before this module existed:
deny-host-process-selectors.py grew its own splitter, and
deny-host-credential-paths.py had none at all and matched anywhere in the line,
which is issue #199.

NOT A SHELL PARSER, and deliberately not trying to be. It closes the ordinary
spellings, which is what a mistake uses. A command assembled from a variable, a
file or an interpreter's stdin is invisible to it — see the speed-bump-versus-
boundary note on #199, which is an open decision and not something this module
settles.
"""

import os
import re
import shlex

# Wrappers that stand in front of the real command without changing what it does.
TRANSPARENT = {"sudo", "doas", "nohup", "nice", "ionice", "stdbuf", "command", "exec", "time", "env"}

# `sh -c`, `bash -lc`, `zsh -ic`. The payload of one of these IS a command
# position and must keep being read as one — that is the half of #199 that must
# not regress while the false positives are fixed.
DASH_C = re.compile(r"^-[a-z]*c$")

_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def strip_heredoc_bodies(text):
    """Remove here-document BODIES, keeping the command line that opened them.

    A heredoc body is data being carried — `cat > notes.md <<'EOF' … EOF` writes
    notes.md whatever the body says, and `python3 - <<'PY' … PY` is a program
    for python, not a command for the shell. Three of #199's five false
    positives were a destructive-looking sentence inside one of these.

    The opening line survives, so a redirect target on it is still graded.
    """
    out = []
    pos = 0
    for m in _HEREDOC.finditer(text):
        tag = m.group(2)
        line_end = text.find("\n", m.end())
        if line_end == -1:
            continue
        closer = re.search(r"^\s*" + re.escape(tag) + r"\s*$", text[line_end:], re.MULTILINE)
        if not closer:
            continue
        if line_end < pos:
            continue
        out.append(text[pos:line_end])
        pos = line_end + closer.end()
    out.append(text[pos:])
    return "\n".join(out)


def split_top_level(text):
    """(offset, segment) for each shell operator-separated segment.

    Quote-aware, and aware of `$(…)` and backticks, so a `|` inside a command
    substitution does not split the segment that contains it. Offsets are
    returned because a guard exemption has to know whether the guard ran BEFORE
    the thing it is guarding.
    """
    out = []
    cur = []
    start = 0
    quote = None
    depth = 0
    i = 0

    def flush(end):
        s = "".join(cur)
        stripped = s.strip()
        if stripped:
            out.append((start + (len(s) - len(s.lstrip())), stripped))

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
            two = text[i:i + 2]
            # NOT INDEPENDENTLY OBSERVABLE, and said out loud rather than
            # covered by a test that cannot fail. Deleting this branch changes
            # no decision: the single-character branch below splits on the first
            # `&` or `|` anyway, and the empty segment between them is dropped.
            # It is here for correct OFFSETS — the guard exemption compares a
            # segment's offset against the end of `blast-radius &&` — and so a
            # reader sees the operator being handled. A mutation removing it
            # SURVIVES the suite, which is the honest result.
            if two in ("&&", "||"):
                flush(i)
                cur = []
                i += 2
                start = i
                continue
            if c in ";|&\n":
                flush(i)
                cur = []
                i += 1
                start = i
                continue
        cur.append(c)
        i += 1
    flush(len(text))
    return out


def words(segment):
    try:
        return shlex.split(segment, comments=False, posix=True)
    except ValueError:
        return segment.split()


def strip_wrappers(argv):
    """Peel env assignments, `--`, and transparent wrappers off the front.

    Returns (argv, via_xargs). `xargs` is reported rather than merely peeled: a
    command reached through xargs took its arguments from a stream.
    """
    via_xargs = False
    i = 0
    while i < len(argv):
        w = argv[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w):
            i += 1
            continue
        if w == "--":
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
                takes_value = argv[i] in ("-n", "-P", "-I", "-d", "-a", "-s", "-L", "-E")
                i += 1
                if takes_value and i < len(argv):
                    i += 1
            continue
        break
    return argv[i:], via_xargs


def nested_payloads(argv):
    """The command strings a shell wrapper is asked to run: `sh -c '<here>'`."""
    return [argv[i + 1] for i, w in enumerate(argv) if DASH_C.match(w) and i + 1 < len(argv)]


def redirect_targets(argv):
    """Paths this command clobbers or appends to.

    `>` and `>>` only. `2>&1` and `>&2` name a descriptor, not a path, and are
    skipped. This is the one place a path can be destroyed without any
    destructive verb appearing at all, which is why `echo x > ~/.config/f` has
    to keep being refused while `git commit -m '… > …'` must not be.
    """
    out = []
    i = 0
    while i < len(argv):
        w = argv[i]
        if w in (">", ">>"):
            if i + 1 < len(argv) and not argv[i + 1].startswith("&"):
                out.append(argv[i + 1])
            i += 2
            continue
        m = re.match(r"^\d*>{1,2}(?!&)(.+)$", w)
        if m:
            out.append(m.group(1))
        i += 1
    return out
