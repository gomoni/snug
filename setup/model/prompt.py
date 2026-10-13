"""The prompt format, byte-exact with Go's intent.FormatPrompt.

setup/internal/intent/testdata/prompts.jsonl is the shared fixture: both
sides are tested against it (test_prompt.py here, the Go test there), so a
drift between what the model was trained on and what snug-setup sends at run
time fails a test instead of quietly degrading the model.
"""

import json
import unicodedata

SYSTEM = "You are snug-setup. Turn the request into snug profile actions. Reply with JSON only."


_HEADERS = ("target:", "draft:", "host ", "file ", "last:", "request:")


def _file_body(body: str) -> str:
    """Go's intent.fileBody: drop control and formatting runes (not tab or
    newline) and U+2028/2029, indent a line that starts like a prompt header."""
    body = "".join(
        c
        for c in body.rstrip("\n")
        if c in "\n\t" or not (unicodedata.category(c) in ("Cc", "Cf") or c in "\u2028\u2029")
    )
    return "\n".join("  " + l if l.startswith(_HEADERS) else l for l in body.split("\n"))


def _list(xs):
    return ",".join(xs) if xs else "-"


def format_user(ctx: dict, request: str) -> str:
    lines = [f"target: {ctx['target']}"]
    d = ctx.get("draft") or {}
    lines.append(
        "draft: name={} include={} rw={} ro={} tmpfs={} env={} identity={}".format(
            d.get("name") or "-",
            _list(d.get("include", [])),
            _list(d.get("rw", [])),
            _list(d.get("ro", [])),
            _list(d.get("tmpfs", [])),
            _list(d.get("env", [])),
            _list(d.get("identity", [])),
        )
    )
    ssh = ctx.get("ssh") or []
    if ssh:
        parts = []
        for k in ssh:
            attrs = [k["comment"]] if k.get("comment") else []
            if k.get("agent"):
                attrs.append("agent")
            parts.append(f"{k['stem']} ({', '.join(attrs)})" if attrs else k["stem"])
        lines.append("host ssh: " + "; ".join(parts))
    gh = ctx.get("github") or []
    if gh:
        lines.append(
            "host github: "
            + "; ".join(f"{a['host']}/{a['user']}" + (" (active)" if a.get("active") else "") for a in gh)
        )
    git = ctx.get("git") or []
    if git:
        lines.append("host git: " + "; ".join(git))
    profiles = ctx.get("profiles") or []
    if profiles:
        lines.append("host profiles: " + "; ".join(profiles))
    f = ctx.get("file")
    if f:
        lines.append(f"file {f['name']}:")
        lines.append(_file_body(f["body"]))
    last = ctx.get("last") or []
    if last:
        lines.append("last: " + "; ".join(last))
    lines.append(f"request: {request}")
    return "\n".join(lines)


def _one_line(s: str) -> str:
    """Go's intent.oneLine: drop control and formatting runes and U+2028/2029."""
    return "".join(c for c in s if not (unicodedata.category(c) in ("Cc", "Cf") or c in "\u2028\u2029"))


_LAST_FIELDS = {
    "use_profile": ("name",), "drop_profile": ("name",), "include_profile": ("name",), "open_door": ("name",),
    "name_profile": ("name",), "grant_path": ("path", "access"), "drop_path": ("path",), "read_file": ("path",),
    "stage_binary": ("host",), "set_env": ("name", "verb"), "list_identities": ("kind",),
    "select_identity": ("kind", "account"), "refuse": ("code",),
}


def last_items(actions: list) -> list:
    """Go's intent.LastItems: one item per action of the previous turn, notes
    left out, the op followed by what it touched (an empty account omitted)."""
    out = []
    for a in actions:
        if a["op"] == "note":
            continue
        f = [a[k] for k in _LAST_FIELDS.get(a["op"], ()) if not (k == "account" and a[k] == "")]
        out.append(" ".join([a["op"]] + [_one_line(x) for x in f]))
    return out


def messages(ctx: dict, request: str, actions: list | None = None) -> list[dict]:
    m = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": format_user(ctx, request)},
    ]
    if actions is not None:
        m.append({"role": "assistant", "content": dump_actions(actions)})
    return m


def dump_actions(actions: list) -> str:
    return json.dumps({"actions": actions}, separators=(",", ":"), ensure_ascii=False)
