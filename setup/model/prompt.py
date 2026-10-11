"""The prompt format, byte-exact with Go's intent.FormatPrompt.

setup/internal/intent/testdata/prompts.jsonl is the shared fixture: both
sides are tested against it (test_prompt.py here, the Go test there), so a
drift between what the model was trained on and what snug-setup sends at run
time fails a test instead of quietly degrading the model.
"""

import json

SYSTEM = "You are snug-setup. Turn the request into snug profile actions. Reply with JSON only."


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
    f = ctx.get("file")
    if f:
        lines.append(f"file {f['name']}:")
        lines.append(f["body"].rstrip("\n"))
    lines.append(f"request: {request}")
    return "\n".join(lines)


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
