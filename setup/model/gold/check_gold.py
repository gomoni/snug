"""Check gold.jsonl against setup/internal/intent/schema.json with no third-party
packages: every line parses, ids are unique, every expected action list
validates (op names, required fields, enums, patterns, path prefix, lengths,
1..8 actions), and the context has the shape prompt.py reads.

    python3 check_gold.py [gold.jsonl]
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA = json.loads((HERE.parent.parent / "internal" / "intent" / "schema.json").read_text())


def resolve(s):
    if "$ref" in s:
        node = SCHEMA
        for part in s["$ref"].lstrip("#/").split("/"):
            node = node[part]
        return node
    return s


def validate(value, schema, where):
    """Return a list of error strings for the subset of JSON Schema used here."""
    s = resolve(schema)
    errs = []
    if "oneOf" in s:
        matches = [i for i, alt in enumerate(s["oneOf"]) if not validate(value, alt, where)]
        if len(matches) != 1:
            op = value.get("op") if isinstance(value, dict) else None
            errs.append(f"{where}: matches {len(matches)} oneOf branches (op={op!r})")
        return errs
    if "const" in s and value != s["const"]:
        return [f"{where}: {value!r} != const {s['const']!r}"]
    if "enum" in s and value not in s["enum"]:
        return [f"{where}: {value!r} not in {s['enum']}"]
    t = s.get("type")
    if t == "object":
        if not isinstance(value, dict):
            return [f"{where}: not an object"]
        for k in s.get("required", []):
            if k not in value:
                errs.append(f"{where}: missing required {k!r}")
        props = s.get("properties", {})
        for k, v in value.items():
            if k in props:
                errs += validate(v, props[k], f"{where}.{k}")
            elif s.get("additionalProperties") is False:
                errs.append(f"{where}: unexpected key {k!r}")
        return errs
    if t == "array":
        if not isinstance(value, list):
            return [f"{where}: not an array"]
        if "minItems" in s and len(value) < s["minItems"]:
            errs.append(f"{where}: fewer than {s['minItems']} items")
        if "maxItems" in s and len(value) > s["maxItems"]:
            errs.append(f"{where}: more than {s['maxItems']} items")
        for i, item in enumerate(value):
            errs += validate(item, s["items"], f"{where}[{i}]")
        return errs
    if t == "string":
        if not isinstance(value, str):
            return [f"{where}: not a string"]
        if "maxLength" in s and len(value) > s["maxLength"]:
            errs.append(f"{where}: longer than {s['maxLength']}")
        if "pattern" in s and not re.search(s["pattern"], value):
            errs.append(f"{where}: {value!r} does not match {s['pattern']}")
        return errs
    return errs


def check_context(ctx, where):
    errs = []
    if not isinstance(ctx.get("target"), str) or not ctx["target"].startswith("/"):
        errs.append(f"{where}: target must be an absolute path")
    d = ctx.get("draft")
    if not isinstance(d, dict):
        errs.append(f"{where}: draft missing")
    else:
        for k in ("include", "rw", "ro", "tmpfs", "env", "identity"):
            if not isinstance(d.get(k), list):
                errs.append(f"{where}: draft.{k} must be a list")
        for inc in d.get("include", []):
            if not inc.startswith("@"):
                errs.append(f"{where}: draft.include entry {inc!r} lacks @")
        for ident in d.get("identity", []):
            if not re.fullmatch(r"(ssh|github|git|signing):.+", ident):
                errs.append(f"{where}: draft.identity entry {ident!r} is not kind:name")
    for k in ctx.get("ssh", []):
        if set(k) != {"stem", "comment", "agent"}:
            errs.append(f"{where}: ssh entry keys {sorted(k)}")
    for a in ctx.get("github", []):
        if set(a) != {"host", "user", "active"}:
            errs.append(f"{where}: github entry keys {sorted(a)}")
    for k in ("profiles", "last"):
        v = ctx.get(k, [])
        if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
            errs.append(f"{where}: {k} must be a list of non-empty strings")
    f = ctx.get("file")
    if f is not None:
        if set(f) != {"name", "body"}:
            errs.append(f"{where}: file keys {sorted(f)}")
        elif len(f["body"].encode()) > 1200 and not f["name"].startswith(("docker-compose", "compose")):
            errs.append(f"{where}: file body over 1200 bytes")
    return errs


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "gold.jsonl"
    errs, ids, tags = [], [], Counter()
    lines = path.read_text(encoding="utf-8").splitlines()
    for n, line in enumerate(lines, 1):
        if not line.strip():
            errs.append(f"line {n}: blank")
            continue
        try:
            c = json.loads(line)
        except json.JSONDecodeError as e:
            errs.append(f"line {n}: {e}")
            continue
        where = c.get("id", f"line {n}")
        for k in ("id", "tags", "context", "request", "expected"):
            if k not in c:
                errs.append(f"{where}: missing {k!r}")
        ids.append(c.get("id"))
        for t in c.get("tags", []):
            tags[t] += 1
        errs += check_context(c.get("context", {}), where)
        errs += validate(c.get("expected", {}), SCHEMA, where)
        if not isinstance(c.get("request"), str) or not c["request"].strip():
            errs.append(f"{where}: empty request")
    dup = [i for i, k in Counter(ids).items() if k > 1]
    if dup:
        errs.append(f"duplicate ids: {dup}")
    print(f"{len(lines)} cases, {len(set(ids))} unique ids")
    for t, k in sorted(tags.items()):
        print(f"  {t:20s} {k}")
    if errs:
        print("\n".join(errs))
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()
