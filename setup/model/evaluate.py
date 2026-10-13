"""Score a GGUF model on the gold set, through llama-server — the same server,
request shape and JSON-schema constraint snug-setup uses at run time.

    uv run python evaluate.py out/qwen2.5-1.5b/snug-setup-q4_k_m.gguf [--gold gold/gold.jsonl]

Metrics per case:
  exact  the action list equals the gold list, in order
  set    the same actions as a multiset (order differs)
  core   the same multiset once `note` actions are dropped — the notes are
         Go-printed commentary, the core is what changes the profile or the
         conversation
`ask.question` text is never compared, only that an `ask` was emitted.

--margin also asks llama-server for logprobs and records, per case, the
smallest gap between the chosen token and the best other token over the
DECISION tokens: the values of op/name/code/topic/kind/access/verb and the
token after each action's closing brace (another action, or the end). It is a
measurement for a confidence threshold (setup-ux-diagnosis §4), not one: the
summary reports coverage and core accuracy above and below a few cut-offs.
The top_logprobs llama-server reports are the model's own distribution before
the grammar, so a margin is the model's confidence, not the grammar's.

    uv run python evaluate.py out/qwen1.5b-v4/snug-setup-q4_k_m.gguf --gold gold/gold-v4.jsonl --margin
"""

import argparse
import collections
import json
import math
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import prompt

HERE = Path(__file__).parent
SCHEMA = json.loads((HERE.parent / "internal" / "intent" / "schema.json").read_text())


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def find_server():
    tag = os.environ.get("LLAMA_CPP_TAG", "b11541")
    p = Path.home() / ".cache/snug-setup/llama.cpp" / tag / f"llama-{tag}" / "llama-server"
    return str(p)


def start(gguf, threads):
    port = free_port()
    exe = find_server()
    env = dict(os.environ, LD_LIBRARY_PATH=str(Path(exe).parent))
    proc = subprocess.Popen([exe, "-m", gguf, "--host", "127.0.0.1", "--port", str(port), "-c", "4096",
                             "-t", str(threads), "-np", "1", "--no-webui"],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            preexec_fn=lambda: os.nice(19))
    url = f"http://127.0.0.1:{port}"
    for _ in range(240):
        try:
            with urllib.request.urlopen(url + "/health", timeout=1) as r:
                if r.status == 200:
                    return proc, url
        except Exception:
            pass
        if proc.poll() is not None:
            sys.exit(f"llama-server exited {proc.returncode}")
        time.sleep(0.5)
    proc.kill()
    sys.exit("llama-server did not become healthy")


def ask(url, ctx, request, logprobs=False):
    body = {
        "messages": prompt.messages(ctx, request),
        "temperature": 0,
        "max_tokens": 320,
        "response_format": {"type": "json_schema", "json_schema": {"name": "actions", "schema": SCHEMA}},
    }
    if logprobs:
        body.update(logprobs=True, top_logprobs=3)
    req = urllib.request.Request(url + "/v1/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    t = time.time()
    with urllib.request.urlopen(req, timeout=300) as r:
        out = json.load(r)
    ch = out["choices"][0]
    return ch["message"]["content"], time.time() - t, (ch.get("logprobs") or {}).get("content")


DECISION = re.compile(r'"(?:op|name|code|topic|kind|access|verb)"\s*:\s*"([^"]*)"|\}\s*([,\]])')


def margins(content, toks):
    """(min margin over decision tokens, min over all tokens). A token's margin
    is its logprob minus the best OTHER candidate's; negative when the grammar
    forced a token the model did not rank first."""
    if not toks:
        return None, None
    spans = []
    for m in DECISION.finditer(content):
        g = 1 if m.group(1) is not None else 2
        spans.append((m.start(g), max(m.end(g), m.start(g) + 1)))
    pos, dec, every = 0, [], []
    for t in toks:
        text = t.get("token", "")
        lo, hi = pos, pos + max(len(text), 1)
        pos += len(text)
        others = [x["logprob"] for x in t.get("top_logprobs", []) if x.get("token") != text]
        mg = t["logprob"] - max(others) if others else math.inf
        every.append(mg)
        if any(lo < b and a < hi for a, b in spans):
            dec.append(mg)
    r = lambda xs: round(min(xs), 3) if xs and min(xs) != math.inf else None
    return r(dec), r(every)


def canon(a):
    a = dict(a)
    if a.get("op") == "ask":
        a["question"] = ""
    return json.dumps(a, sort_keys=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("gguf")
    ap.add_argument("--gold", default=str(HERE / "gold" / "gold.jsonl"))
    ap.add_argument("--threads", type=int, default=max(1, min(len(os.sched_getaffinity(0)), os.cpu_count() - 2)))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--report", default="")
    ap.add_argument("--margin", action="store_true", help="record the logprob margin of each case")
    a = ap.parse_args()
    os.nice(19)

    cases = [json.loads(l) for l in Path(a.gold).read_text().splitlines() if l.strip()]
    if a.limit:
        cases = cases[: a.limit]
    proc, url = start(a.gguf, a.threads)
    rows = []
    try:
        for c in cases:
            raw, dt, toks = ask(url, c["context"], c["request"], a.margin)
            try:
                got = json.loads(raw)["actions"]
                valid = True
            except Exception:
                got, valid = [], False
            want = c.get("expected", {}).get("actions") or c.get("actions")
            g = [canon(x) for x in got]
            w = [canon(x) for x in want]
            gc = [x for x in g if '"op": "note"' not in x]
            wc = [x for x in w if '"op": "note"' not in x]
            r = {"id": c.get("id", ""), "tags": c.get("tags", [c.get("tag", "")]), "valid": valid,
                 "exact": g == w, "set": collections.Counter(g) == collections.Counter(w),
                 "core": collections.Counter(gc) == collections.Counter(wc),
                 "seconds": round(dt, 2), "request": c["request"], "want": want, "got": got if valid else raw}
            if a.margin:
                r["margin"], r["margin_all"] = margins(raw, toks)
            rows.append(r)
            mark = "ok " if r["core"] else "BAD"
            print(f"{mark} {r['id']:>5} {dt:5.1f}s {c['request'][:70]}", flush=True)
    finally:
        proc.terminate()
        proc.wait()

    n = len(rows)
    summary = {k: round(sum(r[k] for r in rows) / n, 3) for k in ("valid", "exact", "set", "core")}
    summary["n"] = n
    summary["median_seconds"] = sorted(r["seconds"] for r in rows)[n // 2]
    by = collections.defaultdict(list)
    for r in rows:
        for t in r["tags"]:
            by[t].append(r["core"])
    summary["core_by_tag"] = {t: f"{sum(v)}/{len(v)}" for t, v in sorted(by.items())}
    if a.margin:
        m = [r for r in rows if r.get("margin") is not None]
        cut = {}
        for th in (0.5, 1, 2, 3, 4, 6):
            lo = [r["core"] for r in m if r["margin"] < th]
            hi = [r["core"] for r in m if r["margin"] >= th]
            cut[str(th)] = {"below": len(lo), "below_core": f"{sum(lo)}/{len(lo)}", "above_core": f"{sum(hi)}/{len(hi)}"}
        summary["margin_cutoffs"] = cut
        ok = sorted(r["margin"] for r in m if r["core"])
        bad = sorted(r["margin"] for r in m if not r["core"])
        summary["margin_median_ok"] = ok[len(ok) // 2] if ok else None
        summary["margin_median_bad"] = bad[len(bad) // 2] if bad else None
    print(json.dumps(summary, indent=1))
    if a.report:
        Path(a.report).write_text(json.dumps({"summary": summary, "rows": rows}, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
