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
"""

import argparse
import collections
import json
import os
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


def ask(url, ctx, request):
    body = {
        "messages": prompt.messages(ctx, request),
        "temperature": 0,
        "max_tokens": 320,
        "response_format": {"type": "json_schema", "json_schema": {"name": "actions", "schema": SCHEMA}},
    }
    req = urllib.request.Request(url + "/v1/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    t = time.time()
    with urllib.request.urlopen(req, timeout=300) as r:
        out = json.load(r)
    return out["choices"][0]["message"]["content"], time.time() - t


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
    a = ap.parse_args()
    os.nice(19)

    cases = [json.loads(l) for l in Path(a.gold).read_text().splitlines() if l.strip()]
    if a.limit:
        cases = cases[: a.limit]
    proc, url = start(a.gguf, a.threads)
    rows = []
    try:
        for c in cases:
            raw, dt = ask(url, c["context"], c["request"])
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
    print(json.dumps(summary, indent=1))
    if a.report:
        Path(a.report).write_text(json.dumps({"summary": summary, "rows": rows}, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
