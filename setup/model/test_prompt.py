"""prompt.format_user must match the fixture Go's intent.FormatPrompt is
tested against, byte for byte, and prompt.last_items must match LastItems on
testdata/last.jsonl: a drift here means the model is served a different prompt
than it was trained on.

    uv run python test_prompt.py
"""

import json
import sys
from pathlib import Path

import prompt

FIXTURE = Path(__file__).parent.parent / "internal" / "intent" / "testdata" / "prompts.jsonl"
LAST = FIXTURE.with_name("last.jsonl")


def main():
    rows = [json.loads(l) for l in FIXTURE.read_text().splitlines() if l.strip()]
    bad = 0
    for i, r in enumerate(rows):
        got = prompt.format_user(r["context"], r["request"])
        if got != r["user"]:
            bad += 1
            print(f"case {i}: mismatch\n--- want\n{r['user']}\n--- got\n{got}")
    print(f"{len(rows) - bad}/{len(rows)} prompt fixtures match")
    last = [json.loads(l) for l in LAST.read_text().split("\n") if l.strip()]
    lbad = 0
    for i, r in enumerate(last):
        got = prompt.last_items(r["actions"])
        if got != r["last"]:
            lbad += 1
            print(f"last case {i}: want {r['last']!r} got {got!r}")
    print(f"{len(last) - lbad}/{len(last)} last fixtures match")
    sys.exit(1 if bad or lbad or not rows or not last else 0)


if __name__ == "__main__":
    main()
