"""prompt.format_user must match the fixture Go's intent.FormatPrompt is
tested against, byte for byte: a drift here means the model is served a
different prompt than it was trained on.

    uv run python test_prompt.py
"""

import json
import sys
from pathlib import Path

import prompt

FIXTURE = Path(__file__).parent.parent / "internal" / "intent" / "testdata" / "prompts.jsonl"


def main():
    rows = [json.loads(l) for l in FIXTURE.read_text().splitlines() if l.strip()]
    bad = 0
    for i, r in enumerate(rows):
        got = prompt.format_user(r["context"], r["request"])
        if got != r["user"]:
            bad += 1
            print(f"case {i}: mismatch\n--- want\n{r['user']}\n--- got\n{got}")
    print(f"{len(rows) - bad}/{len(rows)} prompt fixtures match")
    sys.exit(1 if bad or not rows else 0)


if __name__ == "__main__":
    main()
