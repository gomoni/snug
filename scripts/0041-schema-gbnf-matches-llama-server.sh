#!/bin/sh
# 0041 — setup/internal/gbnf/schema.gbnf is exactly the grammar llama-server
# derives from setup/internal/intent/schema.json.
#
# The in-process engine of snug-setup takes GBNF, not JSON schema, and the
# schema-to-GBNF converter lives in llama.cpp's C++ common library, so the
# grammar is a checked-in copy of what llama-server returns in
# generation_settings.grammar. A schema edit without a regeneration would make
# the in-process backend enforce an older contract than the server backend and
# than the Go gate; TestGBNFMentionsEveryOp catches a missing op in CI, this
# catches every other difference. Regenerate with: WRITE=1 sh THIS_SCRIPT.
#
# SKIP: no llama-server (PATH or ~/.cache/snug-setup/llama.cpp), no GGUF to
# load (the grammar does not depend on which one), no curl or python3.
set -eu

skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }
here=$(cd "$(dirname "$0")/.." && pwd)
schema=$here/setup/internal/intent/schema.json
want=$here/setup/internal/gbnf/schema.gbnf

for c in curl python3; do
	command -v "$c" >/dev/null 2>&1 || { echo "SKIP: no $c on this host" >&2; exit $skip; }
done
bin=$(command -v llama-server 2>/dev/null || true)
[ -n "$bin" ] || bin=$(ls "$HOME"/.cache/snug-setup/llama.cpp/*/*/llama-server 2>/dev/null | sort | tail -n 1 || true)
[ -n "$bin" ] && [ -x "$bin" ] || { echo "SKIP: no llama-server on PATH or under ~/.cache/snug-setup/llama.cpp" >&2; exit $skip; }
gguf=${SNUG_SETUP_GGUF:-}
[ -n "$gguf" ] || gguf=$(ls "$here"/setup/model/out/*/*.gguf 2>/dev/null | head -n 1 || true)
[ -n "$gguf" ] && [ -f "$gguf" ] || { echo "SKIP: no GGUF (set SNUG_SETUP_GGUF)" >&2; exit $skip; }

dir=$(mktemp -d)
pid=
trap '[ -z "$pid" ] || kill "$pid" 2>/dev/null || true; rm -rf "$dir"' EXIT INT TERM
"$bin" --model "$gguf" --host "$dir/s.sock" -c 512 -np 1 >"$dir/log" 2>&1 &
pid=$!
i=0
until curl -fsS --unix-socket "$dir/s.sock" http://x/health >/dev/null 2>&1; do
	kill -0 "$pid" 2>/dev/null || { cat "$dir/log" >&2; fail "llama-server exited before it was ready"; }
	i=$((i + 1))
	[ "$i" -lt 600 ] || fail "llama-server not ready after 60s"
	sleep 0.1
done

python3 -I - "$schema" "$dir/req.json" <<'PY'
import json, sys
json.dump({"prompt": "x", "n_predict": 1, "json_schema": json.load(open(sys.argv[1]))}, open(sys.argv[2], "w"))
PY
curl -fsS --unix-socket "$dir/s.sock" -H 'Content-Type: application/json' -d @"$dir/req.json" http://x/completion >"$dir/resp.json"
python3 -I - "$dir/resp.json" "$dir/got.gbnf" <<'PY'
import json, sys
open(sys.argv[2], "w").write(json.load(open(sys.argv[1]))["generation_settings"]["grammar"])
PY

if [ "${WRITE:-}" = 1 ]; then
	cp "$dir/got.gbnf" "$want"
	echo "wrote $want"
	exit 0
fi
cmp -s "$dir/got.gbnf" "$want" || {
	diff "$want" "$dir/got.gbnf" >&2 || true
	fail "setup/internal/gbnf/schema.gbnf differs from llama-server's grammar for schema.json (WRITE=1 regenerates)"
}
echo "asserted: schema.gbnf is byte-identical to the grammar $(basename "$bin") derives from schema.json ($(wc -c <"$want") bytes)"
