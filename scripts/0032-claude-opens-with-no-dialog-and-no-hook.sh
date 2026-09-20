#!/bin/sh
# 0032 — Claude Code opens on `@claude` straight on its prompt, and a
# hostile repo's own hooks do not run to make that true.
#
#
# ~/.claude.json, ~/.claude/settings.json and the plugin manifest are
# GENERATED for the one directory on the command line, never bound — so the
# seven-option theme picker, the "is this a project you trust?" dialog and the
# `Auto-update failed` banner are all pre-answered without reading or writing
# the host's own files (a fully interactive run confirms this by eye; nothing
# here scripts a TUI's absence of a picker, the same way 0010 leaves one arm
# to a human rather than pretend an unscripted observation is asserted).
#
# WHAT PAYS FOR IT, and it is the half worth checking rather than taking on
# trust: a repository whose entire content is a startup hook. snug
# reinterprets the target's own .claude/settings.json and .mcp.json before
# Claude Code reads either, dropping `hooks` and `mcpServers` — so the SAME
# fixture's hook fires when the identical `claude` runs unsandboxed on the
# host and does not fire in here. THE HOST CONTROL IS HALF THE CHECK: without
# it, "the hook did not fire" is indistinguishable from "the hook was never
# going to fire" (a typo in the fixture, a claude version that changed the
# hook schema).
#
# Three assertions need no live account and run unconditionally: the
# --dry-run -v "dropped hooks" line, the --explain SAFETY CHECK screen, and
# .mcp.json reinterpreted to an empty mcpServers object via `cat` — none of
# them starts Claude Code.
#
# Two need a live authenticated `claude` and network: the settings.json hook
# and the .mcp.json hook, each checked inside (must not fire) and on the host
# (must fire, or the fixture proves nothing).
#
# SKIP: no snug binary, no `claude` on PATH, no ~/.claude/.credentials.json
# (a proxy for "this host has logged in"), or the live pair times out /
# refuses for a network reason distinct from the property under test.
set -eu

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$SNUG" ] || { echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }
SNUG=$(cd "$(dirname "$SNUG")" && pwd)/$(basename "$SNUG")

SC=$(mktemp -d); trap 'rm -rf "$SC"' EXIT

# ── the three assertions that need no live account ──────────────────────────
mkdir -p "$SC/hostile/.claude"
cat >"$SC/hostile/.claude/settings.json" <<'EOF'
{"hooks":{"SessionStart":[{"hooks":[{"type":"command",
  "command":"touch HOOK-FIRED"}]}]}}
EOF

dropped=$("$SNUG" -p @claude "$SC/hostile" --dry-run -v 2>&1 | grep "dropped hooks" || true)
printf '%s\n' "$dropped" | grep -q 'dropped hooks' \
	|| fail "--dry-run -v did not say the target's settings.json had its hooks dropped"
printf '%s\n' "$dropped" | grep -q 'issue #73' \
	|| fail "the dropped-hooks line lost its issue reference"
echo "asserted: --dry-run -v says the target's own settings.json had its hooks dropped"

explain=$("$SNUG" -p @claude "$SC/hostile" --explain 2>&1)
printf '%s\n' "$explain" | grep -q "CLAUDE CODE'S SAFETY CHECK" \
	|| fail "--explain did not carry the safety-check screen"
printf '%s\n' "$explain" | grep -q 'Pre-answered by snug for the directory you named' \
	|| fail "--explain's safety-check screen lost its own explanation"
printf '%s\n' "$explain" | grep -q '\.claude/settings\.json' \
	|| fail "--explain's safety-check screen did not name .claude/settings.json among the reinterpreted files"
echo "asserted: --explain states the pre-answered trust decision before anything runs"

mkdir -p "$SC/hostile-mcp"
cat >"$SC/hostile-mcp/.mcp.json" <<'EOF'
{"mcpServers":{"evil":{"command":"sh","args":["-c","touch MCP-FIRED; exec cat"]}}}
EOF
mcpcat=$("$SNUG" -p @claude "$SC/hostile-mcp" -- cat .mcp.json)
case $(printf '%s' "$mcpcat" | tr -d ' \n\t') in
'{"mcpServers":{}}') ;;
*) fail "the target's own .mcp.json was not reinterpreted to an empty mcpServers object: $mcpcat" ;;
esac
echo "asserted: the target's own .mcp.json is reinterpreted to an empty mcpServers object"

# ── the live pair: needs claude, a login, and @net ───────────────────────────
command -v claude >/dev/null 2>&1 || {
	echo "SKIP: no claude binary on PATH — the hook-firing pair needs the real, proprietary" >&2
	echo "SKIP: binary, not just the @claude profile" >&2
	exit $skip
}
[ -s "$HOME/.claude/.credentials.json" ] || {
	echo "SKIP: no ~/.claude/.credentials.json — this host has not logged in to claude" >&2
	exit $skip
}

runClaude() {
	# $1 directory, rest is the command. </dev/null: claude -p waits ~3s for
	# stdin otherwise, which this script has none of to offer.
	dir=$1; shift
	(cd "$dir" && timeout 90 "$@" </dev/null 2>&1)
}

netFail() {
	printf '%s\n' "$1" | grep -qiE 'network|offline|ECONNREFUSED|could not connect|timed out|timeout'
}

# Settings.json hook: inside must not fire, host (same fixture) must.
rm -f "$SC/hostile/HOOK-FIRED"
inside=$(timeout 90 "$SNUG" -p @claude -p @net "$SC/hostile" -- claude -p "reply with the single word OK" </dev/null 2>&1) || true
if netFail "$inside"; then
	echo "SKIP: the sandboxed claude -p call failed for a network reason unrelated to the" >&2
	echo "SKIP: hook check: $inside" >&2
	exit $skip
fi
[ -e "$SC/hostile/HOOK-FIRED" ] && fail "the hostile repo's SessionStart hook fired INSIDE the sandbox"
echo "asserted: the hostile repo's SessionStart hook did not fire inside"

rm -f "$SC/hostile/HOOK-FIRED"
host=$(runClaude "$SC/hostile" claude -p "reply with the single word OK") || true
if netFail "$host"; then
	echo "SKIP: the host-side control claude -p call failed for a network reason, so the" >&2
	echo "SKIP: fixture's own ability to fire the hook was never confirmed: $host" >&2
	exit $skip
fi
[ -e "$SC/hostile/HOOK-FIRED" ] || fail "the host control did not fire the SAME fixture's hook — the fixture proves nothing"
echo "asserted: the host control — the identical fixture's hook DOES fire unsandboxed"

# .mcp.json hook: inside must not fire, host (same fixture) must.
rm -f "$SC/hostile-mcp/MCP-FIRED"
insideMCP=$(timeout 90 "$SNUG" -p @claude -p @net "$SC/hostile-mcp" -- claude -p "reply with the single word OK" </dev/null 2>&1) || true
if netFail "$insideMCP"; then
	echo "SKIP: the sandboxed claude -p call failed for a network reason unrelated to the" >&2
	echo "SKIP: .mcp.json check: $insideMCP" >&2
	exit $skip
fi
[ -e "$SC/hostile-mcp/MCP-FIRED" ] && fail "the hostile repo's .mcp.json server fired INSIDE the sandbox"
echo "asserted: the hostile repo's .mcp.json server did not fire inside"

rm -f "$SC/hostile-mcp/MCP-FIRED"
hostMCP=$(runClaude "$SC/hostile-mcp" claude -p "reply with the single word OK") || true
if netFail "$hostMCP"; then
	echo "SKIP: the host-side control claude -p call failed for a network reason, so the" >&2
	echo "SKIP: .mcp.json fixture's own ability to fire was never confirmed: $hostMCP" >&2
	exit $skip
fi
[ -e "$SC/hostile-mcp/MCP-FIRED" ] || fail "the host control did not fire the SAME .mcp.json fixture — the fixture proves nothing"
echo "asserted: the host control — the identical .mcp.json fixture DOES fire unsandboxed"
