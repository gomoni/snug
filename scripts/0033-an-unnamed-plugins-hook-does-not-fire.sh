#!/bin/sh
# 0033 — a hook-carrying plugin that `@claude` does not name does not fire
# inside, even though its tree stays bound read-only (the #68 residual).
#
#
# `@claude` still binds `{home}/.claude/plugins` read-only — the plugin's own
# code, skills and hooks.json are all visible inside — but snug regenerates
# `installed_plugins.json` to name only `profile.claude.plugins`, empty by
# default (base.toml). A plugin's manifest hooks.json is read by Claude Code
# itself, not by snug, so the property under test is that Claude Code never
# gets far enough to read a hooks.json for a plugin snug did not name — the
# allowlist has to close the channel before Claude Code opens it, not merely
# hide the plugin from `/plugin list`.
#
# `claude --debug hooks --debug-file <path>` prints, deterministically,
# `Registered N hooks from M plugins` and one `Loading hooks from plugin:
# <name>` line per plugin whose hooks.json it read — a real signal, not model
# behaviour, so this does not depend on an LLM reliably noticing an injected
# instruction. Nothing asserted this by any means before;
# this is the first.
#
# The debug file is written to a path relative to the target directory, which
# keeps its host path inside the sandbox (`./debug.log`), so a log written by
# the payload is still readable once the sandbox exits — the alternative,
# /tmp, is a private tmpfs that dies with the run.
#
# SKIP: no snug binary, no claude on PATH, no ~/.claude/.credentials.json, or
# no plugin on THIS host ships a hooks.json at all — there is nothing for the
# allowlist to be tested against.
set -eu

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$SNUG" ] || { echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }
SNUG=$(cd "$(dirname "$SNUG")" && pwd)/$(basename "$SNUG")

command -v claude >/dev/null 2>&1 || {
	echo "SKIP: no claude binary on PATH" >&2
	exit $skip
}
[ -s "$HOME/.claude/.credentials.json" ] || {
	echo "SKIP: no ~/.claude/.credentials.json — this host has not logged in to claude" >&2
	exit $skip
}
[ -d "$HOME/.claude/plugins" ] && find "$HOME/.claude/plugins" -name hooks.json 2>/dev/null | grep -q . || {
	echo "SKIP: no installed plugin on this host ships a hooks.json — nothing here for" >&2
	echo "SKIP: the allowlist to be tested against" >&2
	exit $skip
}

SC=$(mktemp -d); trap 'rm -rf "$SC"' EXIT
mkdir -p "$SC/proj/sub"

netFail() {
	printf '%s\n' "$1" | grep -qiE 'network|offline|ECONNREFUSED|could not connect|timed out|timeout'
}

# ── host: at least one plugin's hooks.json is read, and at least one loads ──
hostOut=$(cd "$SC/proj/sub" && timeout 90 claude --debug hooks --debug-file ./host-debug.log \
	-p "reply with the single word OK" </dev/null 2>&1) || true
if netFail "$hostOut"; then
	echo "SKIP: the host-side claude call failed for a network reason: $hostOut" >&2
	exit $skip
fi
hostLog="$SC/proj/sub/host-debug.log"
[ -s "$hostLog" ] || fail "the host run produced no debug log at all: $hostOut"

hostRegistered=$(grep -o 'Registered [0-9]* hooks from [0-9]* plugins' "$hostLog" | tail -1)
printf '%s\n' "$hostRegistered"
case $hostRegistered in
'Registered 0 hooks from 0 plugins'|'')
	echo "SKIP: no plugin hook actually loaded on the host either, so this host cannot" >&2
	echo "SKIP: distinguish 'allowlisted' from 'nothing installed carries a hook'" >&2
	exit $skip ;;
esac
echo "asserted: host — at least one installed plugin's SessionStart hook loads unsandboxed"

rm -f "$SC/proj/sub/host-debug.log"

# ── inside @claude, with the default empty allowlist: nothing loads ────────
insideOut=$(timeout 90 "$SNUG" -p @claude -p @net "$SC/proj/sub" -- claude --debug hooks \
	--debug-file ./inside-debug.log -p "reply with the single word OK" </dev/null 2>&1) || true
if netFail "$insideOut"; then
	echo "SKIP: the sandboxed claude call failed for a network reason: $insideOut" >&2
	exit $skip
fi
insideLog="$SC/proj/sub/inside-debug.log"
[ -s "$insideLog" ] || fail "the sandboxed run produced no debug log at all: $insideOut"

insideRegistered=$(grep -o 'Registered [0-9]* hooks from [0-9]* plugins' "$insideLog" | tail -1)
printf '%s\n' "$insideRegistered"
[ "$insideRegistered" = 'Registered 0 hooks from 0 plugins' ] \
	|| fail "a plugin hook was registered inside the sandbox with @claude's default empty allowlist: $insideRegistered"
echo "asserted: inside — @claude's default empty allowlist registers no plugin hook at all"

if grep -q '^Loading hooks from plugin:' "$insideLog"; then
	fail "a plugin's hooks.json was read inside even though nothing was registered from it: $(grep '^Loading hooks from plugin:' "$insideLog")"
fi
echo "asserted: no unnamed plugin's hooks.json is even read inside, not merely unregistered"
