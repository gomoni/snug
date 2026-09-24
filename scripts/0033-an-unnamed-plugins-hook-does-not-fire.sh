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
# `claude --debug hooks --debug-file <path>` prints a real signal, not model
# behaviour, so this does not depend on an LLM reliably noticing an injected
# instruction. The script asserts on plugin IDENTITY, never on a count:
#
#   Loaded N installed plugins from <path>   — upstream of every hook channel
#   Loading hooks from plugin: <name>        — one per hooks.json read
#   plugin.register: <x> (<tier>, <id>)      — one per registered plugin
#   hooks module <id> loaded (native, …)     — one per native hooks module
#
# `Registered N hooks from M plugins` is printed and NOT asserted: M counts
# Claude Code's own `@builtin` plugins (agents-md, telemetry), which load
# inside regardless of snug (issue #606), and N counts only hooks.json hooks,
# so a second channel — installed plugins' native hooks modules, gated by the
# `tengu_plugin_hooks_modules` rollout flag — would never show in it. What is
# asserted inside is that every registered plugin and every loaded hooks
# module is `@builtin`, and that no hooks.json is read.
#
# Every log line carries a `<timestamp> [DEBUG] ` prefix, so no pattern here is
# anchored at `^`. The same checks are first run against the HOST log and must
# FAIL there: a pattern that drifted with the log format would otherwise pass
# inside by matching nothing.
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

# unnamedPluginsSilent LOG — succeeds when LOG shows no installed plugin
# reaching any hook channel; otherwise prints why and fails.
unnamedPluginsSilent() {
	loaded=$(grep -o 'Loaded [0-9]* installed plugins from' "$1" | tail -1)
	[ -n "$loaded" ] || { echo "no 'Loaded N installed plugins from' line"; return 1; }
	[ "$loaded" = 'Loaded 0 installed plugins from' ] || { echo "$loaded"; return 1; }
	read=$(grep -o 'Loading hooks from plugin: .*' "$1") && { echo "$read"; return 1; }
	reg=$(grep -o 'plugin\.register: .*' "$1" | grep -v '^plugin\.register: [^ ]* (builtin, [^ )]*@builtin)') \
		&& { echo "$reg"; return 1; }
	mod=$(grep -o 'hooks module [^ ]* loaded' "$1" | grep -v '^hooks module [^ ]*@builtin loaded$') \
		&& { echo "$mod"; return 1; }
	return 0
}

# ── host: at least one installed plugin's hooks.json is read ───────────────
hostOut=$(cd "$SC/proj/sub" && timeout 90 claude --debug hooks --debug-file ./host-debug.log \
	-p "reply with the single word OK" </dev/null 2>&1) || true
if netFail "$hostOut"; then
	echo "SKIP: the host-side claude call failed for a network reason: $hostOut" >&2
	exit $skip
fi
hostLog="$SC/proj/sub/host-debug.log"
[ -s "$hostLog" ] || fail "the host run produced no debug log at all: $hostOut"

grep -o 'Registered [0-9]* hooks from [0-9]* plugins' "$hostLog" | tail -1
hostPlugins=$(grep -o 'Loading hooks from plugin: .*' "$hostLog" | sed 's/^Loading hooks from plugin: //' | sort -u)
[ -n "$hostPlugins" ] || {
	echo "SKIP: no installed plugin's hooks.json was read on the host either, so this host" >&2
	echo "SKIP: cannot distinguish 'allowlisted' from 'nothing installed carries a hook'" >&2
	exit $skip
}
echo "asserted: host — hooks.json read for: $(echo $hostPlugins)"

why=$(unnamedPluginsSilent "$hostLog") \
	&& fail "the inside checks PASS on the host log, where plugins do load — a pattern no longer matches the log format"
echo "asserted: the inside checks fail on the host log ($why)"

rm -f "$hostLog"

# ── inside @claude, with the default empty allowlist: nothing loads ────────
insideOut=$(timeout 90 "$SNUG" -p @claude -p @net "$SC/proj/sub" -- claude --debug hooks \
	--debug-file ./inside-debug.log -p "reply with the single word OK" </dev/null 2>&1) || true
if netFail "$insideOut"; then
	echo "SKIP: the sandboxed claude call failed for a network reason: $insideOut" >&2
	exit $skip
fi
insideLog="$SC/proj/sub/inside-debug.log"
[ -s "$insideLog" ] || fail "the sandboxed run produced no debug log at all: $insideOut"

grep -o 'Registered [0-9]* hooks from [0-9]* plugins' "$insideLog" | tail -1
why=$(unnamedPluginsSilent "$insideLog") \
	|| fail "an installed plugin reached a hook channel inside with @claude's default empty allowlist: $why"
echo "asserted: inside — 0 installed plugins loaded, no hooks.json read, every registered plugin and hooks module is @builtin"
