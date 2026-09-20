#!/bin/sh
# 0034 — the credential `@claude` projects into the sandbox carries no
# refresh token, and it still authenticates (issue #58).
#
# Migrated from VERIFY.md §6n.
#
# ~/.claude/.credentials.json is the one file `@claude` stages that is a
# CREDENTIAL rather than a configuration, and it used to be copied verbatim —
# access token and refresh token both. The difference is the blast radius of
# a credential stolen from inside: an access token expires in hours, a
# refresh token mints new ones for as long as it lives (measured on the host
# this section was written on: 5h20m against 26 days). snug now PROJECTS the
# file: a fixed set of fields, never the refresh token.
#
# Assert the SET, not the absence of one name — a field added upstream
# tomorrow is dropped rather than carried, and noticing that is the point of
# a projection rather than a denylist.
#
# Then the half that matters more than the field list: that the projection
# still WORKS. A shape that merely LOOKS like a valid credential and gets
# rejected on first use would fail every real run, silently, on whatever turn
# first touched the network — this is "the measurement the whole change
# rests on" (VERIFY.md's own words for it), which is why it is a live,
# authenticated turn and not a shape check alone.
#
# SKIP: no snug binary, no python3, no claude on PATH, no
# ~/.claude/.credentials.json (this host has not logged in), or the live turn
# fails for a network reason distinct from the property under test.
set -eu

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$SNUG" ] || { echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }
SNUG=$(cd "$(dirname "$SNUG")" && pwd)/$(basename "$SNUG")

command -v python3 >/dev/null 2>&1 || { echo "SKIP: no python3 on this host" >&2; exit $skip; }
[ -s "$HOME/.claude/.credentials.json" ] || {
	echo "SKIP: no ~/.claude/.credentials.json — this host has not logged in to claude" >&2
	exit $skip
}

SC=$(mktemp -d); trap 'rm -rf "$SC"' EXIT
mkdir -p "$SC/proj/sub"

# ── the field list: assert the SET, not one name's absence ─────────────────
fields=$("$SNUG" -p @claude "$SC/proj/sub" -- python3 -c \
	'import json,os;print(sorted(json.load(open(os.path.expanduser("~/.claude/.credentials.json")))["claudeAiOauth"]))')
printf '%s\n' "$fields"

want="['accessToken', 'expiresAt', 'rateLimitTier', 'scopes', 'subscriptionType']"
[ "$fields" = "$want" ] || fail "the projected credential's field set is $fields, want exactly $want"
echo "asserted: the projected credential carries exactly accessToken, expiresAt, rateLimitTier, scopes, subscriptionType"

if printf '%s\n' "$fields" | grep -q 'refreshToken'; then
	fail "the projected credential carries a refreshToken — a token that mints new ones for as long as it lives"
fi
echo "asserted: no refreshToken or refreshTokenExpiresAt crosses into the sandbox"

# ── the half that matters more: it still authenticates ──────────────────────
command -v claude >/dev/null 2>&1 || {
	echo "SKIP: no claude binary on PATH — the field-set assertions above still hold" >&2
	exit $skip
}

out=$(timeout 90 "$SNUG" -p @claude -p @net "$SC/proj/sub" -- claude -p \
	'Reply with exactly: PROJECTED-CREDENTIAL-WORKS' </dev/null 2>&1) || true
if printf '%s\n' "$out" | grep -qiE 'network|offline|ECONNREFUSED|could not connect|timed out|timeout'; then
	echo "SKIP: the live authenticated turn failed for a network reason distinct from the" >&2
	echo "SKIP: credential itself: $out" >&2
	exit $skip
fi
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -q 'PROJECTED-CREDENTIAL-WORKS' \
	|| fail "the live turn on the staged, projected credential did not authenticate: $out"
echo "asserted: a live authenticated turn on the staged, refresh-token-free credential succeeds"
