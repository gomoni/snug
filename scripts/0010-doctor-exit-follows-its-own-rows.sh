#!/bin/sh
# 0010 — `snug doctor`'s EXIT CODE agrees with the rows it printed, and
# `snug fix subuid` is safe to call from a distrobox init_hook.
#
# Migrated from VERIFY.md §1, "Can this host run it at all".
#
# WHAT IS ASSERTED, and why it is host-independent. The old section carried a
# transcript of this development host's doctor report, so reading it told you
# about the machine it was written on and nothing about yours. The property
# worth checking is the one that holds on every host:
#
#   a ❌ row is fatal            — at least one ❌  =>  exit 69
#   a ⚠️ row is not             — no ❌, any number of ⚠️  =>  exit 0
#
# Each ⚠️ gates ONE capability (pasta, the podman client, podman's helper
# binaries, the delegated subuid/subgid range) and not snug, so it must leave
# the exit code alone. That is what lets `snug doctor` be run unattended.
#
# `snug fix subuid`'s exit status is a contract, not a detail: the command
# exists to be called from a distrobox `init_hook`, and `distrobox-init` runs
# hooks under `set -o errexit`. A nonzero exit on a host that needs nothing
# would not report a problem — it would stop the box from coming up.
#
# NOT MIGRATED, and deliberately left to a human: §1's `sudo truncate -s 0
# /etc/subuid` arm, which empties a live host's file to watch the ⚠️ say no.
# Emptying /etc/subuid is not a thing to do unattended, and a script that
# SKIPs on every machine is a script that cannot fail.
#
# SKIP: never. Every assertion here holds on any host that built the binary.
set -eu

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go), so a
          # script ending on an uncaptured snug refusal would report SKIP.
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v "$SNUG" >/dev/null 2>&1 || [ -x "$SNUG" ] || {
	echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }

# ── doctor's exit code follows its rows ─────────────────────────────────────
report=$("$SNUG" doctor 2>&1) && code=0 || code=$?
printf '%s\n' "$report"

crosses=$(printf '%s\n' "$report" | grep -c '❌' || true)
warns=$(printf '%s\n' "$report" | grep -c '⚠️' || true)

if [ "$crosses" -gt 0 ]; then
	[ "$code" -eq 69 ] || fail "doctor printed $crosses ❌ row(s) and exited $code, want 69"
	echo "asserted: $crosses ❌ row(s), exit 69"
else
	[ "$code" -eq 0 ] || fail "doctor printed no ❌ row and exited $code, want 0"
	echo "asserted: no ❌ row, $warns ⚠️ row(s), exit 0 — a ⚠️ gates one capability, not snug"
fi

# ── fix subuid says nothing and exits 0 where there is nothing to do ─────────
out=$("$SNUG" fix subuid 2>/dev/null) && code=0 || code=$?
if [ "$code" -eq 0 ]; then
	[ -z "$out" ] || fail "fix subuid exited 0 but wrote to stdout: $out"
	echo "asserted: fix subuid — empty stdout, reason on stderr, exit 0 (an errexit init_hook survives it)"
else
	# This host has no range. The command still must not be fatal to a hook.
	fail "fix subuid exited $code on this host; only 0 is safe for a distrobox init_hook"
fi

# ── and it refuses rather than naming the wrong account ──────────────────────
# Under sudo, os.Getuid() is 0, which is the trap the obvious implementation
# falls into: it would "fix" root instead of saying it cannot find the user.
"$SNUG" fix subuid nosuchuser42 >/dev/null 2>&1 && code=0 || code=$?
[ "$code" -eq 64 ] || fail "fix subuid nosuchuser42 exited $code, want 64 (a usage error, not a guess)"
echo "asserted: fix subuid nosuchuser42 — exit 64, no account guessed"
