#!/bin/bash
# 0035 — Claude Code's /login completes through the login bridge with the
# host's real browser, in ONE sandbox run, and the host's own credential file
# is never touched (issue #455).
#
# Interactive. It needs a human to click in a browser and a claude binary that
# can reach claude.com, which is why CI cannot run it. It also exists to take
# two measurements the bridge's design waits on, and prints them as labelled
# lines so the output of one run can be pasted back as the record:
#
#   MEASURED (b) authorize auto-redirect: yes|no   (the human's answer: did
#       claude.com ask for a click on Authorize, or redirect straight back)
#   MEASURED (e) callback query keys: ...           (from snug's own log)
#
# (e) is what internal/loginbridge/callback.go's callbackKeysPendingMeasurement0e
# waits for. snug's refusal line names only the FIRST parameter outside the
# accepted set, so a refused callback reports a lower bound on the key set, not
# the whole set; a delivered callback proves the set is exactly {code, state},
# because ParseCallback refuses any other key and any missing one.
#
# The login's token dies with the run, so the proof that login worked is made
# INSIDE the same sandbox invocation: run.sh does `claude auth login` and then
# `claude -p` in one go. A second invocation would not see the token.
#
# SKIP: no snug binary, stdin or stderr not a tty, no DISPLAY or
# WAYLAND_DISPLAY, no xdg-open, no claude on PATH.
set -u

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$SNUG" ] || { echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }
SNUG=$(cd "$(dirname "$SNUG")" && pwd)/$(basename "$SNUG")
[ -t 0 ] && [ -t 2 ] || { echo "SKIP: not on a terminal — this check needs a human" >&2; exit $skip; }
[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] || { echo "SKIP: neither DISPLAY nor WAYLAND_DISPLAY is set, so there is no browser to open" >&2; exit $skip; }
command -v xdg-open >/dev/null 2>&1 || { echo "SKIP: no xdg-open on PATH" >&2; exit $skip; }
command -v claude >/dev/null 2>&1 || { echo "SKIP: no claude binary on PATH" >&2; exit $skip; }

SC=$(mktemp -d); trap 'rm -rf "$SC"' EXIT
mkdir -p "$SC/proj" "$SC/cfg/snug/profiles.d"
cat > "$SC/cfg/snug/profiles.d/login.toml" <<'TOML'
[profile.login]
description = "the login bridge, for scripts/0035"
browser = "claude-login"
TOML

# run.sh is what runs inside the sandbox: both halves in one invocation.
cat > "$SC/proj/run.sh" <<'SH'
claude auth login || { echo "RUN-LOGIN-FAILED rc=$?"; exit 1; }
echo "RUN-LOGIN-RETURNED"
out=$(claude -p 'say ok' 2>&1) || { echo "RUN-TURN-FAILED: $out"; exit 1; }
echo "RUN-TURN-OUTPUT: $out"
SH

cred="$HOME/.claude/.credentials.json"
hash_cred() { if [ -e "$cred" ]; then sha256sum "$cred" | cut -d' ' -f1; else echo absent; fi; }
before=$(hash_cred)
echo "host credential sha256 before: $before"

echo
echo "A browser tab will open. Authorize in it if claude.com asks, and note whether"
echo "it asked you to click Authorize or sent you straight back. Press Enter to start."
read -r _ </dev/tty

log="$SC/snug.stderr"
XDG_CONFIG_HOME="$SC/cfg" "$SNUG" -p @claude -p @net -p login "$SC/proj" -- sh ./run.sh \
	2> >(tee "$log" >&2)
rc=$?
sleep 1   # let the process substitution's tee flush the log

echo
printf 'Did claude.com ask you to click Authorize (y), or redirect straight back (n)? [y/n] '
read -r ans </dev/tty
case $ans in
	y|Y) b=no ;;
	n|N) b=yes ;;
	*) b="unanswered" ;;
esac
echo "MEASURED (b) authorize auto-redirect: $b (human answer)"

after=$(hash_cred)
echo "host credential sha256 after:  $after"

refused=$(grep -E 'login bridge: .*(answered [0-9]+|refused)' "$log" || true)
if grep -q 'delivered the login callback' "$log"; then
	echo "MEASURED (e) callback query keys: code,state (delivered: ParseCallback accepts exactly this set, so a delivered callback carried no other key)"
else
	echo "MEASURED (e) callback query keys: not measured — no callback was delivered; snug logged:"
	printf '%s\n' "${refused:-(no refusal lines)}"
	keys=$(printf '%s\n' "$refused" | sed -n 's/.*parameter "\([^"]*\)" is not one snug relays.*/\1/p' | sort -u | tr '\n' ' ')
	[ -z "$keys" ] || echo "MEASURED (e) callback query keys: unknown parameter(s) seen: $keys"
fi

[ "$before" = "$after" ] || fail "the host's ~/.claude/.credentials.json changed across the run ($before -> $after)"
echo "asserted: the host's ~/.claude/.credentials.json is byte-identical before and after"

if [ -n "${keys:-}" ]; then
	fail "the callback was refused for parameter(s) [ $keys]: callbackKeysPendingMeasurement0e in internal/loginbridge/callback.go needs this key set"
fi
grep -q 'delivered the login callback' "$log" \
	|| fail "snug never logged 'delivered the login callback' (snug exited $rc); refusals it logged are printed above"
echo "asserted: the bridge relayed the browser's callback into the sandbox"

[ "$rc" -eq 0 ] || fail "the run exited $rc; claude auth login or the follow-up turn failed (see RUN- lines above)"
echo "asserted: claude auth login and a following claude -p turn both succeeded in the same sandbox run"
