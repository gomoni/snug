#!/bin/bash
# 0037 — login.claude = "host": a /login started inside is completed by snug
# ON THE HOST, rewrites the host's ~/.claude/.credentials.json for the
# account the host is signed in to, and renews the sandbox's credential
# without a restart (issue #662).
#
# Interactive. It needs a human to click in a real browser, a host already
# signed in to claude, and a claude binary that can reach claude.com, which
# is why CI cannot run it. It takes the measurements the design waits on and
# prints them as `MEASURED (x)` lines to paste back as the record.
#
# THIS REPLACES THE HOST'S REFRESH TOKEN. The old credential file is copied
# into a scratch CLAUDE_CONFIG_DIR first (mode 0600, removed at exit) so (h)
# can ask whether the new login invalidated the old refresh token; no token
# value is printed by this script, only key names, types, lengths and hashes.
#
# SKIP: no snug binary, stdin or stderr not a tty, no DISPLAY or
# WAYLAND_DISPLAY, no xdg-open, no claude on PATH, no python3, or the host is
# not signed in (no ~/.claude/.credentials.json or no oauthAccount).
set -u

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$SNUG" ] || { echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }
SNUG=$(cd "$(dirname "$SNUG")" && pwd)/$(basename "$SNUG")
[ -t 0 ] && [ -t 2 ] || { echo "SKIP: not on a terminal — this check needs a human" >&2; exit $skip; }
[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] || { echo "SKIP: neither DISPLAY nor WAYLAND_DISPLAY is set" >&2; exit $skip; }
command -v xdg-open >/dev/null 2>&1 || { echo "SKIP: no xdg-open on PATH" >&2; exit $skip; }
command -v claude >/dev/null 2>&1 || { echo "SKIP: no claude binary on PATH" >&2; exit $skip; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: no python3 on this host" >&2; exit $skip; }
cred="$HOME/.claude/.credentials.json"
[ -f "$cred" ] || { echo "SKIP: no $cred — sign in once with claude on the host" >&2; exit $skip; }

SC=$(mktemp -d); trap 'rm -rf "$SC"' EXIT
mkdir -p "$SC/proj" "$SC/cfg/snug/profiles.d" "$SC/old"
chmod 700 "$SC/old"
cat > "$SC/cfg/snug/profiles.d/login-host.toml" <<'TOML'
[profile.login-host]
description = "login.claude = host, for scripts/0037"
login.claude = "host"
TOML

# shape prints the credential file's SHAPE, never a value: byte count, mode,
# trailing newline, key order, value types and lengths, and a hash of every
# top-level key other than claudeAiOauth.
shape() {
	python3 -I - "$1" <<'PY'
import hashlib, json, os, stat, sys
p = sys.argv[1]
raw = open(p, "rb").read()
st = os.lstat(p)
d = json.loads(raw, object_pairs_hook=lambda kv: kv)
top = [k for k, _ in d]
o = dict(d).get("claudeAiOauth") or []
print("bytes=%d mode=%o newline=%s compact=%s" % (len(raw), stat.S_IMODE(st.st_mode),
      raw.endswith(b"\n"), b": " not in raw and b"\n" not in raw.rstrip(b"\n")))
print("top=" + ",".join(top))
print("oauth=" + ",".join(k for k, _ in o))
for k, v in o:
    if k in ("accessToken", "refreshToken"):
        print("  %s: str len %d" % (k, len(v)))
    else:
        print("  %s: %s" % (k, json.dumps(v)))
for k, v in d:
    if k != "claudeAiOauth":
        print("foreign %s sha256=%s" % (k, hashlib.sha256(json.dumps(v, sort_keys=True).encode()).hexdigest()[:16]))
PY
}

pin() { python3 -I -c 'import json,os;a=json.load(open(os.path.expanduser("~/.claude.json"))).get("oauthAccount") or {};print(a.get("accountUuid",""),a.get("organizationUuid",""))'; }
read -r acc org < <(pin)
[ -n "$acc" ] && [ -n "$org" ] || { echo "SKIP: ~/.claude.json names no oauthAccount — sign in with claude first" >&2; exit $skip; }

before_hash=$(sha256sum "$cred" | cut -d' ' -f1)
before_shape=$(shape "$cred")
cp -p "$cred" "$SC/old/.credentials.json"
echo "host credential before (shape only):"; printf '%s\n' "$before_shape"

cat > "$SC/proj/run.sh" <<'SH'
echo "RUN-ENV CLAUDE_SECURESTORAGE_CONFIG_DIR=$CLAUDE_SECURESTORAGE_CONFIG_DIR"
ls -la /snug/claude
claude auth login; echo "RUN-LOGIN-RETURNED rc=$? at $(date +%s.%N)"
for i in 1 2 3; do
	if out=$(claude -p 'say ok' 2>&1); then echo "RUN-TURN-$i OK at $(date +%s.%N): $out"; exit 0; fi
	echo "RUN-TURN-$i FAILED at $(date +%s.%N): $out"
done
exit 1
SH

echo
echo "A browser tab will open. Approve the sign-in for the account this host is signed"
echo "in to. When claude inside says its /login failed, do NOT open the URL it prints"
echo "and do NOT paste a code; the run continues by itself. Press Enter to start."
read -r _ </dev/tty

log="$SC/snug.stderr"
XDG_CONFIG_HOME="$SC/cfg" "$SNUG" -p @claude -p @net -p login-host "$SC/proj" -- sh ./run.sh \
	2> >(tee "$log" >&2) | tee "$SC/run.out"
rc=${PIPESTATUS[0]}
sleep 1

printf 'Did claude.com ask you to click Authorize (y), or redirect straight back (n)? [y/n] '
read -r ans </dev/tty
echo "MEASURED (k) consent page asked for a click: $ans (human answer)"
grep -q 'completed the login as' "$log" && echo "MEASURED (a) claude.com accepted snug's URL and called back on snug's listener: yes" \
	|| echo "MEASURED (a) no completed login in snug's log"
grep -o 'ended the sandbox.s /login wait; it answered HTTP [0-9]*' "$log" | sed 's/^/MEASURED (p) /'
grep -o 'RUN-TURN-[0-9] [A-Z]*' "$SC/run.out" | sed 's/^/MEASURED (n,o) /'

after_shape=$(shape "$cred")
echo "host credential after (shape only):"; printf '%s\n' "$after_shape"
[ "$before_hash" != "$(sha256sum "$cred" | cut -d' ' -f1)" ] || fail "the host's credential file did not change (snug's log is above)"
echo "asserted: the host's ~/.claude/.credentials.json was rewritten"
printf '%s\n' "$after_shape" | grep -q '^bytes=[0-9]* mode=600 newline=False compact=True$' \
	|| fail "the rewritten file is not 0600, compact and without a trailing newline"
printf '%s\n' "$after_shape" | grep -q '^oauth=accessToken,refreshToken,expiresAt,refreshTokenExpiresAt,scopes,subscriptionType,' \
	|| fail "the rewritten claudeAiOauth keys are not Claude Code's order"
echo "asserted: 0600, compact, no trailing newline, Claude Code's key order"
[ "$(printf '%s\n' "$before_shape" | grep '^foreign')" = "$(printf '%s\n' "$after_shape" | grep '^foreign')" ] \
	|| fail "a top-level key other than claudeAiOauth changed"
echo "asserted: every other top-level key is unchanged"
ls -a "$HOME/.claude" | grep -q '\.tmp\.\|^\.storage-write\.lock$' && fail "a temp file or the lock was left in ~/.claude"
echo "asserted: no temp file and no lock left in ~/.claude"
grep -q 'RUN-TURN-[0-9] OK' "$SC/run.out" || fail "no claude -p turn succeeded inside after the renewal (rc $rc)"
echo "asserted: a claude -p turn inside succeeded on the renewed credential in the same run"

# (h): does the new login invalidate the old refresh token? Spends it.
printf 'Spend the OLD refresh token now to measure (h)? [y/N] '
read -r ans </dev/tty
if [ "$ans" = y ]; then
	python3 -I -c 'import json,sys;p=sys.argv[1];d=json.load(open(p));d["claudeAiOauth"]["expiresAt"]=0;open(p,"w").write(json.dumps(d))' "$SC/old/.credentials.json"
	if CLAUDE_CONFIG_DIR="$SC/old" claude -p 'say ok' >"$SC/h.out" 2>&1; then
		echo "MEASURED (h) the old refresh token still worked after the new login"
	else
		echo "MEASURED (h) the old refresh token was refused: $(grep -o 'invalid_grant\|401\|refresh[^.]*' "$SC/h.out" | head -n 1)"
	fi
fi
