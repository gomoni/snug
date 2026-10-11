#!/bin/bash
# 0036 — another user on the host cannot deliver the login callback, and the
# owner still can afterwards (issue #455).
#
# The bridge listens on host localhost:P, and every uid on the machine can
# connect to it. What stops `nobody` from feeding a callback in is the
# listener's check of the connecting uid against the run's. This check starts a
# real flow with the integration fixtures (loginprobe as the sandbox half, the
# fake xdg-open in "hold" mode so the callback is NOT sent by the opener),
# takes the real state from the argv the opener recorded, and:
#
#   1. `sudo -u nobody curl` of the CORRECT callback gets 403 and snug's
#      "another user" page, and the probe has received nothing;
#   2. the owner's curl of the same URL gets 200 and the probe receives
#      exactly one request. This is the positive control: a flow that never
#      accepted anything would also have refused nobody.
#
# SKIP: no snug binary, no go, no pasta, no curl, no sudo that works (passwordless,
# or interactively on a terminal), no nobody user.
set -u

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$SNUG" ] || { echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }
SNUG=$(cd "$(dirname "$SNUG")" && pwd)/$(basename "$SNUG")
ROOT=$(pwd)
for tool in go curl sudo pasta; do
	command -v "$tool" >/dev/null 2>&1 || { echo "SKIP: no $tool on PATH" >&2; exit $skip; }
done
id nobody >/dev/null 2>&1 || { echo "SKIP: no 'nobody' user on this host" >&2; exit $skip; }
# Probe the exact thing used below. A sudoers rule can grant `(root) NOPASSWD`
# and still ask a password for `-u nobody` — a rootless distrobox does exactly
# that, with no password set — so the second route goes through root, which
# never asks.
if sudo -n -u nobody true 2>/dev/null; then
	as_nobody() { sudo -n -u nobody "$@"; }
elif sudo -n sudo -n -u nobody true 2>/dev/null; then
	as_nobody() { sudo -n sudo -n -u nobody "$@"; }
else
	[ -t 0 ] || { echo "SKIP: sudo -u nobody needs a password and there is no terminal to ask on" >&2; exit $skip; }
	sudo -u nobody true || { echo "SKIP: sudo -u nobody refused" >&2; exit $skip; }
	as_nobody() { sudo -u nobody "$@"; }
fi
[ "$(id -u nobody)" != "$(id -u)" ] || { echo "SKIP: this check is running as nobody" >&2; exit $skip; }

SC=$(mktemp -d)
spid=
cleanup() { [ -z "$spid" ] || kill "$spid" 2>/dev/null; rm -rf "$SC"; }
trap cleanup EXIT
mkdir -p "$SC/bin" "$SC/proj" "$SC/rec" "$SC/cfg/snug/profiles.d"
CGO_ENABLED=0 go build -o "$SC/proj/loginprobe" ./test/integration/testdata/loginprobe || fail "building loginprobe"
CGO_ENABLED=0 go build -o "$SC/bin/xdg-open" ./test/integration/testdata/fakeopener || fail "building fakeopener"
cat > "$SC/cfg/snug/profiles.d/login.toml" <<'TOML'
[profile.login]
description = "the login bridge, for scripts/0036"
login = ["claude"]
TOML

XDG_CONFIG_HOME="$SC/cfg" PATH="$SC/bin:$PATH" DISPLAY=${DISPLAY:-:99} \
	FAKEOPENER_DIR="$SC/rec" FAKEOPENER_MODE=hold \
	"$SNUG" -p @claude -p @net -p login "$SC/proj" -- ./loginprobe wait=60s \
	>"$SC/out" 2>&1 &
spid=$!

for _ in $(seq 1 100); do [ -s "$SC/rec/argv" ] && break; sleep 0.3; done
[ -s "$SC/rec/argv" ] || fail "the fake opener never recorded an argv, so no flow started:
$(cat "$SC/out")"
url=$(sed -n 's/^argv=//p' "$SC/rec/argv")
port=$(printf '%s\n' "$url" | sed -n 's/.*localhost%3A\([0-9]*\)%2Fcallback.*/\1/p')
state=$(printf '%s\n' "$url" | sed -n 's/.*[&?]state=\([A-Za-z0-9_-]*\).*/\1/p')
[ -n "$port" ] && [ -n "$state" ] || fail "no port or state in the opener's argv: $url"
echo "flow: localhost:$port, state taken from the opener's recorded argv"
cb="http://localhost:$port/callback?code=CODE-1_x&state=$state"

nobody_out=$(as_nobody curl -sS -m 10 -o - -w '\nHTTP %{http_code}\n' "$cb" 2>&1)
printf '%s\n' "$nobody_out"
printf '%s\n' "$nobody_out" | grep -q '^HTTP 403$' || fail "nobody's curl was not answered 403"
printf '%s\n' "$nobody_out" | grep -q 'belongs to another user on this machine' \
	|| fail "nobody got a 403 but not snug's own another-user page, so something else refused it"
echo "asserted: nobody's correct callback was refused 403 with snug's another-user page"
grep -q '^RECEIVED ' "$SC/out" && fail "the probe received a request from nobody's callback"
echo "asserted: the probe, inside, had received nothing after nobody's attempt"

owner_out=$(curl -sS -m 10 -o - -w '\nHTTP %{http_code}\n' "$cb" 2>&1)
printf '%s\n' "$owner_out"
printf '%s\n' "$owner_out" | grep -q '^HTTP 200$' || fail "the owner's curl of the same URL was not answered 200 — the control failed, so the 403 above proves nothing"
for _ in $(seq 1 30); do grep -q '^RECEIVED ' "$SC/out" && break; sleep 0.3; done
n=$(grep -c '^RECEIVED ' "$SC/out")
[ "$n" -eq 1 ] || fail "the probe received $n requests after the owner's callback, want exactly 1:
$(cat "$SC/out")"
echo "asserted: the owner's identical callback was relayed (control): the probe received exactly one request"
