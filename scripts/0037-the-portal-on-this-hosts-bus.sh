#!/bin/bash
# 0037 — the login bridge's D-Bus client against THIS host's real session bus
# (issue #661). CI has no session bus, so test/integration only ever talks to
# testdata/fakeportal, which shares package internal/dbus with the client: a
# marshalling bug in that package would pass both sides. Here the decoder is
# sd-bus's, through `busctl --user monitor`, and the portal is the real one.
#
#   1. An OpenURI-shaped call (ssa{sv}) to a name nobody owns decodes in
#      busctl as the two strings and the two-entry dict that were sent, and
#      the bus answers ServiceUnknown. Nothing is opened.
#   2. When this host's portal answers the OpenURI version property,
#      `snug --dry-run` names it as the opener, with DISPLAY and
#      WAYLAND_DISPLAY unset; with the bus address also emptied and no
#      display, the same command says a real run would refuse (control).
#
# Nothing here opens a browser.
#
# SKIP: no DBUS_SESSION_BUS_ADDRESS, no busctl, no go, no snug binary.
set -u

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] || { echo "SKIP: DBUS_SESSION_BUS_ADDRESS is not set — no session bus" >&2; exit $skip; }
command -v busctl >/dev/null 2>&1 || { echo "SKIP: no busctl, so no independent decoder" >&2; exit $skip; }
command -v go >/dev/null 2>&1 || { echo "SKIP: no go toolchain" >&2; exit $skip; }
[ -x "$SNUG" ] || { echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }
SNUG=$(cd "$(dirname "$SNUG")" && pwd)/$(basename "$SNUG")

SC=$(mktemp -d)
mpid=
cleanup() { [ -z "$mpid" ] || kill "$mpid" 2>/dev/null; rm -rf "$SC"; }
trap cleanup EXIT

busctl --user monitor >"$SC/mon" 2>&1 &
mpid=$!
for _ in $(seq 1 30); do grep -q 'Monitoring' "$SC/mon" && break; sleep 0.1; done
grep -q 'Monitoring' "$SC/mon" || fail "busctl --user monitor did not start:
$(cat "$SC/mon")"
SNUG_REAL_BUS=$DBUS_SESSION_BUS_ADDRESS CGO_ENABLED=0 go test -count=1 -v \
	-run '^TestOpenURIShapedCallOnARealBus$' ./internal/dbus >"$SC/test" 2>&1 \
	|| fail "the call did not get ServiceUnknown from the bus:
$(cat "$SC/test")"
sleep 0.5
kill "$mpid"; mpid=
call=$(awk '/Destination=org.snug.NoSuchName0037/{on=1} on{print} on&&/^  };/{exit}' "$SC/mon")
[ -n "$call" ] || fail "busctl never saw the call"
printf '%s\n' "$call"
want='  MESSAGE "ssa{sv}" {
          STRING "";
          STRING "https://claude.com/snug-0037";
          ARRAY "{sv}" {
                  DICT_ENTRY "sv" {
                          STRING "handle_token";
                          VARIANT "s" {
                                  STRING "snug0037";
                          };
                  };
                  DICT_ENTRY "sv" {
                          STRING "activation_token";
                          VARIANT "s" {
                                  STRING "x";
                          };
                  };
          };
  };'
body=$(printf '%s\n' "$call" | sed -n '/^  MESSAGE/,$p')
[ "$body" = "$want" ] || fail "sd-bus decoded a different body than internal/dbus encoded:
$body"
echo "asserted: sd-bus decodes internal/dbus's ssa{sv} body exactly as sent, and the bus answered ServiceUnknown"

if ! busctl --user get-property org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop \
	org.freedesktop.portal.OpenURI version >"$SC/ver" 2>&1; then
	echo "SKIP: this host's portal does not answer the OpenURI version property: $(cat "$SC/ver")" >&2
	exit $skip
fi
echo "busctl: OpenURI version $(cat "$SC/ver")"
mkdir -p "$SC/proj" "$SC/cfg/snug/profiles.d"
cat >"$SC/cfg/snug/profiles.d/login.toml" <<'TOML'
[profile.login]
description = "the login bridge, for scripts/0037"
login = ["claude"]
TOML
out=$(env -u DISPLAY -u WAYLAND_DISPLAY XDG_CONFIG_HOME="$SC/cfg" \
	"$SNUG" --dry-run -p @claude -p @net -p login "$SC/proj" 2>&1)
row=$(printf '%s\n' "$out" | grep -E '^ +opener +')
echo "$row"
printf '%s\n' "$row" | grep -q "desktop portal, org.freedesktop.portal.OpenURI version" \
	|| fail "--dry-run does not name the portal as the opener:
$out"
echo "asserted: with no display, --dry-run names this host's portal as the opener"
out=$(env -u DISPLAY -u WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS= XDG_CONFIG_HOME="$SC/cfg" \
	"$SNUG" --dry-run -p @claude -p @net -p login "$SC/proj" 2>&1)
printf '%s\n' "$out" | grep -qE '^ +opener +NONE — a real run would REFUSE' \
	|| fail "control: with no bus and no display, --dry-run did not say a real run would refuse:
$out"
echo "asserted: control — no bus and no display, and --dry-run says a real run would refuse"
