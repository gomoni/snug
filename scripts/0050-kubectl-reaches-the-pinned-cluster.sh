#!/bin/bash
# 0050 — kubectl inside reaches the one pinned cluster as the pinned
# ServiceAccount, and nothing else from the host kubeconfig (issue #664).
#
# Needs a REAL cluster, so CI cannot run it: test/integration/kube_test.go owns
# everything a stub kubectl can show. This one asserts what only a real API
# server answers:
#
#   1. inside, `kubectl auth whoami` names system:serviceaccount:<ns>:<name>,
#      the pinned account — not the host user;
#   2. `kubectl config get-contexts -o name` inside lists exactly one context;
#   3. the generated ~/.kube/config carries no client-key-data and no token;
#   4. the token the shim hands out expires within the requested hour plus
#      the 10-minute slack snug warns past, and the script prints the real
#      lifetime the cluster granted (the AKS maximum is not measured anywhere
#      else);
#   5. the host's other contexts are not there: `kubectl --context <other>`
#      fails inside.
#
# Set SNUG_KUBE_PROFILE to a profile in your profiles.d carrying
# [identity.kube] and a kubectl bind into /snug/bin (base.toml's KUBE
# template), and SNUG_KUBE_OTHER_CONTEXT to a second context in your host
# kubeconfig for the negative.
#
# SKIP: no snug binary, no SNUG_KUBE_PROFILE, no host kubectl.
set -u

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$SNUG" ] || { echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }
[ -n "${SNUG_KUBE_PROFILE:-}" ] || { echo "SKIP: set SNUG_KUBE_PROFILE to a profile with [identity.kube]" >&2; exit $skip; }
command -v kubectl >/dev/null 2>&1 || { echo "SKIP: no host kubectl on PATH" >&2; exit $skip; }

echo "host kubectl: $(kubectl version --client -o yaml 2>/dev/null | sed -n 's/^ *gitVersion: //p' | head -1)"
proj=$(mktemp -d)
trap 'rm -rf "$proj"' EXIT
other=${SNUG_KUBE_OTHER_CONTEXT:-}

out=$("$SNUG" -p "$SNUG_KUBE_PROFILE" "$proj" -- /bin/sh -c '
	echo "WHOAMI $(kubectl auth whoami -o jsonpath={.status.userInfo.username} 2>&1)"
	echo "CONTEXTS $(kubectl config get-contexts -o name | wc -l)"
	echo "SERVER $(kubectl version -o yaml 2>/dev/null | sed -n "/serverVersion/,\$ s/^ *gitVersion: //p" | head -1)"
	grep -c -e client-key-data -e "\"token\"" ~/.kube/config | sed "s/^/SECRETS /"
	/snug/bin/snug-kube-token | sed -n "s/.*\"expirationTimestamp\":\"\([^\"]*\)\".*/EXPIRY \1/p"
	if [ -n "'"$other"'" ]; then kubectl --context "'"$other"'" get ns >/dev/null 2>&1 && echo OTHER-REACHED || echo OTHER-REFUSED; fi
' 2>&1) || fail "the sandbox run failed:
$out"
echo "$out"

echo "$out" | grep -q '^WHOAMI system:serviceaccount:' || fail "kubectl inside is not the pinned ServiceAccount"
echo "$out" | grep -q '^CONTEXTS 1$' || fail "the generated kubeconfig does not hold exactly one context"
echo "$out" | grep -q '^SECRETS 0$' || fail "the generated kubeconfig carries a credential field"
exp=$(echo "$out" | sed -n 's/^EXPIRY //p')
[ -n "$exp" ] || fail "the shim printed no expiry"
left=$(( $(date -d "$exp" +%s) - $(date +%s) ))
echo "token lifetime left as handed out: ${left}s (requested 1h, snug states the expiry minus 60s)"
[ "$left" -le $((70 * 60)) ] || fail "the cluster granted ${left}s, past the 1h+10m snug warns about"
if [ -n "$other" ]; then
	echo "$out" | grep -q '^OTHER-REFUSED$' || fail "context $other is reachable inside"
fi
echo "asserted: kubectl inside is the pinned ServiceAccount on one context, with no credential in its kubeconfig, a token under ~1h, and no other host context"
