#!/bin/bash
# 0050 — kubectl inside reaches the one pinned cluster as the pinned
# ServiceAccount through snug's proxy, holds no credential, and reaches
# nothing else from the host kubeconfig (issues #664, #659).
#
# Needs a REAL cluster, so CI cannot run it: test/integration/kube_test.go owns
# everything a stub kubectl and an httptest server can show. This one asserts
# what only a real API server answers:
#
#   1. inside, `kubectl auth whoami` names system:serviceaccount:<ns>:<name>,
#      the pinned account — not the host user;
#   2. `kubectl config get-contexts -o name` inside lists exactly one context;
#   3. the generated ~/.kube/config carries no client-key-data, no token and
#      no exec plugin, and names http://127.0.0.1:6443;
#   4. the token minted at start expires within the requested hour plus the
#      10-minute slack snug warns past, and the script prints the lifetime the
#      cluster granted (the AKS maximum is not measured anywhere else) — read
#      from snug's own -v line on the host, because nothing inside holds it;
#   5. `kubectl --as` inside is refused by the proxy, not run as the SA;
#   6. the host's other contexts are not there: `kubectl --context <other>`
#      fails inside;
#   7. with SNUG_KUBE_ECHO_SERVICE=<ns>/<svc>:<port> naming a Service that
#      echoes request headers, a request through services/proxy shows no
#      Bearer: the API server does not forward the proxy's credential to the
#      workload. Not verifiable offline; this is where it is measured.
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
echo_svc=${SNUG_KUBE_ECHO_SERVICE:-}

out=$("$SNUG" -v -p "$SNUG_KUBE_PROFILE" "$proj" -- /bin/sh -c '
	echo "WHOAMI $(kubectl auth whoami -o jsonpath={.status.userInfo.username} 2>&1)"
	echo "CONTEXTS $(kubectl config get-contexts -o name | wc -l)"
	echo "SERVER $(kubectl version -o yaml 2>/dev/null | sed -n "/serverVersion/,\$ s/^ *gitVersion: //p" | head -1)"
	grep -c -e client-key-data -e "\"token\"" -e "\"exec\"" ~/.kube/config | sed "s/^/SECRETS /"
	grep -q "\"server\": \"http://127.0.0.1:6443\"" ~/.kube/config && echo PROXIED
	kubectl --as=system:admin get ns 2>&1 | grep -q "refused" && echo AS-REFUSED || echo AS-NOT-REFUSED
	if [ -n "'"$other"'" ]; then kubectl --context "'"$other"'" get ns >/dev/null 2>&1 && echo OTHER-REACHED || echo OTHER-REFUSED; fi
	if [ -n "'"$echo_svc"'" ]; then
		kubectl get --raw "/api/v1/namespaces/'"${echo_svc%%/*}"'/services/'"${echo_svc#*/}"'/proxy/" 2>&1 | grep -qi bearer && echo ECHO-BEARER || echo ECHO-CLEAN
	fi
' 2>&1) || fail "the sandbox run failed:
$out"
echo "$out" | grep -v '^snug: kube: [A-Z]* /'

echo "$out" | grep -q '^WHOAMI system:serviceaccount:' || fail "kubectl inside is not the pinned ServiceAccount"
echo "$out" | grep -q '^CONTEXTS 1$' || fail "the generated kubeconfig does not hold exactly one context"
echo "$out" | grep -q '^SECRETS 0$' || fail "the generated kubeconfig carries a credential field"
echo "$out" | grep -q '^PROXIED$' || fail "the generated kubeconfig does not name snug's proxy"
echo "$out" | grep -q '^AS-REFUSED$' || fail "kubectl --as was not refused by the proxy"
exp=$(echo "$out" | sed -n 's/^snug: kube: kube token minted at start, valid until //p')
[ -n "$exp" ] || fail "snug -v printed no start-of-run mint"
left=$(( $(date -d "$exp" +%s) - $(date +%s) ))
echo "token lifetime the cluster granted, as of now: ${left}s (requested 1h)"
[ "$left" -le $((70 * 60)) ] || fail "the cluster granted ${left}s, past the 1h+10m snug warns about"
if [ -n "$other" ]; then
	echo "$out" | grep -q '^OTHER-REFUSED$' || fail "context $other is reachable inside"
fi
if [ -n "$echo_svc" ]; then
	echo "$out" | grep -q '^ECHO-CLEAN$' || fail "a Bearer reached the workload behind services/proxy"
fi
echo "asserted: kubectl inside is the pinned ServiceAccount on one context through snug's proxy, with no credential in its kubeconfig, --as refused, a token under ~1h, and no other host context"
