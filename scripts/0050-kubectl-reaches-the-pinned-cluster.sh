#!/bin/bash
# 0050 — kubectl inside reaches the one pinned cluster as the host context's
# own identity through snug's proxy, holds no credential, and reaches nothing
# else from the host kubeconfig (issues #664, #659). Nothing is created on the
# cluster: every call is a GET, except `kubectl auth whoami` and `kubectl auth
# can-i`, which store nothing.
#
# Needs a REAL cluster, so CI cannot run it: test/integration/kube_test.go owns
# everything an httptest server can show (that the proxy sends the certificate
# and no bearer, or the token and no certificate, and writes nothing to disk).
# This one asserts what only a real API server answers, once per profile given:
#
#   1. inside, `kubectl auth whoami` names the identity the profile's
#      credential is — the direct proof of which credential the server
#      accepted. Two profiles over the SAME context, differing only in
#      credential, name DIFFERENT subjects on an AKS local account
#      (masterclient for the certificate, clusterUser for the token): the
#      profile's key chose, not the file;
#   2. `snug -v` on the host names what the proxy presented — the certificate's
#      subject, or the token's length — and never a value;
#   3. `kubectl auth can-i get secrets -A` is PRINTED, not asserted: what the
#      cluster lets this identity do is the cluster's business, and the line a
#      human should read;
#   4. `kubectl version`, `get ns` and `get services -A` succeed through the
#      proxy;
#   5. exactly one context inside; the generated ~/.kube/config carries no
#      client-key-data, no token and no exec plugin, and names
#      http://127.0.0.1:6443;
#   6. the host's other contexts are not there: `kubectl --context <other>`
#      fails inside;
#   7. with SNUG_KUBE_ECHO_SERVICE=<ns>/<svc>:<port> naming a Service that
#      echoes request headers, a GET through services/proxy shows whether the
#      API server forwards the proxy's bearer to the workload. Not verifiable
#      offline; this is where it is measured. Printed, not asserted.
#
# Set SNUG_KUBE_PROFILE_CERT and/or SNUG_KUBE_PROFILE_TOKEN to profiles in your
# profiles.d carrying [identity.kubectl] with credential = "client-certificate"
# / "token" and a kubectl bind into /snug/bin (base.toml's KUBE template);
# SNUG_KUBE_WHOAMI_CERT / SNUG_KUBE_WHOAMI_TOKEN to the usernames you expect
# (unset: printed, not asserted); SNUG_KUBE_OTHER_CONTEXT to a second context
# in your host kubeconfig for the negative. No `--as` is sent: on a real
# cluster that is an impersonated request, and this script makes none.
#
# SKIP: no snug binary, no profile given.
set -u

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$SNUG" ] || { echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }
[ -n "${SNUG_KUBE_PROFILE_CERT:-}${SNUG_KUBE_PROFILE_TOKEN:-}" ] ||
	{ echo "SKIP: set SNUG_KUBE_PROFILE_CERT and/or SNUG_KUBE_PROFILE_TOKEN to a profile with [identity.kubectl]" >&2; exit $skip; }

proj=$(mktemp -d)
trap 'rm -rf "$proj"' EXIT
other=${SNUG_KUBE_OTHER_CONTEXT:-}
echo_svc=${SNUG_KUBE_ECHO_SERVICE:-}
declare -A WHO

# check SHAPE PROFILE WANT_WHOAMI runs one profile and asserts 1-7.
check() {
	local shape=$1 profile=$2 want=$3 out who
	echo "── credential = $shape (profile $profile)"
	out=$("$SNUG" -v -p "$profile" "$proj" -- /bin/sh -c '
		echo "WHOAMI $(kubectl auth whoami -o jsonpath={.status.userInfo.username} 2>&1)"
		echo "CANI-SECRETS $(kubectl auth can-i get secrets -A 2>&1)"
		echo "CONTEXTS $(kubectl config get-contexts -o name | wc -l)"
		echo "SERVER $(kubectl version -o yaml 2>/dev/null | sed -n "/serverVersion/,\$ s/^ *gitVersion: //p" | head -1)"
		kubectl get ns >/dev/null 2>&1 && echo NS-OK || echo NS-FAILED
		kubectl get services -A >/dev/null 2>&1 && echo SVC-OK || echo SVC-FAILED
		grep -c -e client-key-data -e "\"token\"" -e "\"exec\"" ~/.kube/config | sed "s/^/SECRETS /"
		grep -q "\"server\": \"http://127.0.0.1:6443\"" ~/.kube/config && echo PROXIED
		if [ -n "'"$other"'" ]; then kubectl --context "'"$other"'" get ns >/dev/null 2>&1 && echo OTHER-REACHED || echo OTHER-REFUSED; fi
		if [ -n "'"$echo_svc"'" ]; then
			kubectl get --raw "/api/v1/namespaces/'"${echo_svc%%/*}"'/services/'"${echo_svc#*/}"'/proxy/" 2>&1 | grep -qi bearer && echo ECHO-BEARER || echo ECHO-CLEAN
		fi
	' 2>&1) || fail "the sandbox run failed:
$out"
	echo "$out" | grep -v '^snug: kubectl: [A-Z]* /'

	who=$(echo "$out" | sed -n 's/^WHOAMI //p')
	if [ -n "$want" ]; then
		[ "$who" = "$want" ] || fail "kubectl inside is $who, want $want"
	else
		echo "measured: kubectl inside is $who (unasserted: no SNUG_KUBE_WHOAMI_* for $shape)"
	fi
	case $shape in
	client-certificate)
		echo "$out" | grep -q '^snug: kubectl: presenting client certificate ' ||
			fail "snug -v did not name the client certificate it presented"
		echo "$out" | grep -q '^snug: kubectl: server requested a client certificate; sent ' ||
			fail "no handshake asked for the client certificate"
		;;
	token)
		echo "$out" | grep -q '^snug: kubectl: presenting static token ([0-9]* chars)' ||
			fail "snug -v did not name the static token it presented"
		;;
	esac
	echo "$out" | grep -q '^NS-OK$' || fail "kubectl get ns failed through the proxy"
	echo "$out" | grep -q '^SVC-OK$' || fail "kubectl get services -A failed through the proxy"
	echo "$out" | grep -q '^CONTEXTS 1$' || fail "the generated kubeconfig does not hold exactly one context"
	echo "$out" | grep -q '^SECRETS 0$' || fail "the generated kubeconfig carries a credential field"
	echo "$out" | grep -q '^PROXIED$' || fail "the generated kubeconfig does not name snug's proxy"
	if [ -n "$other" ]; then
		echo "$out" | grep -q '^OTHER-REFUSED$' || fail "context $other is reachable inside"
	fi
	echo "measured: can-i get secrets -A: $(echo "$out" | sed -n 's/^CANI-SECRETS //p')"
	if [ -n "$echo_svc" ]; then
		echo "measured: services/proxy echo: $(echo "$out" | grep -o '^ECHO-[A-Z]*')"
	fi
	WHO[$shape]=$who
}

if [ -n "${SNUG_KUBE_PROFILE_CERT:-}" ]; then
	check client-certificate "$SNUG_KUBE_PROFILE_CERT" "${SNUG_KUBE_WHOAMI_CERT:-}"
fi
if [ -n "${SNUG_KUBE_PROFILE_TOKEN:-}" ]; then
	check token "$SNUG_KUBE_PROFILE_TOKEN" "${SNUG_KUBE_WHOAMI_TOKEN:-}"
fi
if [ -n "${WHO[client-certificate]:-}" ] && [ "${WHO[client-certificate]:-}" = "${WHO[token]:-}" ]; then
	echo "note: both credentials are ${WHO[token]} on this cluster; the key still chose which one was sent"
fi
echo "asserted: kubectl inside is the profile's chosen identity on one context through snug's proxy, with no" \
	"credential in its kubeconfig and no other host context; nothing created on the cluster"
