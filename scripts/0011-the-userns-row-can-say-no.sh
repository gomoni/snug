#!/bin/sh
# 0011 — `snug doctor`'s user-namespace row is MEASURED, and can say no.
#
# Migrated from VERIFY.md §1 (issue #98).
#
# A green tick never proves a check can fail. This one could not: the probe
# passed `--unshare-all`, whose `-try` spellings skip silently and exit 0, and
# the check read the exit code alone — so `✅ unprivileged user namespaces work`
# printed on a host where they do not.
#
# The fabricated host is a user namespace of our own with
# /proc/sys/user/max_user_namespaces set to 0. That file is per-user-namespace,
# so nothing about the real machine changes and no root is needed.
#
# THE POSITIVE CONTROL IS THE HALF THAT MATTERS: a nested `unshare` must FAIL
# there. Without it, a doctor that printed ❌ for an unrelated reason would pass
# this script, which is the same defect in a new costume.
#
# SKIP: a host that cannot create an unprivileged user namespace at all — there
# is no fabricated weak host to build, and doctor is right to say no.
set -eu

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$SNUG" ] || { echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }
command -v unshare >/dev/null 2>&1 || { echo "SKIP: no unshare(1) on this host" >&2; exit $skip; }
unshare --user --map-root-user -- /bin/true 2>/dev/null || {
	echo "SKIP: this host cannot create an unprivileged user namespace, so there is" >&2
	echo "SKIP: no weak host to fabricate. See kernel.apparmor_restrict_unprivileged_userns" >&2
	echo "SKIP: and /proc/sys/kernel/unprivileged_userns_clone." >&2
	exit $skip; }

SNUG=$(cd "$(dirname "$SNUG")" && pwd)/$(basename "$SNUG")

out=$(unshare --user --map-root-user -- sh -c '
	echo 0 > /proc/sys/user/max_user_namespaces
	if unshare --user --map-root-user -- /bin/true 2>&1; then
		echo "CONTROL-PASSED"
	else
		echo "CONTROL-FAILED"
	fi
	'"$SNUG"' doctor 2>&1; echo "doctor-exit=$?"') || true

printf '%s\n' "$out" | grep -q 'CONTROL-FAILED' \
	|| fail "the positive control still created a namespace, so this host was never made weak"
echo "asserted: positive control — namespace creation really is blocked"

# Spelled as an `if`, not as `grep && fail`: under `set -e` the status of a
# non-final command in an AND-OR list is ignored, so the negative assertion
# would read as passing for a reason that has nothing to do with the output.
if printf '%s\n' "$out" | grep -q '✅ unprivileged user namespaces work'; then
	fail "doctor printed ✅ unprivileged user namespaces work on a host where they do not (issue #98)"
fi
echo "asserted: doctor did NOT print ✅ unprivileged user namespaces work"

printf '%s\n' "$out" | grep -q '❌ cannot create a user namespace here' \
	|| fail "doctor did not print ❌ cannot create a user namespace here; it said:
$out"
echo "asserted: doctor printed ❌ cannot create a user namespace here"

printf '%s\n' "$out" | grep -q 'doctor-exit=69' \
	|| fail "doctor did not exit 69 on a host it cannot serve; it said:
$(printf '%s\n' "$out" | grep doctor-exit=)"
echo "asserted: exit 69"
