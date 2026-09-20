#!/bin/sh
# 0021 — a knob this kernel does not HAVE is never reported as a knob the host
# failed to set, and never gets a line in the drop-in.
#
# Migrated from VERIFY.md §27b (issue #526).
#
# kernel.yama.ptrace_scope does not exist without the Yama LSM. The fabricated
# host is an empty directory bound over /proc/sys/kernel/yama — no root, no
# change to the real machine.
#
# Never `= 0`, and never a line in the file. A sysctl.d file naming a knob the
# kernel does not have FAILS ON EVERY BOOT, and it would be a file snug left
# behind — which is the one thing "no daemon, no state that survives them" does
# not permit.
#
# Three states, three sentences, because they send a reader to three different
# places: `this kernel does not have it` (ENOENT, the case here), `could not be
# read` (it is there and the read failed), and `holds "…", which is not a
# number`. All three used to print as the single phrase "not readable", which
# told a reader nothing about which of the three they had.
#
# SKIP: a host that cannot create an unprivileged user namespace, or cannot
# mount inside one.
set -eu

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$SNUG" ] || { echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }
command -v unshare >/dev/null 2>&1 || { echo "SKIP: no unshare(1) on this host" >&2; exit $skip; }

SNUG=$(cd "$(dirname "$SNUG")" && pwd)/$(basename "$SNUG")
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/empty"

yamaless() {
	unshare -Urm --propagation private sh -c '
		mount --bind '"$work"'/empty /proc/sys/kernel/yama || exit 79
		'"$*"''
}

yamaless true || {
	echo "SKIP: cannot bind over /proc/sys/kernel/yama in an unprivileged user namespace here" >&2
	exit $skip; }

report=$(yamaless "$SNUG doctor 2>&1")
printf '%s\n' "$report" | grep -E 'knobs|ptrace_scope' || true

printf '%s\n' "$report" | grep -q 'have no usable value here' \
	|| fail "doctor did not distinguish an ABSENT knob from an unset one"
echo "asserted: doctor says the knob has no usable value, not that it is 0"

if printf '%s\n' "$report" | grep -q 'kernel.yama.ptrace_scope = 0'; then
	fail "doctor reported an absent knob as = 0, which blames the host for the kernel's build"
fi
echo "asserted: never reported as = 0"

out=$(yamaless "$SNUG fix sysctl 2>&1 >/dev/null; echo fix-exit=\$?")
printf '%s\n' "$out" | grep -E 'ptrace_scope|fix-exit' || true

printf '%s\n' "$out" | grep -q 'this kernel does not have it' \
	|| fail "fix sysctl did not name the absent knob as absent"
printf '%s\n' "$out" | grep -q 'no line for it will be written' \
	|| fail "fix sysctl did not say it would write no line for the absent knob"
printf '%s\n' "$out" | grep -q 'fix-exit=0' \
	|| fail "fix sysctl exited nonzero over a knob the kernel does not have: $(printf '%s\n' "$out" | grep fix-exit=)"
echo "asserted: fix sysctl names it absent, promises no line, exit 0"

drop=$(yamaless "$SNUG fix sysctl 2>/dev/null")
if printf '%s\n' "$drop" | grep -q 'ptrace_scope'; then
	fail "the drop-in names kernel.yama.ptrace_scope; that file would fail on every boot"
fi
echo "asserted: the drop-in carries no line for the absent knob"
