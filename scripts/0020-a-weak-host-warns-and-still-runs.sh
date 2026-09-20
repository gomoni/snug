#!/bin/sh
# 0020 — the five kernel knobs snug's threat model INHERITS are reported, never
# refused, and the drop-in `snug fix sysctl` prints is a function of the table
# rather than of this boot.
#
# Migrated from VERIFY.md §27a (issue #526).
#
# The weak host is fabricated, not this machine: a user namespace can bind a
# file over a /proc/sys entry, so four knobs are made 0 with no root and no
# change to the real box. kernel.yama.ptrace_scope is left alone on purpose —
# it is what makes the "4 applied, 5 written" assertion below say anything.
#
# WARN, NEVER FAIL, is the property under test. Key feature 3 says snug must
# work inside a container, and a container is exactly where /proc/sys is
# read-only and these values are the host's anyway. A host missing all four
# must still finish `🎉 This host can run snug.` with exit 0 — refusing would
# make snug unusable on the hosts .claude/design/PSEUDOFS-AUDIT.md was written
# about. This is invariant 5 applied to a guarantee snug inherits: doctor
# discloses, and nothing new refuses.
#
# FOUR settings applied, FIVE lines written, and the gap is the whole design.
# `snug doctor` reads the RUNNING kernel; /etc/sysctl.d/00-snug.conf governs the
# NEXT BOOT. ptrace_scope is already 1 here so there is nothing to apply for it,
# and it is in the file because the file's job is the next boot (§27d).
#
# SKIP: a host that cannot create an unprivileged user namespace, or cannot
# mount inside one — there is no weak host to fabricate.

# CONTROL — THE FABRICATION HAS TO BE THE ONLY THING THAT CHANGED.
#
# `unshare -Urm` is a NESTED user namespace, and whether bwrap can build a
# sandbox inside one is a per-host answer. Where it cannot, doctor prints a ❌
# for a probe this check is not about and exits 69 — MEASURED on GitHub
# Actions' ubuntu runner (bubblewrap 0.9.0, CI run 35505315762):
#
#     ❌ bwrap cannot start a sandbox here, and the reason is not one this probe recognises
#        💬 bwrap said: bwrap: Can't mount proc on /newroot/proc: Operation not permitted
#
# So ask doctor the same question with NOTHING bound. A ❌ there belongs to the
# host and not to the knobs, and the check SKIPs naming it. A clean control is
# what makes the ❌ this check refuses attributable to the fabrication — without
# one, "warn, never fail" would be graded against a host that fails for an
# unrelated reason, which is a check that cannot pass rather than one that
# cannot fail.
set -eu

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$SNUG" ] || { echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }
command -v unshare >/dev/null 2>&1 || { echo "SKIP: no unshare(1) on this host" >&2; exit $skip; }

SNUG=$(cd "$(dirname "$SNUG")" && pwd)/$(basename "$SNUG")
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
echo 0 > "$work/zero"

KNOBS='kptr_restrict dmesg_restrict perf_event_paranoid unprivileged_bpf_disabled'

weak() {   # run "$@" on the fabricated host
	unshare -Urm --propagation private sh -c '
		for k in '"$KNOBS"'; do
			mount --bind '"$work"'/zero /proc/sys/kernel/$k || exit 79
		done
		'"$*"''
}

weak true || {
	echo "SKIP: cannot bind over /proc/sys/kernel in an unprivileged user namespace here" >&2
	exit $skip; }

plain() {  # the same nested namespace, with nothing fabricated in it
	unshare -Urm --propagation private sh -c "$*"
}

control=$(plain "$SNUG doctor 2>&1; echo doctor-exit=\$?")
case $control in
*doctor-exit=0*) ;;
*)
	echo "SKIP: snug doctor already refuses a nested user namespace on this host, with" >&2
	echo "SKIP: nothing fabricated in it — so a ❌ under the fabrication would not be" >&2
	echo "SKIP: the knobs'. The row it refused on:" >&2
	printf '%s\n' "$control" | grep '❌' >&2 || true
	exit $skip ;;
esac
echo "asserted: control — doctor is clean in a nested namespace with nothing fabricated"

# ── doctor discloses all four and still runs ────────────────────────────────
report=$(weak "$SNUG doctor 2>&1; echo doctor-exit=\$?")
printf '%s\n' "$report"

for k in $KNOBS; do
	printf '%s\n' "$report" | grep -q "⚠️  kernel.$k = 0, want " \
		|| fail "doctor did not report kernel.$k as unset on a host where it is 0"
done
echo "asserted: all 4 zeroed knobs reported ⚠️ with the value wanted"

printf '%s\n' "$report" | grep -q '✅ kernel.yama.ptrace_scope' \
	|| fail "doctor did not tick kernel.yama.ptrace_scope, which this fabricated host left alone"
echo "asserted: the knob that IS set is still ticked"

printf '%s\n' "$report" | grep -q '🎉 This host can run snug.' \
	|| fail "doctor refused a host missing four knobs; it must warn, never fail (key feature 3)"
printf '%s\n' "$report" | grep -q 'doctor-exit=0' \
	|| fail "doctor exited nonzero on a weak host: $(printf '%s\n' "$report" | grep doctor-exit=)"
echo "asserted: 🎉 and exit 0 — a weak host is disclosed, not refused"

# ── fix sysctl: stdout is the file and nothing else ─────────────────────────
drop=$(weak "$SNUG fix sysctl 2>/dev/null")
printf '%s\n' "$drop"

lines=$(printf '%s\n' "$drop" | grep -c '^kernel\.' || true)
[ "$lines" -eq 5 ] || fail "the drop-in carries $lines kernel lines, want 5 (the file's job is the next boot, not this one)"
echo "asserted: 5 kernel lines in the drop-in"

printf '%s\n' "$drop" | grep -q '^kernel.yama.ptrace_scope = 1' \
	|| fail "the drop-in omits ptrace_scope, which is already correct HERE but must survive the next boot (§27d)"
echo "asserted: the already-correct knob is in the file anyway"

applied=$(weak "$SNUG fix sysctl 2>&1 >/dev/null" | grep -o 'applies the [0-9]* setting' | grep -o '[0-9]*' || true)
[ "$applied" = "4" ] || fail "fix sysctl says it would apply '$applied' settings, want 4"
echo "asserted: 4 settings to apply, 5 lines to write — doctor reads this boot, the file governs the next"

# stdout must be the file alone, so `snug fix sysctl > 00-snug.conf` does what
# it looks like. Every word of explanation belongs on stderr.
if printf '%s\n' "$drop" | grep -q '^snug:'; then
	fail "an explanation reached stdout; \`snug fix sysctl > 00-snug.conf\` would write a broken file"
fi
echo "asserted: stdout is the file alone, explanation on stderr"
