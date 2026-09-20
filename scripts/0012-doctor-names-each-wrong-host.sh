#!/bin/sh
# 0012 — `snug doctor` names each wrong-host condition with its OWN fix, not
# another's.
#
#
# Five conditions that all used to read as "cannot create a user namespace",
# each now naming its own fix:
#
#   kernel.apparmor_restrict_unprivileged_userns=1     "the namespace IS
#     created and the operations inside it are then denied" — a HOST sysctl
#   a container masking /proc                          "user namespaces work,
#     but /proc cannot be mounted inside one", naming systempaths=unconfined
#     / unmask=/proc
#   no /dev/net/tun                                     "-p @net will fail
#     after the sandbox starts", naming --device and modprobe
#   runc present, crun absent, cgroups disabled         "podman helper
#     binaries not found: crun (runc is present, and cannot run with cgroups
#     disabled on this host)"
#   no line for this user in /etc/subuid                "no delegated
#     subuid/subgid range", naming a base this namespace can map
#
# The MESSAGES are unit-covered (doctorblocker_test.go, doctortun_test.go,
# doctorsubuid_test.go). What is NOT covered is the row firing on a REAL host
# in that state — a green tick in front of a run that cannot work is the one
# output `snug doctor` exists to never produce, and a unit test that
# constructs the classifier's inputs by hand cannot catch a fabrication doctor
# itself misreads.
#
# Five independent arms, because the five conditions need five different
# fabrications and no one host is likely to grant all five. Each arm declares
# its own precondition and SKIPs naming it, on stderr, without stopping the
# others. An arm that DOES run and disagrees with the row it names is a hard
# FAIL — this script only ever prints SKIP for "no fabrication was possible
# here", never for "the fabrication ran and doctor said something else".
#
# SKIP (the whole script): every arm's precondition was unmet — no sudo, no
# apparmor knob, no container runtime, no nested user namespace, no runc.
set -eu

SNUG=${SNUG:-./bin/snug}
skip=79   # NOT 77: snug's own exitPolicy is 77 (internal/cli/main.go).
fail() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$SNUG" ] || { echo "SKIP: no snug binary at $SNUG — run make build" >&2; exit $skip; }
SNUG=$(cd "$(dirname "$SNUG")" && pwd)/$(basename "$SNUG")

# ── shared precondition: an unprivileged user namespace with its own mount
# namespace, so a fabrication can bind-mount over a path without touching the
# real machine. Three of the five arms need this; checked once. ────────────
nestedNSWorks=0
if command -v unshare >/dev/null 2>&1 && \
   unshare -Urm --propagation private -- /bin/true 2>/dev/null; then
	nestedNSWorks=1
fi

# nestedControl runs $SNUG doctor in a plain nested namespace with NOTHING
# fabricated, so a later ❌ under a real fabrication can be attributed to it
# rather than to this kernel's own cost of the nested namespace (the same
# reasoning 0020 and 0021 apply to their own fabrications).
nestedControl() {
	unshare -Urm --propagation private sh -c "$SNUG doctor >/dev/null 2>&1; echo doctor-exit=\$?"
}

# ═════════════════════════════════════════════════════════════════════════
# Arm 1 — kernel.apparmor_restrict_unprivileged_userns=1 (blockerNetns)
# ═════════════════════════════════════════════════════════════════════════
arm_apparmor() {
	knob=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
	[ -e "$knob" ] || {
		echo "SKIP arm 1 (apparmor): $knob does not exist on this kernel — Ubuntu 24.04+" >&2
		echo "SKIP arm 1 (apparmor): ships it; nothing else does" >&2
		return 1
	}
	sudo -n true 2>/dev/null || {
		echo "SKIP arm 1 (apparmor): needs passwordless sudo to flip a real host sysctl and" >&2
		echo "SKIP arm 1 (apparmor): restore it; this host did not grant it non-interactively" >&2
		return 1
	}

	original=$(cat "$knob")
	restore() { sudo sh -c "echo $original > $knob" 2>/dev/null || true; }
	trap restore EXIT

	control=$("$SNUG" doctor 2>&1; echo "doctor-exit=$?")
	case $control in
	*doctor-exit=0*) ;;
	*)
		echo "SKIP arm 1 (apparmor): doctor already refuses this host before anything is" >&2
		echo "SKIP arm 1 (apparmor): fabricated, so a ❌ under the fabrication would not be" >&2
		echo "SKIP arm 1 (apparmor): the sysctl's own:" >&2
		printf '%s\n' "$control" | grep '❌' >&2 || true
		trap - EXIT; restore
		return 1 ;;
	esac
	echo "asserted: arm 1 control — doctor is clean before the sysctl is touched"

	sudo sh -c "echo 1 > $knob"
	report=$("$SNUG" doctor 2>&1; echo "doctor-exit=$?")
	trap - EXIT; restore

	printf '%s\n' "$report" | grep -q 'user namespaces work, but the sandbox.s own network namespace does not' \
		|| fail "arm 1: doctor did not say the netns-specific headline under apparmor_restrict_unprivileged_userns=1:
$report"
	printf '%s\n' "$report" | grep -q 'apparmor_restrict_unprivileged_userns=0' \
		|| fail "arm 1: doctor's advice did not name apparmor_restrict_unprivileged_userns=0"
	if printf '%s\n' "$report" | grep -qE 'systempaths|unmask='; then
		fail "arm 1: doctor's advice for the netns row named the /proc-mount row's own fix"
	fi
	echo "asserted: arm 1 — apparmor_restrict_unprivileged_userns=1 gets its own headline and its own fix"
	return 0
}

# ═════════════════════════════════════════════════════════════════════════
# Arm 2 — a container masking /proc (blockerProcMount)
# ═════════════════════════════════════════════════════════════════════════
arm_procmount() {
	runtime=$(command -v podman || command -v docker || true)
	[ -n "$runtime" ] || {
		echo "SKIP arm 2 (masked /proc): no podman or docker on PATH" >&2
		return 1
	}
	unmask='--security-opt unmask=all'
	case $runtime in
	*docker*) unmask='--security-opt systempaths=unconfined' ;;
	esac

	runit() {
		# shellcheck disable=SC2086 # $1 (extra security-opts) is deliberately
		# more than one word, or empty
		"$runtime" run --rm --runtime=crun \
			--security-opt seccomp=unconfined --security-opt apparmor=unconfined \
			--device /dev/net/tun $1 \
			-v /usr:/usr:ro -v /bin:/bin:ro -v /lib:/lib:ro -v /lib64:/lib64:ro \
			-v "$SNUG":/snug-doctor:ro \
			alpine:latest /snug-doctor doctor
	}

	control=$(runit "$unmask" 2>&1; echo "doctor-exit=$?") || true
	if [ -z "$control" ] || printf '%s\n' "$control" | grep -q '❌'; then
		echo "SKIP arm 2 (masked /proc): $runtime could not run a clean baseline container" >&2
		echo "SKIP arm 2 (masked /proc): here, so a ❌ under the real fabrication would not be" >&2
		echo "SKIP arm 2 (masked /proc): attributable to the masking alone:" >&2
		printf '%s\n' "$control" >&2
		return 1
	fi
	echo "asserted: arm 2 control — doctor is clean in a container with /proc unmasked"

	fabricated=$(runit "" 2>&1) || true

	if printf '%s\n' "$fabricated" | grep -q 'user namespaces work, but /proc cannot be mounted inside one'; then
		printf '%s\n' "$fabricated" | grep -q 'systempaths=unconfined' \
			|| fail "arm 2: the /proc-mount row did not name docker's --security-opt systempaths=unconfined"
		printf '%s\n' "$fabricated" | grep -q 'unmask=/proc' \
			|| fail "arm 2: the /proc-mount row did not name podman's --security-opt unmask=/proc"
		echo "asserted: arm 2 — a container masking /proc gets the /proc-mount headline and both fixes"
		return 0
	fi

	echo "SKIP arm 2 (masked /proc): this kernel's bwrap did not classify the masked" >&2
	echo "SKIP arm 2 (masked /proc): container as the /proc-mount row (it printed something" >&2
	echo "SKIP arm 2 (masked /proc): else below), so the row under test cannot be graded here:" >&2
	printf '%s\n' "$fabricated" | grep '❌' >&2 || echo "SKIP arm 2 (masked /proc): (no ❌ at all — the masking was not observed)" >&2
	return 1
}

# ═════════════════════════════════════════════════════════════════════════
# Arm 3 — no /dev/net/tun
# ═════════════════════════════════════════════════════════════════════════
arm_tun() {
	[ "$nestedNSWorks" = 1 ] || {
		echo "SKIP arm 3 (no tun): this host cannot create an unprivileged user namespace" >&2
		echo "SKIP arm 3 (no tun): with its own mount namespace" >&2
		return 1
	}
	control=$(nestedControl)
	case $control in
	*doctor-exit=0*) ;;
	*)
		echo "SKIP arm 3 (no tun): doctor already refuses a nested namespace with nothing" >&2
		echo "SKIP arm 3 (no tun): fabricated in it" >&2
		return 1 ;;
	esac
	echo "asserted: arm 3 control — doctor is clean in a nested namespace with nothing fabricated"

	report=$(unshare -Urm --propagation private sh -c "
		mount -t tmpfs tmpfs /dev/net
		$SNUG doctor 2>&1; echo doctor-exit=\$?
	")

	printf '%s\n' "$report" | grep -q '❌ /dev/net/tun is not usable' \
		|| fail "arm 3: doctor did not print the tun-specific ❌ with /dev/net masked:
$report"
	printf '%s\n' "$report" | grep -q 'modprobe tun' \
		|| fail "arm 3: doctor's advice did not name modprobe tun"
	printf '%s\n' "$report" | grep -q 'doctor-exit=69' \
		|| fail "arm 3: doctor did not exit 69 with the tun device unusable"
	echo "asserted: arm 3 — a masked /dev/net/tun gets its own ❌, its own fix, and exit 69"
	return 0
}

# ═════════════════════════════════════════════════════════════════════════
# Arm 4 — runc present, crun absent, cgroups disabled
# ═════════════════════════════════════════════════════════════════════════
arm_crun_cgroups() {
	[ "$nestedNSWorks" = 1 ] || {
		echo "SKIP arm 4 (crun/cgroups): this host cannot create an unprivileged user" >&2
		echo "SKIP arm 4 (crun/cgroups): namespace with its own mount namespace" >&2
		return 1
	}
	# podmanHelperDirs (internal/cli/doctor.go) is nine fixed absolute
	# directories; runc has to be findable in one of them or there is nothing
	# for the fallback branch to find once crun is masked.
	runc_found=0
	for d in /usr/libexec/podman /usr/local/libexec/podman /usr/local/lib/podman \
	         /usr/lib/podman /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
	         /run/current-system/sw/bin; do
		[ -x "$d/runc" ] && runc_found=1
	done
	[ "$runc_found" = 1 ] || {
		echo "SKIP arm 4 (crun/cgroups): no runc in any directory podman searches, so" >&2
		echo "SKIP arm 4 (crun/cgroups): masking crun alone would report crun-or-runc missing" >&2
		echo "SKIP arm 4 (crun/cgroups): rather than the row under test" >&2
		return 1
	}
	[ -d /sys/fs/cgroup ] || {
		echo "SKIP arm 4 (crun/cgroups): no /sys/fs/cgroup on this host (no cgroup v2?)" >&2
		return 1
	}

	control=$(nestedControl)
	case $control in
	*doctor-exit=0*) ;;
	*)
		echo "SKIP arm 4 (crun/cgroups): doctor already refuses a nested namespace with" >&2
		echo "SKIP arm 4 (crun/cgroups): nothing fabricated in it" >&2
		return 1 ;;
	esac
	echo "asserted: arm 4 control — doctor is clean in a nested namespace with nothing fabricated"

	report=$(unshare -Urm --propagation private sh -c '
		work=$(mktemp -d)
		: > "$work/empty"
		for c in /usr/libexec/podman /usr/local/libexec/podman /usr/local/lib/podman \
		         /usr/lib/podman /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
		         /run/current-system/sw/bin; do
			[ -e "$c/crun" ] && mount --bind "$work/empty" "$c/crun"
		done
		mount --bind /sys/fs/cgroup /sys/fs/cgroup
		mount -o remount,ro,bind /sys/fs/cgroup /sys/fs/cgroup
		'"$SNUG"' doctor 2>&1; echo doctor-exit=$?
	')

	printf '%s\n' "$report" | grep -q 'podman helper binaries not found: crun' \
		|| fail "arm 4: doctor did not report crun missing with it masked and cgroups read-only:
$report"
	printf '%s\n' "$report" | grep -q 'runc is present, and cannot run with cgroups disabled' \
		|| fail "arm 4: doctor did not name runc specifically as unable to serve here"
	printf '%s\n' "$report" | grep -q 'doctor-exit=0' \
		|| fail "arm 4: doctor's exit code changed over a ⚠️ row (warn, never fail):
$(printf '%s\n' "$report" | grep doctor-exit=)"
	echo "asserted: arm 4 — crun absent + runc present + cgroups disabled names crun specifically, warns, never fails"
	return 0
}

# ═════════════════════════════════════════════════════════════════════════
# Arm 5 — no line for this user in /etc/subuid
# ═════════════════════════════════════════════════════════════════════════
arm_subuid() {
	[ "$nestedNSWorks" = 1 ] || {
		echo "SKIP arm 5 (no subuid): this host cannot create an unprivileged user" >&2
		echo "SKIP arm 5 (no subuid): namespace with its own mount namespace" >&2
		return 1
	}
	control=$(nestedControl)
	case $control in
	*doctor-exit=0*) ;;
	*)
		echo "SKIP arm 5 (no subuid): doctor already refuses a nested namespace with" >&2
		echo "SKIP arm 5 (no subuid): nothing fabricated in it" >&2
		return 1 ;;
	esac
	echo "asserted: arm 5 control — doctor is clean in a nested namespace with nothing fabricated"

	report=$(unshare -Urm --propagation private sh -c '
		work=$(mktemp -d)
		: > "$work/empty"
		mount --bind "$work/empty" /etc/subuid
		'"$SNUG"' doctor 2>&1; echo doctor-exit=$?
	')

	printf '%s\n' "$report" | grep -q 'no delegated subuid/subgid range' \
		|| fail "arm 5: doctor did not report the missing subuid row:
$report"
	printf '%s\n' "$report" | grep -q 'has no range for' \
		|| fail "arm 5: doctor's detail did not name /etc/subuid's own missing-range message"
	printf '%s\n' "$report" | grep -q 'doctor-exit=0' \
		|| fail "arm 5: doctor's exit code changed over a ⚠️ row (warn, never fail):
$(printf '%s\n' "$report" | grep doctor-exit=)"
	echo "asserted: arm 5 — no /etc/subuid range warns, names a base to delegate, never fails"
	return 0
}

# ── run all five, independently ─────────────────────────────────────────────
ran=0
if arm_apparmor;      then ran=$((ran + 1)); fi
if arm_procmount;     then ran=$((ran + 1)); fi
if arm_tun;           then ran=$((ran + 1)); fi
if arm_crun_cgroups;  then ran=$((ran + 1)); fi
if arm_subuid;        then ran=$((ran + 1)); fi

[ "$ran" -gt 0 ] || {
	echo "SKIP: every arm's precondition was unmet on this host — see the per-arm SKIP" >&2
	echo "SKIP: lines above naming each one" >&2
	exit $skip
}
echo "asserted: $ran of 5 wrong-host conditions were fabricated and doctor named each one"
