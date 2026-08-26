#!/usr/bin/env bash
# The engine tier, run in a throwaway openSUSE Tumbleweed container (issue #395).
#
# ONE copy of the container's flags and its provisioning, called from two places:
#
#   make integration-engine                 a developer, locally
#   .github/workflows/ci.yml, job `engine`  CI
#
# That is the whole point of the file. A CI job carrying an inline script and a
# Makefile carrying a second copy would drift, and the flags here are not
# decoration — six of them are the difference between the engine tier running
# and the suite reporting green having measured nothing.
#
# Two subcommands, and the second one is NOT for a real machine:
#
#   launch      (default) start the container and run `provision` inside it
#   provision   zypper, a non-root user, a subuid range, then the suite
#
# `provision` installs packages and creates a user, so it refuses to run unless
# $SNUG_ENGINE_CONTAINER says a throwaway container is what it is in.
set -euo pipefail

IMAGE=${SNUG_ENGINE_IMAGE:-registry.opensuse.org/opensuse/tumbleweed:latest}
RUNTIME=${SNUG_ENGINE_RUNTIME:-$(command -v docker || command -v podman || true)}

# Where the engine STORE lives, and it must be a real filesystem rather than
# the container's own. podman mounts an overlay over the store, docker's
# container root IS overlayfs, and the kernel refuses an overlay whose lower
# layer is overlayfs — measured as
# `creating overlay mount to /snug/engine/store/overlay/…/merged … invalid
# argument` (run 32943065911). A bind mount rather than a tmpfs because images
# live here and a tmpfs would put them in RAM.
STORE=${SNUG_ENGINE_STORE:-${RUNNER_TEMP:-$PWD/.engine-store}/store}

# The uid the suite runs as INSIDE the container is the CALLER's, not a constant.
# The workspace is bind-mounted, so a container user with a different uid writes
# bin/snug as that uid and the caller's next `make build` fails on its own tree.
# It was 1001 — the GitHub runner's uid — which is right there and wrong
# everywhere else. Falls back to 1001 when invoked as root, since useradd cannot
# create uid 0.
SNUG_ENGINE_UID=${SNUG_ENGINE_UID:-$(id -u)}
if [ "$SNUG_ENGINE_UID" = 0 ]; then SNUG_ENGINE_UID=1001; fi

launch() {
	if [ -z "$RUNTIME" ]; then
		echo "engine-container: no docker or podman on PATH." >&2
		echo "                  set SNUG_ENGINE_RUNTIME=/path/to/docker to name one." >&2
		exit 1
	fi

	# The Go toolchain is MOUNTED rather than installed by zypper: snug is
	# cgo-free by constraint (.claude/design/NOCGO.md) and the toolchain's own
	# binaries are static Go, so the caller's toolchain runs unchanged on
	# Tumbleweed's glibc and the version stays the one the caller tested with.
	# The one precondition that is NOT inside the container, checked here so it
	# fails in one second with the fix rather than twenty tests later.
	#
	# kernel.apparmor_restrict_unprivileged_userns lets an unprivileged user
	# namespace be CREATED and then denies the capability-requiring operations
	# inside it, so bwrap fails in two different-looking ways — `unshare: write
	# failed /proc/self/uid_map: Operation not permitted` and `bwrap: loopback:
	# Failed RTM_NEWADDR: Operation not permitted` (runs 32941285136 and
	# 32940873115). It is not namespaced, so it cannot be set from inside a
	# container: only read here, never written, because a Makefile target is no
	# place to change a host's kernel settings.
	local knob=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
	if [ -e "$knob" ] && [ "$(cat "$knob")" != 0 ]; then
		echo "engine-container: $knob is $(cat "$knob")." >&2
		echo "                  bwrap cannot hold capabilities in its own user namespace with" >&2
		echo "                  that set, and it cannot be changed from inside the container." >&2
		echo "                  Fix: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0" >&2
		exit 1
	fi

	local goroot
	goroot=$(go env GOROOT)

	mkdir -p "$STORE"

	# NOT --privileged (#395's unknown 3). Every flag below is the narrowest
	# answer to one measured refusal, and none of them is a capability:
	#
	#   apparmor=unconfined     docker-default denies mount(2); bwrap mounts
	#                           inside its own user namespace.
	#   seccomp=unconfined      REQUIRED, and the syscall is named. Removed once
	#                           the job was green (run 32945827262) to measure
	#                           whether docker's default profile was in the way;
	#                           run 32946939204 says it is. With the default
	#                           profile and every userns sysctl already correct,
	#                           bwrap said "No permissions to create a new
	#                           namespace" and the stage said "fork/exec
	#                           /proc/self/exe: operation not permitted" — the
	#                           profile denies clone(2) with CLONE_NEWUSER for a
	#                           process without CAP_SYS_ADMIN, and the whole
	#                           engine floor went to 0. Preferred over
	#                           --cap-add SYS_ADMIN, which would buy far more
	#                           than this needs.
	#   the unmask flag         docker masks entries under /proc with its own
	#                           submounts, and the kernel refuses a fresh
	#                           procfs mount in a userns while the mounter's
	#                           view of /proc is obstructed. Measured as
	#                           `bwrap: Can't mount proc on /newroot/proc:
	#                           Operation not permitted` (run 32941695379).
	#   --device /dev/fuse      rootless podman's fuse-overlayfs driver.
	#   --device /dev/net/tun   pasta puts a tap device in the sandbox's netns.
	#                           Without it every `-p @net` run died with
	#                           `Failed to open() /dev/net/tun` (run 32942207790).
	#   --tmpfs /tmp            the engine runroot is os.TempDir()-rooted
	#                           (internal/engine/paths.go), and the same
	#                           overlay-on-overlay rule as $STORE applies to it.
	#                           This is issue #399 seen from outside: a runroot
	#                           under /run/user/<uid> would need no flag here.
	local unmask='--security-opt systempaths=unconfined'
	case $RUNTIME in
	*podman*) unmask='--security-opt unmask=all' ;;
	esac

	# shellcheck disable=SC2086 # $unmask is two words on purpose
	exec "$RUNTIME" run --rm \
		--security-opt apparmor=unconfined \
		--security-opt seccomp=unconfined \
		$unmask \
		--device /dev/fuse \
		--device /dev/net/tun \
		--tmpfs /tmp:exec,mode=1777 \
		-v "$PWD":/src \
		-v "$STORE":/enginestore \
		-v "$goroot":/usr/local/go:ro \
		-e SNUG_ENGINE_CONTAINER=1 \
		-e SNUG_ENGINE_UID="$SNUG_ENGINE_UID" \
		"$IMAGE" \
		/src/test/engine-container.sh provision
}

provision() {
	if [ "${SNUG_ENGINE_CONTAINER:-}" != 1 ]; then
		echo "engine-container: 'provision' installs packages and creates a user." >&2
		echo "                  It is meant for a throwaway container, not a real machine." >&2
		echo "                  Run 'make integration-engine' instead." >&2
		exit 1
	fi
	set -x

	# bash, bash-sh, coreutils, gawk, grep, sed, findutils, diffutils and make
	# are named EXPLICITLY, and that is measured rather than defensive: without
	# them `--no-recommends` satisfied the new dependencies with busybox
	# variants and REMOVED what the image had — "214.9 MiB … released by
	# packages that will be removed" (run 32940231386) — taking /bin/sh with it,
	# and the next step died `exec: "sh": executable file not found in $PATH`.
	zypper -n --gpg-auto-import-keys refresh
	zypper -n install --no-recommends \
		bash bash-sh coreutils gawk grep sed findutils diffutils \
		make tar gzip git which curl \
		podman crun fuse-overlayfs \
		bubblewrap passt iproute2 \
		python3 shadow util-linux util-linux-systemd \
		openssh-clients

	# util-linux-systemd, not util-linux: openSUSE puts findmnt there (measured,
	# `rpm -qf $(command -v findmnt)` = util-linux-systemd-2.42.2). Without it
	# the tmpfs-bound tests read `findmnt: command not found` — while the bound
	# itself was working, `dd: error writing '/tmp/probe': No space left on
	# device` at 16 MiB. A missing tool that reads as a failed assertion.
	#
	# openssh-clients because five identity tests refuse to skip under
	# SNUG_REQUIRE_SANDBOX: "ssh is not installed; there is no system ssh_config
	# to protect" — right, since the suite is asked to mean something here.
	export PATH=/usr/local/go/bin:$PATH
	command -v bash make go podman bwrap pasta python3 findmnt ssh
	podman --version
	bwrap --version
	pasta --version | head -1

	# The harness makes the same check (requirePasta); this is here so a passt
	# too old for --map-host-loopback is reported by the step that installed it
	# rather than twenty tests later.
	pasta --help 2>&1 | grep -q -- --map-host-loopback

	# The caller's uid (see the top of this file): the workspace is bind-mounted,
	# so anything this user writes must land owned by whoever ran the target.
	useradd --create-home --uid "$SNUG_ENGINE_UID" --shell /bin/bash snug
	# A range inside the container's own uid space. newuidmap is setuid and
	# needs one to map anything at all; without it rootless podman fails
	# "write to uid_map failed: Operation not permitted".
	#
	# ONLY IF USERADD DID NOT ALREADY ALLOCATE ONE. openSUSE's shadow gives
	# useradd a SUB_UID_COUNT in /etc/login.defs, so it allocates a subuid range
	# by itself; appending a second one unconditionally left podman building a
	# map with the same outer range twice and newuidmap refusing it — MEASURED
	# in run 32944442005:
	#
	#	running `/usr/bin/newuidmap 15015 0 1001 1 1 100000 65536 65537 100000 65536`
	#	Error: cannot set up namespace using "/usr/bin/newuidmap": exit status 1
	#
	# (1 -> 100000 count 65536, then 65537 -> 100000 count 65536: the same outer
	# range mapped twice.)
	grep -q '^snug:' /etc/subuid || echo snug:100000:65536 >>/etc/subuid
	grep -q '^snug:' /etc/subgid || echo snug:100000:65536 >>/etc/subgid
	echo "subuid: $(grep '^snug:' /etc/subuid)  subgid: $(grep '^snug:' /etc/subgid)"
	# XDG_RUNTIME_DIR is pinned SHORT on purpose: the proxy socket is
	# <runtime>/snug/run-<pid>/podman.sock and AF_UNIX's sun_path has 107 usable
	# bytes. A runtime dir inherited from a long workspace path overshot it at
	# 110 and the suite rendered that as "no usable real container engine" — a
	# skip predicate absorbing the test's own defect (issue #33).
	# /run/user/<uid> is 14 bytes for a four-digit uid.
	install -d -m 0700 -o snug -g users "/run/user/$SNUG_ENGINE_UID"
	chown snug: /enginestore

	# SNUG_ENGINE_FLOOR is 42 HERE and 33 on a development host: this container
	# can actually start containers, so more tests reach the marker. MEASURED at
	# 42 on two independent green runs (32945338390, 32945827262). The point of
	# raising it is that CI silently losing nine engine tests would otherwise
	# still clear a floor of 33.
	#
	# SNUG_SANDBOX_TIMEOUT raises the per-suite `go test -timeout` from the 8m
	# that fits a runner where the engine tier skips. With the tier really
	# running it fired at `panic: test timed out after 8m0s` with 19 of 33 engine
	# tests done and still progressing (run 32943468831). The job bound above it
	# is 30 minutes, so the three bounds still nest.
	#
	# SNUG_REQUIRE_ENGINE is what makes this mean anything: "no usable real
	# container engine" becomes t.Fatal instead of t.Skip, and the floor in
	# `make integration-sandbox` fails the run when fewer than
	# SNUG_ENGINE_FLOOR distinct tests reached the "snug-engine-ran:" marker.
	runuser -u snug -- env \
		HOME=/home/snug \
		PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin \
		XDG_RUNTIME_DIR=/run/user/"$SNUG_ENGINE_UID" \
		XDG_DATA_HOME=/enginestore \
		SNUG_ENGINE_FLOOR=42 \
		SNUG_SANDBOX_TIMEOUT=18m \
		SNUG_REQUIRE_SANDBOX=1 \
		SNUG_REQUIRE_ENGINE=1 \
		SNUG_TEST_NET=1 \
		bash -c 'cd /src && make build && ./bin/snug doctor; make integration-sandbox'
}

case ${1:-launch} in
launch) launch ;;
provision) provision ;;
*)
	echo "engine-container: unknown subcommand $(printf %q "$1") (want launch or provision)" >&2
	exit 1
	;;
esac
