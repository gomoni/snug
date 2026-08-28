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
# Three subcommands, and only the first is for a real machine:
#
#   launch           (default) start the container and run `provision` inside it
#   provision        packages if they are missing, a user, a subuid range, the suite
#   install-packages the zypper half of provision, ALONE — this is what
#                    test/engine-container.dockerfile calls, so that CI can bake
#                    and cache a provisioned image and reach the network zero
#                    times on a cache hit (issue #478)
#
# `provision` and `install-packages` change the machine they run on, so both
# refuse unless $SNUG_ENGINE_CONTAINER says a throwaway container is what they
# are in.
#
# THE PACKAGE LIST LIVES IN EXACTLY ONE PLACE, install_packages below, and the
# dockerfile calls this script rather than repeating it. A second copy in a
# dockerfile is this project's recurring defect and would drift on the first
# package added.
set -euo pipefail

# ── `:latest`, and the repositories stay UNPINNED (issue #478, ruled) ────────
#
# The tag is rolling on purpose, and the purpose is the job: snug drives podman,
# crun, passt and bubblewrap, and it must FIND OUT when a recent version of one
# of them breaks it. podman 5.x -> 6.x is the measured example of how large that
# change can be — the supported set refuses 5.8.4, which is what the
# ubuntu-latest runner ships, so `ci.yml`'s engine job runs Tumbleweed for the
# 6.x it carries. A pinned tree tests snug against a distribution that has
# stopped existing, and it fails by going GREEN.
#
# So pinning `repo-oss` to `http://download.opensuse.org/history/<snapshot>/`
# was proposed with a measurement and REFUSED. What it would have bought is
# real and is not enough: that tree serves payloads from openSUSE's own
# `downloadcontentcdn.opensuse.org` rather than a volunteer mirror, a frozen
# index cannot rotate under the client, and it drops `codecs.opensuse.org`
# entirely. What it costs is the point of the job, plus a monthly bump against
# ~4-week snapshot retention — a chore nobody does is how the pin ends up three
# months stale.
#
# The cost of rolling is accepted and it is LABELLED rather than removed: every
# network step below classifies its own failure and exits EX_TEMPFAIL, so an
# openSUSE incident says it is one. Measured rate over 57 concluded jobs in 40
# hours: 1 infra incident against 5 real test failures.
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

# ── an infrastructure failure says so, in one line, without the log ──────────
#
# Everything this job needs from the network arrives BEFORE a single test runs:
# the base image from registry.opensuse.org, then repository metadata and
# packages from download.opensuse.org's mirror pool. When one of those fails
# the job dies in setup, prints no test name, no `--- FAIL` and no
# `engine tests: N ran` line, and surfaces as the exit code of whichever tool
# gave up — `make: *** [Makefile:394: integration-engine] Error 4`, which is
# zypper's 4 and reads to a skimming human like a count of failed tests.
#
# MEASURED over 57 concluded engine jobs (2026-08-26T15:22Z..2026-08-28T07:29Z):
# 8 failures, 5 of them real test failures and 3 of them one openSUSE mirror
# event caught three times inside 54 minutes — runs 33112408141, 33116498388,
# 33116787758, byte-identical text down to the repodata hash. The two classes
# are perfectly separated by duration in that window (infra 24-32s, test
# failures 199-215s, successes 189-280s), which is exactly the tell that is
# invisible unless somebody opens the log and looks at the clock.
#
# So the classification is made HERE, by the step that knows, instead of being
# inferred later. The job still FAILS — invariant 5: a refresh that leaves the
# container unusable must not read as green, and "retry until green" is the
# reflex issue #478 is about — but it fails saying which of the two it is.
#
# Exit 75 is EX_TEMPFAIL from sysexits(3), "temporary failure; the user is
# invited to retry", and it is chosen so the code itself carries the
# classification: 75 out of this script means no test ran.
readonly EX_TEMPFAIL=75

infra_fail() {
	local what=$1 rc=$2 blame=$3
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		echo "::error title=openSUSE infrastructure, not snug::$what exited $rc. NO TEST RAN — this is $blame, not a change in this diff. Re-running is legitimate here and only here."
	fi
	echo "engine-container: $what exited $rc." >&2
	echo "                  NO TEST RAN. This is $blame, not a snug regression." >&2
	echo "                  Exiting $EX_TEMPFAIL (EX_TEMPFAIL) so the code says so too." >&2
	exit "$EX_TEMPFAIL"
}

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

	# The pull is done HERE rather than implicitly by `run`, for one reason: it
	# is a separate network dependency on a separate host (registry.opensuse.org,
	# whose certificate expiry took this job out on 2026-08-27) and `run` would
	# blend its failure into the container's own exit code. Split, each can name
	# itself.
	#
	# SKIPPED when the image is already local, which is how the CI cache pays
	# off: the workflow bakes a provisioned image with buildx, loads it, and
	# names it in SNUG_ENGINE_IMAGE. There is nothing to fetch, and a `pull` of
	# a local-only tag would fail against a registry that never had it. This is
	# a presence check, not a freshness one — the workflow owns how old a baked
	# image may get, and does it by rotating the build's cache key weekly.
	local rc=0
	if "$RUNTIME" image inspect "$IMAGE" >/dev/null 2>&1; then
		echo "engine-container: $IMAGE is already present locally; not pulling." >&2
	else
		"$RUNTIME" pull "$IMAGE" || rc=$?
		[ "$rc" -eq 0 ] || infra_fail "$RUNTIME pull $IMAGE" "$rc" "the container registry"
	fi

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

# throwaway_only refuses a subcommand that changes the machine it runs on unless
# $SNUG_ENGINE_CONTAINER says a throwaway container is what it is in.
throwaway_only() {
	if [ "${SNUG_ENGINE_CONTAINER:-}" != 1 ]; then
		echo "engine-container: '$1' installs packages and changes the machine." >&2
		echo "                  It is meant for a throwaway container, not a real machine." >&2
		echo "                  Run 'make integration-engine' instead." >&2
		exit 1
	fi
}

# engine_tools_present is the verify step's list MINUS go, and the omission is
# the whole correctness of it: go is MOUNTED at /usr/local/go by launch, not
# installed by zypper, and it is not on provision's own PATH. Asking for it here
# would report "not provisioned" on a perfectly baked image and run zypper
# anyway — the cache would be built, stored, restored, and then ignored, which
# is worse than not having one because it looks like it works.
engine_tools_present() {
	command -v bash make podman bwrap pasta python3 findmnt ssh >/dev/null 2>&1
}

# install_packages is the ONLY place the package list exists. Called from
# provision when the tools are missing, and from
# test/engine-container.dockerfile so CI can bake and cache the result.
install_packages() {
	throwaway_only install-packages

	# bash, bash-sh, coreutils, gawk, grep, sed, findutils, diffutils and make
	# are named EXPLICITLY, and that is measured rather than defensive: without
	# them `--no-recommends` satisfied the new dependencies with busybox
	# variants and REMOVED what the image had — "214.9 MiB … released by
	# packages that will be removed" (run 32940231386) — taking /bin/sh with it,
	# and the next step died `exec: "sh": executable file not found in $PATH`.
	# Both of these are network, both are before any test, and both are the
	# measured way this job dies without naming a test. `|| rc=$?` rather than
	# `if !`, because `set -e` is on and the exit code is the thing being
	# reported.
	#
	# The refresh is NOT optional and cannot be dropped to remove the
	# dependency: MEASURED, registry.opensuse.org/opensuse/tumbleweed:latest
	# ships an EMPTY /var/cache/zypp, so `zypper install` would simply
	# auto-refresh and fail in the same place with a less specific message.
	local rc=0
	zypper -n --gpg-auto-import-keys refresh || rc=$?
	[ "$rc" -eq 0 ] || infra_fail "zypper refresh" "$rc" \
		"openSUSE repository metadata — mirror lag, a dead mirror or a CDN timeout"

	rc=0
	zypper -n install --no-recommends \
		bash bash-sh coreutils gawk grep sed findutils diffutils \
		make tar gzip git which curl \
		podman crun fuse-overlayfs \
		bubblewrap passt iproute2 \
		python3 shadow util-linux util-linux-systemd \
		openssh-clients || rc=$?
	[ "$rc" -eq 0 ] || infra_fail "zypper install" "$rc" "an openSUSE mirror or the package set it served"
}

provision() {
	throwaway_only provision
	set -x

	# The packages may already be here, because CI bakes them into a cached
	# image (see install-packages and test/engine-container.dockerfile). Then
	# BOTH remaining network steps are skipped and this job reaches the network
	# zero times before its first test — which is the whole of issue #478's
	# measured failure surface.
	#
	# Detected rather than flagged. A flag would say "somebody meant to
	# pre-provision"; this says "the tools are here", which is the thing the
	# suite actually needs and is true however they arrived. If the detection is
	# wrong in the cautious direction it costs one redundant zypper run, and in
	# the other direction the verify step below fails naming the missing tool.
	if engine_tools_present; then
		echo "engine-container: every required tool is already present; skipping zypper." >&2
	else
		install_packages
	fi

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

	# SNUG_ENGINE_FLOOR is 46 HERE, MEASURED on three independent green runs of
	# this container: 33147986207 (job 98773191199) reported 47, 33148019154
	# (job 98773292664) reported 46, and 33150580747 (job 98781426659) reported
	# 46. It is the whole point of the variable that the number is per
	# environment: CI silently losing engine tests must not still clear the
	# floor.
	#
	# THE FLOOR IS THE MINIMUM OVER RUNS, NOT ONE RUN'S COUNT. The readings
	# differ by exactly one test — TestAHostRegistriesConfDoesNotSteerTheEnginesPull
	# marks only when its own control fires. A floor at 47 would go red on the
	# two runs where it did not, which is a test that cannot pass rather than a
	# test that caught something.
	#
	# Raise it from a green run of THIS container, never from the Makefile
	# default: that one is a development host and reaches a different set.
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
		SNUG_ENGINE_FLOOR=46 \
		SNUG_SANDBOX_TIMEOUT=18m \
		SNUG_REQUIRE_SANDBOX=1 \
		SNUG_REQUIRE_ENGINE=1 \
		SNUG_TEST_NET=1 \
		bash -c 'cd /src && make build && ./bin/snug doctor; make integration-sandbox'
}

case ${1:-launch} in
launch) launch ;;
provision) provision ;;
install-packages) install_packages ;;
*)
	echo "engine-container: unknown subcommand $(printf %q "$1") (want launch, provision or install-packages)" >&2
	exit 1
	;;
esac
