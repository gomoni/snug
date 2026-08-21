BIN := bin/snug

.PHONY: all build test gate integration integration-sandbox integration-signals integration-hostless forkstress golden clean install

all: build

build:
	go build -o $(BIN) ./cmd/snug

# Everything here runs with no privileges and no namespaces, which is the point
# of keeping internal/policy pure: the security-critical tests work in any CI.
test:
	go test ./...

gate:
	gofmt -l . | (! grep .) || (echo "gofmt needed"; exit 1)
	go vet ./...
	# Same reason as the integration line below, for the other build tag in
	# this tree: internal/attach's fork-stress arm is `forkstress`-tagged, so
	# `go vet ./...` never compiles it and it could sit broken indefinitely
	# with every gate green. Type-checking costs nothing; RUNNING it is the
	# part deliberately kept out of the gate (see the forkstress target).
	go vet -tags forkstress ./internal/attach/...
	# `go vet ./...` does NOT compile build-tagged files, so the integration
	# harness could sit broken indefinitely and every gate would still be green.
	# Type-checking it costs nothing and needs no privileges — unlike running it.
	go vet -tags integration ./test/integration/...
	# Named explicitly, not swept in by a `...` pattern: the go tool ignores any
	# directory named testdata when EXPANDING a wildcard, which is what lets
	# fixtures live there undisturbed, but the same rule means neither
	# `go vet ./...` above nor `go vet -tags integration ./test/integration/...`
	# ever looks inside test/integration/testdata/pidfdprobe — it is a real Go
	# package (issue #23/#47's regression probe), built unconditionally by
	# TestMain, and a compile error in it would pass gate green and then fail
	# every test in the integration suite via TestMain's os.Exit(1), not just
	# the pidfd ones. Naming the path directly (no "...") sidesteps the
	# testdata exclusion, which only applies to wildcard expansion.
	go vet ./test/integration/testdata/pidfdprobe
	# testdata/netprobe (issue #63, Tier B) is a real Go package too — the
	# static `FROM scratch` container entrypoint the engine-in-N tests build
	# on demand (containerengine_test.go's netprobeBin) — built lazily rather
	# than unconditionally by TestMain, so a break in it would otherwise sit
	# undetected until a host with a real engine bundle happened to run those
	# specific tests. Same fix, same reasoning as pidfdprobe above.
	go vet ./test/integration/testdata/netprobe
	# testdata/resolvprobe (issue #126) is the third of these: a `FROM
	# scratch` container entrypoint that dumps /etc/resolv.conf and
	# /etc/hosts, built lazily by containerengine_test.go's resolvprobeBin.
	# Same fix, same reasoning as pidfdprobe and netprobe above.
	go vet ./test/integration/testdata/resolvprobe
	# testdata/holder (issue #113) is the fourth: a `FROM scratch` entrypoint
	# that stays RUNNING, so a test can signal snug while a container of its
	# own is still up. Built lazily by containerengine_test.go's holderBin.
	# Same fix, same reasoning as the three above.
	go vet ./test/integration/testdata/holder
	# testdata/pidnsprobe (issue #145) is the fifth: a `FROM scratch`
	# entrypoint that starts a child of itself and reads back /proc/1/root
	# and its own pid listing, for TestContainerCannotJoinTheEnginesPidNamespace
	# and TestContainerSeesOnlyItsOwnPids. Built lazily by
	# containerengine_test.go's pidnsprobeBin. Same fix, same reasoning as
	# the four above.
	go vet ./test/integration/testdata/pidnsprobe
	# testdata/fakepodman (issue #125, C2-gate) is the sixth: a stand-in
	# `podman system service` gate_test.go's own tests use to control WHEN
	# the engine's socket appears and what its first response is, built
	# lazily by gate_test.go's fakePodmanBin. Same fix, same reasoning as
	# the five above.
	go vet ./test/integration/testdata/fakepodman
	# testdata/buildmarker (issue #235) is the seventh: the RUN step of the
	# build probe's Dockerfile, which is what let that probe stop building
	# FROM alpine and stop needing an anonymous Docker Hub pull. Built lazily
	# by sandbox_test.go's buildMarkerBin. Same fix, same reasoning as the
	# six above.
	go vet ./test/integration/testdata/buildmarker
	# testdata/egressprobe (issue #235) is the eighth: a `FROM scratch`
	# entrypoint that dials the addresses it is given, which is what let
	# TestContainerEgressFollowsNetProfile stop proving egress with an
	# anonymous Docker Hub pull. Built lazily by containerengine_test.go's
	# egressprobeBin. Same fix, same reasoning as the seven above.
	go vet ./test/integration/testdata/egressprobe
	go test ./...

# Tier 3: really launch sandboxes and assert what is and is not reachable. This
# is the automated half of VERIFY.md — the by-hand checklist stays, because
# it carries the reasoning; this is the ratchet.
#
# Build-tagged, so it is excluded from `make gate` by construction: it needs
# bubblewrap, user namespaces and pasta, none of which every machine has. Where
# they are missing the tests SKIP with a reason. Set SNUG_REQUIRE_SANDBOX=1 (CI
# does) to turn those skips into failures, and SNUG_TEST_NET=1 to allow the
# checks that reach the public internet.
#
# -timeout is 4m, not 15m. The whole suite runs in about 6 seconds here and every
# test carries its own budget (see test/integration: budget()), so this is the
# outermost of three nested bounds and should never be the one that fires. When
# it was 15m it was the ONLY bound, and a single hung test could burn the entire
# CI job and end in an anonymous goroutine dump. If this timeout fires, the
# per-test watchdog did not — which is itself the bug worth looking at.
#
# SNUG_REQUIRE_SANDBOX=1 make integration used to FAIL outright, every time,
# on any host — requireInternet (test/integration/sandbox_test.go) correctly
# treats "require the sandbox but leave SNUG_TEST_NET unset" as a config
# error rather than a silent skip, because there is no such thing as a
# "strict but no network" mode: the code has no third state for it. So
# without this default, the one CLI invocation that means "run the whole
# committed suite" (this target) was guaranteed to fail unless the caller
# separately knew to export a second variable — a trap three prior sessions
# walked into and each recorded as "known pre-existing failure", which it was
# not. If the caller has already set SNUG_TEST_NET (to anything, including
# empty-to-opt-out — see requireInternet), that choice is left alone; this
# only fills in the value SNUG_REQUIRE_SANDBOX already implies. A bare
# `go test -tags integration ./test/integration/...`, run outside `make`,
# still gets no defaults and fails loudly if asked to be strict about a host
# it was not told is allowed to reach the network — exactly per "a bare go
# test invocation still refuses to pretend".
integration:
	SNUG_TEST_NET=$${SNUG_TEST_NET:-$${SNUG_REQUIRE_SANDBOX:+1}} \
		go test -tags integration -timeout 4m -v ./test/integration/...

# bash, not sh: both split targets read $${PIPESTATUS[0]} so that a real test
# failure is still a failure after the output has been through `tee`. With
# /bin/sh the guard would swallow it, which is the failure mode these two
# targets exist to prevent — a job that goes green having proved nothing.
SHELL := /bin/bash

SIGNALS_LOG ?= $(CURDIR)/.integration-signals.log
HOSTLESS_LOG ?= $(CURDIR)/.integration-hostless.log

# ── the same suite, split three ways for CI ─────────────────────────────────
#
# `make integration` above still runs EVERYTHING and is what a human runs. The
# three targets below exist because one CI job was doing all of it serially:
# measured on run 32471090448, `real sandbox behaviour` took 147s, of which the
# test binary was 106s — and 68s of that 106s was three tests.
#
# The split is by COST and by WHAT THE HOST MUST PROVIDE, not by subject:
#
#   integration-signals   the three kill-during-startup tests. 68s of the 106s.
#                         They are slow because they must be: each one signals a
#                         real sandbox at a real moment and repeats to make the
#                         race show up, so the seconds ARE the measurement.
#   integration-sandbox   everything else that needs bwrap or pasta. ~37s.
#   integration-hostless  the tests that need neither, which is decided by the
#                         RUNNER rather than by a list here — see below.
#
# SNUG_SIGNAL_TESTS is written once and used twice, as a -run and as a -skip, so
# the two halves cannot drift into overlapping or into leaving a test unrun.
SNUG_SIGNAL_TESTS = TestSignallingSnugDuringStartupLeavesNoOrphanedSandbox|TestAKilledSnugCannotReleaseTheParkedPayload|TestKillingSnugDuringStartupNeverRunsThePayload

integration-sandbox:
	SNUG_TEST_NET=$${SNUG_TEST_NET:-$${SNUG_REQUIRE_SANDBOX:+1}} \
		go test -tags integration -timeout 4m -v \
			-skip '$(SNUG_SIGNAL_TESTS)' ./test/integration/...

# A -run regexp that matches nothing exits 0 and prints a warning, which is the
# "test that cannot fail" shape: the job would go green having run none of the
# three tests it exists for. So the warning is turned into a failure here, and
# the message names the variable to fix rather than the symptom.
integration-signals:
	@SNUG_TEST_NET=$${SNUG_TEST_NET:-$${SNUG_REQUIRE_SANDBOX:+1}} \
		go test -tags integration -timeout 4m -v \
			-run '$(SNUG_SIGNAL_TESTS)' ./test/integration/... 2>&1 \
		| tee $(SIGNALS_LOG); \
	status=$${PIPESTATUS[0]}; \
	if grep -q 'no tests to run' $(SIGNALS_LOG); then \
		echo 'ERROR: SNUG_SIGNAL_TESTS matched no test — a name in the Makefile has'; \
		echo 'ERROR: drifted from the suite, so this job would have gone green having'; \
		echo 'ERROR: run none of the three tests it exists for.'; \
		exit 1; \
	fi; \
	exit $$status

# The hostless half, and the interesting part is what decides membership.
#
# NOTHING here lists which tests do not need a sandbox. The suite already gates
# every sandbox test on requireSandbox/requirePasta/requireEngine, so on a host
# with neither binary installed those tests SKIP and what remains — the dry-run
# screens, the refusals that happen before anything is launched, the generated
# identity files — runs. Membership is therefore answered by the runner, and a
# test that stops needing bwrap joins this job by itself. A list would be the
# catalogue shape this project keeps deleting.
#
# SNUG_REQUIRE_SANDBOX must stay UNSET for this target: with it, every skip
# becomes a failure, which is exactly right for the sandbox job and exactly
# wrong here.
#
# The floor is what stops it becoming a job that passes having run nothing —
# the failure this whole suite exists to refuse. It is a floor, not the count:
# adding hostless tests keeps it true, and deleting them all makes it fail.
SNUG_HOSTLESS_FLOOR = 15

integration-hostless:
	@go test -tags integration -timeout 4m -v ./test/integration/... 2>&1 \
		| tee $(HOSTLESS_LOG); \
	status=$${PIPESTATUS[0]}; \
	ran=$$(grep -c '^--- PASS' $(HOSTLESS_LOG) || true); \
	echo "tests that ran without a sandbox: $$ran (floor $(SNUG_HOSTLESS_FLOOR))"; \
	if [ "$$ran" -lt "$(SNUG_HOSTLESS_FLOOR)" ]; then \
		echo "ERROR: only $$ran test(s) ran here. Either bwrap/pasta leaked into this"; \
		echo "ERROR: environment and changed what this job measures, or the tests that"; \
		echo "ERROR: need no sandbox have gone. Both are worth a look."; \
		exit 1; \
	fi; \
	exit $$status

# The regression test for issue #221 — a raw-fork child that wedged in the Go
# runtime — behind its own tag and its own CI job, deliberately NOT in `go test
# ./...`.
#
# It is not slow by accident: to be a test at all it has to PROVOKE the
# condition, which means a stop-the-world storm and up to 240 forked processes,
# a few seconds of a loaded machine. That buys re-proving a property that only
# moves when internal/attach's fork path moves, so the gate should not pay it on
# every run — but it stays in CI, in parallel, because the alternative to a slow
# test here is no test (the mechanism is invisible without load).
#
# Its structural twin, TestEveryFunctionOnTheChildPathIsNosplit, is untagged and
# takes 0.00s: that is the one that catches the everyday regression (a pragma
# dropped, a splittable call added), and it runs in `make gate` like everything
# else.
# -v deliberately: the control arm's own line ("a splittable fork child wedged
# on round N — the pressure is real") is the evidence that this run provoked the
# condition at all, and a green tick without it says nothing.
forkstress:
	go test -tags forkstress -count=1 -timeout 5m -v -run TestForkChild ./internal/attach/

# Regenerate the golden argv files, then READ THE DIFF. A change to a golden
# file is a change to the sandbox boundary.
golden:
	go test ./internal/policy -update

install: build
	install -Dm755 $(BIN) $(HOME)/.local/bin/snug

clean:
	rm -rf bin

