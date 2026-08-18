BIN := bin/snug

.PHONY: all build test gate integration golden clean install

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

# Regenerate the golden argv files, then READ THE DIFF. A change to a golden
# file is a change to the sandbox boundary.
golden:
	go test ./internal/policy -update

install: build
	install -Dm755 $(BIN) $(HOME)/.local/bin/snug

clean:
	rm -rf bin

