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
integration:
	go test -tags integration -timeout 4m -v ./test/integration/...

# Regenerate the golden argv files, then READ THE DIFF. A change to a golden
# file is a change to the sandbox boundary.
golden:
	go test ./internal/policy -update

install: build
	install -Dm755 $(BIN) $(HOME)/.local/bin/snug

clean:
	rm -rf bin

