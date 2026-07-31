BIN := bin/snug

.PHONY: all build test gate golden clean install

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
	go test ./...

# Regenerate the golden argv files, then READ THE DIFF. A change to a golden
# file is a change to the sandbox boundary.
golden:
	go test ./internal/policy -update

install: build
	install -Dm755 $(BIN) $(HOME)/.local/bin/snug

clean:
	rm -rf bin
