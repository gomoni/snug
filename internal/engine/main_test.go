package engine

import (
	"fmt"
	"os"
	"testing"
)

// TestMain points $TMPDIR at one throwaway directory for the whole package and
// removes it afterwards, which is what stops this package littering the real
// /tmp.
//
// THE LEAK IT CLOSES, measured on issue #425: `go test ./internal/engine/` took
// /tmp/snug-1000-* from 855 to 896 in one run — 41 directories from one package,
// one run. New allocates a run directory under os.TempDir() and only Stop
// removes it; two tests in this package call Stop and the ~30 other New call
// sites do not, because almost none of them are ABOUT teardown and adding a
// cleanup to each is a rule enforced by nobody. Redirecting the root they are
// allocated from is one place instead of thirty, and a test added tomorrow
// inherits it without knowing it exists.
//
// It is deliberately NOT a substitute for reclamation, and the distinction
// matters because a green package would otherwise be read as evidence
// reclamation works. `go test` cleaning up after itself says nothing about
// whether snug does. TestStopRemovesTheRunDirectory asserts the path snug
// controls, and TestSweepReclaimsARunDirectoryWhoseOwnerIsGone asserts the one
// it cannot — those two are the evidence; this is hygiene.
//
// A SHORT prefix on purpose: everything under a run directory is prefixed by
// this path, and a unix socket path over AF_UNIX's 107 usable sun_path bytes
// fails in a way that reads as a test defect rather than a name-length one
// (test/guard/runtimedirlengthsweep_test.go exists for the same reason one
// directory over).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "se")
	if err != nil {
		fmt.Fprintf(os.Stderr, "engine tests: creating a scratch TMPDIR: %v\n", err)
		os.Exit(1)
	}
	os.Setenv("TMPDIR", dir)

	code := m.Run()

	// Not deferred: os.Exit does not run deferred functions, so the removal
	// has to be here, before it.
	if rmErr := os.RemoveAll(dir); rmErr != nil {
		fmt.Fprintf(os.Stderr, "engine tests: removing %s: %v\n", dir, rmErr)
	}
	os.Exit(code)
}
