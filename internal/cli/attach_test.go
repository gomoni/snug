package cli

// attach_test.go is §13.2 of .claude/scratchpad/ATTACH-SHAPE.md: the
// confinement PLAN's unit tests — everything that can be checked without
// forking or joining a real sandbox's namespaces. Tests 12-29 (the parts that
// need a real running sandbox) live in test/integration.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/sandbox"
)

// TestAttachRefusesASeccompDigestMismatch is §13.2 test 7. A run recorded as
// "active" with a digest that does not match what THIS binary's own
// sandbox.BuildFilter produces must be refused — attaching less filtered than
// the payload is the exact hole §5.1 exists to close.
func TestAttachRefusesASeccompDigestMismatch(t *testing.T) {
	real, ok, err := sandbox.BuildFilter()
	if err != nil || !ok {
		t.Skipf("this test host cannot build a real filter at all (%v, ok=%v) — "+
			"there is nothing to compare a mismatch against", err, ok)
	}
	realDigest := sandbox.FilterDigest(real)

	st := runState{Seccomp: runStateSeccomp{State: "active", Digest: "sha256:" + zeros(64)}}
	if st.Seccomp.Digest == realDigest {
		t.Fatal("test setup produced a digest that happens to collide with the real one")
	}

	if _, err := attachSeccompProgram(st, sandbox.BuildFilter); err == nil {
		t.Fatal("expected a digest mismatch to be refused")
	} else if !strings.Contains(err.Error(), "not the one this binary builds") {
		t.Errorf("refused for what looks like the wrong reason: %v", err)
	}

	// CONTROL: the MATCHING digest proceeds and returns the program bytes.
	// Without this, the refusal above is equally consistent with
	// attachSeccompProgram refusing EVERY digest, matching or not.
	st.Seccomp.Digest = realDigest
	prog, err := attachSeccompProgram(st, sandbox.BuildFilter)
	if err != nil {
		t.Fatalf("control: a matching digest should proceed: %v", err)
	}
	if len(prog) == 0 {
		t.Fatal("control: a matching digest should return the filter's program bytes, got none")
	}
}

// TestAttachRefusesWhenItCannotBuildAFilterTheRunHad is §13.2 test 8.
// buildFilter is injected specifically so this branch can be forced on any
// host/architecture — attachSeccompProgram's own doc comment explains why:
// the only real way sandbox.BuildFilter fails is an unsupported GOARCH, which
// this test machine is very unlikely to be.
func TestAttachRefusesWhenItCannotBuildAFilterTheRunHad(t *testing.T) {
	st := runState{Seccomp: runStateSeccomp{State: "active", Digest: "sha256:" + zeros(64)}}

	broken := func() ([]byte, bool, error) { return nil, false, nil }
	if _, err := attachSeccompProgram(st, broken); err == nil {
		t.Fatal("expected a refusal when the filter cannot be built at all")
	} else if !strings.Contains(err.Error(), "cannot build the seccomp filter") {
		t.Errorf("refused for what looks like the wrong reason: %v", err)
	}

	// The err != nil half of the same branch.
	failing := func() ([]byte, bool, error) { return nil, false, errors.New("boom") }
	if _, err := attachSeccompProgram(st, failing); err == nil {
		t.Fatal("expected a refusal when building the filter returns an error")
	}

	// CONTROL: a builder that succeeds is not refused by this branch — proves
	// the two refusals above are attributable to !ok / err != nil specifically,
	// not to attachSeccompProgram refusing unconditionally.
	digest := ""
	ok := func() ([]byte, bool, error) {
		prog := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		digest = sandbox.FilterDigest(prog)
		return prog, true, nil
	}
	// Prime st.Seccomp.Digest to match what ok() will produce.
	prog, _, _ := ok()
	st.Seccomp.Digest = sandbox.FilterDigest(prog)
	_ = digest
	if _, err := attachSeccompProgram(st, ok); err != nil {
		t.Fatalf("control: a working builder whose digest matches should not be refused: %v", err)
	}
}

// TestAttachCapBoundingLoopUsesCapLastCapFromProc is §13.2 test 9. The
// capability-bounding-set drop loop (internal/attach/child.go step 6) is
// bounded by CapLastCap, which MUST be read from
// /proc/sys/kernel/cap_last_cap at run time — attach.Config's own doc comment
// says a hardcoded value would silently leave newer capabilities in the
// bounding set on a kernel with more of them than this binary knows about.
//
// A hardcoded 40 (this host's own value, per .claude/scratchpad/
// ATTACH-SHAPE.md's measurements) would NOT be caught by comparing against
// the real /proc file on THIS host, so this test instead points
// capLastCapPath at a FAKE file whose value is deliberately not 40 — a
// hardcoded 40 fails this test on every host, including this one.
func TestAttachCapBoundingLoopUsesCapLastCapFromProc(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "cap_last_cap")
	const wantNotFortyValue = 123
	if err := os.WriteFile(fake, []byte(fmt.Sprintf("%d\n", wantNotFortyValue)), 0o644); err != nil {
		t.Fatal(err)
	}

	old := capLastCapPath
	capLastCapPath = fake
	t.Cleanup(func() { capLastCapPath = old })

	got, err := readCapLastCap()
	if err != nil {
		t.Fatal(err)
	}
	if got != wantNotFortyValue {
		t.Fatalf("readCapLastCap() = %d, want %d (the value in the fake file) — if this reads "+
			"40 instead, the read is not really wired to capLastCapPath and a hardcoded 40 "+
			"would pass silently", got, wantNotFortyValue)
	}

	// CONTROL: pointed at the REAL file, it agrees with a from-scratch read of
	// that same file — so the function genuinely reads whatever path it is
	// given, rather than this test's fake plumbing being the only thing that
	// works.
	capLastCapPath = old
	fromFunc, err := readCapLastCap()
	if err != nil {
		t.Fatal(err)
	}
	fromScratch, err := readCapLastCapFrom(old)
	if err != nil {
		t.Fatal(err)
	}
	if fromFunc != fromScratch {
		t.Fatalf("control: readCapLastCap() = %d but a fresh read of %s = %d", fromFunc, old, fromScratch)
	}
}

// TestAttachNeverAsksForTheParentUserNamespace is §13.2 test 11: a
// source-level sweep for NS_GET_PARENT/NS_GET_USERNS anywhere in the attach
// path. §3.1 of the design is the reason this must never appear: entering the
// MOUNT-OWNING user namespace (userns1) lands the attached process as uid 0
// with CAP_SYS_ADMIN over the sandbox's own mount namespace — strictly more
// authority than the payload has, for no gain. Grepping the SOURCE rather
// than testing behaviour is deliberate here: by the time a build calls either
// ioctl, the escalation has already been authored into the binary, and a
// behavioural test would need to construct the exact vulnerable topology to
// catch it, which is a much larger and more fragile test for the same
// guarantee a string search gives directly.
func TestAttachNeverAsksForTheParentUserNamespace(t *testing.T) {
	forbidden := []string{"NS_GET_PARENT", "NS_GET_USERNS"}

	files := []string{
		"attach.go",
		"attachstdio.go",
		"runstate.go",
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, sym := range forbidden {
			if strings.Contains(string(data), sym) {
				t.Errorf("%s mentions %s — §3.1 of the attach design says the pidfd must name a "+
					"process INSIDE the sandbox (the payload's own, owning-nothing user namespace, "+
					"userns2), and must never resolve the mount-owning parent namespace "+
					"(userns1), which would hand the attached process uid 0 with CAP_SYS_ADMIN "+
					"over the sandbox's mounts", f, sym)
			}
		}
	}

	sweepDir(t, "../attach", forbidden)
}

// sweepDir is TestAttachNeverAsksForTheParentUserNamespace's other half:
// internal/attach is a different package, reached by a relative path from
// this test's own working directory (go test always runs with cwd set to the
// package under test).
func sweepDir(t *testing.T, dir string, forbidden []string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		found = true
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, sym := range forbidden {
			if strings.Contains(string(data), sym) {
				t.Errorf("%s/%s mentions %s — see the reasoning in this test's doc comment",
					dir, e.Name(), sym)
			}
		}
	}
	if !found {
		t.Fatalf("swept zero .go files in %s — this sweep would pass on a directory "+
			"that does not exist, which proves nothing", dir)
	}
}
