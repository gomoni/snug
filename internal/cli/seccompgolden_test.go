package cli

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/sandbox"
)

// compatArchParagraph is the compat-arch REFUSAL describeSeccomp's "active"
// branch renders on an architecture that has a second, 32-bit audit arch. The
// wording is copied here verbatim rather than derived, so a change to either
// side is visible as a diff instead of two copies silently drifting apart —
// but the ARCH NAME in it is not: it comes from sandbox.CompatArchName, the
// same source the renderer reads, because a hardcoded "i386" here would make
// this test amd64-only in the one place whose job is proving the screen is
// right on every architecture.
func compatArchParagraph(name string) string {
	p := "         32-bit binaries do NOT run on this architecture: they issue their\n" +
		"         syscalls under the " + name + " compat audit arch, whose numbers mean\n" +
		"         something else, so the filter KILLS the process (SIGSYS) rather\n" +
		"         than allowing it through unfiltered. --no-seccomp lifts this.\n"
	if name == "i386" {
		p += "         A 64-bit binary reaches that same table with `int $0x80`, and is\n" +
			"         killed for it too.\n"
	}
	return p
}

// TestGoldenSeccomp is the review artifact for issue #23's own gap: before
// this fix `snug --dry-run` contained ZERO matches for
// seccomp|ptrace|yama|filter, in EITHER mode — a run with the hardening
// deliberately switched off was indistinguishable, on screen, from one with
// it on. That is invariant 5's shape: a guarantee a human cannot check on
// screen is not one they can trust, and a security change with no golden
// diff is probably untested (CLAUDE.md, "Golden argv diffs are the review
// artifact").
//
// This is the first golden covering the TTY/SECCOMP screen area; nothing
// upstream of this commit exercised it. Follows TestGoldenTopology's shape
// exactly: describeSeccomp takes an *os.File the same way describeTopology
// does, so captureFile (dryrun_test.go) drives the real function rather than
// a copy of its logic.
//
// # Two architecture dependencies in "active", handled two different ways
//
// describeSeccomp calls sandbox.BuildFilter() to decide which of THREE
// branches to render, and two of those three vary with GOARCH:
//
//  1. On a GOARCH with no syscall table (386, riscv64, ppc64le — anything
//     nativeAuditArch does not name), it takes the UNAVAILABLE branch
//     instead of "active" at all. There is no "active" text to compare a
//     golden against there, so this case SKIPS, with the exact message
//     internal/sandbox/seccomp_test.go already uses for the same reason
//     ("no syscall table for this GOARCH") rather than inventing a second
//     way of saying it. The UNAVAILABLE branch itself has no golden —
//     producing one honestly would mean cross-building for an unsupported
//     GOARCH and running the test there, not asserting the
//     strings.Contains it would print.
//  2. On every ARCHITECTURE THAT DOES have a syscall table, "active" renders
//     — but arm64 (which has one) does NOT get the i386-compat refusal
//     paragraph, because that paragraph is specifically about x86_64's
//     32-bit compat ABI (`if runtime.GOARCH == "amd64"` in dryrun.go). A
//     golden generated on amd64 and compared verbatim on arm64 would fail
//     there with no defect present — skipping the golden case entirely
//     would "fix" that by leaving the WHOLE SECCOMP screen unchecked on
//     arm64, which is worse. So instead: assertCompatArchParagraph (below)
//     checks the paragraph is present, verbatim, on amd64 and ABSENT
//     everywhere else with a syscall table, then strips it out before the
//     golden comparison — making testdata/seccomp.active.txt one file that
//     is genuinely correct on every supported architecture, not an
//     amd64-only fixture nobody else's CI can pass.
//
// # The third branch, BROKEN, has no golden here either
//
// BuildFilter also returns (nil, false, err) when asm.offset's jump-range
// check trips — an assembly bug in snug's OWN filter construction, reachable
// on a fully-supported GOARCH, and unlike UNAVAILABLE it is not hypothetical:
// internal/sandbox's TestBuildFilterReturnsAnErrorWhenTheJumpRangeOverflows
// injects enough denied syscalls to trigger it for real and asserts the error
// text. That proves the STRING describeSeccomp's BROKEN row renders verbatim
// is meaningful.
//
// It no longer needs a seam to reach describeSeccomp itself. Issue #52 split
// the FACTS (buildSeccompReport, which is now the only caller of
// sandbox.BuildFilter on this path) from the rendering, so the BROKEN branch
// is reachable by handing describeSeccomp a reportSeccomp with that Reason —
// see TestSeccompBrokenBranchRenders in dryrunjson_test.go. What still has no
// seam is BuildFilter failing for real inside internal/cli, and that is the
// half internal/sandbox's own test covers.
func TestGoldenSeccomp(t *testing.T) {
	cases := []struct {
		name string
		cfg  config
	}{
		{"active", config{}},
		{"disabled", config{noSeccomp: true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "active" {
				if _, ok, _ := sandbox.BuildFilter(); !ok {
					t.Skip("no syscall table for this GOARCH")
				}
			}
			got := captureFile(t, func(f io.Writer) { describeSeccomp(f, buildSeccompReport(tc.cfg)) })

			if tc.name == "active" {
				got = assertCompatArchParagraph(t, got)
			}

			path := filepath.Join("testdata", "seccomp."+tc.name+".txt")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run: go test ./internal/cli -update)", err)
			}
			if got != string(want) {
				t.Errorf("the SECCOMP row changed — this is the line invariant 5 exists for, "+
					"and a change here is a change to what a human can trust on screen.\n"+
					"--- got\n%s\n--- want\n%s", got, want)
			}
		})
	}
}

// assertCompatArchParagraph checks describeSeccomp's compat-arch paragraph is
// exactly where it should be — present and verbatim wherever
// sandbox.CompatArchName reports one, absent where it does not — and returns
// `got` with it removed, so the golden comparison this feeds into is the same
// file on every architecture. See TestGoldenSeccomp's doc comment for why this
// is preferred over an amd64-only golden or a non-amd64 skip.
func assertCompatArchParagraph(t *testing.T, got string) string {
	t.Helper()
	name, has := sandbox.CompatArchName()
	if has {
		want := compatArchParagraph(name)
		if !strings.Contains(got, want) {
			t.Fatalf("GOARCH=%s has a %s compat audit arch, which the filter kills, so the "+
				"SECCOMP block must render the refusal paragraph verbatim — and did not. "+
				"A payload finding this out from a SIGSYS instead of from --dry-run is "+
				"invariant 5's shape:\n%s", runtime.GOARCH, name, got)
		}
		return strings.Replace(got, want, "", 1)
	}
	if strings.Contains(got, "32-bit binaries do NOT run on this architecture") {
		t.Fatalf("GOARCH=%s has no compat audit arch this filter would meet, so the refusal "+
			"paragraph must not appear:\n%s", runtime.GOARCH, got)
	}
	return got
}

// TestGoldenSeccompRowsDiffer pins the PROPERTY the two golden files above
// cannot pin by themselves: nothing stops a future -update run from
// regenerating both files identically (e.g. a refactor that stops branching
// on cfg.noSeccomp), and the golden comparison above would go right on
// passing against two matching, wrong files. This is the same shape as
// TestTheStagedArgvIsNotPrintedAsSelfContained pins the bwrap-note golden's
// property beside its wording.
//
// Needs no architecture guard, unlike TestGoldenSeccomp/active above: it
// never compares against a golden file, only the two live outputs against
// each other, and "active" reads either the real active text or the
// UNAVAILABLE text depending on GOARCH — either way that text is not the
// DISABLED text, so the inequality holds on every architecture.
func TestGoldenSeccompRowsDiffer(t *testing.T) {
	active := captureFile(t, func(f io.Writer) { describeSeccomp(f, buildSeccompReport(config{})) })
	disabled := captureFile(t, func(f io.Writer) { describeSeccomp(f, buildSeccompReport(config{noSeccomp: true})) })
	if active == disabled {
		t.Fatalf("--no-seccomp produced BYTE-IDENTICAL output to the active filter — a "+
			"security feature deliberately switched off must read differently on screen "+
			"from one that is active:\n%s", active)
	}
}
