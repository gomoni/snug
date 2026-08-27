//go:build integration

package integration

import (
	"fmt"
	"testing"
)

// TestExitStatusFromInsideIsNotAByteChannel pins today's wanted behaviour:
// `snug <dir> -- sh -c 'exit 137'` returns 137. SECRETS.md:785 measures why
// this is worth pinning rather than assuming: "Exit status is a byte channel,
// and it is fast … a stub that did not propagate status would be useless,
// because `gh` callers branch on it. Arbitrary code in the sibling does
// `exit(secret[i])`." That paragraph is about a DIFFERENT process (a
// credential-holding sibling snug has not built), but the mechanism it
// measures is generic: any future design that runs a tool ON THE PAYLOAD'S
// BEHALF and returns THAT TOOL's exit status — a wrapper that inspects,
// retries or reports on the payload — hands the payload 256 values per
// invocation to signal out with, for the cost of one `exit N`. If that design
// is ever built, it has to change what this test asserts, deliberately.
func TestExitStatusFromInsideIsNotAByteChannel(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	// Three values, not one, and the choice of which three is the control:
	// 137 and 3 are both nonzero AND distinct from each other and from 1. A
	// design that collapsed every nonzero payload exit to a fixed status (the
	// shape a WRAPPING tool's own exit code would take, and exactly the
	// failure this test exists to catch) would make 137 and 3 read identical
	// — a single-value test cannot tell "passed through" from "collapsed to
	// something that happens to equal the one value tried". 0 checks the
	// success path is not itself reported as failure.
	for _, want := range []int{137, 3, 0} {
		r := run(t, nil, proj, fmt.Sprintf("exit %d", want)).mustRun(t)
		if r.code != want {
			t.Errorf("snug <dir> -- sh -c 'exit %d' exited %d, want %d — the payload's own "+
				"exit status did not survive unchanged", want, r.code, want)
		}
	}
}
