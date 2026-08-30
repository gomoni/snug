//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestTheFDBudgetPolicySnugAcceptsIsOneTheStageCanActuallyBuild is the
// permanent regression for the red team round on #537.
//
// checkFDBudget refuses a pass-through block that would reach the reserved
// descriptors, and the number it names is maxPassthrough. That number was
// three too high: __stage-setup allocates the N socket, and the Go runtime
// allocates its netpoll epoll and eventfd (any armed timer creates them),
// ABOVE the inherited block and before the second parking — so a policy P0
// accepted was refused three descriptors later by P1, at the parking, and the
// unit test's positive control certified a size no real run survived.
//
// MEASURED with the binary as shipped at the time, K = N doors + 9 under
// @net: K=53 ran 15/15; K=54, 55, 56 refused 20/20 with fd 62 already holding
// an eventfd, an eventpoll and the N socket respectively; K=57 refused earlier
// by checkFDBudget. After the fix, K=54, 55 and 56 all run.
//
// This test drives the boundary from OUTSIDE snug, because that divergence is
// between two processes and no unit test in internal/stage can see it: P0's
// arithmetic must agree with what P1's descriptor table permits. It asserts
// both sides — the largest accepted policy really reaches the payload, and one
// descriptor more is refused by the budget with a message naming the fix.
func TestTheFDBudgetPolicySnugAcceptsIsOneTheStageCanActuallyBuild(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requireInternet(t)
	proj, _ := target(t)

	// K = doors + 9 under @net (measured: at 48 doors snug says "this policy
	// needs 57 pass-through descriptors"), so the largest policy the budget
	// accepts is the one that fills it exactly. Derived from what snug itself
	// reports rather than from a copy of maxPassthrough, so a change to either
	// constant moves this test with it instead of falsifying it.
	const doorsPerK = 9
	atBudget := reportedFDBudget(t, proj) - doorsPerK

	for _, tc := range []struct {
		name  string
		doors int
		run   bool
	}{
		{"exactly at the budget", atBudget, true},
		{"one under", atBudget - 1, true},
		{"one over", atBudget + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runWithDoors(t, proj, tc.doors)
			switch {
			case tc.run && err != nil:
				t.Fatalf("a policy of %d doors was ACCEPTED by checkFDBudget and then failed "+
					"in the stage — P0's budget and what P1 can actually park disagree, which "+
					"is the whole subject of this test: %v\n%s", tc.doors, err, out)
			case tc.run && !strings.Contains(out, "FD-BUDGET-PAYLOAD-RAN"):
				t.Fatalf("a policy of %d doors exited 0 but the payload never ran:\n%s", tc.doors, out)
			case !tc.run && err == nil:
				t.Fatalf("a policy of %d doors was accepted; it reaches the reserved "+
					"descriptors and must be refused:\n%s", tc.doors, out)
			case !tc.run:
				// "Errors name the fix": the reader of this one has no idea
				// what fdNetnsN is.
				for _, want := range []string{"pass-through descriptors", "fdNetnsN", "internal/stage/fds.go"} {
					if !strings.Contains(out, want) {
						t.Errorf("the refusal does not mention %q, so it does not name the fix:\n%s", want, out)
					}
				}
			}
		})
	}
}

// reportedFDBudget asks snug for the budget rather than copying it: a
// deliberately over-large profile is refused, and the refusal states the
// number. A test that re-typed maxPassthrough would keep passing after a
// change that moved it.
func reportedFDBudget(t *testing.T, proj string) int {
	t.Helper()
	out, err := runWithDoors(t, proj, 200)
	if err == nil {
		t.Fatalf("a policy of 200 doors was accepted; nothing here can find the boundary:\n%s", out)
	}
	const marker = "(the budget is "
	i := strings.Index(out, marker)
	if i < 0 {
		t.Fatalf("the over-large refusal does not state the budget, so this test cannot "+
			"derive the boundary from snug itself:\n%s", out)
	}
	var n int
	if _, err := fmt.Sscanf(out[i+len(marker):], "%d", &n); err != nil || n <= 0 {
		t.Fatalf("could not read the budget out of %q: %v", out[i:], err)
	}
	return n
}

// runWithDoors runs a payload under @net plus a profile declaring n http
// doors. listen_names is the only user-reachable knob that grows the
// pass-through block, which is what makes the block's size policy-dependent
// and the budget worth checking at all.
func runWithDoors(t *testing.T, proj string, n int) (string, error) {
	t.Helper()
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("%q", fmt.Sprintf("d%03d", i))
	}
	env := envProfileLayer(t, "doors.toml", fmt.Sprintf(`[profile.doors]
description = "as many http doors as this case needs, to size the pass-through block"
listen_names = [%s]
`, strings.Join(names, ", ")), os.Getenv("PATH"))

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, snugBin, "-p", "@net", "-p", "doors", proj,
		"--", "/bin/sh", "-c", "echo FD-BUDGET-PAYLOAD-RAN")
	cmd.Env = env
	cmd.WaitDelay = waitDelay
	out, err := cmd.CombinedOutput()
	return string(out), err
}
