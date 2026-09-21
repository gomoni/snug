// Command ignoresterm is a from-scratch container's entrypoint that IGNORES
// its stop signal ON PURPOSE, as opposed to holder next door, which merely
// installs no handler for anything.
//
// The distinction is red-team finding F5 against issue #174:
// holder's absence of a handler does NOT make it ignore SIGTERM the way a
// pid-1-of-a-fresh-pid-namespace process with no signal code at all would
// under signal(7)'s rule — that rule does not engage for a Go binary, because
// the Go runtime installs its own handler for every signal at process start,
// and SIGTERM's default table entry terminates the process. A test whose
// premise is "this container ignores its stop signal" needs a probe that
// calls signal.Ignore on purpose, or it is silently testing "this container
// exits promptly like any other Go program" instead — which is what
// TestContainerIgnoringUSR1StopSignalDoesNotDelaySnugsExitPastBudget's own
// SIGUSR1 choice worked around rather than fixed: SIGUSR1 happens to be one
// of the few signals the Go runtime does not act on by default, so that test
// survived, but only by accident of which signal it picked.
//
// Usage: ignoresterm TOKEN
//
// Prints "HOLDING <TOKEN>" and then sleeps for holdFor regardless of what
// arrives — SIGTERM, SIGINT, SIGQUIT and SIGHUP are all explicitly ignored,
// covering every stop signal a payload could plausibly name and expect a
// container runtime to send by default. holdFor bounds the wait for the same
// reason holder's own doc comment gives: a test that fails before its own
// cleanup runs must not leave a container holding a namespace indefinitely.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const holdFor = 5 * time.Minute

func main() {
	token := "no-token"
	if len(os.Args) > 1 {
		token = os.Args[1]
	}

	signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP)

	fmt.Printf("HOLDING %s\n", token)
	os.Stdout.Sync()
	time.Sleep(holdFor)
}
