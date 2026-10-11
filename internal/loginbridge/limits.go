package loginbridge

import "time"

// The bridge's limits, in one place so the host half and every screen that
// reports them read the same numbers (.claude/design/LOGIN-BRIDGE.md §7).
const (
	// MaxLiveFlows is how many logins may be pending at once.
	MaxLiveFlows = 1
	// MaxOpensPerRun bounds how many browser tabs the sandbox can cause.
	MaxOpensPerRun = 5
	// MaxRelaysPerRun is how many callbacks snug relays into the sandbox; it
	// equals the relay sockets requested from the stage.
	MaxRelaysPerRun = 3
	// SupersedeAfter is how long an unconfirmed flow must have been pending
	// before a new open may replace it.
	SupersedeAfter = 30 * time.Second
	// FlowTTL is how long snug holds the host port for one flow.
	FlowTTL = 10 * time.Minute
	// OpenerPatience is how long snug waits for xdg-open to exit.
	OpenerPatience = 30 * time.Second
)
