// Command egressprobe is a from-scratch container's own entrypoint: it dials
// the addresses it is given and reports one line per address. It is the
// registry-free replacement for the anonymous Docker Hub pull
// TestContainerEgressFollowsNetProfile used to prove egress with (issue
// #235), and it is a separate binary from netprobe next door because the two
// ask opposite questions: netprobe dials addresses that must be REFUSED (this
// netns's own loopback, pasta's gateway), this one dials an address that must
// be REACHED when @net is selected and refused when it is not.
//
// Nothing here resolves a name. The caller passes an IP literal it has
// already resolved and dialled from the HOST — see internetTarget in
// ../../sandbox_test.go — so that a failure inside the container cannot be a
// DNS failure, and so that the host-side leg is a positive control for the
// sandbox-side one. A container built FROM scratch has no /etc/resolv.conf of
// its own anyway; whether podman injects one is TestContainerGetsGenerated-
// ResolvConfNotTheHosts's property, not this one's.
//
// CGO_ENABLED=0 and stdlib only, like every other probe in testdata: the
// image is `FROM scratch` with nothing in it but this binary, which is what
// lets the offline half of the test BUILD the image with the sandbox's egress
// closed.
//
// Usage: egressprobe ADDR [ADDR...]
//
// Prints one line per address, then PROBE-COMPLETE:
//
//	RESULT <addr> REACHED
//	RESULT <addr> REFUSED <error>
//
// The dial timeout is short and fixed. That is the whole point of this file:
// the failure this replaces was a thirty-second budget expiring with nothing
// on screen naming what had not answered (issue #235, misdiagnosed four
// times). A probe that cannot reach its target must SAY SO, in seconds.
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

// dialTimeout is short because every use of this probe is inside a test with
// a budget: an unreachable address must produce a RESULT line well before the
// budget fires, so the test's own failure message is the one a human reads.
const dialTimeout = 3 * time.Second

func main() {
	if len(os.Args) < 2 {
		fmt.Println("RESULT usage ERROR missing-address")
		fmt.Println("PROBE-COMPLETE")
		return
	}
	for _, addr := range os.Args[1:] {
		c, err := net.DialTimeout("tcp", addr, dialTimeout)
		if err != nil {
			fmt.Printf("RESULT %s REFUSED %v\n", addr, err)
			continue
		}
		c.Close()
		fmt.Printf("RESULT %s REACHED\n", addr)
	}
	fmt.Println("PROBE-COMPLETE")
}
