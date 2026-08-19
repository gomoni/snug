// Command holder is a from-scratch container's entrypoint for tests that need
// a container to still be RUNNING at the moment something happens to snug —
// as opposed to netprobe next door, which measures something and exits.
//
// It exists because the alternative is a base image. The container in
// TestASignalledContainerRunLeavesNothingRunning has to outlive the signal, and
// `alpine sleep 300` (which is what issue #113's own measurement used) needs a
// registry pull, which needs egress, which the test must be able to run
// without. `FROM scratch` + one static binary needs neither.
//
// Usage: holder TOKEN
//
// Prints "HOLDING <TOKEN>" and then sleeps for holdFor. The token is the whole
// point: it is carried in argv, so the HOST can find this process — and
// therefore this container — by scanning /proc/<pid>/cmdline, exactly the way
// the rest of this suite identifies processes it must prove are gone. It is
// never matched on `comm`, which a container runtime is free to rewrite.
//
// The sleep is bounded rather than infinite so that a test which fails before
// its own cleanup runs cannot leave a container holding a namespace on the
// developer's machine indefinitely.
package main

import (
	"fmt"
	"os"
	"time"
)

const holdFor = 5 * time.Minute

func main() {
	token := "no-token"
	if len(os.Args) > 1 {
		token = os.Args[1]
	}
	fmt.Printf("HOLDING %s\n", token)
	os.Stdout.Sync()
	time.Sleep(holdFor)
}
