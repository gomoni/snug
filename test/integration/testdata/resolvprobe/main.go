// Command resolvprobe is a from-scratch container's own entrypoint (issue
// #126): it has no shell, no libc and nothing else to borrow a `cat` from
// (CGO_ENABLED=0, a static binary with nothing else in the image), because
// the whole point of building it `FROM scratch` is that the image needs no
// base layer and therefore no registry pull — see
// TestContainerGetsGeneratedResolvConfNotHosts in
// ../../containerengine_test.go for why that matters: this probe has to be
// constructible with the sandbox's egress CLOSED.
//
// It prints the two files a leaked HOST tree could hand a container:
// /etc/resolv.conf (issue #126's own finding) and /etc/hosts (flagged by the
// same red-team pass as worth the identical look), each delimited so the Go
// test can extract exactly one file's content without guessing at a shell
// quoting convention.
//
// This directory is named testdata for the same reason
// test/integration/testdata/netprobe is: the Go toolchain ignores it for `go
// build ./...` everywhere else, and only the integration test compiles it
// (for the HOST architecture, since it also has to run as the entrypoint of a
// container built and started through the very engine under test).
package main

import (
	"fmt"
	"os"
)

func main() {
	dump("RESOLV", "/etc/resolv.conf")
	dump("HOSTS", "/etc/hosts")
	fmt.Println("PROBE-COMPLETE")
}

func dump(label, path string) {
	fmt.Printf("%s-BEGIN\n", label)
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("%s-READ-ERROR %v\n", label, err)
	} else {
		os.Stdout.Write(b)
	}
	fmt.Printf("%s-END\n", label)
}
