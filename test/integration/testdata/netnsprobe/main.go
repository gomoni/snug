// Command netnsprobe is a from-scratch entrypoint (issue #401): it prints its
// own network namespace, exactly as the kernel spells it in
// /proc/self/ns/net's symlink target ("net:[<inode>]"), and reading a symlink
// needs no shell and no libc — CGO_ENABLED=0, and nothing else in the image.
//
// The same binary plays two roles, both about where issue #401's
// containers.conf pin (netns = "host") actually lands a process, as opposed
// to what containers.conf merely says:
//
//   - a container ENTRYPOINT, for
//     TestAContainerThatNamesNoNetworkModeJoinsTheSandboxsNetns, which
//     compares the value this prints against what the SANDBOX PAYLOAD itself
//     reads from the same path;
//   - a build's RUN step, for TestABuildsRunStepRunsInTheSandboxsNetns, where
//     buildah/crun execs it directly (the EXEC form of RUN needs no shell),
//     and its stdout lands in the streamed build response body the same way
//     testdata/buildmarker's BUILT-INSIDE-SNUG does.
//
// A namespace inode number means the same thing wherever it is read from —
// inside the namespace via /proc/self, or from outside via
// /proc/<pid>/ns/net — so the two readings this probe feeds are directly
// comparable text.
package main

import (
	"fmt"
	"os"
)

func main() {
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		fmt.Println("NETNS-ERROR", err)
		return
	}
	fmt.Println("NETNS", ns)
}
