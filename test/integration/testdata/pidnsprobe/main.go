// Command pidnsprobe is a from-scratch container's own entrypoint (issue
// #145): it has no shell, no libc and nothing else to borrow a `readlink` or
// a `ps` from (CGO_ENABLED=0, a static binary with nothing else in the
// image), because the whole point of building it `FROM scratch` is that the
// image needs no base layer and therefore no registry pull — see
// TestContainerSeesOnlyItsOwnPids in ../../containerengine_test.go for why
// that matters: this probe has to be constructible with the sandbox's
// egress CLOSED.
//
// It answers the two questions that pin the negative
// TestContainerCannotJoinTheEnginesPidNamespace's refusal is protecting:
//
//   - What does /proc/1/root resolve to, from INSIDE this container's own
//     pid namespace? A container that shares no pid namespace with anything
//     else sees only itself at pid 1, so this must be its OWN tiny
//     from-scratch root (just this binary plus whatever podman itself
//     bind-mounts in — /etc/resolv.conf, /etc/hosts, /etc/hostname, /dev,
//     /proc) — never a host-shaped tree with /usr, /home, /root, /var.
//   - What pids does /proc list? A positive control lives in the same
//     process tree: the entrypoint starts a second, short-lived child
//     (itself, re-exec'd with "child") before listing /proc, so "only its
//     own pids" is checked against a process count known to be at least two,
//     not against an empty or single-entry /proc a broken probe would also
//     produce.
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
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "child" {
		// The positive control's own marker: a second process actually
		// existing under this container's pid namespace, distinguishable in
		// its own cmdline from the parent's.
		fmt.Println("CHILD-MARKER-READY")
		time.Sleep(3 * time.Second)
		return
	}

	// Start the child BEFORE reading /proc, so the pid listing below has a
	// known-present second member to find — os.Args[0] is the absolute path
	// podman COPYs this binary to (see buildScratchProbeImageFor), so no PATH
	// lookup and no shell is needed to launch it.
	child := exec.Command(os.Args[0], "child")
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		fmt.Println("CHILD-START-ERROR", err)
	} else {
		fmt.Println("CHILD-STARTED", child.Process.Pid)
	}
	// Give the child time to actually print its own marker before this
	// process lists /proc, so the snapshot below is not a race against a
	// child that has not been scheduled yet.
	time.Sleep(300 * time.Millisecond)

	root, err := os.Readlink("/proc/1/root")
	fmt.Println("ROOT-LINK", root, err)

	entries, err := os.ReadDir("/proc/1/root")
	if err != nil {
		fmt.Println("ROOT-LIST-ERROR", err)
	} else {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		fmt.Println("ROOT-ENTRIES", strings.Join(names, ","))
	}

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		fmt.Println("PROC-LIST-ERROR", err)
	} else {
		var pids []string
		for _, e := range procEntries {
			if _, convErr := strconv.Atoi(e.Name()); convErr == nil {
				pids = append(pids, e.Name())
			}
		}
		sort.Strings(pids)
		fmt.Println("PIDS", strings.Join(pids, ","))
	}

	if child.Process != nil {
		_ = child.Wait()
	}
	fmt.Println("PROBE-COMPLETE")
}
