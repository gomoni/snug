//go:build integration

package integration

import (
	"os"
	"strings"
	"testing"
)

// TestSandboxUnsharesTheTimeNamespace pins that a payload's own
// /proc/self/ns/time names the SAME namespace as the process that started the
// sandbox — i.e. bwrap creates no time namespace of its own, even though it
// unshares user, ipc, pid, uts, net and (where the kernel allows it) cgroup.
//
// NAMED FOR WHAT IT ASSERTS, not for the gap, per #274's precedent
// (TestTheRunDirectoryIsInMountinfoOnlyWhenAProxySocketIsMounted): a test
// called "TimeIsUnshared" would be a claim the tree does not support.
//
// Three places already say this in prose: internal/policy/bwrap.go's
// UnshareFlags lists user/ipc/pid/uts and cgroup-try with no time flag,
// internal/attach/bridge.go:61 ("CLONE_NEWTIME is deliberately absent: bwrap
// creates no time namespace"), and PSEUDOFS-AUDIT.md's P6 row (uptime/btime
// leak as a direct consequence). None of them had ever been measured from
// inside a running sandbox; this is that measurement.
//
// bwrap 0.11.2 has no --unshare-time flag at all (confirmed against `bwrap
// --help` on this host), so there is no argv this test could ever pin the
// ABSENCE of the way TestTheEmittedArgvUnsharesWhatEachTopologyRequires pins
// the others — the only place the fact is checkable is the namespace itself.
func TestSandboxUnsharesTheTimeNamespace(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	hostTime, err := os.Readlink("/proc/self/ns/time")
	if err != nil {
		t.Fatalf("reading this test process's own /proc/self/ns/time: %v", err)
	}
	hostPid, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		t.Fatalf("reading this test process's own /proc/self/ns/pid: %v", err)
	}

	r := run(t, nil, proj, "readlink /proc/self/ns/time; readlink /proc/self/ns/pid").mustRun(t)
	lines := strings.Split(strings.TrimSpace(r.out), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two readlink lines (time, then pid) from the payload, got:\n%s", r.out)
	}
	sandboxTime, sandboxPid := lines[0], lines[1]

	// POSITIVE CONTROL, and it is what tells "the probe can tell two
	// namespaces apart" from "this probe always reads the same string
	// regardless of what it points at". pid IS unshared unconditionally
	// (UnshareFlags), so if the sandboxed payload's pid namespace ever
	// matched this test process's own, either bwrap stopped unsharing pid or
	// this probe never reached the sandbox at all — and either way the time
	// comparison below would be comparing nothing to nothing.
	if sandboxPid == hostPid {
		t.Fatalf("control: the payload's pid namespace (%s) matches this test process's own "+
			"(%s) — the readlink probe is not distinguishing namespaces, so the time-namespace "+
			"comparison below would prove nothing:\n%s", sandboxPid, hostPid, r.out)
	}

	if sandboxTime != hostTime {
		t.Errorf("the payload's time namespace is %s, this test process's own (the sandbox's "+
			"parent) is %s — bwrap created a NEW time namespace. internal/attach's "+
			"SevenNamespaceFlags does not join CLONE_NEWTIME, so `snug attach` would now be "+
			"joining the wrong (host) time namespace instead of the sandbox's own:\n%s",
			sandboxTime, hostTime, r.out)
	}
}
