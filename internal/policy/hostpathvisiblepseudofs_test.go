package policy

import "testing"

// TestHostPathVisibleRefusesPseudoFilesystems pins issue #145's "read from
// code, not executed" premise for the integration test
// TestEngineProcfsIsNotBindMountable (test/integration): the container proxy's
// bind filter refuses `-v /proc:/hostproc` only because HostPathVisible walks
// KindBind mounts and nothing else — /proc and /dev are snug's own synthetic
// mounts (KindProc, KindDev; resolve.go's yieldTo calls), not a bind of a host
// path, so they can never satisfy the loop no matter what a profile grants.
// /sys and /dev/shm are not mounted into the sandbox at all by default, so
// they fail for the simpler reason: no mount covers them either.
//
// This matters beyond tidiness because a pid namespace makes /proc a second
// route to exactly the filesystem escape PidMode="host" is refused for
// (issue #145's decision): if HostPathVisible ever started matching a
// pseudo-filesystem mount, `podman run -v /proc:/hostproc` inside a container
// whose PidMode is otherwise still refused would reach the same
// /proc/<pid>/root dereference by a completely different HostConfig field.
func TestHostPathVisibleRefusesPseudoFilesystems(t *testing.T) {
	p := mustResolveDefaults(t)

	for _, host := range []string{"/proc", "/sys", "/dev", "/dev/shm"} {
		for _, needWrite := range []bool{false, true} {
			if p.HostPathVisible(host, needWrite) {
				t.Errorf("HostPathVisible(%q, needWrite=%v) = true; a pseudo-filesystem is never "+
					"a KindBind mount and must never be visible to the container bind filter",
					host, needWrite)
			}
		}
	}

	// POSITIVE CONTROL: an ordinary bind grant IS visible, so the sweep above
	// is not passing because HostPathVisible always returns false regardless
	// of what it is asked about.
	if !p.HostPathVisible("/usr", false) {
		t.Fatal("control: HostPathVisible(\"/usr\", false) = false; @sys grants /usr read-only, " +
			"so the predicate itself is broken and the pseudo-filesystem checks above prove nothing")
	}
}
