//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestGetentWorksWhenOnlyTheVendorNsswitchIsVisible reproduces, with a raw
// bwrap invocation rather than snug, the exact filesystem shape
// registry.opensuse.org/opensuse/tumbleweed:latest has: no /etc/nsswitch.conf,
// only /usr/etc/nsswitch.conf. Fails if @sys's now-optional grant for
// /etc/nsswitch.conf stops being sufficient — i.e. if glibc's own fallback to
// the vendor copy ever needs something this sandbox does not already give it
// through the /usr bind.
//
// The probe is raw bwrap, deliberately not snug, for requireSandbox's own
// reason: a bug in snug's handling of the optional grant must not be able to
// make this test pass by skipping the sandbox rather than by exercising it.
func TestGetentWorksWhenOnlyTheVendorNsswitchIsVisible(t *testing.T) {
	budget(t)
	requireSandbox(t)

	if _, err := os.Stat("/usr/etc/nsswitch.conf"); err != nil {
		t.Skip("SKIP: this host has no /usr/etc/nsswitch.conf; this test reproduces the " +
			"openSUSE vendor-config layout where glibc's NSS configuration lives under " +
			"/usr/etc rather than /etc")
	}

	args := []string{
		"--unshare-all",
		"--ro-bind", "/usr", "/usr",
		"--tmpfs", "/etc",
		"--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache",
		"--ro-bind", "/etc/ld.so.conf", "/etc/ld.so.conf",
		"--ro-bind", "/etc/passwd", "/etc/passwd",
		"--ro-bind", "/etc/group", "/etc/group",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--dev", "/dev",
		"--proc", "/proc",
		"--die-with-parent",
		"--", "/usr/bin/sh", "-c",
		`[ -e /etc/nsswitch.conf ] && echo NSSWITCH-PRESENT || echo NSSWITCH-ABSENT
/usr/bin/getent passwd root`,
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bwrap", args...)
	cmd.WaitDelay = waitDelay
	out, err := cmd.CombinedOutput()

	if errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("bwrap exited but something it started still holds its output pipe after "+
			"%s:\n%s", waitDelay, out)
	}
	if ctx.Err() != nil {
		t.Fatalf("bwrap did not finish within %s (a hang is a finding):\n%s", cmdTimeout, out)
	}

	// POSITIVE CONTROL: the synthetic /etc genuinely carries no nsswitch.conf,
	// so a passing getent below is the /usr fallback answering and not some
	// other path putting the file back in view.
	if !strings.Contains(string(out), "NSSWITCH-ABSENT") {
		t.Fatalf("the fixture's /etc unexpectedly has a nsswitch.conf, so this run does not "+
			"test the vendor-only fallback:\n%s", out)
	}

	if err != nil {
		t.Fatalf("getent passwd root failed with only /usr/etc/nsswitch.conf visible: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "root:") {
		t.Fatalf("getent produced no root: entry, so NSS did not resolve via the vendor "+
			"nsswitch.conf under /usr:\n%s", out)
	}
}

// TestGetentWorksInADefaultSandbox is the consumer-side half of the same
// regression: nothing else in this suite runs a name lookup inside a sandbox,
// which is how a profile that refuses to resolve at all — the exit-77 case
// this milestone fixed — could have shipped while every other default-profile
// test stayed green. Fails if the default profile set ever again leaves NSS
// unable to answer for the sandbox's own uid.
func TestGetentWorksInADefaultSandbox(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	r := run(t, nil, proj, `u=$(id -un); printf 'USER-IS:%s\n' "$u"; getent passwd "$u"`).mustRun(t)

	var user string
	for _, line := range strings.Split(r.out, "\n") {
		if v, ok := strings.CutPrefix(line, "USER-IS:"); ok {
			user = v
		}
	}
	// POSITIVE CONTROL: id -un must have produced a real name, or the getent
	// call below looked up nothing and its outcome says nothing about NSS.
	if user == "" {
		t.Fatalf("positive control failed: id -un produced no name inside the sandbox, so "+
			"the getent lookup below has nothing to check:\n%s", r.out)
	}
	if r.code != 0 {
		t.Fatalf("getent passwd %q exited %d inside the default sandbox:\n%s", user, r.code, r.out)
	}
	if !strings.Contains(r.out, user+":") {
		t.Fatalf("getent produced no %q entry, so name resolution did not work for the "+
			"sandbox's own uid:\n%s", user, r.out)
	}
}
