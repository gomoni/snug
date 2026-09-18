//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTheDNSLineOnScreenMatchesTheFileInsideTheSandbox is issue #28's
// regression test, and it is deliberately a CROSS-CHECK of two artifacts
// rather than an assertion about either one.
//
// The defect was that --dry-run printed a hardcoded `169.254.1.1 -> pasta ->
// host resolver` whenever DNS was on, while the sandbox was handed the host's
// real resolvers. Unit tests cover each renderer; what neither can see is the
// two disagreeing about the same run. Here the screen and the file are
// produced by two separate invocations of the real binary and compared.
func TestTheDNSLineOnScreenMatchesTheFileInsideTheSandbox(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	prof := "@net"
	screen, code := cli(t, nil, "--dry-run", "-p", prof, proj, "--", "true")
	if code != 0 {
		t.Fatalf("--dry-run -p %s exited %d:\n%s", prof, code, screen)
	}
	var dns string
	for _, line := range strings.Split(screen, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "dns" {
			dns = strings.Join(f[1:], " ")
			break
		}
	}
	if dns == "" {
		t.Fatalf("--dry-run printed no dns line for %s, so there is nothing to "+
			"cross-check:\n%s", prof, screen)
	}

	r := run(t, []string{"-p", prof}, proj, `cat /etc/resolv.conf`).mustRun(t)
	var inside []string
	for _, line := range strings.Split(r.out, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "nameserver" {
			inside = append(inside, f[1])
		}
	}
	if len(inside) == 0 {
		t.Fatalf("the sandbox's /etc/resolv.conf names no resolver at all:\n%s", r.out)
	}
	for _, ns := range inside {
		if !strings.Contains(dns, ns) {
			t.Errorf("--dry-run's dns line says %q, but the sandbox is actually told "+
				"to use %s. The screen a human uses to decide whether a sandbox leaks "+
				"its network position does not describe the sandbox they ran:\n%s",
				dns, ns, r.out)
		}
	}
}

// resolvConfDest is the path the outer wrapper actually mounts the fixture
// onto: /etc/resolv.conf with its symlinks RESOLVED, and the resolution is the
// whole of what makes the cheap shape below work on a GitHub runner.
//
// bubblewrap refuses to mount on a symlink destination since CVE-2026-87766
// (upstream 0.12.0; Ubuntu noble 0.9.0-1ubuntu0.2, which reached the runner
// image between 14:41 and 19:21 UTC on 2026-09-17):
//
//	bwrap: Can't mount on symlink destination /etc/resolv.conf
//
// and on a systemd-resolved host — every GitHub runner among them —
// /etc/resolv.conf IS a symlink to ../run/systemd/resolve/stub-resolv.conf.
// Binding the resolved path puts the fixture where that symlink lands, so
// /etc/resolv.conf inside still reads it and hostNameservers
// (internal/cli/main.go) — a plain os.ReadFile, which follows the link — sees
// the fixture and nothing else.
//
// The failure this replaces named neither DNS nor bwrap: the probe below
// answered false, every call fell back to copying /etc at ~19s a time, and
// TestNoResolverHostFailsFastAndSaysSo — four such calls — was killed by
// budget()'s watchdog at 20s (main, f85489d, run 35264394910).
var resolvConfDest = sync.OnceValue(func() string {
	if p, err := filepath.EvalSymlinks("/etc/resolv.conf"); err == nil {
		return p
	}
	// Dangling (a stub symlink with no resolved daemon behind it) or
	// unreadable: name the literal path and let the probe answer for it.
	return "/etc/resolv.conf"
})

// resolvConfOverlay returns the bwrap arguments that put `content` at
// /etc/resolv.conf inside the outer wrapper, choosing between two shapes
// because the cheap one does not work everywhere.
//
// PREFERRED — bind the one file, at resolvConfDest(). One 4-byte fixture, no
// copying.
//
// FALLBACK — bind a whole synthetic /etc. Needed where the destination is
// ITSELF a bind mount whose source inode has since been deleted (a distrobox
// holding the inode NetworkManager replaced by rename, which is this project's
// development environment): nothing mounts onto a deleted dentry, and both
// tests in this file failed there with
//
//	bwrap: Can't bind mount /oldroot/.../resolv.conf on /newroot/etc/resolv.conf:
//	Unable to mount source on destination: No such file or directory
//
// — a message with nothing to do with DNS.
//
// The choice is MEASURED once per process rather than reasoned about from the
// host's shape, because the condition is a property of a mount and not of a
// distribution. Fallback-always was tried and rejected: copying /etc cost 19s
// on a GitHub runner, which is most of a test's whole time budget.
func resolvConfOverlay(t *testing.T, content string) []string {
	t.Helper()
	if singleFileResolvConfBind() {
		path := filepath.Join(t.TempDir(), "resolv.conf")
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return []string{"--ro-bind", path, resolvConfDest()}
	}
	return []string{"--ro-bind", fakeHostEtc(t, content), "/etc"}
}

// singleFileResolvConfBind reports whether an outer bwrap on THIS host can
// mount anything onto resolvConfDest() at all. The probe is raw bwrap and a
// throwaway file, deliberately not snug, for requireSandbox's own reason: a
// bug in snug must not be able to choose the harness.
//
// It ANNOUNCES the fallback on stderr, and that line is not decoration. The
// fallback is ~19s per call against a 10s budget() whose watchdog panics
// without flushing the test's own log, so the shape that costs the suite its
// job is otherwise invisible in CI output — which is exactly how the bwrap
// change above cost a session to diagnose.
var singleFileResolvConfBind = sync.OnceValue(func() bool {
	f, err := os.CreateTemp("", "snug-resolvconf-probe")
	if err != nil {
		return false
	}
	defer os.Remove(f.Name())
	f.Close()
	out, err := exec.Command("bwrap", "--dev-bind", "/", "/",
		"--ro-bind", f.Name(), resolvConfDest(), "--", "true").CombinedOutput()
	if err == nil {
		return true
	}
	fmt.Fprintf(os.Stderr, "integration: nothing mounts onto %s here, so every fake-resolv.conf "+
		"run copies the whole of /etc instead (~19s each on a GitHub runner, against a %s "+
		"test budget). bwrap said: %s (%v)\n",
		resolvConfDest(), defaultBudget, strings.TrimSpace(string(out)), err)
	return false
})

// fakeHostEtc builds a copy of this host's /etc with `content` substituted for
// resolv.conf and returns its path, for resolvConfOverlay's fallback shape.
//
// CACHED PER CONTENT, under TestMain's directory rather than t.TempDir: the
// copy is the expensive half, a test calls this several times with the same
// fixture, and a t.TempDir copy would also be removed the moment the first
// test that made it ended.
//
// The copy is made as the test user, so files it cannot read are dropped.
// That is faithful rather than lossy: bwrap runs the sandbox as that same uid,
// and a file unreadable to the copy is equally unreadable inside.
func fakeHostEtc(t *testing.T, content string) string {
	t.Helper()
	fakeEtcMu.Lock()
	defer fakeEtcMu.Unlock()
	if dir, ok := fakeEtcByContent[content]; ok {
		return dir
	}

	dir, err := os.MkdirTemp(integrationTmp, "etc")
	if err != nil {
		t.Fatal(err)
	}
	// cp exits non-zero on the files this uid may not read (shadow, gshadow),
	// which is expected, so the exit code is not the check — the assertions
	// below are, and they are what stops a silently empty copy from turning
	// every test using this harness into a confusing pass.
	out, _ := exec.Command("cp", "-a", "/etc/.", dir+"/").CombinedOutput()
	// nsswitch.conf is deliberately NOT in this list, and the omission is a
	// measurement rather than a relaxation: `cp -a /etc/. dir/` cannot produce
	// a file /etc/ does not have, and openSUSE container images ship nsswitch
	// only at /usr/etc/nsswitch.conf (measured: none in /etc on
	// registry.opensuse.org/opensuse/tumbleweed:latest). glibc reads the vendor
	// copy by itself and @sys already binds /usr read-only, so a sandbox built
	// on this fake /etc resolves names there without it. Requiring it here
	// would fail every test in this file on such a host for a reason none of
	// them is about.
	for _, must := range []string{"passwd"} {
		if _, err := os.Stat(filepath.Join(dir, must)); err != nil {
			t.Fatalf("the /etc copy this harness binds is missing %s, so the sandbox "+
				"below would be failing for that reason rather than the one under "+
				"test: %v\ncp said:\n%s", must, err, out)
		}
	}
	// REMOVE before writing, never write through. `cp -a` preserves symlinks,
	// and on a systemd-resolved distribution /etc/resolv.conf IS one —
	// ../run/systemd/resolve/stub-resolv.conf on a GitHub runner. Writing to
	// the copy would follow it into a path that does not exist under the copy
	// and fail with a bare "no such file or directory" naming a file that is
	// plainly there.
	if err := os.Remove(filepath.Join(dir, "resolv.conf")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "resolv.conf"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeEtcByContent[content] = dir
	return dir
}

var (
	fakeEtcMu        sync.Mutex
	fakeEtcByContent = map[string]string{}
)

// cliWithFakeHostResolvConf is cli() (internal/cli's entry point, invoked
// directly), wrapped in the SAME outer-bwrap /etc overlay
// runWithFakeHostResolvConf uses — needed so --dry-run's own hostNameservers()
// read sees the fixture too, not the real host's file.
func cliWithFakeHostResolvConf(t *testing.T, resolvConf string, args ...string) (string, int) {
	t.Helper()
	bwrapArgs := append([]string{"--dev-bind", "/", "/"}, resolvConfOverlay(t, resolvConf)...)
	bwrapArgs = append(append(bwrapArgs, "--share-net", "--", snugBin), args...)

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bwrap", bwrapArgs...)
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	out, err := cmd.CombinedOutput()

	if errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("the outer bwrap exited but something it started still holds its output "+
			"pipe after %s:\n%s", waitDelay, out)
	}
	if ctx.Err() != nil {
		t.Fatalf("the outer bwrap did not finish within %s (a hang is a finding):\n%s", cmdTimeout, out)
	}
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running the outer bwrap: %v\n%s", err, out)
		}
		code = ee.ExitCode()
	}
	return string(out), code
}

// runWithFakeHostResolvConf runs a scripted sandbox payload with snug ITSELF
// wrapped in an outer bwrap that overlays an /etc carrying a FIXTURE
// resolv.conf (fakeHostEtc) — the only way to make hostNameservers()
// (internal/cli/main.go) read something other than this real machine's file,
// since it reads the fixed path directly rather than through an injected
// Environ.
//
// --dev-bind / / keeps everything else exactly as the real host is;
// --share-net is what lets the sandbox snug creates INSIDE this wrapper still
// reach the real network for pasta's egress — the outer bwrap must not put
// itself in a netns of its own, or every DNS/egress assertion downstream
// would be testing the wrapper instead of snug.
func runWithFakeHostResolvConf(t *testing.T, fixture string, args []string, dir, script string) sandboxRun {
	t.Helper()

	full := append(append([]string{}, args...), dir, "--", "/bin/bash", "-c",
		"printf '%s\\n' "+payloadMarker+"\n"+script)
	out, code := cliWithFakeHostResolvConf(t, fixture, full...)

	ran := false
	var kept []string
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == payloadMarker {
			ran = true
			continue
		}
		kept = append(kept, line)
	}
	return sandboxRun{out: strings.Join(kept, "\n"), ran: ran, code: code}
}

// TestTheFakeResolvConfHarnessReallySubstitutes is the harness's own
// regression test, and the only POSITIVE use of the overlay in this file: the
// fixture names a resolver this host does not have, and both the generated
// file inside the sandbox and --dry-run's screen must name it back.
//
// Every other assertion here is a negative — "no nameserver directive inside"
// — and a negative passes just as well when the overlay silently fails to
// apply. It nearly did: bubblewrap's CVE-2026-87766 fix refuses to mount on a
// symlink destination, which is what /etc/resolv.conf is on every
// systemd-resolved host, and the harness answered by copying the whole of /etc
// per call until budget()'s watchdog killed the test at 20s naming neither
// bwrap nor DNS. See resolvConfDest.
//
// 198.51.100.53 is TEST-NET-2 (RFC 5737), routable as far as
// RoutableNameservers is concerned and reachable by nothing.
func TestTheFakeResolvConfHarnessReallySubstitutes(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	const fixture = "nameserver 198.51.100.53\n"
	r := runWithFakeHostResolvConf(t, fixture, []string{"-p", "@net"}, proj,
		`cat /etc/resolv.conf`).mustRun(t)
	if !strings.Contains(r.out, "nameserver 198.51.100.53") {
		t.Errorf("the sandbox was not told about the fixture's resolver, so the outer "+
			"wrapper's /etc/resolv.conf overlay did not reach hostNameservers and every "+
			"other test in this file is asserting against this host's real resolvers:\n%s", r.out)
	}

	screen, code := cliWithFakeHostResolvConf(t, fixture, "--dry-run", "-p", "@net", proj, "--", "true")
	if code != 0 {
		t.Fatalf("--dry-run -p @net exited %d:\n%s", code, screen)
	}
	if !strings.Contains(screen, "198.51.100.53") {
		t.Errorf("--dry-run's dns line does not name the fixture's resolver:\n%s", screen)
	}
}

// TestNoResolverHostFailsFastAndSaysSo is issue #162's remnant: a host that
// names no nameserver at all used to be handed `nameserver 169.254.1.1`
// regardless, with nothing behind it — every lookup inside waited out a
// multi-second stall. Fixed by naming NONE, which fails in milliseconds
// rather than seconds, and the host side warns why.
func TestNoResolverHostFailsFastAndSaysSo(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	start := time.Now()
	r := runWithFakeHostResolvConf(t, "", []string{"-p", "@net"}, proj,
		`cat /etc/resolv.conf; getent hosts example.com; echo "exit=$?"`).mustRun(t)
	elapsed := time.Since(start)

	// A 5s bound cannot pass on the old 40s-per-lookup behaviour, and is
	// generous next to the 2ms this fix measures — this is a smoke bound
	// against a regression to the old stall, not a tight timing assertion.
	if elapsed > 5*time.Second {
		t.Errorf("the sandbox took %s to fail a lookup with no resolver at all — the old "+
			"behaviour (naming the interception address with nothing behind it) stalled "+
			"~40s per lookup; this should fail in milliseconds:\n%s", elapsed, r.out)
	}
	// A real `nameserver <addr>` DIRECTIVE line, not a bare substring match —
	// the warning this same run prints, and ResolvConf()'s own comment, both
	// legitimately say the word "nameserver" in PROSE, so a raw
	// strings.Contains would fail on the fix's own honest message.
	for _, line := range strings.Split(r.out, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "nameserver" {
			t.Errorf("a host naming no resolver at all still produced a nameserver directive "+
				"inside (%q):\n%s", line, r.out)
		}
	}
	if strings.Contains(r.out, "exit=0") {
		t.Errorf("getent succeeded with no resolver configured, which should be impossible:\n%s", r.out)
	}

	screen, code := cliWithFakeHostResolvConf(t, "",
		"--dry-run", "-p", "@net", proj, "--", "true")
	if code != 0 {
		t.Fatalf("--dry-run -p @net exited %d:\n%s", code, screen)
	}
	if !strings.Contains(screen, "NONE") {
		t.Errorf("--dry-run does not print the 'dns NONE' arm for a host with no resolver at all:\n%s", screen)
	}

	// The host-side warning (internal/cli/main.go), on the real run rather
	// than --dry-run — the message says it is suppressed there because the
	// NETWORK block already carries the fact.
	//
	// UNDER -v, and the flag is the assertion rather than a way to make the
	// test pass. This is an ASIDE in the collector's sense (internal/cli/notes.go,
	// issue #541): the warning's own comment at the site says why it is not an
	// invariant-5 downgrade — "a missing resolver is not a guarantee that no
	// longer holds; the sandbox is unchanged, a payload with no DNS is strictly
	// less capable". A boundary that got weaker prints unconditionally; a
	// sandbox that can do less waits to be asked.
	warn := runWithFakeHostResolvConf(t, "", []string{"-v", "-p", "@net"}, proj, `true`).mustRun(t)
	if !strings.Contains(warn.out, "this host names no nameserver") {
		t.Errorf("no warning was printed under -v for a host naming no resolver at all while "+
			"a profile asked for DNS:\n%s", warn.out)
	}
	// AND THE NEGATIVE, which is the half that is actually new: without -v the
	// same run says nothing. Issue #541's complaint was a wall of startup text
	// erased by the TUI that started a moment later, and a "quiet by default"
	// that still printed this line would not have fixed it.
	quiet := runWithFakeHostResolvConf(t, "", []string{"-p", "@net"}, proj, `true`).mustRun(t)
	if strings.Contains(quiet.out, "this host names no nameserver") {
		t.Errorf("the no-resolver warning still reached a quiet run's stderr. It is an aside: "+
			"-v and both screens carry it, an ordinary run does not (issue #541):\n%s", quiet.out)
	}
}
