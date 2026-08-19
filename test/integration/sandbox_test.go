//go:build integration

// Package integration launches real sandboxes and asserts what is and is not
// reachable from inside them.
//
// These are Go tests rather than shell in a CI workflow, and the difference is
// not cosmetic. The shell version hung a CI job for eleven minutes because a
// backgrounded listener held the step's stdout open; every assertion had
// passed. In Go the listener is a net.Listener owned by the test and closed by
// t.Cleanup.
//
// That is not by itself enough, and the earlier version of this comment claimed
// more than it delivered: it said "there is no stdout pipe for a child to
// inherit", which is false. exec.Cmd.CombinedOutput — and any Cmd whose Stdout
// is not an *os.File — creates exactly such a pipe, and Wait does not return
// until every write end is closed. Killing snug does not close a pipe some
// grandchild is holding, so a CommandContext timeout bounds the process and not
// the wait. Every Cmd here therefore sets WaitDelay; see waitDelay.
//
// The rest of what it buys: one language instead of three, named subtests
// instead of `echo FAIL; exit 1`, structured failure output, `t.Skip` with a
// reason when the host cannot run sandboxes at all, and — most importantly —
// every redteam finding becomes a permanent NAMED test, which is what the
// definition of done in CLAUDE.md actually requires.
//
//	go test -tags integration ./test/integration/...
//	make integration
//
// VERIFY.md still exists and is not redundant: it is for a human checking
// by hand, with the reasoning inline. This is the automated ratchet.
//
// # Two environment knobs, deliberately separate
//
//   - SNUG_REQUIRE_SANDBOX=1 — "this host MUST be able to run sandboxes".
//     Every skip that means "the host cannot do this" becomes a failure. CI sets
//     it, because a green run that silently checked nothing is the same failure
//     mode as a silent security downgrade. A laptop without bubblewrap leaves it
//     unset and degrades to skips.
//   - SNUG_TEST_NET=1 — "outbound internet is permitted from here". A separate
//     concern: a developer may have a working sandbox and still not want the
//     suite reaching example.com. CI sets both.
//
// # These tests are deliberately NOT parallel
//
// Several of them observe global state — the set of pasta processes on the host,
// the host's own loopback — and one of them uses t.Setenv, which forbids
// t.Parallel outright. A useful side effect: wall-clock time IS test time, so
// the budget helper below measures what it claims to.
//
// # Negative assertions must be fast
//
// "Nothing happened" is never proven by waiting out a long timeout. A TCP
// connect to a port nobody is listening on returns ECONNREFUSED in microseconds;
// only a DROPPED packet makes you wait, and a drop is a weaker observation than
// a refusal anyway — so where these tests can, they assert the refusal itself
// and report a timeout as a defect in the probe.
//
// Where a wait genuinely cannot be avoided it is a wait for an event that WILL
// arrive (a file appearing, a process exiting), the deadline is a backstop
// rather than the measurement, and the bound is justified in a comment at the
// site.
//
// # Every test has a time budget
//
// budget() gives each test a wall-clock allowance. Over it, the test fails and
// names itself; at twice it, a watchdog panics. The point is that a future slow
// or hanging test produces an attributable failure in seconds instead of
// silently eating the CI job's whole -timeout allowance and ending in an
// anonymous goroutine dump.
package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

var (
	snugBin string

	// emptyConfig is an empty $XDG_CONFIG_HOME handed to every snug invocation.
	// See baseEnv.
	emptyConfig string

	// pidfdProbeBin is testdata/pidfdprobe, built once here for the same
	// reason snugBin is: pidfd_getfd, process_vm_readv and process_vm_writev
	// are not shell-reachable (no builtin or /bin/* utility calls them), so
	// issue #23's regression tests (pidfd_test.go) need a compiled helper
	// rather than a bash script. See that file's package doc for why the
	// probe targets the calling process itself rather than a sibling.
	pidfdProbeBin string
)

// cmdTimeout bounds every snug invocation. Nothing in this suite should take
// anywhere near this long; the point is that a hang produces a named failure
// with output instead of the whole package dying on go test's global -timeout.
//
// It was 90s, which was not a bound so much as a gesture: one test makes twenty
// invocations, so a systematic hang cost half an hour inside a single test and
// the job ended on go test's -timeout with no idea which test was to blame. The
// slowest legitimate invocation in the suite is TestEgressWorks, whose curl is
// itself capped at 10s; 30s is three times that and roughly two hundred times
// every other invocation observed locally.
const cmdTimeout = 30 * time.Second

// exitPolicyCode mirrors internal/cli's unexported exitPolicy (main.go). Repeated
// here rather than imported: this package cannot see it (it is unexported in
// package main, and this suite deliberately drives the built binary rather
// than linking against it — see the package doc above), so a change to the
// exit-code scheme in main.go and a change to the number below are two
// separate edits. If internal/cli ever changes what exitPolicy means, the tests
// that use this constant are exactly what should go red.
const exitPolicyCode = 77

// waitDelay bounds Wait() AFTER the process has gone.
//
// os/exec gives a Cmd whose Stdout is not an *os.File a pipe, and Wait blocks
// until every write end of that pipe is closed — including ends held by
// grandchildren snug never knew about. Without this, a leaked descriptor turns
// cmdTimeout into a suggestion: the context kills snug and Wait keeps waiting.
// With it, Wait returns ErrWaitDelay and the test reports a real finding.
//
// Two seconds is generous: by the time it starts counting the process has
// already exited, so all that remains is for the kernel to flush a pipe.
const waitDelay = 2 * time.Second

// defaultBudget is the wall-clock allowance for a test that says nothing else.
//
// Every test but four runs in well under a second on a developer machine, so
// ten seconds is not a performance target — it is a tripwire with an order of
// magnitude of slack for a loaded shared runner. A test that trips it is either
// hanging or has quietly acquired a sleep.
const defaultBudget = 10 * time.Second

// budget gives a test a wall-clock allowance, in two halves that do different
// jobs.
//
// The soft half reports afterwards, so the rest of the suite still runs and the
// failure names the test and the overrun. The hard half is a watchdog that
// panics at twice the budget, on the assumption that a test that far over is
// hung rather than slow: a panic names the test in its message, whereas letting
// go test's -timeout fire produces a dump of every goroutine in the process and
// costs the job its entire remaining allowance.
//
// Registered first in each test, so — t.Cleanup being LIFO — it runs last and
// measures the whole test including its own fixtures' teardown.
func budget(t *testing.T, d ...time.Duration) {
	t.Helper()
	limit := defaultBudget
	if len(d) > 0 {
		limit = d[0]
	}

	start := time.Now()
	name := t.Name()
	stop := make(chan struct{})

	go func() {
		select {
		case <-stop:
		case <-time.After(2 * limit):
			panic(fmt.Sprintf("integration: %s has run for more than twice its %s "+
				"time budget and is presumed hung. Nothing here should take seconds; "+
				"a negative assertion in particular must never be waiting out a timeout.",
				name, limit))
		}
	}()

	t.Cleanup(func() {
		close(stop)
		if el := time.Since(start); el > limit {
			t.Errorf("%s took %s, over its %s time budget. Either it acquired a wait "+
				"it does not need, or this host is far slower than the one the budget "+
				"was set on — decide which before raising the number.",
				name, el.Round(time.Millisecond), limit)
		}
	})
}

// payloadMarker is echoed by every scripted payload before anything else.
//
// Without it, most of the negative tests below pass vacuously: "the sandbox did
// not reach the host loopback" is equally true when snug failed to start at all.
// run() strips the marker line back out so assertions see only the payload's own
// output.
const payloadMarker = "__snug_payload_ran__"

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "snug-integration")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	snugBin = filepath.Join(dir, "snug")
	build := exec.Command("go", "build", "-o", snugBin, "./cmd/snug")
	build.Dir = "../.."
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building snug:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}

	emptyConfig = filepath.Join(dir, "xdg-config")
	if err := os.MkdirAll(emptyConfig, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.RemoveAll(dir)
		os.Exit(1)
	}

	pidfdProbeBin = filepath.Join(dir, "pidfdprobe")
	buildPidfdProbe := exec.Command("go", "build", "-o", pidfdProbeBin, "./test/integration/testdata/pidfdprobe")
	buildPidfdProbe.Dir = "../.."
	buildPidfdProbe.Stderr = os.Stderr
	if err := buildPidfdProbe.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building pidfdprobe:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// ── host capability gates ───────────────────────────────────────────────────

// skipOrFail skips, unless SNUG_REQUIRE_SANDBOX says this host is supposed to be
// able to do the thing — in which case it fails.
//
// A silent skip is the same failure mode as a silent security downgrade: the
// suite goes green having checked nothing. Developers get graceful degradation;
// CI gets an assertion.
func skipOrFail(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("SNUG_REQUIRE_SANDBOX") != "" {
		t.Fatalf("SNUG_REQUIRE_SANDBOX is set, so this may not be skipped: "+format, args...)
	}
	t.Skipf(format, args...)
}

// requireSandbox gates on this host being able to create a user namespace at
// all. The probe is raw bwrap, deliberately not snug: a bug in snug must not be
// able to turn the whole suite into skips.
func requireSandbox(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		skipOrFail(t, "bubblewrap is not installed")
	}
	probe := exec.Command("bwrap", "--unshare-all", "--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev",
		"--die-with-parent", "--", "/bin/true")
	if out, err := probe.CombinedOutput(); err != nil {
		skipOrFail(t, "cannot create a user namespace here (see "+
			"kernel.apparmor_restrict_unprivileged_userns and "+
			"kernel.unprivileged_userns_clone): %s", strings.TrimSpace(string(out)))
	}
}

// requirePasta gates on pasta being installed AND new enough to understand the
// flags snug's whole network posture rests on.
//
// The version check is not defensive programming, it is triage. --map-host-loopback
// and --map-guest-addr arrived in passt 2024_08_21; Debian/Ubuntu stable images
// can be older than that. On such a host pasta exits instantly with
// "unrecognized option", snug correctly refuses to run the payload, and every
// single -p net test fails with a different confusing message about the network
// not coming up. One named failure that says "your passt is too old" is worth an
// afternoon.
func requirePasta(t *testing.T) {
	t.Helper()
	pasta, err := exec.LookPath("pasta")
	if err != nil {
		skipOrFail(t, "pasta is not installed (package passt)")
	}
	// pasta --help exits non-zero, so the output is what matters, not the code.
	help, _ := exec.Command(pasta, "--help").CombinedOutput()
	if !strings.Contains(string(help), "--map-host-loopback") {
		skipOrFail(t, "this pasta does not support --map-host-loopback, which snug "+
			"passes to close the host loopback; it predates passt 2024_08_21. "+
			"Every -p net check would fail for that reason alone. Upgrade passt.\n"+
			"      %s", firstLine(capture(pasta, "--version")))
	}
}

func capture(name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return string(out)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func requirePython(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		skipOrFail(t, "python3 is not installed and this check needs it")
	}
}

// requireInternet gates the tests that reach the public internet. Whether
// outbound traffic is acceptable is a policy of the machine running the suite
// rather than a capability it either has or lacks, so on a laptop this is a
// plain skip.
//
// Under SNUG_REQUIRE_SANDBOX it is a failure, because otherwise dropping
// SNUG_TEST_NET from the CI workflow would silently delete the egress coverage —
// exactly the "green run that checked nothing" this suite exists to prevent.
func requireInternet(t *testing.T) {
	t.Helper()
	if os.Getenv("SNUG_TEST_NET") != "" {
		return
	}
	if os.Getenv("SNUG_REQUIRE_SANDBOX") != "" {
		t.Fatal("SNUG_REQUIRE_SANDBOX is set but SNUG_TEST_NET is not: " +
			"set SNUG_TEST_NET=1 to allow the tests that reach the internet, " +
			"or unset SNUG_REQUIRE_SANDBOX to let them skip")
	}
	t.Skip("SKIP: set SNUG_TEST_NET=1 to allow tests that reach the internet")
}

// ── plumbing ────────────────────────────────────────────────────────────────

// target builds a throwaway project directory with a sibling beside it and a
// secret above it, mirroring the shape VERIFY.md uses.
//
//	root/                 (two levels above the target — must be invisible)
//	  SECRET
//	  proj/               (the parent — dotdot grants this read-only)
//	    sibling/
//	    sub/              (the target — writable)
func target(t *testing.T) (proj, secret string) {
	t.Helper()
	root := t.TempDir()
	proj = filepath.Join(root, "proj", "sub")
	if err := os.MkdirAll(filepath.Join(root, "proj", "sibling"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	secret = filepath.Join(root, "SECRET")
	if err := os.WriteFile(secret, []byte("must-not-be-readable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return proj, secret
}

// baseEnv is the environment every snug invocation in this suite gets.
//
// XDG_CONFIG_HOME points at an empty directory on purpose. snug reads
// $XDG_CONFIG_HOME/snug/profiles.d and $XDG_CONFIG_HOME/snug/config.toml, so
// without this a developer with their own profiles — or a `default_profile`
// preference — would be testing a different sandbox from CI, and a test could
// pass or fail for reasons unrelated to the code. Tests that need their own
// profile layer append their own XDG_CONFIG_HOME; os/exec keeps the LAST
// duplicate, so theirs wins.
func baseEnv(extra ...string) []string {
	env := append(os.Environ(), "XDG_CONFIG_HOME="+emptyConfig, "SNUG_TEST=1")
	return append(env, extra...)
}

// cli invokes snug directly and returns its combined output and exit code. It is
// the bottom of the stack: `run` and the --dry-run tests both sit on it.
func cli(t *testing.T, env []string, args ...string) (string, int) {
	t.Helper()
	if env == nil {
		env = baseEnv()
	}

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, snugBin, args...)
	cmd.Env = env
	cmd.WaitDelay = waitDelay
	out, err := cmd.CombinedOutput()

	if errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("snug %s exited but something it started still holds its output pipe "+
			"after %s — that is a leaked descriptor and a finding:\n%s",
			strings.Join(args, " "), waitDelay, out)
	}
	if ctx.Err() != nil {
		t.Fatalf("snug %s did not finish within %s (a hang is a finding):\n%s",
			strings.Join(args, " "), cmdTimeout, out)
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running snug %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out), ee.ExitCode()
	}
	return string(out), 0
}

// sandboxRun is the outcome of running a scripted payload inside a sandbox.
type sandboxRun struct {
	out  string // combined stdout+stderr, with the marker line removed
	ran  bool   // the payload actually started (see payloadMarker)
	code int    // snug's exit code, which is the payload's when it ran
}

// mustRun fails unless the payload actually executed. Call it in every test
// whose assertion is a negative — "the sandbox could not reach X" is trivially
// true of a sandbox that never started.
func (r sandboxRun) mustRun(t *testing.T) sandboxRun {
	t.Helper()
	if !r.ran {
		t.Fatalf("the payload never ran, so this test would prove nothing (snug exited %d):\n%s",
			r.code, r.out)
	}
	return r
}

// run executes a shell script inside a sandbox.
//
// The argument order is snug's documented one, `snug [flags] [dir] [-- cmd ...]`:
// parseArgs takes the first non-flag word as the target directory and hands
// everything after `--` to the payload verbatim.
func run(t *testing.T, args []string, dir, script string) sandboxRun {
	t.Helper()
	return runEnv(t, nil, args, dir, script)
}

func runEnv(t *testing.T, env, args []string, dir, script string) sandboxRun {
	t.Helper()
	full := append(append([]string{}, args...), dir, "--", "/bin/bash", "-c",
		"printf '%s\\n' "+payloadMarker+"\n"+script)

	out, code := cli(t, env, full...)

	ran := false
	kept := make([]string, 0, 8)
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == payloadMarker {
			ran = true
			continue
		}
		kept = append(kept, line)
	}
	return sandboxRun{out: strings.Join(kept, "\n"), ran: ran, code: code}
}

// ── the filesystem boundary ─────────────────────────────────────────────────

func TestUngrantedPathsAreAbsent(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, secret := target(t)

	// CONTROL: the file exists and IS readable from the host. "The sandbox could
	// not read it" is trivially true of a file that was never written.
	if got, err := os.ReadFile(secret); err != nil || !strings.Contains(string(got), "must-not-be-readable") {
		t.Fatalf("precondition: the secret is not readable on the host (%v), so the "+
			"assertion below would prove nothing", err)
	}

	// Absent, not permission-denied. There is nothing there to deny access to.
	r := run(t, nil, proj, fmt.Sprintf(
		`ls %s 2>&1; ls ~/.ssh 2>&1; ls /sys 2>&1`, secret)).mustRun(t)

	for _, want := range []string{secret, ".ssh", "/sys"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("expected a mention of %s in output:\n%s", want, r.out)
		}
	}
	if strings.Contains(r.out, "must-not-be-readable") {
		t.Errorf("the sandbox READ a secret above the target:\n%s", r.out)
	}
	if strings.Contains(r.out, "Permission denied") {
		t.Errorf("paths should be absent, not denied — a denial implies they were mounted:\n%s", r.out)
	}
}

func TestTargetWritableParentReadOnly(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	if r := run(t, nil, proj, `touch ok`).mustRun(t); r.code != 0 {
		t.Errorf("target should be writable: %s", r.out)
	}
	if r := run(t, nil, proj, `touch ../NOPE`).mustRun(t); r.code == 0 {
		t.Error("the parent directory should be read-only")
	}
}

// One sandbox for all six directories, not six.
//
// The six-launch version was the second slowest test in the suite and, more to
// the point, the one with the least headroom against its budget: on a machine
// with twice as many spinning processes as cores it took 6.6s of its 10s, purely
// in namespace setup it repeated six times. The directories are independent, the
// payload names whichever ones it managed to write, and the assertion is
// unchanged — a failure still says exactly which directory was writable.
func TestRootSkeletonIsReadOnly(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	dirs := []string{"/", "/home", "/usr", "/etc", "/var", "/proc"}
	var script strings.Builder
	for _, dir := range dirs {
		fmt.Fprintf(&script, "touch %s/ZZ 2>/dev/null && echo WRITABLE:%s\n", dir, dir)
	}
	// Proves the loop ran to the end, so "no WRITABLE lines" cannot be satisfied
	// by a payload that died on the first touch.
	//
	// The second line is the positive control: the same `touch`, in the same
	// payload, on the one directory that IS supposed to be writable. Without it
	// "nothing was writable" is equally true of a sandbox where nothing is
	// writable at all, or where the shell's touch is broken.
	script.WriteString("touch ./CONTROL 2>/dev/null && echo CONTROL-WRITABLE\n")
	script.WriteString("echo CHECKED-ALL\n")

	r := run(t, nil, proj, script.String()).mustRun(t)
	// Matched line by line, not by substring: "WRITABLE:/" is a prefix of
	// "WRITABLE:/home", so a substring test would report / as writable whenever
	// /home was.
	said := map[string]bool{}
	for _, line := range strings.Split(r.out, "\n") {
		said[strings.TrimSpace(line)] = true
	}
	for _, dir := range dirs {
		if said["WRITABLE:"+dir] {
			t.Errorf("%s is writable inside the sandbox:\n%s", dir, r.out)
		}
	}
	if !said["CHECKED-ALL"] {
		t.Errorf("the payload did not reach the end, so the checks above prove nothing:\n%s", r.out)
	}
	if !said["CONTROL-WRITABLE"] {
		t.Errorf("the target itself was not writable, so `touch` proves nothing about "+
			"the skeleton directories above:\n%s", r.out)
	}
}

// /dev is writable and that surprises people — it surprised the author, and it
// was found by running VERIFY.md rather than by review. It is bwrap's own
// synthetic device tree on a private tmpfs, so what matters is not that it is
// read-only (it is not) but that a write there reaches neither the host nor the
// next sandbox. Say "the only writable thing that PERSISTS", never "the only
// writable thing".
//
// # The identity check, and why the escape check alone was vacuous
//
// This test used to open with "if the write failed, t.Skip". Bind the HOST's
// /dev into the sandbox and the write fails with EACCES — an unprivileged user
// cannot create a file in /dev — so the test SKIPPED, silently, on precisely the
// escape it exists to detect. Under SNUG_REQUIRE_SANDBOX too: skipOrFail was not
// used, so the "a green run that checked nothing" guard did not apply.
//
// The fix is to lead with a check that cannot be skipped and does not depend on
// writing anything: the sandbox's /dev must be bwrap's fourteen-entry synthetic
// tree, not the host's. The host-only entry is discovered at runtime rather than
// hard-coded, so it cannot rot into another literal that matches nothing.
func TestDevIsWritableButNeitherPersistsNorEscapes(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	// bwrap's --dev creates exactly this set. Anything the HOST has in /dev that
	// is not in it is a fingerprint of the host's device tree.
	synthetic := map[string]bool{
		"console": true, "core": true, "fd": true, "full": true, "null": true,
		"ptmx": true, "pts": true, "random": true, "shm": true, "stderr": true,
		"stdin": true, "stdout": true, "tty": true, "urandom": true, "zero": true,
	}
	entries, err := os.ReadDir("/dev")
	if err != nil {
		t.Fatal(err)
	}
	hostOnly := ""
	for _, e := range entries {
		if !synthetic[e.Name()] {
			hostOnly = e.Name()
			break
		}
	}
	if hostOnly == "" {
		t.Fatal("the host's /dev contains nothing outside bwrap's synthetic set, so " +
			"there is no way to tell the two apart and this test would prove nothing")
	}

	r := run(t, nil, proj, `ls /dev
echo "---"
echo pwned > /dev/ESCAPE_PROBE 2>&1 && echo DEV-WRITABLE || echo DEV-READ-ONLY
echo CHECKED-ALL`).mustRun(t)
	if !strings.Contains(r.out, "CHECKED-ALL") {
		t.Fatalf("the payload did not reach the end:\n%s", r.out)
	}

	listing, _, _ := strings.Cut(r.out, "---")
	seen := map[string]bool{}
	for _, line := range strings.Split(listing, "\n") {
		seen[strings.TrimSpace(line)] = true
	}
	// Control: we really listed a device tree, so the absence below is a fact
	// about /dev and not about `ls` having failed.
	if !seen["null"] {
		t.Fatalf("/dev inside the sandbox does not even contain `null`, so it was not "+
			"listed and the check below proves nothing:\n%s", r.out)
	}
	if seen[hostOnly] {
		t.Errorf("the sandbox's /dev contains %q, which only the HOST's /dev has — "+
			"this is a bind of the host device tree, not bwrap's synthetic one:\n%s",
			hostOnly, r.out)
	}

	// The escape check. It runs whether or not the write succeeded; a failed
	// write is reported, never skipped over, because "we could not write" is
	// itself a signal that /dev is not the private tmpfs it should be.
	if _, err := os.Stat("/dev/ESCAPE_PROBE"); err == nil {
		os.Remove("/dev/ESCAPE_PROBE")
		t.Fatal("a write to /dev inside the sandbox reached the HOST's /dev")
	}
	if strings.Contains(r.out, "DEV-READ-ONLY") {
		t.Logf("/dev was not writable here, which is tighter than the documented "+
			"behaviour. The identity check above still ran:\n%s", r.out)
		return
	}

	next := run(t, nil, proj, `ls /dev/ESCAPE_PROBE 2>&1`).mustRun(t)
	if next.code == 0 {
		t.Errorf("a write to /dev survived into the next sandbox:\n%s", next.out)
	}
}

// dotdot grants the target's PARENT, so siblings are readable — that is what
// makes ../other-package work in a monorepo, and it is intentional. What must
// never be reachable is anything above the parent.
func TestDotdotGrantsTheParentAndNothingAbove(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, secret := target(t)

	r := run(t, nil, proj, `ls ..`).mustRun(t)
	for _, want := range []string{"sibling", "sub"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("dotdot should expose the parent's contents; %q missing from:\n%s", want, r.out)
		}
	}

	above := filepath.Dir(filepath.Dir(proj))
	r = run(t, nil, proj, "ls "+above+" 2>&1; cat "+secret+" 2>&1").mustRun(t)
	if strings.Contains(r.out, "must-not-be-readable") {
		t.Errorf("the grandparent directory was reachable:\n%s", r.out)
	}

	// Drop parent-ro and the parent's other children disappear. Only the
	// directory bwrap had to create to host the target's bind mount remains.
	r = run(t, []string{"--no-defaults", "-p", "@sys", "-p", "@home", "-p", "@cwd-rw"},
		proj, `ls ..`).mustRun(t)
	if strings.Contains(r.out, "sibling") {
		t.Errorf("without parent-ro the sibling must not be visible:\n%s", r.out)
	}
	// Positive control for the line above. "sibling is not in the output" is
	// equally true of a payload whose `ls ..` failed for an unrelated reason, so
	// require the listing to have happened at all.
	if r.code != 0 {
		t.Errorf("`ls ..` itself failed without parent-ro, so its silence about "+
			"the sibling proves nothing:\n%s", r.out)
	}
}

// CLAUDE.md invariant 1, second half, and the sentence it ends with is why this
// test exists: "Verified by execution, not inferred."
//
// Visibility is monotone, but effective WRITE access at a strict subpath is not:
// `join` is keyed by Mount.Guest, so grants at different depths become two
// mounts and the access at a path is that of the deepest mount covering it. A
// profile adding `ro {target}/.git` therefore DEMOTES .git inside an otherwise
// writable target. TestResolveDeeperMountWins in internal/policy proves the
// resolver computes that; only running it proves bwrap honours the ordering.
//
// (This replaced a test for `--read-only`, a CLI clamp that no longer exists —
// the flag was removed and parseArgs now rejects it as unknown, so the test had
// stopped exercising anything. Same invariant, mechanism that still ships.)
func TestADeeperReadOnlyGrantDemotesASubpathOfTheWritableTarget(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// CONTROL. Without the demoting profile .git is writable like the rest of the
	// target, so the refusal below is attributable to the profile and not to the
	// sandbox simply being broken.
	ctl := run(t, nil, proj, `touch .git/CONTROL && echo GIT-WRITABLE`).mustRun(t)
	if !strings.Contains(ctl.out, "GIT-WRITABLE") {
		t.Fatalf("precondition: .git should be writable without the demoting profile:\n%s", ctl.out)
	}

	cfg := t.TempDir()
	dir := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "protect-git.toml"), []byte(
		"[profile.protect-git]\n"+
			"description = \"demote .git inside an otherwise writable target\"\n"+
			"ro = [\"{target}/.git\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := baseEnv("XDG_CONFIG_HOME=" + cfg)

	r := runEnv(t, env, []string{"-p", "protect-git"}, proj,
		`touch ./sibling-file && echo TARGET-STILL-WRITABLE
cat .git/HEAD
touch .git/DEMOTED 2>&1 && echo GIT-WRITABLE || echo GIT-READ-ONLY`).mustRun(t)

	if !strings.Contains(r.out, "GIT-READ-ONLY") {
		t.Errorf("a deeper `ro {target}/.git` grant did not demote .git:\n%s", r.out)
	}
	// Demoted, not removed: the tightening must leave the content readable, or
	// the "no subtraction" invariant is broken in the other direction.
	if !strings.Contains(r.out, "ref: refs/heads/main") {
		t.Errorf(".git was hidden rather than demoted; profiles may only ever grant:\n%s", r.out)
	}
	// And the demotion must be scoped to the deeper path, not to the whole target.
	if !strings.Contains(r.out, "TARGET-STILL-WRITABLE") {
		t.Errorf("the deeper grant demoted the whole target, not just .git:\n%s", r.out)
	}
}

// -p ADDS to the default rather than replacing it: naming a profile can never
// take anything away, and --no-default is the only way to start from nothing.
// The functional half matters more than the SNUG_PROFILES string — if -p
// replaced the default, /usr and a writable target would both vanish.
func TestProfileFlagAddsToTheDefaultRatherThanReplacingIt(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	r := run(t, []string{"-p", "@git-ro"}, proj,
		`ls /usr >/dev/null && echo SYS-PRESENT; touch ./x && echo TARGET-WRITABLE; echo "$SNUG_PROFILES"`).mustRun(t)
	for _, want := range []string{"SYS-PRESENT", "TARGET-WRITABLE"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("-p git-ro appears to have REPLACED the default (%s missing):\n%s", want, r.out)
		}
	}
	for _, want := range []string{"@git-ro", "@sys", "@cwd-rw"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("SNUG_PROFILES should list %q:\n%s", want, r.out)
		}
	}

	// --no-defaults is the escape hatch, and it really does start from nothing.
	//
	// The name of the profile being looked for is load-bearing, and the previous
	// version of this check got it wrong in the way this file exists to prevent:
	// it asserted the absence of "dotdot", a profile that was renamed to
	// `parent-ro` and therefore could never appear in SNUG_PROFILES at all. The
	// assertion was structurally unable to fail. The guard against a repeat is
	// the positive half below — the same string MUST be present without
	// --no-defaults, so a future rename turns this into a failure rather than
	// into silence.
	const fromDefaults = "@parent-ro"

	withDefaults := run(t, nil, proj, `echo "$SNUG_PROFILES"`).mustRun(t)
	if !strings.Contains(withDefaults.out, fromDefaults) {
		t.Fatalf("the defaults no longer include %q, so asserting its ABSENCE below "+
			"would prove nothing. Update the constant to a profile the defaults "+
			"really contain:\n%s", fromDefaults, withDefaults.out)
	}

	r = run(t, []string{"--no-defaults", "-p", "@sys", "-p", "@home", "-p", "@cwd-rw"},
		proj, `echo "$SNUG_PROFILES"`).mustRun(t)
	if strings.Contains(r.out, fromDefaults) {
		t.Errorf("--no-defaults should not pull in the defaults' profiles:\n%s", r.out)
	}
	if !strings.Contains(r.out, "@sys") {
		t.Errorf("SNUG_PROFILES was not printed at all, so the check above is "+
			"satisfied by empty output:\n%s", r.out)
	}
}

// ── the process boundary ────────────────────────────────────────────────────

// REGRESSION (redteam, M0): bwrap is PID 1 of the sandbox's own PID namespace
// and runs as the same uid, so /proc/1/environ was readable and held the entire
// host environment — 106 variables including SSH_AUTH_SOCK — while the
// payload's own env was correctly clean.
//
// t.Setenv puts the canary in this process's environment; baseEnv passes
// os.Environ() through to snug, so the variable genuinely reaches snug. On the
// pre-fix build exec.Cmd had a nil Env, which means os.Environ() — snug's whole
// environment, canary included — became bwrap's, and therefore /proc/1/environ.
func TestNoHostEnvironmentViaPid1(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	t.Setenv("SNUG_CANARY_MUST_NOT_APPEAR", "canary-secret-value")

	// Confirm the canary is really in the environment snug is launched with,
	// otherwise the assertion below is vacuous.
	if os.Getenv("SNUG_CANARY_MUST_NOT_APPEAR") == "" {
		t.Fatal("precondition: the canary is not in this process's environment")
	}

	r := run(t, nil, proj,
		`tr '\0' '\n' < /proc/1/environ; echo "--payload--"; printenv`).mustRun(t)

	if strings.Contains(r.out, "canary-secret-value") {
		t.Errorf("a host environment variable leaked into the sandbox:\n%s", r.out)
	}
	before, _, _ := strings.Cut(r.out, "--payload--")
	if strings.TrimSpace(before) != "" {
		t.Errorf("/proc/1/environ is not empty:\n%s", before)
	}
}

// REGRESSION (redteam, M1): --seccomp was appended after bwrap's `--`
// separator, so bwrap treated it as an argument to the payload and installed
// nothing. Exit code 0, no warning; Seccomp: 0 was the only evidence.
//
// Requested is not the same as active, which is why this reads the kernel's own
// view rather than snug's claim.
func TestSeccompIsActuallyInstalled(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	r := run(t, nil, proj, `grep '^Seccomp:' /proc/self/status`).mustRun(t)

	mode := ""
	for _, line := range strings.Split(r.out, "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "Seccomp:" {
			mode = f[1]
		}
	}
	if mode != "2" {
		t.Errorf("Seccomp mode is %q, want \"2\" (filter). Requested is not the same as active:\n%s",
			mode, r.out)
	}
}

// The filter must deny the syscalls it claims to deny. A mode-2 filter that
// allows everything would satisfy the check above and nothing else.
func TestSeccompDeniesTheHardeningSyscalls(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePython(t)
	proj, _ := target(t)

	// x86_64 syscall numbers, as in VERIFY.md §6c. userfaultfd is
	// deliberately absent: many kernels already refuse it via
	// vm.unprivileged_userfaultfd, so it cannot distinguish our filter from the
	// host's default.
	probe := `import ctypes, os
libc = ctypes.CDLL("libc.so.6", use_errno=True)
for name, nr in [("ptrace",101),("add_key",248),("keyctl",250),
                 ("perf_event_open",298),("bpf",321)]:
    ctypes.set_errno(0)
    libc.syscall(nr, 0, 0, 0, 0, 0)
    e = ctypes.get_errno()
    print("%s=%s" % (name, os.strerror(e) if e else "ALLOWED"))
`
	if err := os.WriteFile(filepath.Join(proj, "probe.py"), []byte(probe), 0o644); err != nil {
		t.Fatal(err)
	}

	r := run(t, nil, proj, `python3 probe.py`).mustRun(t)
	for _, name := range []string{"ptrace", "add_key", "keyctl", "perf_event_open", "bpf"} {
		if !strings.Contains(r.out, name+"=Operation not permitted") {
			t.Errorf("%s is not denied by the seccomp filter:\n%s", name, r.out)
		}
	}

	// Control: with the filter off the host's own behaviour returns. Without
	// this the test could pass on a build where the payload never ran python.
	r = run(t, []string{"--no-seccomp"}, proj, `python3 probe.py`).mustRun(t)
	if !strings.Contains(r.out, "ptrace=ALLOWED") {
		t.Errorf("--no-seccomp did not restore host behaviour, so the check above "+
			"may not be measuring the filter:\n%s", r.out)
	}
}

// REGRESSION (redteam, M1): clone3 bypassed the CLONE_NEWUSER guard because
// classic BPF cannot dereference its argument pointer.
//
// Two positive controls, because a bare "the command exited non-zero" is the
// weakest possible evidence: `unshare: command not found` is also non-zero, and
// so is every other way the payload might fail. So the binary is located first,
// and the same command is shown to SUCCEED with the filter off.
func TestNestedUserNamespaceIsRefused(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	r := run(t, nil, proj,
		`command -v unshare >/dev/null || { echo NO-UNSHARE; exit 0; }
unshare -U /bin/true && echo NESTED-USERNS-CREATED || echo REFUSED
echo CHECKED`).mustRun(t)
	if strings.Contains(r.out, "NO-UNSHARE") {
		skipOrFail(t, "util-linux's unshare is not available inside the sandbox, so "+
			"this check has nothing to run")
	}
	if !strings.Contains(r.out, "CHECKED") {
		t.Fatalf("the payload did not reach the end:\n%s", r.out)
	}
	if strings.Contains(r.out, "NESTED-USERNS-CREATED") {
		t.Errorf("a nested user namespace was created; that is the standard escape "+
			"first move:\n%s", r.out)
	}

	// CONTROL: with the filter off the same command succeeds, so the refusal
	// above is attributable to seccomp and not to `unshare` failing for some
	// unrelated reason on this kernel.
	ctl := run(t, []string{"--no-seccomp"}, proj, `unshare -U /bin/true && echo CONTROL-CREATED`).mustRun(t)
	if !strings.Contains(ctl.out, "CONTROL-CREATED") {
		t.Errorf("--no-seccomp did not restore nested-userns creation, so the check "+
			"above may be measuring something other than the filter:\n%s", ctl.out)
	}
}

// clone3 must return ENOSYS, not EPERM: glibc's pthread_create falls back to
// clone() only on ENOSYS, and EPERM broke every threaded program — curl's
// resolver among them, which presented as a DNS failure and cost an hour in
// pasta before the cause turned out to be seccomp.
func TestThreadedProgramsStillWork(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePython(t)
	proj, _ := target(t)

	r := run(t, nil, proj,
		`python3 -c 'import threading; t=threading.Thread(target=lambda: None); t.start(); t.join(); print("threads ok")'`).mustRun(t)
	if r.code != 0 || !strings.Contains(r.out, "threads ok") {
		t.Errorf("threads do not work inside the sandbox (clone3 errno regression?):\n%s", r.out)
	}
}

// REGRESSION (redteam, M1): fds >2 are sealed CLOEXEC because a directory fd
// bypasses the mount policy entirely — openat(2) walks from that descriptor's
// own vfsmount and never consults the sandbox's mount namespace. Fds 0/1/2 were
// exempt so stdio could pass through, leaving the same hole standing on three
// well-known numbers. safeStdio now substitutes /dev/null for a directory.
//
// cmd.Stdin is an *os.File on purpose: os/exec passes an *os.File straight
// through as the child's descriptor 0. Any other io.Reader would be copied
// through an os.Pipe, the child would receive a pipe rather than a dirfd, and
// the test would prove nothing.
func TestDirectoryOnStdinCannotEscape(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, secret := target(t)

	dir, err := os.Open(filepath.Dir(secret))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, snugBin, proj, "--", "/bin/bash", "-c",
		`printf '%s\n' `+payloadMarker+`
ls /proc/self/fd/0/ 2>&1
cat /proc/self/fd/0/SECRET 2>&1`)
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	cmd.Stdin = dir
	raw, _ := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("snug did not finish within %s:\n%s", cmdTimeout, raw)
	}
	out := string(raw)

	if !strings.Contains(out, payloadMarker) {
		t.Fatalf("the payload never ran, so this test would prove nothing:\n%s", out)
	}
	if strings.Contains(out, "must-not-be-readable") {
		t.Errorf("a directory on stdin bypassed the mount policy:\n%s", out)
	}
	// The substitution must be announced. Silence here would mean the directory
	// simply failed to open for some unrelated reason.
	if !strings.Contains(out, "stdin is a directory") {
		t.Errorf("snug did not report replacing the directory on stdin with /dev/null:\n%s", out)
	}
}

// ── the environment boundary ────────────────────────────────────────────────

// envProfileLayer writes one throwaway profile into a fresh $XDG_CONFIG_HOME and
// returns the environment that selects it, with PATH REPLACED by hostPath.
//
// Replaced, not extended, because both tests below are about what the host's
// PATH does and does not contribute — one filters it, the other checks that a
// binary reachable only through it never runs — and a test that inherited the
// developer's PATH would be measuring a different string on every machine.
// os/exec keeps the LAST duplicate, so these win over the copy baseEnv inherits.
//
// hostPath must contain the directory holding bwrap: snug finds it with
// exec.LookPath against its own environment, so a PATH that omits it turns every
// assertion below into "snug could not start".
func envProfileLayer(t *testing.T, file, toml, hostPath string) []string {
	t.Helper()
	cfg := t.TempDir()
	dir := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	return baseEnv("XDG_CONFIG_HOME="+cfg, "PATH="+hostPath)
}

// writeScript plants an executable shell script that announces itself. Every
// binary these tests plant emits a marker, so "the sandbox did not run X" can
// never be satisfied by an X that could not have run anywhere.
func writeScript(t *testing.T, path, marker string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Control on the plumbing itself: a script that does not execute on the HOST
	// would make every assertion about it inside the sandbox meaningless.
	out, err := exec.Command(path).CombinedOutput()
	if err != nil || !strings.Contains(string(out), marker) {
		t.Fatalf("precondition: the planted binary %s does not run on the host (%v):\n%s",
			path, err, out)
	}
}

// pathElements splits a rendered PATH the way execvp(3) does — on every colon,
// keeping empties — because the empties are the whole subject of the test below.
func pathElements(rendered string) []string { return strings.Split(rendered, ":") }

// 2026-08-10. The empty-element hazard, and the ONE place in the environment
// design where getting it wrong ADDS a hole rather than failing to close one.
// ENVIRONMENT-VARIABLES.md §4.3 and §2.2.
//
// An empty element in PATH is the CURRENT DIRECTORY, and inside snug the current
// directory is the target — the one writable thing a hostile payload controls.
// Measured: `env -i PATH="/usr/bin:" sh -c 'victim'` runs ./victim, through the
// shell and through execvp(3) alike. So a `sanitise` written the obvious way, as
// a string replacement, turns "/usr/bin:/ungranted" into "/usr/bin:" — and a
// feature sold as TIGHTENING the environment becomes "drop a file named git in
// the project root and it runs". Hence §2.2: snug never splits a string on a
// separator, and a variable whose elements all fail the filter is UNSET rather
// than set empty.
//
// The host PATH below is chosen to push the filter into exactly that state:
// four elements, of which policy grants precisely one, so three gaps have to be
// closed by construction rather than by an implementer remembering.
//
// # The positive control, and what it is controlling for
//
// The last thing the payload does is run the planted binary with an empty
// element deliberately present. It MUST print VICTIM-RAN. Without it, "the
// sandbox did not run ./snugvictim" is equally true of a sandbox that never
// started, of a target that is not on the search path for unrelated reasons, and
// of a binary that was never executable — the pasta.avx2 failure shape, where a
// matcher that cannot match passes forever.
func TestSanitiseNeverLeavesAnEmptyPATHElement(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	// The one host PATH element policy grants. It lives inside the target, so
	// @cwd-rw covers it, and it holds a symlink to bwrap so that snug can still
	// find bwrap through the PATH it is about to filter.
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatal(err) // requireSandbox already proved it is installed
	}
	granted := filepath.Join(proj, "hostbin")
	if err := os.MkdirAll(granted, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bwrap, filepath.Join(granted, "bwrap")); err != nil {
		t.Fatal(err)
	}

	// The binary a gap would reach. In the target, which is where an empty
	// element resolves to.
	writeScript(t, filepath.Join(proj, "snugvictim"), "VICTIM-RAN")

	hostPath := strings.Join([]string{
		"/nonexistent/one", granted, "/nonexistent/two", "/nonexistent/three",
	}, ":")
	env := envProfileLayer(t, "sanitise-path.toml",
		"[profile.sanitise-path]\n"+
			"description = \"copy the host PATH, keep only what policy grants\"\n"+
			"\n[profile.sanitise-path.environ.sanitise]\nPATH = true\n",
		hostPath)

	r := runEnv(t, env, []string{"-p", "sanitise-path"}, proj,
		`echo "RENDERED[$PATH]"
echo "--- bare ---"
snugvictim 2>&1 || echo VICTIM-NOT-FOUND
echo "--- control ---"
/usr/bin/env PATH="/usr/bin:" snugvictim 2>&1 || echo CONTROL-NOT-FOUND
echo CHECKED-ALL`).mustRun(t)

	if !strings.Contains(r.out, "CHECKED-ALL") {
		t.Fatalf("the payload did not reach the end, so nothing below is attributable:\n%s", r.out)
	}

	_, rest, ok := strings.Cut(r.out, "RENDERED[")
	if !ok {
		t.Fatalf("the payload did not print its PATH:\n%s", r.out)
	}
	rendered, _, _ := strings.Cut(rest, "]")

	// CONTROL for the filter itself: the one granted element survived. Without
	// this, every assertion below is equally satisfied by a `sanitise` that
	// contributed nothing at all, which is a different bug wearing the same
	// green tick.
	if !strings.Contains(rendered, granted) {
		t.Fatalf("the one host PATH element policy grants (%s) is not in the sandbox's "+
			"PATH, so sanitise did not run and its output cannot be checked:\n%s",
			granted, rendered)
	}
	if strings.Contains(rendered, "/nonexistent") {
		t.Errorf("sanitise kept a host PATH element nothing grants:\n%s", rendered)
	}

	// THE ASSERTION. Not "the value looks tidy" — every one of these spellings
	// is the current directory to execvp(3).
	if strings.HasPrefix(rendered, ":") {
		t.Errorf("PATH begins with an empty element, which is the target directory:\n%s", rendered)
	}
	if strings.HasSuffix(rendered, ":") {
		t.Errorf("PATH ends with an empty element, which is the target directory:\n%s", rendered)
	}
	if strings.Contains(rendered, "::") {
		t.Errorf("PATH contains '::', an empty element in the middle, which is the "+
			"target directory:\n%s", rendered)
	}
	for i, elem := range pathElements(rendered) {
		if elem == "" {
			t.Errorf("PATH element %d is empty, which resolves to the current directory — "+
				"inside snug that is the target, and a hostile payload writes there:\n%s",
				i, rendered)
		}
	}

	bare, control, _ := strings.Cut(r.out, "--- control ---")
	_, bare, _ = strings.Cut(bare, "--- bare ---")
	if strings.Contains(bare, "VICTIM-RAN") {
		t.Errorf("a binary in the target ran off the sandbox's own PATH, so an empty "+
			"element reached it:\n%s", r.out)
	}
	// The positive control. See the comment above the test: if this stops being
	// true the negative just above proves nothing, so it is a Fatal.
	if !strings.Contains(control, "VICTIM-RAN") {
		t.Fatalf("the planted binary did NOT run even with an empty PATH element present, "+
			"so the check above cannot distinguish a closed hazard from a payload that "+
			"could never have executed it:\n%s", r.out)
	}
}

// 2026-08-10. §4.1's untested precondition: `snug . -- podman` resolves against
// the SANDBOX's PATH, not the host's. Measured true and, until this test,
// asserted nowhere — which matters because it is what makes the whole ordering
// model mean anything. A profile that puts a directory on PATH is only a grant
// if the payload's own name is looked up inside.
//
// Three parts, and the third is the one that earns its place:
//
//  1. a binary only on the HOST's PATH, in a directory no profile grants, must
//     not run — the negative;
//  2. a binary in a directory a profile grants and merges onto PATH must run —
//     its positive control, through the identical invocation shape, so "did not
//     run" cannot mean "snug cannot run anything";
//  3. a name present in BOTH resolves to the profile's, even though the host
//     directory comes first on the host's PATH.
//
// Why (3) rather than (1) is the discriminator. Refactor the lookup to a
// host-side exec.LookPath and (1) still fails — snug would resolve the name to a
// host path that does not exist inside, and bwrap would still refuse. It reads
// like the feature working. (3) is where that refactor goes red: the host copy
// would win the lookup and then fail to exist inside, so the profile's binary
// never runs.
func TestThePayloadNameResolvesAgainstTheSandboxPATH(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatal(err)
	}

	// Two directories outside the target's tree. hostOnly is granted by nothing;
	// tools is granted by the profile below, which is the only difference between
	// them.
	hostOnly, tools := t.TempDir(), t.TempDir()
	writeScript(t, filepath.Join(hostOnly, "snughostmarker"), "HOST-ONLY-RAN")
	writeScript(t, filepath.Join(hostOnly, "snugbothmarker"), "HOST-VERSION-RAN")
	writeScript(t, filepath.Join(tools, "snugtoolmarker"), "PROFILE-TOOL-RAN")
	writeScript(t, filepath.Join(tools, "snugbothmarker"), "PROFILE-VERSION-RAN")

	// hostOnly is FIRST, ahead of the directory holding bwrap, so nothing about
	// the result can be blamed on it having been at the back.
	env := envProfileLayer(t, "toolbox.toml",
		"[profile.toolbox]\n"+
			"description = \"a directory of tools, granted and merged onto PATH\"\n"+
			"ro = [\""+tools+"\"]\n"+
			"\n[profile.toolbox.environ.merge]\nPATH = [\""+tools+"\"]\n",
		hostOnly+":"+filepath.Dir(bwrap))

	// CONTROL: both host-only binaries really are reachable through the PATH snug
	// is being launched with. Otherwise "the sandbox did not run it" is a fact
	// about the fixture and not about the sandbox.
	ctl := exec.Command("/bin/sh", "-c", "snughostmarker; snugbothmarker")
	ctl.Env = env
	ctlOut, err := ctl.CombinedOutput()
	if err != nil || !strings.Contains(string(ctlOut), "HOST-ONLY-RAN") ||
		!strings.Contains(string(ctlOut), "HOST-VERSION-RAN") {
		t.Fatalf("precondition: the host-only binaries are not reachable through the PATH "+
			"snug is given (%v), so their absence inside proves nothing:\n%s", err, ctlOut)
	}

	// 1. Only on the host's PATH.
	out, code := cli(t, env, "-p", "toolbox", proj, "--", "snughostmarker")
	if code == 0 {
		t.Errorf("a binary reachable only through the HOST's PATH ran inside the sandbox:\n%s", out)
	}
	if strings.Contains(out, "HOST-ONLY-RAN") {
		t.Errorf("the host's PATH contributed a binary to the sandbox:\n%s", out)
	}

	// 2. The positive control for 1: same flags, same target, same machinery,
	// binary in a directory the profile grants and merges.
	out, code = cli(t, env, "-p", "toolbox", proj, "--", "snugtoolmarker")
	if code != 0 || !strings.Contains(out, "PROFILE-TOOL-RAN") {
		t.Fatalf("a binary in a directory the profile grants and merges onto PATH did not "+
			"run (exit %d), so the refusal above is not attributable to the host PATH:\n%s",
			code, out)
	}

	// 3. The same name in both. The profile's must win — and this is the part a
	// host-side lookup would break while leaving 1 and 2 green.
	out, code = cli(t, env, "-p", "toolbox", proj, "--", "snugbothmarker")
	if strings.Contains(out, "HOST-VERSION-RAN") {
		t.Errorf("a name present on both PATHs resolved to the HOST's copy, so the lookup "+
			"is not happening inside the sandbox:\n%s", out)
	}
	if code != 0 || !strings.Contains(out, "PROFILE-VERSION-RAN") {
		t.Errorf("a name present on both PATHs did not resolve to the profile's copy "+
			"(exit %d):\n%s", code, out)
	}
}

// Nothing snug puts on PATH ahead of /usr/bin may be writable from inside.
//
// The permanent regression test for the shadow slot @claude shipped for a
// milestone: it bound one file read-only under {home}/.local/bin and merged that
// DIRECTORY onto PATH, and {home} is a writable tmpfs. The bind was sound; the
// directory was the hole. The repair stages every executable snug fronts the
// payload with in policy.StagedBinDir (/run/snug/bin), which sits on the root
// tmpfs and is covered by --remount-ro /.
//
// It asserts the EFFECT rather than the argv, because that is the half a golden
// cannot reach: --remount-ro / is a flag that either took or did not, and only a
// write attempt from inside knows which. The end-to-end half matters as much —
// creating `git` in the writable slot and running `git` in a SECOND payload is
// how a shadow slot is actually cashed in, and a test that only checked EROFS
// would pass on a sandbox where PATH pointed somewhere else entirely.
//
// What this deliberately does NOT claim: the payload can always run
// `export PATH=/tmp/x:$PATH` and shadow anything for ITSELF. Nothing stops that
// and nothing can. The property is that snug does not hand over an environment
// with the slot already installed.
func TestSnugStagesNoCommandInAWritableDirectory(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	// 1. Every PATH element ahead of /usr/bin must refuse a write. The marker
	// makes "no output" distinguishable from "the sandbox never started".
	out, code := cli(t, nil, proj, "--", "/bin/sh", "-c", `
		echo SNUG-PROBE-RAN
		IFS=:
		for d in $PATH; do
			[ "$d" = /usr/bin ] && break
			# mkdir -p FIRST, because a PATH element that does not exist yet on a
			# writable tmpfs is still a shadow slot — the payload creates it and
			# the shell searches it on the next lookup. Probing with touch alone
			# fails with ENOENT there and reads as "refused".
			mkdir -p "$d" 2>/dev/null
			if touch "$d/snugshadowmarker" 2>/dev/null; then
				echo "WRITABLE-PATH-ELEMENT $d"
			fi
		done`)
	if code != 0 || !strings.Contains(out, "SNUG-PROBE-RAN") {
		t.Fatalf("the probe payload did not run (exit %d), so it proves nothing:\n%s", code, out)
	}
	if strings.Contains(out, "WRITABLE-PATH-ELEMENT") {
		t.Errorf("snug handed over a PATH with a writable directory ahead of /usr/bin:\n%s\n"+
			"That is a shadow slot: the payload writes a file called `git` into it and the "+
			"next `git` anything in this sandbox runs is that file. Stage the command in "+
			"/run/snug/bin instead.", out)
	}

	// 2. Same probe with @claude, which is the profile that had the defect and
	// the only shipped one that stages a bound executable.
	out, code = cli(t, nil, "-p", "@claude", proj, "--", "/bin/sh", "-c", `
		echo SNUG-PROBE-RAN
		echo "PATH=$PATH"
		IFS=:
		for d in $PATH; do
			[ "$d" = /usr/bin ] && break
			# mkdir -p FIRST, because a PATH element that does not exist yet on a
			# writable tmpfs is still a shadow slot — the payload creates it and
			# the shell searches it on the next lookup. Probing with touch alone
			# fails with ENOENT there and reads as "refused".
			mkdir -p "$d" 2>/dev/null
			if touch "$d/snugshadowmarker" 2>/dev/null; then
				echo "WRITABLE-PATH-ELEMENT $d"
			fi
		done`)
	if code != 0 || !strings.Contains(out, "SNUG-PROBE-RAN") {
		t.Fatalf("the probe payload did not run under @claude (exit %d):\n%s", code, out)
	}
	if strings.Contains(out, "WRITABLE-PATH-ELEMENT") {
		t.Errorf("@claude handed over a PATH with a writable directory ahead of /usr/bin:\n%s", out)
	}
	// The exact spelling of the regression, named so a future edit that
	// reintroduces it fails with the reason rather than with a generic message.
	if strings.Contains(out, filepath.Join(os.Getenv("HOME"), ".local/bin")+":") {
		t.Errorf("@claude put {home}/.local/bin back on PATH; it is @home's writable "+
			"tmpfs. Bind the binary at /run/snug/bin/claude instead:\n%s", out)
	}

	// 3. CONTROL. The probe must be able to SEE a writable directory when one is
	// there, or step 1 passes on a payload whose `touch` never worked. /tmp is
	// writable in every sandbox and is not on PATH, so this asserts the
	// mechanism without asserting a defect.
	out, code = cli(t, nil, proj, "--", "/bin/sh", "-c",
		`touch /tmp/snugshadowmarker && echo CONTROL-WROTE`)
	if code != 0 || !strings.Contains(out, "CONTROL-WROTE") {
		t.Fatalf("the control could not write to /tmp, so the probe above cannot "+
			"distinguish 'refused' from 'never tried' (exit %d):\n%s", code, out)
	}
}

// A profile may not author a bwrap flag through an environment VALUE, and it may
// not turn snug's own staging directory into a writable one. Both were reached
// end to end before the fix; both are refused before a sandbox starts now.
//
// These live here rather than only in the unit suite because both defects were
// invisible at every layer above the kernel: the first produced a real mount
// with no Mount in the policy, and the second produced a real writable directory
// that --dry-run described as unwritable. Only a running sandbox can tell you
// which one was true.
func TestAProfileCannotAuthorAMountThroughTheEnvironment(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(home, ".ssh")
	if _, err := os.Stat(secret); err != nil {
		t.Skipf("no %s on this host to attempt to steal", secret)
	}

	// 1. THE INJECTION. `--setenv NAME VALUE` is three elements of a flag list
	// that is NUL-joined into the args memfd, and bwrap's --args splits on NUL.
	// VALUE is last in the triple, so the parser re-syncs on whatever follows.
	// A raw NUL never reaches here — go-toml refuses control characters in a
	// basic string — but the \u0000 ESCAPE does, and produces the same byte.
	inject := `[profile.nully]
description = "harmless-looking"
[profile.nully.environ.set]
EDITOR = "vim\u0000--ro-bind\u0000SECRET\u0000SECRET"
`
	inject = strings.ReplaceAll(inject, "SECRET", secret)
	env := envProfileLayer(t, "nully.toml", inject, os.Getenv("PATH"))

	out, code := cli(t, env, "-p", "nully", proj, "--", "/bin/sh", "-c",
		"echo SNUG-PROBE-RAN; ls "+secret+" 2>&1 | head -2")
	if code == 0 && strings.Contains(out, "SNUG-PROBE-RAN") {
		t.Errorf("the sandbox STARTED with a profile whose environ value carries a NUL. "+
			"Everything after that byte is read by bwrap as further flags — a mount "+
			"Validate, rejectMasking and --dry-run never saw:\n%s", out)
	}
	if !strings.Contains(out, "NUL") {
		t.Errorf("snug refused, but not for this reason. The message must name the NUL, "+
			"because the character is invisible in the writer's editor:\n%s", out)
	}
	// --dry-run must refuse identically. It is the screen someone reads BEFORE
	// running, so a policy it renders happily and the runner then rejects is the
	// two disagreeing about what the profile means.
	if out, code := cli(t, env, "--dry-run", "-p", "nully", proj); code == 0 {
		t.Errorf("--dry-run accepted what the runner refuses:\n%s", out)
	}

	// 2. CONTROL, and it is what makes step 1 mean anything: the identical
	// profile WITHOUT the NUL runs, and the secret is still not there. Otherwise
	// "the sandbox did not start" would be satisfied by a snug that refuses every
	// profile in this layer.
	clean := strings.ReplaceAll(inject, `vim\u0000--ro-bind\u0000`+secret+`\u0000`+secret, "vim")
	env = envProfileLayer(t, "nully.toml", clean, os.Getenv("PATH"))
	out, code = cli(t, env, "-p", "nully", proj, "--", "/bin/sh", "-c",
		"echo SNUG-PROBE-RAN; echo EDITOR=$EDITOR; ls "+secret+" 2>&1 | head -1")
	if code != 0 || !strings.Contains(out, "SNUG-PROBE-RAN") {
		t.Fatalf("control: the same profile without the NUL must run (exit %d):\n%s", code, out)
	}
	if !strings.Contains(out, "EDITOR=vim") {
		t.Errorf("control: the profile's environ.set never reached the sandbox, so step 1 "+
			"proves nothing about values:\n%s", out)
	}
	if !strings.Contains(out, "No such file") {
		t.Errorf("control: %s is visible inside a sandbox that never granted it:\n%s", secret, out)
	}
}

// snug's staging directory is unwritable because it is a plain directory on the
// root tmpfs and `--remount-ro /` covers it. A profile mounting ANYTHING there
// makes it a separate mount, which that remount does not cover — and snug then
// puts the now-writable directory FIRST on PATH itself, in its own provenance,
// without the profile ever naming PATH.
//
// TestAProfileCannotMountOverTheStagingDirectory covers both shapes issue #22
// distinguishes: a grant AT policy.StagedBinDir (/run/snug/bin) and a grant
// COVERING it — a mount at an ANCESTOR, /run or /run/snug, which takes the
// staging directory down with it. Before the #22 fix, `snugsOwn` was keyed on
// the exact guest path, so the "at" cases here were refused and the
// "covering" ones were silently ACCEPTED: the sandbox started, and a payload
// could write /run/snug/bin/git and have the shadowed command win PATH.
//
// The refusal now happens in Validate, before bwrap ever runs, so the
// assertion is "the sandbox did not start" rather than "the write failed" —
// there is no live sandbox in which to attempt the write at all.
func TestAProfileCannotMountOverTheStagingDirectory(t *testing.T) {
	budget(t)
	requireSandbox(t)

	cases := []struct {
		name string
		toml string
	}{
		{"tmpfs_at_the_directory", `[profile.stagey]
description = "stage a tool, and quietly make the staging dir a tmpfs"
tmpfs = ["/run/snug/bin"]
ro    = ["/etc/hostname:/run/snug/bin/mytool"]
`},
		{"tmpfs_covers_via_run", `[profile.stagey]
description = "a tmpfs at an ANCESTOR of the staging dir"
tmpfs = ["/run"]
`},
		{"tmpfs_covers_via_run_snug", `[profile.stagey]
description = "a tmpfs one directory closer to the staging dir"
tmpfs = ["/run/snug"]
`},
		{"ro_bind_covers_via_run", `[profile.stagey]
description = "a read-only bind over an ANCESTOR of the staging dir"
ro = ["/etc:/run"]
`},
		{"rw_bind_covers_via_run", `[profile.stagey]
description = "a writable bind over an ANCESTOR of the staging dir — the worse variant: it persists the shadowed command to the HOST"
rw = ["/tmp:/run"]
`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proj, _ := target(t)
			env := envProfileLayer(t, "stagey.toml", tc.toml, os.Getenv("PATH"))

			out, code := cli(t, env, "-p", "stagey", proj, "--", "/bin/sh", "-c", `
				echo SNUG-PROBE-RAN
				echo "#!/bin/sh" > /run/snug/bin/git && echo WROTE-A-COMMAND-INTO-PATH`)
			if strings.Contains(out, "SNUG-PROBE-RAN") {
				t.Errorf("the sandbox started with a profile grant that covers /run/snug/bin:\n%s", out)
			}
			if code == 0 {
				t.Errorf("snug exited 0 on a profile grant that covers /run/snug/bin; the refusal "+
					"must be fatal, not a warning:\n%s", out)
			}
			if strings.Contains(out, "WROTE-A-COMMAND-INTO-PATH") {
				t.Error("the payload wrote an executable into the directory snug puts first on PATH")
			}
			if !strings.Contains(out, "/run/snug/bin") {
				t.Errorf("snug refused, but the message does not name the staging directory:\n%s", out)
			}
		})
	}

	proj, _ := target(t)

	// CONTROL: staging a file INSIDE the directory is the legitimate shape — it
	// is what @claude does on every run — and it must still work, with the
	// directory still refusing writes.
	const ok = `[profile.stagey]
description = "stage one tool, the right way"
ro = ["/etc/hostname:/run/snug/bin/mytool"]
`
	env := envProfileLayer(t, "stagey.toml", ok, os.Getenv("PATH"))
	out, code := cli(t, env, "-p", "stagey", proj, "--", "/bin/sh", "-c", `
		echo SNUG-PROBE-RAN
		[ -e /run/snug/bin/mytool ] && echo STAGED-TOOL-IS-THERE
		echo "#!/bin/sh" > /run/snug/bin/git 2>/dev/null && echo WROTE-A-COMMAND-INTO-PATH
		echo "PATH=$PATH"`)
	if code != 0 || !strings.Contains(out, "SNUG-PROBE-RAN") {
		t.Fatalf("control: staging one file must still work (exit %d):\n%s", code, out)
	}
	if !strings.Contains(out, "STAGED-TOOL-IS-THERE") {
		t.Errorf("control: the staged file is not in the sandbox, so this control does not "+
			"exercise the staging path at all:\n%s", out)
	}
	if !strings.Contains(out, "PATH=/run/snug/bin:") {
		t.Errorf("control: snug did not put the staging directory first on PATH, so the "+
			"refusal above is about a directory nothing searches:\n%s", out)
	}
	if strings.Contains(out, "WROTE-A-COMMAND-INTO-PATH") {
		t.Error("the staging directory is writable in the LEGITIMATE shape, which is the " +
			"defect one indirection out: --remount-ro / is meant to cover it")
	}
}

// ── the network boundary ────────────────────────────────────────────────────

func TestOfflineHasOnlyLoopback(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	const list = `awk 'NR>2{print $1}' /proc/net/dev | tr -d ' :'`

	r := run(t, nil, proj, list).mustRun(t)
	if got := strings.Fields(r.out); len(got) != 1 || got[0] != "lo" {
		t.Errorf("offline sandbox has interfaces %v, want only lo", got)
	}

	// CONTROL: with `net` the same command reports a second interface. Without
	// it, "only lo" is equally what you get from a payload whose awk printed
	// nothing useful, or from a /proc/net/dev that was never readable.
	requirePasta(t)
	c := run(t, []string{"-p", "@net"}, proj, list).mustRun(t)
	if got := strings.Fields(c.out); len(got) < 2 {
		t.Errorf("control: with -p net the same probe still reports only %v, so it "+
			"cannot distinguish offline from online and the check above proves "+
			"nothing:\n%s", got, c.out)
	}
}

// THE test for M2. The previous generation of this project passed
// --map-host-loopback none but not -T none -U none, and its "private" netns
// could reach every host loopback service. A golden-argv test passed on that
// build; only a behavioural check catches it, and only this one catches a pasta
// default changing upstream.
//
// # Why the GATEWAY address is probed, and why the earlier version was vacuous
//
// This test used to probe 127.0.0.1 and ::1 only, and it could not fail. Removing
// `--map-host-loopback none` — restoring pasta's own default, which is THE
// GATEWAY ADDRESS — left it passing, while a payload inside the sandbox read the
// banner off a host loopback service over both TCP and UDP at 192.168.1.1.
// Verified by execution, not reasoned about: the mutation was applied, the suite
// stayed green, and the escape was performed by hand on the same build.
//
// The reason is that `--map-host-loopback ADDR` does not open 127.0.0.1 inside
// the namespace. It makes ADDR — the gateway, i.e. pasta itself — a door onto the
// host's loopback. So the address the flag actually controls was the one address
// the test never looked at. CLAUDE.md's layer-3 list has said "plus the network
// helper's gateway address" since M2; the test simply did not do it.
//
// UDP is here for the same reason: `-u`/`-U` are separate flags from `-t`/`-T`,
// and a TCP-only probe cannot tell them apart. The gateway UDP path was live in
// the same mutation.
func TestHostLoopbackIsUnreachable(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	requirePython(t)
	// Needed for the egress positive control below (a public resolver on
	// tcp/53): without it a sandbox with NO working network at all would pass
	// every refusal in this test for the wrong reason.
	requireInternet(t)
	proj, _ := target(t)

	// Both families, as INDEX §12.4 spells out: v4 and v6 loopback are closed
	// by different pasta flags, so checking only 127.0.0.1 leaves half the
	// property untested.
	//
	// A net.Listener owned by the test and closed by t.Cleanup. This is the whole
	// reason these checks are no longer shell: the bash version backgrounded
	// `python3 -m http.server`, which held the CI step's stdout open, and the
	// runner waited eleven minutes on that pipe before cancelling a job whose
	// every assertion had passed.
	ln4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveBanner(t, ln4)
	tcpPort := ln4.Addr().(*net.TCPAddr).Port

	udpPort := serveUDPBanner(t, "127.0.0.1")

	haveV6 := true
	v6Port := 0
	if ln6, err := net.Listen("tcp6", "[::1]:0"); err != nil {
		t.Logf("no IPv6 loopback on this host, skipping the v6 half: %v", err)
		haveV6 = false
	} else {
		serveBanner(t, ln6)
		v6Port = ln6.Addr().(*net.TCPAddr).Port
	}

	// THE INTERESTING CASE (issue #86): the host's own real LAN address, not
	// loopback and not the gateway. pasta's default (flat, no-NAT) topology
	// copies the host's own outbound-facing address onto the sandbox's guest
	// interface verbatim — measured on this developer's box: the identical IP
	// appears on the host's real NIC and on the sandbox's snug0, with an `ip
	// route get` for it inside the sandbox resolving `local ... dev lo`. So the
	// refusal below is not pasta actively blocking a route to the host; it is
	// that address being in the SANDBOX's own local routing table, and the
	// packet never leaves the netns to ask pasta anything. That is worth
	// stating plainly rather than letting a reader credit pasta for it — and it
	// is still a property worth a regression test, because it depends on pasta
	// continuing to assign the sandbox the SAME address rather than something
	// else in the same subnet. A future change to that assignment could make
	// this address stop being locally owned, at which point the connection
	// would actually travel out to pasta — and reach the real host listener
	// below, if nothing else changed. Discovered at runtime by asking the
	// kernel what source address it would use to reach the public internet
	// (a connected UDP socket sends nothing on the wire); never hardcoded,
	// because the round's own 192.168.1.120 is this network, not every
	// network.
	lanAddr, lanErr := hostOutboundAddr()
	haveLAN := lanErr == nil
	var lanTCPPort, lanUDPPort int
	if !haveLAN {
		t.Logf("could not discover this host's own outbound-facing address, "+
			"skipping the LAN-address half of this test: %v", lanErr)
	} else if lnLAN, err := net.Listen("tcp4", lanAddr+":0"); err != nil {
		t.Logf("could not bind a listener on %s (this host's own outbound address), "+
			"skipping the LAN-address half of this test: %v", lanAddr, err)
		haveLAN = false
	} else {
		serveBanner(t, lnLAN)
		lanTCPPort = lnLAN.Addr().(*net.TCPAddr).Port
		lanUDPPort = serveUDPBanner(t, lanAddr)
	}

	// PRECONDITIONS. Every one of them is "the measurement works", and without
	// them each assertion below is equally true of a listener nobody could ever
	// have reached.
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", tcpPort), 5*time.Second)
	if err != nil {
		t.Fatalf("precondition: the host cannot reach its own tcp4 listener: %v", err)
	}
	c.Close()
	if haveV6 {
		c, err := net.DialTimeout("tcp6", fmt.Sprintf("[::1]:%d", v6Port), 5*time.Second)
		if err != nil {
			t.Fatalf("precondition: the host cannot reach its own tcp6 listener: %v", err)
		}
		c.Close()
	}
	if got := dialUDPBanner(t, "127.0.0.1", udpPort); got != hostBanner {
		t.Fatalf("precondition: the host cannot reach its own UDP listener (got %q), "+
			"so the UDP half below would pass on a probe that never works", got)
	}
	if haveLAN {
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", lanAddr, lanTCPPort), 5*time.Second)
		if err != nil {
			t.Fatalf("precondition: the host cannot reach its own listener on its own "+
				"LAN address %s: %v", lanAddr, err)
		}
		c.Close()
		if got := dialUDPBanner(t, lanAddr, lanUDPPort); got != hostBanner {
			t.Fatalf("precondition: the host cannot reach its own UDP listener on %s "+
				"(got %q)", lanAddr, got)
		}
	}

	// The probe runs inside the sandbox and prints one RESULT line per address,
	// so a verdict is RECORDED rather than inferred from silence. The gateway
	// comes from /proc/net/route rather than from `ip`, which keeps the probe
	// independent of iproute2 being present.
	//
	// Timeouts are backstops, never the measurement. In the expected case the
	// sandbox's own kernel answers with RST (its loopback is empty) or pasta
	// refuses, both in microseconds; only a DROPPED packet costs the timeout, and
	// a drop is a weaker observation than a refusal anyway.
	probe := fmt.Sprintf(`import socket, struct

def gateway():
    with open("/proc/net/route") as f:
        for line in f.read().splitlines()[1:]:
            fs = line.split()
            if len(fs) > 3 and fs[1] == "00000000":
                return socket.inet_ntoa(struct.pack("<L", int(fs[2], 16)))
    return None

# The v6 counterpart of gateway() above, read from /proc/net/ipv6_route rather
# than "ip -6 route" for the same reason: no dependency on iproute2 being
# present. A default route is destination all-zero with a zero prefix length;
# its "nexthop" field is the gateway. Real-world IPv6 default gateways are
# link-local (fe80::/10, advertised by the router itself), which is not
# connectable without a scope/zone id — so this also returns the outgoing
# interface, needed to resolve that scope.
def gateway6():
    try:
        with open("/proc/net/ipv6_route") as f:
            for line in f.read().splitlines():
                fs = line.split()
                if len(fs) < 10:
                    continue
                dest, destplen, nexthop, dev = fs[0], fs[1], fs[4], fs[-1]
                if dest == "0" * 32 and destplen == "00" and nexthop != "0" * 32:
                    return ":".join(nexthop[i:i+4] for i in range(0, 32, 4)), dev
    except FileNotFoundError:
        pass
    return None, None

gw = gateway()
print("GATEWAY", gw or "NONE")
gw6, gw6dev = gateway6()
print("GATEWAY6", gw6 or "NONE", gw6dev or "")

def probe(label, family, kind, host, port, timeout, scope=0):
    s = socket.socket(family, kind)
    s.settimeout(timeout)
    try:
        if family == socket.AF_INET6:
            s.connect((host, port, 0, scope))
        else:
            s.connect((host, port))
        if kind == socket.SOCK_DGRAM:
            s.send(b"probe")
        print("RESULT", label, "REACHED", s.recv(64).decode(errors="replace").strip())
    except ConnectionRefusedError:
        print("RESULT", label, "REFUSED")
    except socket.timeout:
        print("RESULT", label, "TIMEDOUT")
    except OSError as e:
        print("RESULT", label, "ERROR", type(e).__name__, e)
    finally:
        s.close()

# EGRESS POSITIVE CONTROL, run FIRST. Without it, every REFUSED/TIMEDOUT
# verdict below is equally what a sandbox with NO working network at all would
# produce, and every negative in this file would be the "test that cannot
# fail" shape. 8.8.8.8 rather than the gateway: a home router answering on
# tcp/53 is common but not guaranteed, while a public resolver on tcp/53 is a
# dependable, non-host-specific target reachable only through a WORKING
# egress path. (Not 1.1.1.1: repeated runs from the same source address
# during development got silently rate-limited by Cloudflare's resolver —
# bimodal instant-success-or-full-timeout, nothing to do with the sandbox —
# which is exactly the kind of third-party flakiness a positive control must
# not import.)
probe("egress-tcp", socket.AF_INET, socket.SOCK_STREAM, "8.8.8.8", 53, 5)

probe("v4-tcp", socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", %[1]d, 2)
probe("v4-udp", socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1", %[2]d, 0.5)
if %[4]s:
    probe("v6-tcp", socket.AF_INET6, socket.SOCK_STREAM, "::1", %[3]d, 2)
if gw:
    probe("gw-tcp", socket.AF_INET, socket.SOCK_STREAM, gw, %[1]d, 2)
    probe("gw-udp", socket.AF_INET, socket.SOCK_DGRAM, gw, %[2]d, 0.5)
if gw6:
    scope = socket.if_nametoindex(gw6dev)
    probe("gw6-tcp", socket.AF_INET6, socket.SOCK_STREAM, gw6, %[1]d, 2, scope)
    probe("gw6-udp", socket.AF_INET6, socket.SOCK_DGRAM, gw6, %[2]d, 0.5, scope)
if %[5]s:
    probe("lan-tcp", socket.AF_INET, socket.SOCK_STREAM, %[6]q, %[7]d, 2)
    probe("lan-udp", socket.AF_INET, socket.SOCK_DGRAM, %[6]q, %[8]d, 0.5)

print("PROBE-COMPLETE")
`, tcpPort, udpPort, v6Port, map[bool]string{true: "True", false: "False"}[haveV6],
		map[bool]string{true: "True", false: "False"}[haveLAN], lanAddr, lanTCPPort, lanUDPPort)

	if err := os.WriteFile(filepath.Join(proj, "loopback.py"), []byte(probe), 0o644); err != nil {
		t.Fatal(err)
	}

	r := run(t, []string{"-p", "@net"}, proj, `python3 loopback.py`).mustRun(t)

	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the probe did not run to the end, so every verdict below is missing "+
			"rather than negative:\n%s", r.out)
	}
	if strings.Contains(r.out, hostBanner) {
		t.Errorf("the sandbox READ from a host loopback service:\n%s", r.out)
	}

	// The gateway must have been found. "The gateway was unreachable" is
	// trivially true of a probe that had no gateway address to try, and that is
	// the shape of vacuous pass this file exists to prevent.
	if strings.Contains(r.out, "GATEWAY NONE") {
		t.Fatalf("the sandbox has no default route, so the gateway — the address "+
			"--map-host-loopback actually controls — was never probed:\n%s", r.out)
	}

	// Unlike the v4 default route, an IPv6 one is not guaranteed on every host
	// this suite runs on, so its absence is a partial skip rather than a fatal
	// — exactly the haveV6 treatment above, applied to routing instead of
	// loopback.
	haveGW6 := !strings.Contains(r.out, "GATEWAY6 NONE")
	if !haveGW6 {
		t.Logf("the sandbox has no IPv6 default route, skipping the v6-gateway half:\n%s", r.out)
	}

	verdicts := map[string]string{}
	for _, line := range strings.Split(r.out, "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[0] == "RESULT" {
			verdicts[f[1]] = f[2]
		}
	}

	// LOOPBACK TCP: only a REFUSED tells us something answered "there is nothing
	// here". A drop is weaker, and it is where seconds of CI time go, so it is
	// reported as a defect in the probe rather than accepted as a pass. These
	// addresses are the sandbox's OWN loopback, which is empty, so its kernel
	// sends RST in microseconds — there is no environment in which a timeout
	// here is legitimate.
	wantRefused := []string{"v4-tcp"}
	if haveV6 {
		wantRefused = append(wantRefused, "v6-tcp")
	}
	// The LAN address belongs in this group, not the gateway's: the measurement
	// above (see the comment where lanAddr is discovered) is that the address is
	// in the SANDBOX's own local routing table, so its kernel answers exactly as
	// certainly and as fast as it does for its own loopback.
	if haveLAN {
		wantRefused = append(wantRefused, "lan-tcp")
	}
	for _, label := range wantRefused {
		switch verdicts[label] {
		case "REFUSED":
		case "":
			t.Errorf("the %s probe produced no verdict at all:\n%s", label, r.out)
		case "REACHED":
			t.Errorf("the sandbox REACHED a host service via %s:\n%s", label, r.out)
		default:
			t.Errorf("the %s probe was %s, neither refused nor reached. That is a weaker "+
				"result than this test claims to establish:\n%s", label, verdicts[label], r.out)
		}
	}

	// THE GATEWAY is different in kind, and demanding REFUSED of it was wrong.
	//
	// It is the address --map-host-loopback would map the host's 127.0.0.1 onto,
	// so it is the one that matters most — but with `none` the packet is not
	// translated at all and goes to a REAL router, which is under no obligation
	// to answer. On this developer's box (inside podman) it sends RST; on a
	// GitHub runner it drops, and the job failed with the sandbox behaving
	// perfectly. What establishes the property is that the probe did not REACH
	// anything and the host's banner appears nowhere in the output — both still
	// asserted, and both still fail loudly.
	switch verdicts["gw-tcp"] {
	case "REFUSED", "TIMEDOUT":
	case "":
		t.Errorf("the gw-tcp probe produced no verdict at all:\n%s", r.out)
	case "REACHED":
		t.Errorf("the sandbox REACHED a service on the host's loopback via the gateway "+
			"address, which is exactly what --map-host-loopback none exists to prevent:\n%s", r.out)
	default:
		t.Errorf("the gw-tcp probe ended as %s; only a refusal or a drop is a negative "+
			"result:\n%s", verdicts["gw-tcp"], r.out)
	}

	// THE V6 GATEWAY, same reasoning as the v4 one above: a drop is an
	// acceptable negative, a REACHED is not.
	if haveGW6 {
		switch verdicts["gw6-tcp"] {
		case "REFUSED", "TIMEDOUT":
		case "":
			t.Errorf("the gw6-tcp probe produced no verdict at all:\n%s", r.out)
		case "REACHED":
			t.Errorf("the sandbox REACHED a service on the host's loopback via the IPv6 "+
				"gateway address:\n%s", r.out)
		default:
			t.Errorf("the gw6-tcp probe ended as %s; only a refusal or a drop is a negative "+
				"result:\n%s", verdicts["gw6-tcp"], r.out)
		}
	}

	// UDP: a refusal needs an ICMP port-unreachable getting back, which pasta is
	// under no obligation to relay, so a timeout is an acceptable negative here.
	// REACHED is not, and neither is a missing verdict.
	udpLabels := []string{"v4-udp", "gw-udp"}
	if haveLAN {
		udpLabels = append(udpLabels, "lan-udp")
	}
	if haveGW6 {
		udpLabels = append(udpLabels, "gw6-udp")
	}
	for _, label := range udpLabels {
		switch verdicts[label] {
		case "REFUSED", "TIMEDOUT":
		case "":
			t.Errorf("the %s probe produced no verdict at all:\n%s", label, r.out)
		default:
			t.Errorf("the sandbox reached a host UDP service via %s (%s):\n%s",
				label, verdicts[label], r.out)
		}
	}

	// EGRESS POSITIVE CONTROL: the sandbox's network must actually work, or
	// every refusal above is equally what a sandbox with no network at all
	// would produce. See the comment beside the probe for why a public
	// resolver and not the gateway.
	switch verdicts["egress-tcp"] {
	case "REACHED":
	case "":
		t.Errorf("the egress-tcp probe produced no verdict at all, so this test cannot "+
			"tell a properly-refused sandbox from one with no network:\n%s", r.out)
	default:
		t.Errorf("egress does not work inside this sandbox (egress-tcp: %s), so none of "+
			"the refusals above prove anything — the same result is what a sandbox with "+
			"no network at all would produce:\n%s", verdicts["egress-tcp"], r.out)
	}
}

// hostBanner is what every host-side probe listener answers with. Seeing it
// inside the sandbox is proof of a completed conversation, not merely of a
// completed handshake.
const hostBanner = "SECRET-SERVICE-BANNER"

// hostOutboundAddr discovers the address the kernel would use to source a
// packet leaving for the public internet — never hardcoded, because the
// address on any given machine is that network, not every network. Dialing a
// connected UDP socket does not put anything on the wire (no handshake, no
// DNS), it only asks the routing table which local address and interface
// would carry the traffic, so this needs no actual connectivity — only a
// route. Returns an error naming what could not be found, for a caller to
// turn into a skip reason.
func hostOutboundAddr() (string, error) {
	c, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return "", fmt.Errorf("no route to a public address: %w", err)
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return "", fmt.Errorf("the outbound-facing address resolved to %v, "+
			"which is not a real host address", ip)
	}
	return ip.String(), nil
}

// serveUDPBanner answers every datagram with the banner and shuts down when the
// test ends. Returns the port. addr is the bind address, e.g. "127.0.0.1" —
// parameterised so the same helper can stand up a listener on the host's own
// LAN-facing address, not only on loopback.
func serveUDPBanner(t *testing.T, addr string) int {
	t.Helper()
	pc, err := net.ListenPacket("udp4", addr+":0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return // closed
			}
			_ = n
			pc.WriteTo([]byte(hostBanner), addr)
		}
	}()
	t.Cleanup(func() { pc.Close(); <-done })
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// dialUDPBanner is the host-side positive control for the UDP half.
func dialUDPBanner(t *testing.T, host string, port int) string {
	t.Helper()
	c, err := net.DialTimeout("udp4", fmt.Sprintf("%s:%d", host, port), time.Second)
	if err != nil {
		t.Fatalf("precondition: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("probe")); err != nil {
		t.Fatalf("precondition: %v", err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		return fmt.Sprintf("<%v>", err)
	}
	return string(buf[:n])
}

// serveBanner answers every connection with a token and shuts the listener down
// when the test ends. Nothing here outlives the test, and nothing holds a
// descriptor the test framework did not create.
func serveBanner(t *testing.T, ln net.Listener) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return // the listener was closed; nothing is left running
			}
			c.SetDeadline(time.Now().Add(5 * time.Second))
			c.Write([]byte(hostBanner + "\n"))
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
}

// Abstract AF_UNIX sockets are scoped by the NETWORK namespace, not by the
// filesystem, so no mount grant can hide one and no mount grant is what keeps
// them out. X11 and D-Bus both listen on abstract sockets; if the sandbox could
// reach them it could log keystrokes and screenshot the desktop. This property
// is the reason `net-host` needs --i-know, and nothing else in the suite covers
// it (INDEX §12.4).
func TestAbstractSocketsAreUnreachable(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePython(t)
	proj, _ := target(t)

	// Go spells an abstract socket with a leading "@".
	name := fmt.Sprintf("snug-abstract-probe-%d", os.Getpid())
	ln, err := net.Listen("unix", "@"+name)
	if err != nil {
		t.Fatal(err)
	}
	serveBanner(t, ln)

	// The host can reach it — otherwise the test proves nothing.
	c, err := net.Dial("unix", "@"+name)
	if err != nil {
		t.Fatalf("precondition: the host cannot reach its own abstract socket: %v", err)
	}
	c.Close()

	// An abstract name that does not exist in this netns is refused by the
	// kernel immediately — there is no route, no retry and nothing to wait for.
	// The one-second timeout is a backstop so a hang becomes a named failure
	// rather than a stuck job, and TIMEDOUT is reported as its own outcome: it
	// would mean something answered and then stalled, which is a finding, not a
	// pass. socket.timeout is a subclass of OSError, hence the ordering.
	probe := fmt.Sprintf(`import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1)
try:
    s.connect("\0%s")
    print("ABSTRACT-REACHED " + s.recv(64).decode(errors="replace"))
except socket.timeout:
    print("TIMEDOUT")
except OSError as e:
    print("refused:", e)
`, name)
	if err := os.WriteFile(filepath.Join(proj, "abstract.py"), []byte(probe), 0o644); err != nil {
		t.Fatal(err)
	}

	// Both offline and with networking: the netns is private in either case, and
	// the `net` half is the one that would regress if pasta were ever given the
	// host's namespace. The pasta gate sits inside the loop so a host without it
	// still gets the offline half checked before skipping.
	for _, args := range [][]string{nil, {"-p", "@net"}} {
		if args != nil {
			requirePasta(t)
		}
		r := run(t, args, proj, `python3 abstract.py`).mustRun(t)
		if strings.Contains(r.out, "ABSTRACT-REACHED") || strings.Contains(r.out, "SECRET-SERVICE-BANNER") {
			t.Errorf("the sandbox reached a host abstract socket with args %v:\n%s", args, r.out)
		}
		// Positive confirmation that the probe ran and got a refusal, rather than
		// dying on an import or stalling: without it the two checks above are
		// satisfied by any output at all.
		if !strings.Contains(r.out, "refused:") {
			t.Errorf("the probe did not report a refusal with args %v, so the checks "+
				"above prove nothing:\n%s", args, r.out)
		}
	}
}

// Host→sandbox publishing is OFF by default and only a `publish = [...]` profile
// turns it on.
// With pasta's -t auto the SANDBOX would choose which host loopback ports
// appear, which inverts the guiding principle: the agent would be punching its
// own holes.
//
// This test used to cost eight seconds — two thirds of the whole suite — because
// the in-sandbox listener sat on an eight-second accept timeout to establish
// that nobody had connected. That is the anti-pattern this file exists to avoid,
// and the reasoning that removes it is worth stating: connect(2) does not return
// until the three-way handshake is complete, so a connection the host managed to
// make is already sitting on the listener's accept backlog by the time the
// host's dial has returned. The listener therefore does not have to WAIT for a
// connection that will never come; it only has to LOOK, once, after the host has
// finished trying. The two sides synchronise through the target bind, which they
// both see.
//
// The assertion is unchanged and, in three places, stronger: the host now
// requires the specific ECONNREFUSED rather than any failure, the sandbox's
// verdict must appear in the output rather than merely not contradicting us,
// and — the one that matters most — there is now a POSITIVE CONTROL.
//
// The control was not paranoia. Running the old test against a profile that
// publishes showed it passing: it could not fail, and had been unable to fail
// since it was written. See TestPublishedPortsAreReachable, which is the control
// extracted into a named test of its own. (The `publish_auto` form it was first
// written against is gone: it never forwarded anything — see base.toml.)
func TestSandboxPortsAreNotPublishedByDefault(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	requirePasta(t)
	requirePython(t)
	proj, _ := target(t)
	writeListener(t, proj)

	// THE CONTROL. A profile that publishes exactly one port, so the host's probe
	// is known to be able to observe a reachable sandbox listener at all — and,
	// just as importantly, so the half-second accept window the negative half
	// relies on is shown to be enough to catch a connection that really happened.
	// A negative result is worth only as much as the positive one beside it.
	pub := probeSandboxPort(t, proj, publishProfileEnv(t, 0), "-p", "published")
	if pub.dialErr != nil {
		t.Fatalf("control: the host could not reach a port the profile explicitly "+
			"publishes (%v). Until that works, the check below cannot fail and "+
			"proves nothing:\n%s", pub.dialErr, pub.out)
	}
	if !strings.Contains(pub.out, "HOST-REACHED-THE-SANDBOX") {
		t.Fatalf("control: the host connected but the sandbox's listener did not see "+
			"it within its accept window, so that window is too short for the check "+
			"below to be trusted:\n%s", pub.out)
	}

	// THE ASSERTION. Same payload, same probe, same machine — only the profile
	// differs, so a difference in outcome is attributable to the profile alone.
	def := probeSandboxPort(t, proj, baseEnv(), "-p", "@net")
	switch {
	case def.dialErr == nil:
		t.Errorf("the host reached a sandbox listener on 127.0.0.1:%d without a publish grant", def.port)
	case !errors.Is(def.dialErr, syscall.ECONNREFUSED):
		// A refusal is the host's kernel saying "there is nothing here". Anything
		// else — a timeout above all — means the packet went somewhere and was
		// dropped, which is both a weaker result and the thing that makes this
		// kind of test take seconds.
		t.Errorf("the connect to 127.0.0.1:%d was not REFUSED but failed as %v after %s. "+
			"Only a refusal shows the port is absent; a drop would leave this test "+
			"proving less than it claims",
			def.port, def.dialErr, def.dialTook.Round(time.Millisecond))
	}
	if strings.Contains(def.out, "HOST-REACHED-THE-SANDBOX") {
		t.Errorf("the sandbox accepted a connection from the host without a publish grant:\n%s", def.out)
	}
	// The listener has to have reached its verdict. Absent this, a python that
	// died on the bind would satisfy every check above.
	if !strings.Contains(def.out, "nobody connected") {
		t.Errorf("the in-sandbox listener never reported its verdict, so the checks "+
			"above prove nothing:\n%s", def.out)
	}
}

// The other side of the same coin, named so it cannot be lost: when the human
// asks for a port to be published it must actually appear on the host's
// loopback. This is the control above, standing on its own — a `publish` that
// quietly did nothing would make every "not published by default" assertion in
// this file vacuous, and that is precisely what was found when the negative test
// was first run against a publishing profile.
func TestPublishedPortsAreReachable(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	requirePython(t)
	proj, _ := target(t)
	writeListener(t, proj)

	got := probeSandboxPort(t, proj, publishProfileEnv(t, 0), "-p", "published")
	if got.dialErr != nil {
		t.Fatalf("the host could not reach 127.0.0.1:%d, which the profile publishes: %v\n%s",
			got.port, got.dialErr, got.out)
	}
	if !strings.Contains(got.out, "HOST-REACHED-THE-SANDBOX") {
		t.Errorf("the host's connect succeeded but the sandbox's listener never "+
			"accepted it:\n%s", got.out)
	}
}

// portProbe is the outcome of pointing the host at a port the sandbox bound.
type portProbe struct {
	port     int
	dialErr  error // nil means the host reached it
	dialTook time.Duration
	out      string // the sandbox's combined output, marker line included
}

// probeSandboxPort runs listen.py inside a sandbox on a host-chosen port, has the
// host attempt exactly one connection to it, and returns both sides' verdicts.
//
// The HOST picks the port, and picks one it has just seen to be free. With
// bind(0) inside the sandbox the port came from the namespace's own ephemeral
// range and could collide with an unrelated service on the host — the host's dial
// would then succeed and the caller would report a sandbox breach that had not
// happened. The sandbox's netns is empty, so a fixed port always binds there.
func probeSandboxPort(t *testing.T, proj string, env []string, args ...string) portProbe {
	t.Helper()

	port := portFromEnv(env)
	if port == 0 {
		port = freeHostPort(t)
	}

	// The handshake files are per-run state; a second run in the same target
	// directory must not see the first one's.
	ready := filepath.Join(proj, "READY")
	probed := filepath.Join(proj, "PROBED")
	os.Remove(ready)
	os.Remove(probed)

	// Started by hand rather than through run(): the test has to talk to the
	// sandbox while it is still alive, and calling t.Fatal from a helper on
	// another goroutine is not allowed.
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	full := append(append([]string{}, args...), proj, "--", "/bin/bash", "-c",
		fmt.Sprintf("printf '%%s\\n' %s\npython3 listen.py %d", payloadMarker, port))
	cmd := exec.CommandContext(ctx, snugBin, full...)
	cmd.Env = env
	cmd.WaitDelay = waitDelay
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	// Sandbox startup plus a python interpreter, on a runner that may be busy.
	// Five seconds is a backstop; locally this resolves in about 150ms.
	if err := waitForFile(ready, 5*time.Second); err != nil {
		t.Fatalf("the sandbox never reported a listening port: %v\n%s", err, buf.String())
	}

	// One second is a backstop, not the measurement. In the expected case the
	// host's own kernel answers with RST because nothing is bound there, which
	// takes microseconds; in the published case pasta accepts at once.
	start := time.Now()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	took := time.Since(start)
	if c != nil {
		c.Close()
	}

	// Release the sandbox before the caller asserts anything, so a failure does
	// not also leave it sitting out its backstop.
	if werr := os.WriteFile(probed, []byte("done"), 0o644); werr != nil {
		t.Fatal(werr)
	}

	werr := cmd.Wait()
	waited = true
	out := buf.String()
	if errors.Is(werr, exec.ErrWaitDelay) {
		t.Fatalf("the sandbox exited but something still holds its output pipe:\n%s", out)
	}
	if !strings.Contains(out, payloadMarker) {
		t.Fatalf("the payload never ran, so this probe would prove nothing:\n%s", out)
	}
	return portProbe{port: port, dialErr: err, dialTook: took, out: out}
}

// publishProfileEnv writes a throwaway profile that publishes one specific port
// and returns an environment selecting it, along with the port encoded in
// SNUG_TEST_PORT so probeSandboxPort uses the same one.
//
// A named port rather than net-publish's publish_auto: `auto` asks pasta to
// discover ports the sandbox binds after the fact, which is a different
// mechanism with its own failure mode, and a control has to be the mechanism
// that is simplest to be sure of.
func publishProfileEnv(t *testing.T, port int) []string {
	t.Helper()
	if port == 0 {
		port = freeHostPort(t)
	}
	cfg := t.TempDir()
	dir := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	toml := fmt.Sprintf("[profile.published]\n"+
		"description = \"publish exactly one port, as a control\"\n"+
		"include = [\"@net\"]\npublish = [%d]\n", port)
	if err := os.WriteFile(filepath.Join(dir, "published.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	return baseEnv("XDG_CONFIG_HOME="+cfg, fmt.Sprintf("SNUG_TEST_PORT=%d", port))
}

func portFromEnv(env []string) int {
	for i := len(env) - 1; i >= 0; i-- {
		if v, ok := strings.CutPrefix(env[i], "SNUG_TEST_PORT="); ok {
			p := 0
			fmt.Sscanf(v, "%d", &p)
			return p
		}
	}
	return 0
}

// writeListener drops the in-sandbox half of the port probe into the target.
func writeListener(t *testing.T, proj string) {
	t.Helper()
	listener := `import os, socket, sys, time

port = int(sys.argv[1])
target = os.environ["SNUG_TARGET"]

s = socket.socket()
s.bind(("0.0.0.0", port))
s.listen(1)

# Announce readiness through the target bind. Written-then-renamed so the host
# can never observe a half-written file, and no background process is involved,
# so nothing holds this sandbox's stdout open.
with open(target + "/READY.tmp", "w") as f:
    f.write("listening")
os.rename(target + "/READY.tmp", target + "/READY")

# Wait for the host to finish its attempt. This is a wait for an event that WILL
# arrive — the host writes PROBED whether its connect succeeded or failed — so
# the deadline is a backstop against a host that died, not a proof of anything.
deadline = time.monotonic() + 10
while not os.path.exists(target + "/PROBED") and time.monotonic() < deadline:
    time.sleep(0.005)

# Now look, once. Anything the host connected to is already queued here. The
# half second is slack for pasta, which in the failing case would accept on the
# host side and then dial into the namespace: on loopback that is microseconds.
# Waiting longer cannot turn a "no" into a "yes"; it can only cost CI time.
s.settimeout(0.5)
try:
    s.accept()
    print("HOST-REACHED-THE-SANDBOX")
except socket.timeout:
    print("nobody connected")
`
	if err := os.WriteFile(filepath.Join(proj, "listen.py"), []byte(listener), 0o644); err != nil {
		t.Fatal(err)
	}
}

// freeHostPort returns a TCP port that the host's loopback had free a moment
// ago. The listener is closed again before returning: the caller wants the
// NUMBER, and wants nothing listening on it.
func freeHostPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// waitForFile polls for a path to appear. Used only where the file is a
// handshake the other side is about to perform, so the deadline is a backstop
// against a dead peer and never the thing being measured.
func waitForFile(path string, within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not appear within %s", filepath.Base(path), within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The sandbox's own loopback must still work — the closure above is of the
// HOST's 127.0.0.1, not of loopback as a concept, and an agent running a dev
// server and curling it is the ordinary case.
func TestSandboxHasItsOwnWorkingLoopback(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	r := run(t, []string{"-p", "@net"}, proj, `
command -v python3 >/dev/null || { echo NO-PYTHON; exit 0; }
python3 - <<'EOF'
import socket, threading
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
port = s.getsockname()[1]
threading.Thread(target=lambda: s.accept()[0].sendall(b"INSIDE-OK"), daemon=True).start()
c = socket.create_connection(("127.0.0.1", port), 5)
print(c.recv(64).decode())
EOF`).mustRun(t)
	if strings.Contains(r.out, "NO-PYTHON") {
		t.Skip("SKIP: python3 is not available inside the sandbox")
	}
	if !strings.Contains(r.out, "INSIDE-OK") {
		t.Errorf("the sandbox's own loopback does not work:\n%s", r.out)
	}
}

func TestEgressWorks(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	requirePasta(t)
	requireInternet(t)
	proj, _ := target(t)

	// A POSITIVE assertion, so a generous timeout costs nothing when it holds —
	// but it is still the only check here whose duration depends on a network
	// snug does not control, so it is capped tightly enough that a runner with
	// broken DNS produces a failure in seconds rather than a stalled job.
	//
	// --connect-timeout is separate from --max-time on purpose: it distinguishes
	// "the name did not resolve or the SYN went nowhere" from "the transfer was
	// slow", and the first is the failure mode a CI runner actually has.
	r := run(t, []string{"-p", "@net"}, proj,
		`curl -sf -o /dev/null --connect-timeout 5 --max-time 10 https://example.com && echo EGRESS-OK`).mustRun(t)
	if r.code != 0 || !strings.Contains(r.out, "EGRESS-OK") {
		t.Errorf("no egress with the net profile (exit %d). If DNS is the cause, note "+
			"that a host whose only resolver is on loopback — systemd-resolved's "+
			"127.0.0.53, which is what most CI images use — takes snug's pasta "+
			"--dns-forward path, and that path is the one with known client "+
			"compatibility limits (see internal/policy/net.go):\n%s", r.code, r.out)
	}
}

// net-host is a knowingly-large hole — it shares the HOST network namespace,
// which means host loopback services and abstract AF_UNIX sockets (X11, D-Bus)
// are all reachable. Selecting the profile must not be enough; the human has to
// say --i-know. This needs no sandbox to run, so it is checked with --dry-run.
func TestNetHostIsRefusedWithoutIKnow(t *testing.T) {
	budget(t)
	proj, _ := target(t)

	out, code := cli(t, nil, "--dry-run", "-p", "@net-host", proj)
	if code == 0 {
		t.Fatalf("net-host was accepted without --i-know:\n%s", out)
	}
	if !strings.Contains(out, "--i-know") {
		t.Errorf("the refusal should name the flag that overrides it:\n%s", out)
	}

	out, code = cli(t, nil, "--dry-run", "--i-know", "-p", "@net-host", proj)
	if code != 0 {
		t.Errorf("net-host with --i-know should be accepted (exit %d):\n%s", code, out)
	}
}

// REGRESSION (redteam, M2): when the network could not be brought up, snug
// reported failure with exit 69 — and ran the payload anyway. The payload WAS
// parked on bwrap's --block-fd, which releases on EOF as readily as on a byte,
// so the deferred close during teardown released a child that killing bwrap had
// not reliably taken down. One abort in fifteen executed the payload and wrote
// to the target.
//
// The mechanism is gone rather than fixed: under the stage the netns exists
// before bwrap does, so pasta attaches first and there is no parked payload to
// release — see INDEX.md §4.3. The test stays, and asserts something stronger
// than it used to, because the guarantee is the same one either way: an aborted
// network means the payload never ran.
//
// Twenty iterations because the original failure was a race, not a certainty.
func TestAbortedNetworkNeverRunsThePayload(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	proj, _ := target(t)

	// A PATH with the essentials but no pasta, so the network setup fails on the
	// path that was not fail-closed — which is now the startPasta step, before
	// stage.StartSandbox has forked anything at all.
	fakeBin := t.TempDir()
	for _, b := range []string{"bwrap", "sh", "bash", "cat", "echo", "sleep", "touch"} {
		p, err := exec.LookPath(b)
		if err != nil {
			continue
		}
		if err := os.Symlink(p, filepath.Join(fakeBin, b)); err != nil {
			t.Fatal(err)
		}
	}

	marker := filepath.Join(proj, "PWNED")
	sawExpectedFailure := false
	for i := range 20 {
		os.Remove(marker)
		out, code := cli(t, baseEnv("PATH="+fakeBin), "-p", "@net", proj, "--",
			"/bin/sh", "-c", `echo pwned > "$SNUG_TARGET/PWNED"`)

		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("iteration %d: the payload executed on a run snug reported as aborted (exit %d):\n%s",
				i, code, out)
		}
		if strings.Contains(out, "pasta is not installed") {
			sawExpectedFailure = true
		}
	}
	// Without this the test passes on any build where snug fails for some
	// unrelated reason before it ever gets near the abort path.
	if !sawExpectedFailure {
		t.Error("snug never reported the missing-pasta failure, so the abort path was probably not exercised")
	}
}

// --die-with-parent must take the whole tree down even when snug is SIGKILLed
// and never gets to clean up. A leaked pasta is a network namespace still
// attached to something.
func TestNoLeakedHelpersAfterSIGKILL(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	before := pastaPIDs()

	cmd := exec.Command(snugBin, "-p", "@net", proj, "--", "/bin/sleep", "30")
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	// Wait for a helper to appear rather than sleeping a fixed interval. This
	// half is load-bearing: the first cut of this test compared counts of
	// processes whose /proc/<pid>/comm equalled "pasta", but pasta's comm is
	// "pasta.avx2" on both this host and the CI runner, so the count was always
	// zero and the test could never fail.
	//
	// A wait for something that WILL happen, so the deadline is a backstop. Five
	// seconds: snug itself gives pasta three (waitForNetDevice) before declaring
	// the network dead, so a helper that has not appeared by five is not going to.
	var helpers []int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if helpers = newPIDs(before, pastaPIDs()); len(helpers) > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if len(helpers) == 0 {
		t.Fatal("no pasta helper ever appeared, so this test would pass vacuously")
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	killed = true

	// Poll rather than sleep: Pdeathsig delivery is asynchronous and a fixed
	// sleep is exactly how this class of test becomes flaky on a loaded runner.
	//
	// This is the one wait in the suite that cannot be replaced by an immediate
	// observation, because the property is "the helper eventually dies" and the
	// kernel queues SIGKILL at the parent's exit rather than delivering it
	// synchronously. Five seconds is the bound, not twenty: cmd.Wait above has
	// already reaped snug, so the signal was queued before this loop started and
	// what remains is one scheduling quantum. Locally it is gone on the first
	// poll. If a helper is still there after five seconds it has not been
	// delayed, it has survived — which is the finding.
	deadline = time.Now().Add(5 * time.Second)
	for {
		left := newPIDs(before, pastaPIDs())
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("network helper(s) %v survived snug being SIGKILLed", left)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// pastaPIDs returns the pids of pasta processes owned by this user, read out of
// /proc rather than shelled out to pgrep.
//
// The comm prefix match is not laziness: passt ships CPU-dispatched binaries, so
// the kernel's comm is "pasta.avx2" here and may be plain "pasta" elsewhere. An
// equality test against "pasta" silently matches nothing.
func pastaPIDs() map[int]bool {
	pids := map[int]bool{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return pids
	}
	uid := uint32(os.Getuid())
	for _, e := range entries {
		pid := 0
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil || pid <= 0 {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		if !strings.HasPrefix(name, "pasta") && !strings.HasPrefix(name, "passt") {
			continue
		}
		// Only our own: another user's pasta appearing or vanishing mid-test
		// must not be able to fail this.
		fi, err := os.Stat(filepath.Join("/proc", e.Name()))
		if err != nil {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != uid {
			continue
		}
		pids[pid] = true
	}
	return pids
}

func newPIDs(before, now map[int]bool) []int {
	var out []int
	for pid := range now {
		if !before[pid] {
			out = append(out, pid)
		}
	}
	return out
}

// ── the policy boundary ─────────────────────────────────────────────────────
//
// These need no namespaces: they assert that snug REFUSES to build a policy, so
// --dry-run is enough and they run on any host.

// Masking by overmount is subtraction wearing a hat. Adding a profile must never
// make anything worse, and Validate rejects every spelling of "hide".
//
// The bind case is a REGRESSION (redteam, M1): rejectMasking originally
// inspected only tmpfs grants, so a bind of an unrelated empty directory walked
// straight through it and /usr/share/misc went from three entries to zero,
// silently.
func TestMaskingByOvermountIsRefused(t *testing.T) {
	budget(t)
	proj, _ := target(t)

	cfg := t.TempDir()
	empty := filepath.Join(cfg, "empty")
	dir := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	evil := fmt.Sprintf(`
[profile.hide-ssl]
description = "mask part of another profile's grant with an empty tmpfs"
tmpfs = ["/etc/ssl"]

[profile.mask-misc]
description = "mask by binding an unrelated empty dir over it"
ro = [%q]

[profile.greedy]
description = "grant the whole host"
ro = ["/"]

# The tmpfs spelling of the same thing. Refusing only the bind left this
# ACCEPTED (redteam) — and inert only because SortedMounts happens to
# emit / first, so every sibling landed on top of it. An invariant that holds
# by mount ORDER is one that breaks the day the ordering is tuned for something
# else, so both spellings are refused and both are asserted here.
[profile.greedy-tmpfs]
description = "take the root with a tmpfs instead of a bind"
tmpfs = ["/"]

# The control. Same file, same loader, same invocation — it simply does not mask
# anything, and it must be ACCEPTED. Without it "snug refused" is equally true of
# a snug that refuses every profile from this layer, and the three checks below
# would prove nothing about rejectMasking.
[profile.benign]
description = "an ordinary additive grant that masks nothing"
ro = ["/usr/share/misc"]
`, empty+":/usr/share/misc")
	if err := os.WriteFile(filepath.Join(dir, "evil.toml"), []byte(evil), 0o644); err != nil {
		t.Fatal(err)
	}
	env := baseEnv("XDG_CONFIG_HOME=" + cfg)

	if out, code := cli(t, env, "--dry-run", "-p", "benign", proj); code != 0 {
		t.Fatalf("control: an ordinary additive profile from this same file must be "+
			"accepted, or the refusals below say nothing about masking (exit %d):\n%s",
			code, out)
	}

	for _, tc := range []struct{ profile, wantIn string }{
		{"hide-ssl", "/etc/ssl"},
		{"mask-misc", "/usr/share/misc"},
		{"greedy", "root is snug's own"},
		{"greedy-tmpfs", "root is snug's own"},
	} {
		out, code := cli(t, env, "--dry-run", "-p", tc.profile, proj)
		if code == 0 {
			t.Errorf("profile %q was accepted; profiles may only ever grant:\n%s", tc.profile, out)
		}
		if !strings.Contains(out, tc.wantIn) {
			t.Errorf("the refusal of %q should name %q:\n%s", tc.profile, tc.wantIn, out)
		}
	}
}

// Strict decoding is load-bearing rather than pedantry: a silently ignored
// `mask` key would let someone believe their sandbox is tighter than it is.
func TestAnUnknownProfileKeyIsFatal(t *testing.T) {
	budget(t)
	proj, _ := target(t)

	cfg := t.TempDir()
	dir := filepath.Join(cfg, "snug", "profiles.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.toml"),
		[]byte("[profile.x]\nmask = [\"/etc\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// CONTROL: the identical profile with the unknown key REMOVED, in its own
	// config directory, is accepted. Without it "snug refused" is equally what
	// you get from a config layer snug never read, a profile name it does not
	// know, or --dry-run failing for reasons of its own.
	okCfg := t.TempDir()
	okDir := filepath.Join(okCfg, "snug", "profiles.d")
	if err := os.MkdirAll(okDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(okDir, "x.toml"),
		[]byte("[profile.x]\nro = [\"/etc\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+okCfg), "--dry-run", "-p", "x", proj); code != 0 {
		t.Fatalf("control: the same profile without the unknown key must be accepted, "+
			"or the refusal below is not attributable to strict decoding (exit %d):\n%s",
			code, out)
	}

	out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", "-p", "x", proj)
	if code == 0 {
		t.Fatalf("an unknown profile key was ignored rather than refused:\n%s", out)
	}
	if !strings.Contains(out, "unknown") || !strings.Contains(out, "mask") {
		t.Errorf("the parse error should name the unknown key:\n%s", out)
	}
}

// The @ namespace belongs to snug and nobody else. This is what keeps
// provenance honest end to end: a reader who sees `@sys` in --dry-run or in
// SNUG_PROFILES knows the grant is snug's own and not something a file on this
// host defined. It matters most where invariant 3 is weakest — XDG_CONFIG_HOME
// is trusted unconditionally today, so a profiles.d snug read from the wrong
// place must still be unable to impersonate a builtin.
func TestAUserProfileCannotClaimTheBuiltinSigil(t *testing.T) {
	budget(t)
	proj, _ := target(t)

	write := func(body string) string {
		cfg := t.TempDir()
		dir := filepath.Join(cfg, "snug", "profiles.d")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "mine.toml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	// CONTROL: the same grants under a name of the author's own load and run.
	// Without it, "snug refused" would be equally true of a snug that rejects
	// every profile from this layer — which is how a test stops being able to
	// fail.
	okCfg := write("[profile.mysys]\nro = [\"/usr\"]\n")
	if out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+okCfg), "--dry-run", "-p", "mysys", proj); code != 0 {
		t.Fatalf("control: the same profile under an unmarked name must be accepted, "+
			"or the refusals below are not attributable to the sigil (exit %d):\n%s", code, out)
	}

	// Impersonating a builtin, and inventing a new marked name, are both refused
	// — and refused at LOAD, so it is not a question of which name gets selected.
	for _, name := range []string{"@sys", "@mine"} {
		cfg := write("[profile.\"" + name + "\"]\nro = [\"/\"]\n")
		out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", "-p", "@sys", proj)
		if code == 0 {
			t.Errorf("a user profile named %q was loaded; it would be indistinguishable "+
				"from one snug ships:\n%s", name, out)
		}
		if !strings.Contains(out, name) {
			t.Errorf("the refusal of %q should name it:\n%s", name, out)
		}
	}

	// And the mistake this convention creates — typing the bare name — must be
	// answered with the fix rather than a bare "unknown profile".
	out, code := cli(t, nil, "--dry-run", "-p", "sys", proj)
	if code == 0 {
		t.Fatalf("`-p sys` was accepted; snug's own profile is `@sys`:\n%s", out)
	}
	if !strings.Contains(out, "@sys") {
		t.Errorf("the error for a missing sigil should point at %q:\n%s", "@sys", out)
	}
}

// Invariant 3: the trusted profile set comes from OUTSIDE the sandboxed
// material. A hostile repository shipping .snug/ would be an attacker granting
// themselves permissions on the first run — a complete defeat of the threat
// model — so snug has no fourth config layer derived from the target.
func TestRepoLocalConfigIsNeverAutoLoaded(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	// The profile has to be one that WOULD work if it were trusted, or "snug
	// refused it" is attributable to the profile being broken rather than to
	// where it came from. The earlier version wrote `include = ["default"]`, and
	// there is no builtin called `default` — so even a snug that happily loaded
	// repo-local config would have failed this, for the wrong reason, forever.
	// The control below is what keeps that honest.
	const evil = "[profile.evil]\ndescription = \"a hostile repo granting itself /etc\"\n" +
		"include = [\"@sys\", \"@home\", \"@cwd-rw\"]\nrw = [\"/etc\"]\n"

	for _, rel := range []string{
		".snug/profiles.toml",
		"snug.toml",
		".config/snug/profiles.d/evil.toml",
	} {
		path := filepath.Join(proj, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(evil), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// POSITIVE CONTROL: the very same bytes, in a TRUSTED config directory, are
	// loaded and accepted. So the refusal below is caused by the location and by
	// nothing else — which is the whole claim of invariant 3.
	trusted := t.TempDir()
	dir := filepath.Join(trusted, "snug", "profiles.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evil.toml"), []byte(evil), 0o644); err != nil {
		t.Fatal(err)
	}
	ctlOut, ctlCode := cli(t, baseEnv("XDG_CONFIG_HOME="+trusted), "--dry-run", "-p", "evil", proj)
	if ctlCode != 0 {
		t.Fatalf("control: this profile is rejected even from a TRUSTED directory, so "+
			"the check below would pass on any snug at all (exit %d):\n%s", ctlCode, ctlOut)
	}

	// The profile the repo shipped does not exist as far as snug is concerned.
	out, code := cli(t, nil, "--dry-run", "-p", "evil", proj)
	if code == 0 {
		t.Errorf("snug loaded a profile from beside the target:\n%s", out)
	}
	if !strings.Contains(out, "unknown profile") {
		t.Errorf("expected \"unknown profile\", got:\n%s", out)
	}

	// And a plain run is unaffected by the files sitting there.
	r := run(t, nil, proj, `touch /etc/ZZ 2>&1 && echo ETC-WRITABLE; ls / | tr '\n' ' '`).mustRun(t)
	if strings.Contains(r.out, "ETC-WRITABLE") {
		t.Errorf("/etc became writable, so the repo's profile took effect:\n%s", r.out)
	}
	if strings.Contains(r.out, "root") || strings.Contains(r.out, "boot") {
		t.Errorf("the sandbox root looks like the host's:\n%s", r.out)
	}
}

// ── Killing @null, keeping --no-defaults ────────────────────────────────────
//
// There is no @null profile any more — a profile
// that grants nothing is a preference, not a grant, and the lattice floor it
// used to name is what an empty selection already resolves to. Reaching the
// floor is now --no-defaults, not `-p @null`.

// @null is retired, not merely unknown, and both routes that used to reach it
// must say so by name rather than "see: snug profile list". Mirrors
// TestRetiredPublishAutoIsAHardError's shape (internal/profile/file_test.go),
// which does the same for a retired TOML key — this is the CLI-level half of
// TestRetiredNullProfileNamesTheFix (internal/policy/resolve_test.go), which
// pins the same message at the policy.UnknownProfile call site directly.
func TestRetiredNullProfileIsANamedError(t *testing.T) {
	budget(t)
	proj, _ := target(t)

	// POSITIVE CONTROL: a real builtin, through both entry points, works and
	// exits 0. Without this, "exit 77" below could be true of a snug binary
	// that refuses every `-p` and every `profile show` for unrelated reasons.
	if out, code := cli(t, nil, "--dry-run", "-p", "@sys", proj); code != 0 {
		t.Fatalf("control: -p @sys should be accepted, got %d:\n%s", code, out)
	}
	if out, code := cli(t, nil, "profile", "show", "@sys"); code != 0 {
		t.Fatalf("control: `snug profile show @sys` should succeed, got %d:\n%s", code, out)
	}

	out, code := cli(t, nil, "--dry-run", "-p", "@null", proj)
	if code != exitPolicyCode {
		t.Errorf("`-p @null` should exit %d, got %d:\n%s", exitPolicyCode, code, out)
	}
	if !strings.Contains(out, "--no-defaults") {
		t.Errorf("the refusal should point at --no-defaults:\n%s", out)
	}

	out, code = cli(t, nil, "profile", "show", "@null")
	if code != exitPolicyCode {
		t.Errorf("`snug profile show @null` should exit %d, got %d:\n%s", exitPolicyCode, code, out)
	}
	if !strings.Contains(out, "--no-defaults") {
		t.Errorf("the refusal should point at --no-defaults:\n%s", out)
	}
}

// The structural guard for Resolve's riskiest change (see its doc comment):
// on a Validate failure it now returns the refused policy ALONGSIDE the error,
// precisely so --dry-run can show what would have run. The one non-test
// caller (internal/cli/main.go) must never let that non-nil policy reach
// sandbox.Run regardless. If it ever did, this is the test that would catch
// it — not by inspecting the code, but by trying to make the refused policy
// actually do something and checking that it did not.
func TestRefusedPolicyIsNeverExecuted(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	// POSITIVE CONTROL: the identical command, with the default profile
	// selection, actually executes and prints the marker. Without this, "no
	// MARKER" below could mean the payload never runs at all, on any
	// selection — which would make the refusal below vacuous.
	r := run(t, nil, proj, "echo MARKER").mustRun(t)
	if !strings.Contains(r.out, "MARKER") {
		t.Fatalf("control: with the defaults selected the payload must run and print MARKER:\n%s", r.out)
	}

	// --no-defaults resolves to the floor: no OS runtime, no target, and
	// Validate refuses it. The exit code has to be exitPolicyCode AND the marker
	// has to be absent — either one alone is a weaker claim than the pair:
	// a wrong exit code with no marker printed could still be a policy that
	// silently degraded to something narrower but still running, and a right
	// exit code alongside a printed marker would be exactly the escape this
	// test exists to catch.
	out, code := cli(t, nil, "--no-defaults", proj, "--", "/bin/echo", "MARKER")
	if code != exitPolicyCode {
		t.Errorf("--no-defaults should refuse with exit %d, got %d:\n%s", exitPolicyCode, code, out)
	}
	if strings.Contains(out, "MARKER") {
		t.Fatalf("REGRESSION: a policy Validate refused still executed the payload:\n%s", out)
	}
}

// --dry-run must be able to show a REFUSED policy — that is the entire point
// of Resolve returning (p, err) instead of (nil, err) on a Validate failure —
// but it must still exit non-zero, and the argv it prints must be the FLOOR's,
// not the default sandbox's.
func TestDryRunShowsARefusedPolicy(t *testing.T) {
	budget(t)
	proj, _ := target(t)

	// POSITIVE CONTROL: with the defaults, --dry-run succeeds and the argv
	// genuinely mounts /usr. Without this, "no --ro-bind /usr" below could be
	// true of a --dry-run that never renders any argv at all.
	out, code := cli(t, nil, "--dry-run", proj)
	if code != 0 {
		t.Fatalf("control: --dry-run with the defaults should succeed, got %d:\n%s", code, out)
	}
	if !strings.Contains(out, "--ro-bind /usr") {
		t.Fatalf("control: expected --ro-bind /usr in the default argv:\n%s", out)
	}

	out, code = cli(t, nil, "--dry-run", "--no-defaults", proj)
	if code != exitPolicyCode {
		t.Errorf("--dry-run --no-defaults should still exit %d (refused, not runnable), got %d:\n%s",
			exitPolicyCode, code, out)
	}
	if !strings.Contains(out, "--proc /proc") {
		t.Errorf("the refused policy's argv should still show the floor's --proc /proc:\n%s", out)
	}
	if !strings.Contains(out, "--remount-ro /") {
		t.Errorf("the refused policy's argv should still show --remount-ro /:\n%s", out)
	}
	if strings.Contains(out, "--ro-bind /usr") {
		t.Errorf("the floor must not grant /usr:\n%s", out)
	}
}

// ── containers: `podman build` (M5) ─────────────────────────────────────────

// requireEngine gates the checks that need a real container engine.
//
// A plain skip even under SNUG_REQUIRE_SANDBOX, unlike requireInternet: CI
// installs bubblewrap and pasta but not podman, and pretending otherwise would
// turn every CI run red for a capability the runner was never given. What keeps
// that honest is that the unit suite covers the same filter against RECORDED
// podman queries — see internal/dockerproxy/build_test.go — so this tier adds
// end-to-end proof rather than being the only coverage.
func requireEngine(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("SKIP: podman is not installed; the build checks need a real engine")
	}
}

// `podman build` really builds, and really cannot reach past the sandbox.
//
// This drives the container API directly rather than running the podman CLI
// inside the sandbox, and that is not a shortcut: on a host where /usr/bin/podman
// is a distrobox shim the CLI cannot work from inside at all (snug says so, at
// length), while snug's own engine and proxy are fine. The API is the surface
// under test anyway — every escape below is a query parameter, not a CLI flag.
func TestPodmanBuildIsFilteredEndToEnd(t *testing.T) {
	budget(t, 300*time.Second)
	requireSandbox(t)
	requireEngine(t)
	requirePython(t)
	requireInternet(t) // the build pulls alpine
	// requireRealEngine (containerengine_test.go) is the fix for this test
	// FAILING outright on a CI runner instead of skipping: requireEngine
	// above only proves a `podman` binary is on PATH, and a GitHub-hosted
	// ubuntu-latest runner has a real, non-shim one — so this test used to
	// run there, get a 200 from the build, and then find its RUN step never
	// actually executed (the runner's cgroup delegation does not survive
	// __inengine's own private cgroup namespace). requireRealEngine proves
	// the SAME thing this test is about to assert (an ordinary build that
	// really runs) FIRST, against baseEnv() — i.e. whatever `podman` this
	// host's own PATH resolves to, exactly as this test always used — and
	// skips cleanly, with the real reason, if it does not hold.
	requireRealEngine(t, baseEnv())

	proj, _ := target(t)

	if err := os.WriteFile(filepath.Join(proj, "probe.py"), []byte(buildProbe), 0o644); err != nil {
		t.Fatal(err)
	}

	r := run(t, []string{"-p", "@podman-build", "-p", "@net"}, proj, `python3 probe.py`).mustRun(t)

	// THE CONTROL FIRST. Without a build that actually succeeds, every refusal
	// below is equally true of a proxy that refuses all builds, and the profile
	// would be useless with this test green.
	if !strings.Contains(r.out, "ordinary build: 200") {
		t.Fatalf("an ordinary build did not succeed, so the refusals below prove "+
			"nothing about filtering:\n%s", r.out)
	}
	// And the build must really have RUN something. Verified to fail when the
	// marker is broken, rather than assumed to be checking anything.
	if !strings.Contains(r.out, "BUILT-INSIDE-SNUG") {
		t.Errorf("the build reported success but its RUN step never executed, so "+
			"nothing was really built:\n%s", r.out)
	}

	for _, want := range []struct{ marker, why string }{
		{"host bind: 403", "`build -v /etc:/x` binds a host path the sandbox cannot see"},
		{"host network: 403", "`build --network=host` joins the host's network namespace"},
		{"host ns: 403", "the nsoptions spelling of --network=host"},
		{"unknown option: 403", "an option snug has not been taught about must fail closed"},
	} {
		if !strings.Contains(r.out, want.marker) {
			t.Errorf("%s — expected %q in:\n%s", want.why, want.marker, r.out)
		}
	}
	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Errorf("the probe did not run to the end, so a missing marker above is "+
			"absent rather than negative:\n%s", r.out)
	}
}

// buildProbe posts context tars to $CONTAINER_HOST with the query parameters a
// real `podman build` sends, one per case. The parameter sets are the ones
// recorded from podman 5.8.3; see internal/dockerproxy/build_test.go.
const buildProbe = `import http.client, socket, os, tarfile, io, urllib.parse

class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self.path = path
    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.path)
        self.sock = s

sock = os.environ["CONTAINER_HOST"].replace("unix://", "")

buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as tf:
    # A FULLY QUALIFIED reference, not the bare "alpine" this used to say.
    # MEASURED (issue #63, Tier B, sandbox-tester): with a short name,
    # containers/image resolves it through registries.conf's short-name-alias
    # cache, and — because __inengine's own process reports euid 0
    # (root-in-U, not "really" root on this host) — that code picks the
    # SYSTEM cache path (/var/cache/containers) over the user one, which the
    # real host uid cannot write to: "creating build container: mkdir
    # /var/cache/containers: permission denied". The build itself still
    # returns 200 (STEP 1/2 succeeded before the failure), so this is exactly
    # the "200 but BUILT-INSIDE-SNUG never appears" shape probeRealEngine's
    # own doc comment (containerengine_test.go) attributed to cgroup
    # delegation — that diagnosis was WRONG; the private-cgroup-namespace
    # remount warning is a harmless red herring that happens to appear right
    # next to the real failure. A fully qualified name skips short-name
    # resolution entirely, so this never runs regardless of euid.
    data = b"FROM docker.io/library/alpine:3.20\nRUN echo BUILT-INSIDE-SNUG\n"
    ti = tarfile.TarInfo("Dockerfile")
    ti.size = len(data)
    tf.addfile(ti, io.BytesIO(data))
ctx = buf.getvalue()

BASE = {"dockerfile": '["Dockerfile"]', "t": "snugtest:1", "output": "snugtest:1",
        "networkmode": "0", "nsoptions": '[{"Name":"user","Host":true,"Path":""}]',
        "isolation": "0", "rm": "1", "layers": "1", "pullpolicy": "missing",
        "seccomp": "/usr/share/containers/seccomp.json", "shmsize": "67108864"}

def build(label, extra):
    q = dict(BASE)
    q.update(extra)
    c = UnixHTTP(sock)
    c.request("POST", "/v5.0.0/libpod/build?" + urllib.parse.urlencode(q), body=ctx,
              headers={"Content-Type": "application/x-tar"})
    r = c.getresponse()
    body = r.read().decode(errors="replace")
    print("%s: %d" % (label, r.status), flush=True)
    if "BUILT-INSIDE-SNUG" in body:
        print("BUILT-INSIDE-SNUG", flush=True)

# nocache on the control, deliberately: with a warm layer cache podman prints
# "Using cache" and the RUN step's own output never appears, so the
# BUILT-INSIDE-SNUG assertion would pass by not being checked. A control that
# can silently stop controlling is the failure mode this suite exists to avoid.
build("ordinary build", {"nocache": "1"})
build("host bind", {"volume": "/etc:/x"})
build("host network", {"networkmode": "2"})
build("host ns", {"nsoptions": '[{"Name":"network","Host":true,"Path":""}]'})
build("unknown option", {"mountfromhost": "/etc"})
print("PROBE-COMPLETE", flush=True)
`

// TestAPayloadCannotSignalHostProcesses is the property that makes snug worth
// running at all, written down after it was violated ON the host by a person
// rather than by a payload: a stray `pkill -9 -x bwrap`, typed outside any
// sandbox, killed every Flatpak application on the machine, because Flatpak
// runs each app under bwrap and pkill matches by name across the whole uid.
//
// Inside a sandbox that command is inert, and this test pins why. Three
// mechanisms, asserted separately so a regression names which one broke:
//
//  1. the host's processes are not VISIBLE — a private pid namespace means the
//     payload's /proc contains only the sandbox;
//  2. a host pid is not ADDRESSABLE — signalling it by number fails, because
//     that number means something else (or nothing) in the payload's namespace;
//  3. name-matched killing finds nothing to match.
//
// The positive control is the victim itself: this test kills it from the host
// afterwards and requires that to work, so "the payload could not kill it"
// cannot pass on a process that was already dead or unkillable.
func TestAPayloadCannotSignalHostProcesses(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	proj, _ := target(t)

	// A victim on the HOST, ours, killable, and outside the sandbox entirely.
	victim := exec.Command("/bin/sleep", "300")
	if err := victim.Start(); err != nil {
		t.Fatal(err)
	}
	victimPID := victim.Process.Pid
	defer func() {
		_ = victim.Process.Kill()
		_, _ = victim.Process.Wait()
	}()

	script := `
echo MARKER-PAYLOAD-RAN
echo "visible: $(ls -d /proc/[0-9]* 2>/dev/null | wc -l)"
if [ -d /proc/` + strconv.Itoa(victimPID) + ` ]; then echo "SEES-VICTIM"; else echo "no-victim-in-proc"; fi
kill -9 ` + strconv.Itoa(victimPID) + ` 2>/dev/null && echo "KILL-BY-PID-ACCEPTED" || echo "kill-by-pid-refused"
pkill -9 -x sleep 2>/dev/null && echo "PKILL-MATCHED" || echo "pkill-matched-nothing"
`
	out, code := cli(t, baseEnv(), proj, "--", "/bin/sh", "-c", script)
	if !strings.Contains(out, "MARKER-PAYLOAD-RAN") {
		t.Fatalf("PRECONDITION: the payload never ran; this test cannot prove anything.\n%s", out)
	}
	if code != 0 {
		t.Fatalf("PRECONDITION: the sandbox exited %d\n%s", code, out)
	}

	if strings.Contains(out, "SEES-VICTIM") {
		t.Errorf("the payload can see host pid %d in /proc — the pid namespace is not private\n%s",
			victimPID, out)
	}
	if strings.Contains(out, "KILL-BY-PID-ACCEPTED") {
		t.Errorf("kill -9 %d was ACCEPTED inside the sandbox; a host pid must not be addressable\n%s",
			victimPID, out)
	}
	if strings.Contains(out, "PKILL-MATCHED") {
		t.Errorf("pkill -x sleep matched something inside the sandbox; name-matched killing must "+
			"reach nothing outside it\n%s", out)
	}

	// The victim must still be alive — that is the whole claim.
	if err := victim.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("the host victim %d is gone after the sandbox ran: %v\n%s", victimPID, err, out)
	}

	// POSITIVE CONTROL: it was killable all along, from out here.
	if err := victim.Process.Kill(); err != nil {
		t.Fatalf("CONTROL FAILED: could not kill the victim from the host either: %v", err)
	}
	_, _ = victim.Process.Wait()
	if err := victim.Process.Signal(syscall.Signal(0)); err == nil {
		t.Fatal("CONTROL FAILED: the victim survived a kill from the host, so 'the payload could " +
			"not kill it' proves nothing")
	}
}

// TestKillingPidOneFromInsideDoesNotEndTheSandbox is the second half of the
// same question, and the answer is the kernel's rather than snug's: the payload
// CAN name pid 1 (it is bwrap, the init of the sandbox's own pid namespace) and
// signalling it does nothing, because a namespace's init only receives signals
// from inside that namespace if it has installed a handler for them. SIGKILL
// cannot be handled, so it is never delivered.
//
// Worth a test rather than a comment because it is the difference between "an
// agent inside can accidentally destroy its own sandbox mid-run" and "it
// cannot", and nothing in snug's own code would notice if a future topology
// change made the payload a sibling of the init rather than its descendant.
func TestKillingPidOneFromInsideDoesNotEndTheSandbox(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	proj, _ := target(t)

	script := `
echo MARKER-PAYLOAD-RAN
kill -9 1 2>/dev/null; echo "kill1-exit=$?"
sleep 0.2
echo "pid1-still=$(cat /proc/1/comm 2>/dev/null)"
# Positive control: a sibling in the SAME namespace dies normally, so the
# survival above is pid 1's protection and not a broken kill.
sleep 30 & C=$!
kill -9 $C 2>/dev/null
sleep 0.2
if kill -0 $C 2>/dev/null; then echo "CONTROL-FAILED-SIBLING-SURVIVED"; else echo "control-sibling-died"; fi
echo MARKER-STILL-ALIVE
`
	out, code := cli(t, baseEnv(), proj, "--", "/bin/sh", "-c", script)
	if !strings.Contains(out, "MARKER-PAYLOAD-RAN") {
		t.Fatalf("PRECONDITION: the payload never ran\n%s", out)
	}
	if !strings.Contains(out, "control-sibling-died") {
		t.Fatalf("PRECONDITION: killing an ordinary sibling did not work, so nothing below is "+
			"evidence about pid 1\n%s", out)
	}
	if !strings.Contains(out, "MARKER-STILL-ALIVE") {
		t.Errorf("the sandbox did not survive `kill -9 1` from inside\n%s", out)
	}
	if !strings.Contains(out, "pid1-still=bwrap") {
		t.Errorf("pid 1 is not bwrap after the kill; the sandbox's init changed or died\n%s", out)
	}
	if code != 0 {
		t.Errorf("the run exited %d after the payload signalled pid 1\n%s", code, out)
	}
}
