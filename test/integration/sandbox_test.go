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
// docs/VERIFY.md still exists and is not redundant: it is for a human checking
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
// secret above it, mirroring the shape docs/VERIFY.md uses.
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
}

// /dev is writable and that surprises people — it surprised the author, and it
// was found by running docs/VERIFY.md rather than by review. It is bwrap's own
// synthetic device tree on a private tmpfs, so what matters is not that it is
// read-only (it is not) but that a write there reaches neither the host nor the
// next sandbox. Say "the only writable thing that PERSISTS", never "the only
// writable thing".
func TestDevIsWritableButNeitherPersistsNorEscapes(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	if r := run(t, nil, proj, `echo pwned > /dev/ESCAPE_PROBE`).mustRun(t); r.code != 0 {
		t.Skipf("/dev is not writable here, which is tighter than expected: %s", r.out)
	}
	if _, err := os.Stat("/dev/ESCAPE_PROBE"); err == nil {
		os.Remove("/dev/ESCAPE_PROBE")
		t.Fatal("a write to /dev inside the sandbox reached the HOST's /dev")
	}
	r := run(t, nil, proj, `ls /dev/ESCAPE_PROBE 2>&1`).mustRun(t)
	if r.code == 0 {
		t.Errorf("a write to /dev survived into the next sandbox:\n%s", r.out)
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

	// Drop dotdot and the parent's other children disappear. Only the directory
	// bwrap had to create to host the target's bind mount remains.
	r = run(t, []string{"--no-default", "-p", "sys", "-p", "home", "-p", "cwd-rw"},
		proj, `ls ..`).mustRun(t)
	if strings.Contains(r.out, "sibling") {
		t.Errorf("without dotdot the sibling must not be visible:\n%s", r.out)
	}
}

// The clamp is the one place restriction lives, and it belongs to the human at
// the CLI rather than to a file: "a human may tighten; a file may not"
// (CLAUDE.md invariant 1). Verified by execution because a clamp that resolved
// correctly but was applied after BwrapArgs would produce identical --dry-run
// output and a writable sandbox.
func TestReadOnlyClampDemotesTheWritableTarget(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	// Control: without the clamp the target IS writable, so a failure below
	// cannot be the sandbox simply being broken.
	if r := run(t, nil, proj, `touch ./control`).mustRun(t); r.code != 0 {
		t.Fatalf("precondition: the target should be writable without --read-only:\n%s", r.out)
	}

	r := run(t, []string{"--read-only"}, proj, `touch ./clamped`).mustRun(t)
	if r.code == 0 {
		t.Errorf("--read-only left the target writable:\n%s", r.out)
	}
	if r := run(t, []string{"--read-only"}, proj, `ls ./control`).mustRun(t); r.code != 0 {
		t.Errorf("--read-only should demote the target to read-only, not remove it:\n%s", r.out)
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

	r := run(t, []string{"-p", "git-ro"}, proj,
		`ls /usr >/dev/null && echo SYS-PRESENT; touch ./x && echo TARGET-WRITABLE; echo "$SNUG_PROFILES"`).mustRun(t)
	for _, want := range []string{"SYS-PRESENT", "TARGET-WRITABLE"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("-p git-ro appears to have REPLACED the default (%s missing):\n%s", want, r.out)
		}
	}
	for _, want := range []string{"git-ro", "sys", "cwd-rw"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("SNUG_PROFILES should list %q:\n%s", want, r.out)
		}
	}

	// --no-default is the escape hatch, and it really does start from nothing.
	r = run(t, []string{"--no-default", "-p", "sys", "-p", "home", "-p", "cwd-rw"},
		proj, `echo "$SNUG_PROFILES"`).mustRun(t)
	if strings.Contains(r.out, "dotdot") {
		t.Errorf("--no-default should not pull in the default's profiles:\n%s", r.out)
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

	// x86_64 syscall numbers, as in docs/VERIFY.md §6c. userfaultfd is
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
func TestNestedUserNamespaceIsRefused(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	if r := run(t, nil, proj, `unshare -U /bin/true`).mustRun(t); r.code == 0 {
		t.Error("a nested user namespace was created; that is the standard escape first move")
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

// ── the network boundary ────────────────────────────────────────────────────

func TestOfflineHasOnlyLoopback(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	r := run(t, nil, proj, `awk 'NR>2{print $1}' /proc/net/dev | tr -d ' :'`).mustRun(t)
	if got := strings.Fields(r.out); len(got) != 1 || got[0] != "lo" {
		t.Errorf("offline sandbox has interfaces %v, want only lo", got)
	}
}

// THE test for M2. The previous generation of this project passed
// --map-host-loopback none but not -T none -U none, and its "private" netns
// could reach every host loopback service. A golden-argv test passed on that
// build; only a behavioural check catches it, and only this one catches a pasta
// default changing upstream.
func TestHostLoopbackIsUnreachable(t *testing.T) {
	budget(t)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	// Both families, as DESIGN §12.4 spells out: v4 and v6 loopback are closed
	// by different pasta flags, so checking only 127.0.0.1 leaves half the
	// property untested.
	families := []struct{ network, listen, dial string }{
		{"tcp4", "127.0.0.1:0", "127.0.0.1"},
		{"tcp6", "[::1]:0", "::1"},
	}

	var script strings.Builder
	var want []string
	tried := 0
	for _, f := range families {
		// A net.Listener owned by the test and closed by t.Cleanup. This is the
		// whole reason these checks are no longer shell: the bash version
		// backgrounded `python3 -m http.server`, which held the CI step's stdout
		// open, and the runner waited eleven minutes on that pipe before
		// cancelling a job whose every assertion had passed.
		ln, err := net.Listen(f.network, f.listen)
		if err != nil {
			if f.network == "tcp6" {
				t.Logf("no IPv6 loopback on this host, skipping the v6 half: %v", err)
				continue
			}
			t.Fatal(err)
		}
		serveBanner(t, ln)
		port := ln.Addr().(*net.TCPAddr).Port

		// The host can see it — otherwise the test proves nothing.
		c, err := net.DialTimeout(f.network, net.JoinHostPort(f.dial, fmt.Sprint(port)), 5*time.Second)
		if err != nil {
			t.Fatalf("precondition: the host cannot reach its own %s listener: %v", f.network, err)
		}
		c.Close()

		// The probe must REFUSE, not time out. Inside the sandbox's netns the
		// address 127.0.0.1 is its own loopback, where nothing is listening, so
		// the kernel answers with RST and connect() fails in microseconds. The
		// `timeout 2` is a backstop for a hang, never the measurement: waiting
		// longer could not turn a refusal into a connection, and a timeout would
		// mean the packet was silently dropped, which proves strictly less than a
		// refusal does. So the verdict is recorded rather than inferred.
		fmt.Fprintf(&script, `
out=$(timeout 2 bash -c 'exec 3<>/dev/tcp/%[1]s/%[2]d' 2>&1); rc=$?
case "$rc" in
  0)   echo "REACHED-%[3]s" ;;
  124) echo "TIMEDOUT-%[3]s" ;;
  *)   echo "REFUSED-%[3]s ($out)" ;;
esac
`, f.dial, port, f.network)
		want = append(want, f.network)
		tried++
	}
	if tried == 0 {
		t.Fatal("no loopback listener could be started, so nothing was tested")
	}

	r := run(t, []string{"-p", "net"}, proj, script.String()).mustRun(t)
	if strings.Contains(r.out, "REACHED-") {
		t.Errorf("the sandbox reached a service on the HOST's loopback:\n%s", r.out)
	}
	if strings.Contains(r.out, "SECRET-SERVICE-BANNER") {
		t.Errorf("the sandbox read from a host loopback service:\n%s", r.out)
	}
	for _, network := range want {
		if strings.Contains(r.out, "REFUSED-"+network) {
			continue
		}
		// Not a nitpick and not merely slow: an unreachable-because-dropped is a
		// different property from unreachable-because-refused, and only the
		// second one tells us the sandbox's own loopback answered.
		t.Errorf("the %s probe was neither refused nor reached — it was dropped. "+
			"That is a weaker result than this test claims to establish, and it is "+
			"where seconds of CI time go:\n%s", network, r.out)
	}
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
			c.Write([]byte("SECRET-SERVICE-BANNER\n"))
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
// it (DESIGN §12.4).
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
	for _, args := range [][]string{nil, {"-p", "net"}} {
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

// Host→sandbox publishing is OFF by default and only `net-publish` turns it on.
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
// extracted into a named test of its own, and the report on publish_auto.
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
	def := probeSandboxPort(t, proj, baseEnv(), "-p", "net")
	switch {
	case def.dialErr == nil:
		t.Errorf("the host reached a sandbox listener on 127.0.0.1:%d without net-publish", def.port)
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
		t.Errorf("the sandbox accepted a connection from the host without net-publish:\n%s", def.out)
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
		"include = [\"net\"]\npublish = [%d]\n", port)
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

	r := run(t, []string{"-p", "net"}, proj, `
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
	r := run(t, []string{"-p", "net"}, proj,
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

	out, code := cli(t, nil, "--dry-run", "-p", "net-host", proj)
	if code == 0 {
		t.Fatalf("net-host was accepted without --i-know:\n%s", out)
	}
	if !strings.Contains(out, "--i-know") {
		t.Errorf("the refusal should name the flag that overrides it:\n%s", out)
	}

	out, code = cli(t, nil, "--dry-run", "--i-know", "-p", "net-host", proj)
	if code != 0 {
		t.Errorf("net-host with --i-know should be accepted (exit %d):\n%s", code, out)
	}
}

// REGRESSION (redteam, M2): when the network could not be brought up, snug
// reported failure with exit 69 — and ran the payload anyway. The payload is
// parked on bwrap's --block-fd, which releases on EOF as readily as on a byte,
// so the deferred close during teardown released a child that killing bwrap had
// not reliably taken down. One abort in fifteen executed the payload and wrote
// to the target.
//
// Twenty iterations because the original failure was a race, not a certainty.
func TestAbortedNetworkNeverRunsThePayload(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	proj, _ := target(t)

	// A PATH with the essentials but no pasta, so the network setup fails at the
	// point where bwrap is already running and the payload is already parked —
	// which is the path that was not fail-closed.
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
		out, code := cli(t, baseEnv("PATH="+fakeBin), "-p", "net", proj, "--",
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

	cmd := exec.Command(snugBin, "-p", "net", proj, "--", "/bin/sleep", "30")
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
`, empty+":/usr/share/misc")
	if err := os.WriteFile(filepath.Join(dir, "evil.toml"), []byte(evil), 0o644); err != nil {
		t.Fatal(err)
	}
	env := baseEnv("XDG_CONFIG_HOME=" + cfg)

	for _, tc := range []struct{ profile, wantIn string }{
		{"hide-ssl", "/etc/ssl"},
		{"mask-misc", "/usr/share/misc"},
		{"greedy", "refusing to bind /"},
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

	out, code := cli(t, baseEnv("XDG_CONFIG_HOME="+cfg), "--dry-run", "-p", "x", proj)
	if code == 0 {
		t.Fatalf("an unknown profile key was ignored rather than refused:\n%s", out)
	}
	if !strings.Contains(out, "unknown") || !strings.Contains(out, "mask") {
		t.Errorf("the parse error should name the unknown key:\n%s", out)
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

	evil := "[profile.evil]\ninclude = [\"default\"]\nrw = [\"/etc\"]\n"
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
