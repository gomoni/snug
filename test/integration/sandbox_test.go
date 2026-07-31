//go:build integration

// Package integration launches real sandboxes and asserts what is and is not
// reachable from inside them.
//
// These are Go tests rather than shell in a CI workflow, and the difference is
// not cosmetic. The shell version hung a CI job for eleven minutes because a
// backgrounded listener held the step's stdout open; every assertion had
// passed. In Go the listener is a net.Listener owned by the test, closed by
// t.Cleanup, and there is no stdout pipe to leak.
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
// t.Parallel outright.
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
const cmdTimeout = 90 * time.Second

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

func requirePasta(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("pasta"); err != nil {
		skipOrFail(t, "pasta is not installed (package passt)")
	}
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
	out, err := cmd.CombinedOutput()

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
	requireSandbox(t)
	proj, _ := target(t)

	if r := run(t, nil, proj, `touch ok`).mustRun(t); r.code != 0 {
		t.Errorf("target should be writable: %s", r.out)
	}
	if r := run(t, nil, proj, `touch ../NOPE`).mustRun(t); r.code == 0 {
		t.Error("the parent directory should be read-only")
	}
}

func TestRootSkeletonIsReadOnly(t *testing.T) {
	requireSandbox(t)
	proj, _ := target(t)

	for _, dir := range []string{"/", "/home", "/usr", "/etc", "/var", "/proc"} {
		if r := run(t, nil, proj, "touch "+dir+"/ZZ").mustRun(t); r.code == 0 {
			t.Errorf("%s is writable inside the sandbox", dir)
		}
	}
}

// /dev is writable and that surprises people — it surprised the author, and it
// was found by running docs/VERIFY.md rather than by review. It is bwrap's own
// synthetic device tree on a private tmpfs, so what matters is not that it is
// read-only (it is not) but that a write there reaches neither the host nor the
// next sandbox. Say "the only writable thing that PERSISTS", never "the only
// writable thing".
func TestDevIsWritableButNeitherPersistsNorEscapes(t *testing.T) {
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

		fmt.Fprintf(&script,
			"timeout 5 bash -c 'exec 3<>/dev/tcp/%s/%d' 2>&1 && echo REACHED-%s\n",
			f.dial, port, f.network)
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

	probe := fmt.Sprintf(`import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect("\0%s")
    print("ABSTRACT-REACHED " + s.recv(64).decode(errors="replace"))
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
	}
}

// Host→sandbox publishing is OFF by default and only `net-publish` turns it on.
// With pasta's -t auto the SANDBOX would choose which host loopback ports
// appear, which inverts the guiding principle: the agent would be punching its
// own holes.
func TestSandboxPortsAreNotPublishedByDefault(t *testing.T) {
	requireSandbox(t)
	requirePasta(t)
	requirePython(t)
	proj, _ := target(t)

	// The target directory is a host bind, so it is also the synchronisation
	// channel: no sleep-and-hope, and no pipe held open by a background process.
	ready := filepath.Join(proj, "READY")
	listener := `import socket, os
s = socket.socket()
s.bind(("0.0.0.0", 0))
s.listen(1)
with open(os.environ["SNUG_TARGET"] + "/READY.tmp", "w") as f:
    f.write(str(s.getsockname()[1]))
os.rename(os.environ["SNUG_TARGET"] + "/READY.tmp", os.environ["SNUG_TARGET"] + "/READY")
s.settimeout(8)
try:
    s.accept()
    print("HOST-REACHED-THE-SANDBOX")
except OSError:
    print("nobody connected")
`
	if err := os.WriteFile(filepath.Join(proj, "listen.py"), []byte(listener), 0o644); err != nil {
		t.Fatal(err)
	}

	// Started by hand rather than through run(): the test has to talk to the
	// sandbox while it is still alive, and calling t.Fatal from a helper on
	// another goroutine is not allowed.
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, snugBin, "-p", "net", proj, "--", "/bin/bash", "-c",
		"printf '%s\\n' "+payloadMarker+"\npython3 listen.py")
	cmd.Env = baseEnv()
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

	port := 0
	deadline := time.Now().Add(20 * time.Second)
	for port == 0 && time.Now().Before(deadline) {
		if b, err := os.ReadFile(ready); err == nil {
			fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &port)
		}
		if port == 0 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if port == 0 {
		t.Fatal("the sandbox never reported a listening port")
	}

	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err == nil {
		c.Close()
		t.Errorf("the host reached a sandbox listener on 127.0.0.1:%d without net-publish", port)
	}

	cmd.Wait()
	waited = true
	out := buf.String()
	if !strings.Contains(out, payloadMarker) {
		t.Fatalf("the payload never ran, so this test would prove nothing:\n%s", out)
	}
	if strings.Contains(out, "HOST-REACHED-THE-SANDBOX") {
		t.Errorf("the sandbox accepted a connection from the host without net-publish:\n%s", out)
	}
}

// The sandbox's own loopback must still work — the closure above is of the
// HOST's 127.0.0.1, not of loopback as a concept, and an agent running a dev
// server and curling it is the ordinary case.
func TestSandboxHasItsOwnWorkingLoopback(t *testing.T) {
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
	requireSandbox(t)
	requirePasta(t)
	requireInternet(t)
	proj, _ := target(t)

	r := run(t, []string{"-p", "net"}, proj,
		`curl -sf -o /dev/null --max-time 20 https://example.com && echo EGRESS-OK`).mustRun(t)
	if r.code != 0 || !strings.Contains(r.out, "EGRESS-OK") {
		t.Errorf("no egress with the net profile:\n%s", r.out)
	}
}

// net-host is a knowingly-large hole — it shares the HOST network namespace,
// which means host loopback services and abstract AF_UNIX sockets (X11, D-Bus)
// are all reachable. Selecting the profile must not be enough; the human has to
// say --i-know. This needs no sandbox to run, so it is checked with --dry-run.
func TestNetHostIsRefusedWithoutIKnow(t *testing.T) {
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
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	before := pastaPIDs()

	cmd := exec.Command(snugBin, "-p", "net", proj, "--", "/bin/sleep", "30")
	cmd.Env = baseEnv()
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
	var helpers []int
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if helpers = newPIDs(before, pastaPIDs()); len(helpers) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
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
	deadline = time.Now().Add(20 * time.Second)
	for {
		left := newPIDs(before, pastaPIDs())
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("network helper(s) %v survived snug being SIGKILLed", left)
		}
		time.Sleep(100 * time.Millisecond)
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
