package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// snugCLIHelperEnv gates TestSnugCLIHelperProcess: unset, an ordinary `go
// test` run of this file never reaches it. Set — by runSnugMain, below — it
// makes THIS test binary BE `snug`, hidden-verb switch and reserved-word
// switch included, for exactly one subprocess invocation.
const snugCLIHelperEnv = "SNUG_CLI_HELPER_PROCESS"

// TestSnugCLIHelperProcess is internal/sandbox/teardown_test.go's own pattern
// (TestTeardownSignalHelperProcess): a second personality for this same test
// binary, selected at runtime by an environment variable instead of a second
// `go build`. It is what lets a test of Main()'s own argv dispatch — the
// `attach` reserved word is decided inside Main, before parseArgs ever runs —
// live in internal/cli, unprivileged, rather than test/integration building
// ./cmd/snug: nothing this file's tests exercise creates a namespace, so
// nothing here needs one.
//
// The real argv is read off os.Args directly, after a literal "--", never
// through the flag package: go test's generated main() has already consumed
// every "-test.*" flag by the time this body runs, and Main() below reads
// os.Args itself — using flag.Args() here would read a package-level
// FlagSet's idea of what survived "--", not necessarily the same slice.
func TestSnugCLIHelperProcess(t *testing.T) {
	if os.Getenv(snugCLIHelperEnv) == "" {
		return
	}
	var args []string
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	os.Args = append([]string{os.Args[0]}, args...)
	Main() // calls os.Exit; never returns
}

// runSnugMain runs Main() in a fresh subprocess of this test binary, with dir
// as its working directory and args as argv[1:]. env is layered over this
// process's own environ — os/exec keeps the LAST duplicate of a key, so an
// entry here overrides whatever this test process inherited — which is how
// every case below points HOME and XDG_CONFIG_HOME at scratch directories
// rather than the machine running the suite.
//
// Bounded at 15s and reported as a hang, not a timeout, if it is ever hit:
// nothing this file drives Main() through does host I/O anywhere near that
// slow, so hitting the bound is itself the finding.
func runSnugMain(t *testing.T, dir string, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmdArgs := append([]string{"-test.run=^TestSnugCLIHelperProcess$", "--"}, args...)
	cmd := exec.CommandContext(ctx, os.Args[0], cmdArgs...)
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, os.Environ()...), append([]string{snugCLIHelperEnv + "=1"}, env...)...)

	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()

	if ctx.Err() != nil {
		t.Fatalf("snug %s did not finish within 15s (a hang is a finding):\nstdout:\n%s\nstderr:\n%s",
			strings.Join(args, " "), out.String(), errb.String())
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("running the snug CLI helper subprocess (args %v): %v", args, err)
		}
		return out.String(), errb.String(), ee.ExitCode()
	}
	return out.String(), errb.String(), 0
}

// TestAttachVerbIsRefusedAndNamesTheReplacement is the fix for the deleted
// `attach` verb falling through the subcommand switch to parseArgs as a
// positional argument: main.go now has a `case "attach":` in the same switch
// as doctor/profile/config/proxy/engine/fix/help, so the word is refused by
// name before parseArgs ever sees it, on a tree with no directory named
// "attach" at all — this test's companion,
// TestAttachVerbDoesNotSandboxADirectoryNamedAttach, is the one where a
// directory of that name is actually present.
func TestAttachVerbIsRefusedAndNamesTheReplacement(t *testing.T) {
	dir := t.TempDir()
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	stdout, stderr, code := runSnugMain(t, dir, env, "attach")

	if code != exitUsage {
		t.Errorf("`snug attach` exited %d, want exitUsage (%d)", code, exitUsage)
	}
	if stdout != "" {
		t.Errorf("`snug attach` wrote to stdout; a refusal belongs on stderr alone:\n%s", stdout)
	}
	if !strings.HasPrefix(stderr, "snug: ") {
		t.Errorf("the refusal does not begin \"snug: \":\n%s", stderr)
	}
	if !strings.Contains(stderr, "`snug attach` was removed") {
		t.Errorf("the refusal does not say the verb was removed:\n%s", stderr)
	}
	// The replacement it names: a second session is a second, independent
	// sandbox, not a way back into the first one's namespaces.
	if !strings.Contains(stderr, "second, independent sandbox") {
		t.Errorf("the refusal does not name what replaced attach:\n%s", stderr)
	}
	if !strings.Contains(stderr, "snug ./attach") {
		t.Errorf("the refusal does not name the escape hatch for a directory actually "+
			"named \"attach\":\n%s", stderr)
	}
}

// lockPathForTarget returns the exact path lockTarget(target) itself places
// its flock file at: target-<hash(realpath)>.lock, in the per-uid runtime
// directory targetLockBase resolves from the uid ALONE (never from an
// environment variable, which is the one thing this test could not carry
// across the subprocess boundary anyway). It is the one host-visible effect
// of run() that needs no bwrap and no namespace — a plain flock on a regular
// file — which is what makes it usable as a witness from an unprivileged
// test.
func lockPathForTarget(t *testing.T, target string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatalf("resolving %s: %v", target, err)
	}
	base, snugName, err := targetLockBase()
	if err != nil {
		t.Fatalf("targetLockBase: %v", err)
	}
	return filepath.Join(base, snugName, targetLockName(real))
}

// TestAttachVerbDoesNotSandboxADirectoryNamedAttach is the negative half, and
// the one that matters: catches a regression where `snug attach`, run from a
// tree that happens to contain ./attach, falls through the subcommand switch
// and parseArgs reads the bare word "attach" as a target indistinguishable
// from "./attach" — the shape that let the removed `attach` verb silently
// start a sandbox instead of erroring.
//
// The proof is structural, not the exit code alone. run()'s first
// host-visible act on a real invocation is lockTarget, so if `snug attach`
// ever reached run() again, lockPathForTarget's file is where it would show
// up first — before profile resolution, before bwrap, before any namespace.
//
// POSITIVE CONTROL: this test calls lockTarget on the identical path
// in-process before it ever spawns the subprocess, and confirms the file
// really does appear where the assertion below is about to check for its
// absence. Without this, a typo in lockPathForTarget's arithmetic would make
// the negative pass by comparing against a path nothing was ever going to
// write to (the exact "pasta" vs "pasta.avx2" shape: a check that always
// reads zero).
func TestAttachVerbDoesNotSandboxADirectoryNamedAttach(t *testing.T) {
	dir := t.TempDir()
	attachDir := filepath.Join(dir, "attach")
	if err := os.Mkdir(attachDir, 0o755); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	lockPath := lockPathForTarget(t, attachDir)
	t.Cleanup(func() { os.Remove(lockPath) })
	if _, err := os.Lstat(lockPath); err == nil {
		t.Fatalf("a lock file already exists at %s before this test touched anything; the "+
			"target hash collided with something else on this host", lockPath)
	}

	// ── positive control ────────────────────────────────────────────────
	unlock, err := lockTarget(attachDir)
	if err != nil {
		t.Fatalf("lockTarget(%s): %v", attachDir, err)
	}
	if _, err := os.Lstat(lockPath); err != nil {
		t.Fatalf("lockTarget did not create a lock file at %s, the path this test computed: %v — "+
			"the negative assertion below would then pass on a path nothing was ever going to "+
			"write to", lockPath, err)
	}
	unlock()
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("removing the control's own lock file: %v", err)
	}

	// ── the actual case ─────────────────────────────────────────────────
	// "-- true", not a bare word: even if the reserved-word case were
	// removed, argv[0] "attach" would still be intercepted before parseArgs
	// ever reads a trailing command — but pinning that with a fast, harmless
	// command rather than the default interactive shell keeps a REGRESSION
	// of this test from also hanging `go test` on a missing controlling
	// terminal.
	_, stderr, code := runSnugMain(t, dir, env, "attach", "--", "true")

	if code != exitUsage {
		t.Errorf("`snug attach -- true` (cwd contains ./attach) exited %d, want exitUsage (%d): "+
			"a directory literally named \"attach\" must not change the outcome", code, exitUsage)
	}
	if !strings.Contains(stderr, "`snug attach` was removed") {
		t.Errorf("`snug attach -- true` did not refuse by name:\n%s", stderr)
	}
	if _, err := os.Lstat(lockPath); err == nil {
		t.Errorf("a lock file exists at %s after `snug attach -- true`: run() was reached and "+
			"a sandbox on ./attach was started, which is the exact silent fallthrough this "+
			"reserved word exists to close", lockPath)
	}
}

// TestAttachEscapeHatchTargetsADirectoryNamedAttach pins the other half of
// the refusal's own message: "To sandbox a directory actually named
// \"attach\", write it as a path: `snug ./attach`." --dry-run is enough to
// prove it starts nothing while still reaching policy resolution: argv[0] is
// "./attach", which begins with '.', not '-', so the reserved-word switch
// (which only inspects argv[0]) never matches it and parseArgs reads it as an
// ordinary target.
func TestAttachEscapeHatchTargetsADirectoryNamedAttach(t *testing.T) {
	dir := t.TempDir()
	attachDir := filepath.Join(dir, "attach")
	if err := os.Mkdir(attachDir, 0o755); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	stdout, stderr, code := runSnugMain(t, dir, env, "--dry-run", "./attach")

	if code != 0 {
		t.Fatalf("`snug --dry-run ./attach` exited %d, want 0:\nstderr:\n%s", code, stderr)
	}
	// attachDir, not a resolved realpath: dry-run's TARGET line is
	// filepath.Abs(target) exactly as parseArgs sets it, with no symlink
	// resolution, and that is what filepath.Join(dir, "attach") already is
	// for a target given as a plain t.TempDir() path.
	if !strings.Contains(stdout, "TARGET   "+attachDir) {
		t.Errorf("the dry-run screen does not name %s as TARGET; the escape hatch the "+
			"refusal points at does not work:\n%s", attachDir, stdout)
	}
}
