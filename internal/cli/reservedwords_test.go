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
// reserved-word switch runs inside Main, before parseArgs ever sees argv —
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

// TestADeletedVerbIsNotAReservedWord pins the decision that `attach` — the
// one verb snug has ever removed — went back to being an ordinary word the
// moment its code did. The tombstone alternative was written and dropped: a
// `case "attach":` that only refuses costs every user a directory name
// forever, on behalf of a habit that lasts one release, and issue #548 makes
// exactly that argument about the reserved-word list in general ("every flat
// verb permanently removes a word from the set of directory names a user can
// pass bare").
//
// So the assertion is that `snug attach`, run from a tree containing
// ./attach, sandboxes it — the same as any other directory name. --dry-run is
// enough: it reaches policy resolution and prints the TARGET it settled on
// while starting nothing, so this stays an unprivileged test.
//
// The stable spelling this leaves a script with is `snug ./attach`, and
// whether a flag form should make it stable WITHOUT a path prefix is issue
// #564.
func TestADeletedVerbIsNotAReservedWord(t *testing.T) {
	dir := t.TempDir()
	attachDir := filepath.Join(dir, "attach")
	if err := os.Mkdir(attachDir, 0o755); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	stdout, stderr, code := runSnugMain(t, dir, env, "--dry-run", "attach")

	if code != 0 {
		t.Fatalf("`snug --dry-run attach` exited %d, want 0 — a bare \"attach\" must be read "+
			"as a directory, not intercepted:\nstderr:\n%s", code, stderr)
	}
	// attachDir, not a resolved realpath: dry-run's TARGET line is
	// filepath.Abs(target) exactly as parseArgs sets it, with no symlink
	// resolution, and that is what filepath.Join(dir, "attach") already is
	// for a target given as a plain t.TempDir() path.
	if !strings.Contains(stdout, "TARGET   "+attachDir) {
		t.Errorf("the dry-run screen does not name %s as TARGET: something is still "+
			"intercepting the bare word \"attach\":\n%s", attachDir, stdout)
	}
}

// TestALiveSubcommandIsStillAReservedWord is the contrast that makes the test
// above readable, and it is the one that fails if somebody re-adds `attach`
// to the switch: a word that IS dispatched swallows a directory of the same
// name, and that is the cost issue #548 is weighing.
//
// The witness is structural rather than the exit code. run()'s first
// host-visible act is lockTarget, so if `snug config` were ever read as a
// target instead of a subcommand, lockPathForTarget's file is where it would
// show up — before profile resolution, before bwrap, before any namespace.
//
// POSITIVE CONTROL: lockTarget is called on the identical path in-process
// first, so a typo in lockPathForTarget's arithmetic cannot make the negative
// pass by checking a path nothing was ever going to write to (the "pasta" vs
// "pasta.avx2" shape: a check that always reads zero).
func TestALiveSubcommandIsStillAReservedWord(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.Mkdir(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}

	lockPath := lockPathForTarget(t, configDir)
	t.Cleanup(func() { os.Remove(lockPath) })
	if _, err := os.Lstat(lockPath); err == nil {
		t.Fatalf("a lock file already exists at %s before this test touched anything; the "+
			"target hash collided with something else on this host", lockPath)
	}

	// ── positive control ────────────────────────────────────────────────
	unlock, err := lockTarget(configDir)
	if err != nil {
		t.Fatalf("lockTarget(%s): %v", configDir, err)
	}
	if _, err := os.Lstat(lockPath); err != nil {
		t.Fatalf("lockTarget did not create a lock file at %s, the path this test computed: %v — "+
			"the assertion below would then pass on a path nothing was ever going to "+
			"write to", lockPath, err)
	}
	unlock()
	if err := os.Remove(lockPath); err != nil {
		t.Fatalf("removing the control's own lock file: %v", err)
	}

	// ── the actual case ─────────────────────────────────────────────────
	runSnugMain(t, dir, env, "config")

	if _, err := os.Lstat(lockPath); err == nil {
		t.Errorf("a lock file exists at %s after `snug config` (cwd contains ./config): the "+
			"word was read as a target rather than dispatched, so the reserved-word switch "+
			"is not doing what main.go's comment says", lockPath)
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
