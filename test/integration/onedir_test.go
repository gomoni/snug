//go:build integration

package integration

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a concurrency-safe io.Writer: the background snug writes to it
// from os/exec's copier goroutines while the test reads it from the main one.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestTwoLiveSandboxesOnOneDirectory is the rule measured where it lands: a
// second `snug <dir>` on a directory that already has a live sandbox STARTS,
// runs its payload, and the two coexist. Two sessions on one project are two
// sandboxes.
//
// It is the inversion of issue #119's test, which asserted the refusal this
// replaces. What made the refusal wrong was not the footgun it named — two runs
// racing writes on one target is real, and --dry-run's SHARED block states it —
// but that the refusal's only escape hatch was `snug attach`, which put the
// second session inside the first's namespaces where it could read the
// payload's /proc/<pid>/environ and write through its descriptors.
//
// CONTROLS, so a pass is not a harness that starts nothing:
//
//   - POSITIVE (the first run IS up): the live sandbox writes a readiness file
//     into the target before the second is attempted, so the second is known to
//     have started BESIDE a live holder rather than after it died.
//   - LIVENESS: the first sandbox is still RUNNING once the second has come and
//     gone. The second run sweeps for orphans at startup (main.go), and that
//     sweep reads the same per-target lock; a shared lock that stopped
//     answering "live" would have it kill the first run's init.
//   - ISOLATION: the second sandbox does not see the first's tmpfs $HOME. The
//     two share the target and nothing else, which is the whole claim.
//
// The live holder is a background snug whose exact pid this test kills in a
// cleanup; nothing is ever killed by name.
func TestTwoLiveSandboxesOnOneDirectory(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	// A private runtime directory shared by every snug in this test, so they
	// meet on the same per-target lock and never on the developer's real
	// $XDG_RUNTIME_DIR. os/exec keeps the last duplicate, so this wins over the
	// inherited one in baseEnv. shortRuntimeDir, not t.TempDir() (this file's
	// other test has its own comment on why).
	runtimeDir := shortRuntimeDir(t)
	env := baseEnv("XDG_RUNTIME_DIR=" + runtimeDir)

	dir := t.TempDir()

	readyA := filepath.Join(dir, "READY_A")
	beat := filepath.Join(dir, "HEARTBEAT")
	// The live holder: drop a file in its own tmpfs $HOME, announce readiness,
	// then beat until killed. It writes into the target itself (the one
	// writable thing that persists), which the host side sees through the bind.
	//
	// A HEARTBEAT rather than `sleep`, because the liveness check below cannot
	// be a signal: the holder is this test's own unreaped child, so kill(pid,0)
	// succeeds against its zombie exactly as against a running process. An
	// advancing mtime is produced only by a payload that is really executing.
	holder := startBackgroundSnug(t, env, dir,
		"echo first > \"$HOME/whose-home\"; touch "+shQuote(readyA)+
			"; while true; do touch "+shQuote(beat)+"; sleep 0.2; done")

	if err := waitForFile(readyA, 30*time.Second); err != nil {
		t.Fatalf("the live holder never signalled readiness (%v); its output so far:\n%s", err, holder.output())
	}

	// ── the rule: a second run on the SAME directory starts ─────────────────
	readyB := filepath.Join(dir, "READY_B")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	second := exec.CommandContext(ctx, snugBin, dir, "--", "/bin/bash", "-c",
		"touch "+shQuote(readyB)+"; ls \"$HOME/whose-home\" 2>&1; cat "+shQuote(readyA)+" >/dev/null && echo SEES-TARGET")
	second.Env = env
	out, err := second.CombinedOutput()

	if err != nil {
		t.Fatalf("a second `snug %s` was refused while one was live (exit %d):\n%s",
			dir, second.ProcessState.ExitCode(), out)
	}
	if _, statErr := os.Stat(readyB); statErr != nil {
		t.Fatalf("the second run exited 0 but its payload never ran (%v):\n%s", statErr, out)
	}

	// ── ISOLATION: the second sandbox has its own $HOME ─────────────────────
	if !strings.Contains(string(out), "No such file or directory") {
		t.Errorf("the second sandbox can see a file the first wrote into its tmpfs $HOME. The "+
			"two share the target bind and nothing else:\n%s", out)
	}
	// CONTROL for that negative: the second sandbox CAN see the target, so
	// "No such file" above is about $HOME and not about a sandbox that sees
	// nothing at all.
	if !strings.Contains(string(out), "SEES-TARGET") {
		t.Errorf("the second sandbox could not read the file the first wrote into the TARGET, "+
			"so the $HOME negative above proves nothing:\n%s", out)
	}

	// ── LIVENESS: the first sandbox survived the second's startup sweep ─────
	if !beating(t, beat, 3*time.Second) {
		t.Errorf("the first sandbox stopped running after a second run started on the same "+
			"directory. The second run sweeps for orphans once it holds the target lock, and "+
			"a lock that no longer reads as held is what licenses that sweep to SIGKILL the "+
			"first run's init:\n%s", holder.output())
	}

	// ── the holder dies, and the directory keeps working ────────────────────
	holder.killAndWait()

	readyD := filepath.Join(dir, "READY_D")
	ctxD, cancelD := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelD()
	third := exec.CommandContext(ctxD, snugBin, dir, "--", "/bin/bash", "-c", "touch "+shQuote(readyD))
	third.Env = env
	if outD, errD := third.CombinedOutput(); errD != nil {
		t.Fatalf("a fresh run on the same directory after the holder was killed failed:\n%s", outD)
	}
	if _, statErr := os.Stat(readyD); statErr != nil {
		t.Errorf("the third run did not actually run its payload: %v", statErr)
	}
}

// TestARunIsVisibleAcrossXDGRuntimeDir is issue #122 measured end-to-end,
// restated for the shared lock: a run started with $XDG_RUNTIME_DIR SET
// (interactive shell) and a run started with it ABSENT (cron/systemd/ssh) must
// land on the SAME per-target lock inode.
//
// The pre-fix code took the lock under runtimeBase() = $XDG_RUNTIME_DIR/$TMPDIR,
// so the two runs flock'd two inodes. That used to be a fail-OPEN of the
// one-sandbox-per-target rule. The rule is gone and the split is not: the
// per-target lock is what the orphan sweep and `snug engine gc` read, and a run
// on an inode they never look at is a run whose init the sweep is licensed to
// SIGKILL and whose store gc is licensed to reclaim.
//
// It is asserted from the sweeping side, because that is the side that acts on
// the answer: the second run performs its own startup sweep (main.go calls
// sweepOrphanedSandboxes once it holds the lock), and the first run's payload
// must still be alive afterwards.
func TestARunIsVisibleAcrossXDGRuntimeDir(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	dir := t.TempDir()

	// Holder: $XDG_RUNTIME_DIR SET (interactive-shell shape). shortRuntimeDir,
	// not t.TempDir(): every $XDG_RUNTIME_DIR built in this suite is short-
	// rooted uniformly (suiteEnv's own comment), not case by case on whether
	// this particular run happens to bind a proxy socket under it.
	holderEnv := baseEnv("XDG_RUNTIME_DIR=" + shortRuntimeDir(t))
	// Second run: $XDG_RUNTIME_DIR ABSENT (cron/ssh shape). baseEnv carries the
	// developer's real value via os.Environ(); strip it so the two runs genuinely
	// disagree on the mutable base the bug depended on.
	otherEnv := withoutEnv(baseEnv(), "XDG_RUNTIME_DIR")

	ready := filepath.Join(dir, "READY")
	beat := filepath.Join(dir, "HEARTBEAT")
	holder := startBackgroundSnug(t, holderEnv, dir,
		"touch "+shQuote(ready)+"; while true; do touch "+shQuote(beat)+"; sleep 0.2; done")
	if err := waitForFile(ready, 30*time.Second); err != nil {
		t.Fatalf("the live holder never signalled readiness (%v); its output so far:\n%s", err, holder.output())
	}

	marker := filepath.Join(dir, "SECOND_RAN")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	other := exec.CommandContext(ctx, snugBin, dir, "--", "/bin/bash", "-c", "touch "+shQuote(marker))
	other.Env = otherEnv
	out, err := other.CombinedOutput()

	if err != nil {
		t.Fatalf("a run with $XDG_RUNTIME_DIR unset failed on a directory a run with it SET was "+
			"holding (exit %d):\n%s", other.ProcessState.ExitCode(), out)
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatalf("the second run exited 0 but its payload never ran (%v):\n%s", statErr, out)
	}

	// THE ASSERTION: the second run swept, and the first is still executing. If
	// the two had landed on different lock inodes the sweep would have read the
	// holder's target as unheld.
	//
	// The #489 owner gate would also have to fail for the kill to land, so this
	// is the outer of two doors rather than the only one — but a sweep that
	// cannot see a live run is the defect, whether or not the second door held.
	if !beating(t, beat, 3*time.Second) {
		t.Fatalf("the holder stopped running after a second run's startup sweep — the two runs "+
			"resolved different target lock inodes (issue #122):\n%s", holder.output())
	}
}

// beating reports whether path's mtime ADVANCES within timeout, which is the
// only liveness signal available for a payload inside a sandbox this test
// cannot signal: the background snug is this test's own unreaped child, so
// kill(pid, 0) succeeds against its zombie just as it does against a live
// process, and the payload has no pid the host can name at all.
func beating(t *testing.T, path string, timeout time.Duration) bool {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the heartbeat file %s does not exist, so this check measures nothing: %v", path, err)
	}
	was := fi.ModTime()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(path); err == nil && fi.ModTime().After(was) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// withoutEnv returns env with every assignment of key removed. os/exec keeps
// the LAST duplicate, so appending an override cannot UNSET a variable — only
// dropping every occurrence can produce the variable-absent shape a cron or
// non-login ssh session actually has.
func withoutEnv(env []string, key string) []string {
	prefix := key + "="
	out := env[:0:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// backgroundSnug is a snug started with Start() (not Run()) so the test can
// carry on while it holds its per-target lock, and kill it by its exact pid.
type backgroundSnug struct {
	cmd *exec.Cmd
	out *syncBuffer
	t   *testing.T

	killed bool
}

// snugArgs are flags placed BEFORE the target directory — a profile
// selection, say. Variadic so every existing caller reads unchanged; a test
// that needs a live sandbox with a particular profile (issue #21's control:
// only an identity profile binds an agent socket) no longer has to build its
// own copy of this function to get one.
func startBackgroundSnug(t *testing.T, env []string, dir, script string, snugArgs ...string) *backgroundSnug {
	t.Helper()
	argv := append(append([]string{}, snugArgs...), dir, "--", "/bin/bash", "-c", script)
	cmd := exec.Command(snugBin, argv...)
	cmd.Env = env
	buf := &syncBuffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the background snug: %v", err)
	}
	b := &backgroundSnug{cmd: cmd, out: buf, t: t}
	t.Cleanup(b.killAndWait)
	return b
}

func (b *backgroundSnug) killAndWait() {
	if b.killed {
		return
	}
	b.killed = true
	// Exact pid only, never by name (bwrap is Flatpak on some hosts).
	_ = b.cmd.Process.Kill()
	_, _ = b.cmd.Process.Wait()
}

func (b *backgroundSnug) output() string { return b.out.String() }
