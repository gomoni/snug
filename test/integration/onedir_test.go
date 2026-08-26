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

// TestOneLiveSandboxPerDirectory is issue #119 measured where it lands: a
// second `snug <dir>` on a directory that already has a live sandbox is
// refused, the refusal names `snug attach`, and NOTHING is started for it —
// its payload never runs. Three controls sit alongside the negative so it
// cannot pass on a broken harness:
//
//   - POSITIVE CONTROL (the first run IS up): the live sandbox writes a
//     readiness file into the target before the second run is attempted, so
//     the refusal is known to be a live holder and not an empty directory.
//   - PER-TARGET CONTROL: a concurrent run on a DIFFERENT directory starts
//     fine, proving the lock is per-target and not a global mutex.
//   - RECLAIM CONTROL: after the live holder is SIGKILLed, a fresh run on the
//     same directory succeeds — a dead holder does not wedge a directory.
//
// The live holder is a background snug whose exact pid this test kills in a
// cleanup; nothing is ever killed by name.
func TestOneLiveSandboxPerDirectory(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	// A private runtime directory shared by every snug in this test, so they
	// contend on the same per-target lock and never on the developer's real
	// $XDG_RUNTIME_DIR. os/exec keeps the last duplicate, so this wins over the
	// inherited one in baseEnv. shortRuntimeDir, not t.TempDir() (this file's
	// other test has its own comment on why).
	runtimeDir := shortRuntimeDir(t)
	env := baseEnv("XDG_RUNTIME_DIR=" + runtimeDir)

	dirA := t.TempDir()
	dirB := t.TempDir()

	readyA := filepath.Join(dirA, "READY_A")
	// The live holder: announce readiness, then block until killed. It writes
	// into the target itself (the one writable thing that persists), which the
	// host side sees through the bind.
	holder := startBackgroundSnug(t, env, dirA,
		"touch "+shQuote(readyA)+"; while true; do sleep 1; done")

	if err := waitForFile(readyA, 30*time.Second); err != nil {
		t.Fatalf("the live holder never signalled readiness (%v); its output so far:\n%s", err, holder.output())
	}

	// ── the negative: a second run on the SAME directory is refused ──────────
	readyB := filepath.Join(dirA, "READY_B")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	second := exec.CommandContext(ctx, snugBin, dirA, "--", "/bin/bash", "-c", "touch "+shQuote(readyB))
	second.Env = env
	out, err := second.CombinedOutput()

	if err == nil {
		t.Fatalf("a second `snug %s` was NOT refused while one was live:\n%s", dirA, out)
	}
	code := second.ProcessState.ExitCode()
	if code == 0 {
		t.Fatalf("second run exited 0 (not refused):\n%s", out)
	}
	if !strings.Contains(string(out), "snug attach") {
		t.Errorf("refusal does not name `snug attach`:\n%s", out)
	}
	if !strings.Contains(string(out), "already live") {
		t.Errorf("refusal does not say a sandbox is already live:\n%s", out)
	}
	// NOTHING was started for the refused run: its payload never touched READY_B.
	if _, statErr := os.Stat(readyB); statErr == nil {
		t.Errorf("the refused run's payload ran — READY_B exists — so the refusal did not start nothing")
	}

	// ── PER-TARGET CONTROL: a different directory starts fine, concurrently ──
	readyBdir := filepath.Join(dirB, "READY")
	ctxB, cancelB := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelB()
	otherDir := exec.CommandContext(ctxB, snugBin, dirB, "--", "/bin/bash", "-c", "touch "+shQuote(readyBdir))
	otherDir.Env = env
	if outB, errB := otherDir.CombinedOutput(); errB != nil {
		t.Fatalf("a concurrent run on a DIFFERENT directory was refused — the lock is not per-target:\n%s", outB)
	}
	if _, statErr := os.Stat(readyBdir); statErr != nil {
		t.Errorf("the different-directory run did not actually run its payload: %v", statErr)
	}

	// ── RECLAIM CONTROL: kill the holder, the directory must be usable again ─
	holder.killAndWait()

	readyD := filepath.Join(dirA, "READY_D")
	ctxD, cancelD := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelD()
	reclaim := exec.CommandContext(ctxD, snugBin, dirA, "--", "/bin/bash", "-c", "touch "+shQuote(readyD))
	reclaim.Env = env
	if outD, errD := reclaim.CombinedOutput(); errD != nil {
		t.Fatalf("a fresh run on the same directory after the holder was killed was refused — "+
			"the directory is wedged:\n%s", outD)
	}
	if _, statErr := os.Stat(readyD); statErr != nil {
		t.Errorf("the reclaiming run did not actually run its payload: %v", statErr)
	}
}

// TestOneLiveSandboxPerDirectoryHoldsAcrossXDGRuntimeDir is issue #122 measured
// end-to-end: the per-target lock must serialise two runs that see DIFFERENT
// $XDG_RUNTIME_DIR — an interactive shell (variable set) and a cron/systemd/ssh
// session (variable absent). The pre-fix code took the lock under
// runtimeBase() = $XDG_RUNTIME_DIR/$TMPDIR, so the two runs flock'd two inodes
// and BOTH acquired — two live sandboxes on one writable target, a fail-OPEN
// that needs no attacker. The fix resolves the lock's directory from the uid
// alone, so both runs land on the same inode and the contender is refused.
//
// POSITIVE CONTROL: the holder writes a readiness file before the contender is
// attempted, so the refusal is a live holder and not an empty directory.
// DISTINGUISHING CONTROL over TestOneLiveSandboxPerDirectory (which runs both
// under one $XDG_RUNTIME_DIR): here the two runs see DIFFERENT env, so a bare
// "refused" is specifically "refused despite the env split #122 exploited".
func TestOneLiveSandboxPerDirectoryHoldsAcrossXDGRuntimeDir(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	dir := t.TempDir()

	// Holder: $XDG_RUNTIME_DIR SET (interactive-shell shape). shortRuntimeDir,
	// not t.TempDir(): every $XDG_RUNTIME_DIR built in this suite is short-
	// rooted uniformly (attachEnv's own comment), not case by case on whether
	// this particular run happens to bind a proxy socket under it.
	holderEnv := baseEnv("XDG_RUNTIME_DIR=" + shortRuntimeDir(t))
	// Contender: $XDG_RUNTIME_DIR ABSENT (cron/ssh shape). baseEnv carries the
	// developer's real value via os.Environ(); strip it so the two runs genuinely
	// disagree on the mutable base the bug depended on.
	contenderEnv := withoutEnv(baseEnv(), "XDG_RUNTIME_DIR")

	ready := filepath.Join(dir, "READY")
	holder := startBackgroundSnug(t, holderEnv, dir,
		"touch "+shQuote(ready)+"; while true; do sleep 1; done")
	if err := waitForFile(ready, 30*time.Second); err != nil {
		t.Fatalf("the live holder never signalled readiness (%v); its output so far:\n%s", err, holder.output())
	}

	marker := filepath.Join(dir, "CONTENDER_RAN")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	contender := exec.CommandContext(ctx, snugBin, dir, "--", "/bin/bash", "-c", "touch "+shQuote(marker))
	contender.Env = contenderEnv
	out, err := contender.CombinedOutput()

	if err == nil {
		t.Fatalf("a contender with $XDG_RUNTIME_DIR unset was NOT refused while a holder with it "+
			"SET was live — the target lock split across two inodes (issue #122 fail-OPEN):\n%s", out)
	}
	if code := contender.ProcessState.ExitCode(); code != 69 {
		t.Errorf("contender exit code = %d, want 69 (EX_UNAVAILABLE):\n%s", code, out)
	}
	if !strings.Contains(string(out), "snug attach") {
		t.Errorf("refusal does not name `snug attach`:\n%s", out)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Errorf("the refused contender's payload ran — CONTENDER_RAN exists — so the refusal did not start nothing")
	}
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
