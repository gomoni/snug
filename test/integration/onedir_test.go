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
	// inherited one in baseEnv.
	runtimeDir := t.TempDir()
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

// backgroundSnug is a snug started with Start() (not Run()) so the test can
// carry on while it holds its per-target lock, and kill it by its exact pid.
type backgroundSnug struct {
	cmd *exec.Cmd
	out *syncBuffer
	t   *testing.T

	killed bool
}

func startBackgroundSnug(t *testing.T, env []string, dir, script string) *backgroundSnug {
	t.Helper()
	cmd := exec.Command(snugBin, dir, "--", "/bin/bash", "-c", script)
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
