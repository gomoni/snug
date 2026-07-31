// Package engine runs a container engine that belongs to one sandbox.
//
// It is never the host's podman. A sandbox gets its own store, its own runroot
// and its own service process, so:
//
//   - the host's images, containers, volumes and networks are untouched, and
//     the sandbox cannot list or delete them
//   - two projects cannot see each other's containers
//   - a more privileged profile set never inherits a store built under a less
//     privileged one, because the store key includes the profile set
//
// The engine starts LAZILY, on the first request that reaches the proxy, so a
// run that never touches containers pays nothing for having the profile on.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Engine struct {
	sock    string
	store   string
	runroot string

	mu   sync.Mutex
	cmd  *exec.Cmd
	once sync.Once
}

// New computes the paths for a sandbox's engine but starts nothing.
//
// The key is derived from the profile set AND the target, so the same project
// with the same profiles reuses its images across runs (a warm start) while a
// different project — or the same project with wider profiles — gets a
// different store.
func New(profiles []string, target string) (*Engine, error) {
	sorted := append([]string(nil), profiles...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, ",") + "\x00" + target))
	key := hex.EncodeToString(sum[:])[:16]

	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	runHome := os.Getenv("XDG_RUNTIME_DIR")
	if runHome == "" {
		runHome = os.TempDir()
	}

	e := &Engine{
		store: filepath.Join(dataHome, "snug", "engines", key, "storage"),
		// runroot lives on a tmpfs, so a hard-killed snug cannot leave a stale
		// lock that survives a reboot.
		runroot: filepath.Join(runHome, "snug", "engines", key, "rr"),
		sock:    filepath.Join(runHome, "snug", "engines", key, "podman.sock"),
	}
	for _, d := range []string{e.store, e.runroot, filepath.Dir(e.sock)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	return e, nil
}

func (e *Engine) Socket() string { return e.sock }

// Start brings the engine up if it is not already running. Safe to call from
// several requests at once; only the first does the work.
func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cmd != nil {
		return nil
	}

	podman, err := exec.LookPath("podman")
	if err != nil {
		return fmt.Errorf("the podman profile is selected but podman is not installed.\n" +
			"      snug will not silently hand the sandbox no engine, or the host's")
	}

	_ = os.Remove(e.sock) // a stale socket from a hard kill
	cmd := exec.Command(podman,
		"--root", e.store,
		"--runroot", e.runroot,
		"system", "service", "--time", "0",
		"unix://"+e.sock,
	)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	// Its own process group, so teardown's group kill reaps this engine's tree
	// and never the host's other rootless containers.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}

	var errbuf strings.Builder
	cmd.Stderr = &errbuf
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting the container engine: %w", err)
	}
	e.cmd = cmd

	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(e.sock); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			e.stopLocked()
			return fmt.Errorf("the container engine did not come up within 15s: %s",
				strings.TrimSpace(errbuf.String()))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Stop tears the engine down: containers first, then the process group.
func (e *Engine) Stop() {
	e.once.Do(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.stopLocked()
	})
}

func (e *Engine) stopLocked() {
	if e.cmd == nil || e.cmd.Process == nil {
		return
	}
	if podman, err := exec.LookPath("podman"); err == nil {
		stop := exec.Command(podman, "--root", e.store, "--runroot", e.runroot,
			"stop", "--all", "--time", "5")
		stop.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		_ = stop.Run()
	}

	pgid := -e.cmd.Process.Pid
	_ = syscall.Kill(pgid, syscall.SIGTERM)

	done := make(chan struct{})
	go func() { _, _ = e.cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(pgid, syscall.SIGKILL)
		<-done
	}
	_ = os.Remove(e.sock)
	e.cmd = nil
}
