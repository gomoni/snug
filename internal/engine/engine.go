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
//
// # Teardown, and why it is not just a kill
//
// snug's rule is that a helper dies with the sandbox and leaves nothing behind.
// The obvious implementation — start the engine as a child, Setpgid, Pdeathsig,
// kill the group — is a lie on any host where `podman` is a WRAPPER. Inside
// distrobox /usr/bin/podman is a symlink to distrobox-host-exec, which forwards
// the call over D-Bus to the real podman on the HOST: snug's child is the shim,
// the engine lives in a process tree parented to the host's systemd, and the
// group kill and Pdeathsig both hit the shim and miss the engine. A hard-killed
// snug left the engine, its pasta and a running container behind. Verified by
// execution, not inferred.
//
// So teardown here is three independent mechanisms, none of which assumes the
// engine is snug's child:
//
//  1. lifeline.go — the engine runs with a finite idle timeout and snug holds
//     one streaming request open. Any death of snug closes the socket and the
//     engine exits by itself. This is the only one that still works after
//     SIGKILL, and it works for an engine that is not even in our /proc.
//  2. reaper.go — a pipe-triggered child stops this engine's containers when
//     snug dies without cleaning up. Containers outlive the engine, so the
//     lifeline alone is not enough.
//  3. reap.go — teardown on the ordinary path stops containers, kills what it
//     can, and then VERIFIES by looking for processes that name this engine's
//     private paths. It reports loudly rather than assuming the kill landed.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// idleTimeout is how long the engine outlives its last client. It replaces the
// `--time 0` this used to pass, which disabled the timeout and made the engine
// the daemon this project says it does not run. Short enough that a hard kill
// is cleaned up while the human is still looking at the terminal; long enough
// that a slow re-dial of the lifeline cannot expire it.
const idleTimeout = 10 * time.Second

// quietBudget bounds how long Stop waits for the engine's processes to go away
// before it gives up and says so. It exceeds idleTimeout so that the lifeline
// alone is enough to reach a verified-clean state even when the direct kill
// could not land.
const quietBudget = idleTimeout + 5*time.Second

type Engine struct {
	sock    string
	store   string
	runroot string

	mu     sync.Mutex
	podman string
	cmd    *exec.Cmd
	life   *lifeline
	reap   *reaper
	once   sync.Once
}

// New computes the paths for a sandbox's engine but starts nothing.
//
// The key is derived from the profile set AND the target, so the same project
// with the same profiles reuses its images across runs (a warm start) while a
// different project — or the same project with wider profiles — gets a
// different store.
//
// The SOCKET, by contrast, carries snug's pid, so it is unique to this RUN.
// That is what teardown matches on (see reap.go): the store is shared with
// every past and concurrent sandbox that resolved to the same key, so killing
// "whatever names the store" would reach into a sibling sandbox that is still
// working. It also stops two concurrent sandboxes from fighting over one
// socket path, which the fixed name used to guarantee.
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
		sock: filepath.Join(runHome, "snug", "engines", key,
			fmt.Sprintf("podman-%d.sock", os.Getpid())),
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
	e.podman = podman

	// Arm the reaper BEFORE starting anything, so a snug killed during startup
	// is covered too.
	if e.reap, err = startReaper(podman, e.store, e.runroot, e.sock); err != nil {
		return err
	}

	// A pid-named socket can only be left over from a dead snug that had this
	// pid; an engine from a previous run has its own name and is on its own
	// idle timeout, so there is nothing here to race and nothing to kill.
	_ = os.Remove(e.sock)
	cmd := exec.Command(podman,
		"--root", e.store,
		"--runroot", e.runroot,
		// NOT --time 0. The idle timeout is the engine's own "my client went
		// away", and the lifeline below is what keeps it from firing while the
		// sandbox lives. See lifeline.go.
		"system", "service", "--time", strconv.Itoa(int(idleTimeout.Seconds())),
		"unix://"+e.sock,
	)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	// Its own process group, so teardown's group kill reaps this engine's tree
	// and never the host's other rootless containers. This is the fast path for
	// a real podman binary; it is NOT the guarantee — see the package comment.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}

	var errbuf strings.Builder
	cmd.Stderr = &errbuf
	if err := cmd.Start(); err != nil {
		e.reap.standDown()
		e.reap = nil
		return fmt.Errorf("starting the container engine: %w", err)
	}
	e.cmd = cmd

	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(e.sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			e.stopLocked()
			return fmt.Errorf("the container engine did not come up within 15s: %s",
				strings.TrimSpace(errbuf.String()))
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Without the lifeline a hard-killed snug leaves the engine running for
	// ever, so this is a hard failure, not a warning. No silent downgrade.
	life, err := dialLifeline(e.sock)
	if err != nil {
		e.stopLocked()
		return fmt.Errorf("the container engine came up but would not accept the keepalive\n"+
			"      stream that ties its lifetime to this sandbox (%v).\n"+
			"      Without it a hard-killed snug would leave the engine running, so snug\n"+
			"      refuses to hand the sandbox an engine it cannot guarantee to reap", err)
	}
	e.life = life
	return nil
}

// Stop tears the engine down: containers first, then the engine, then a
// verification that neither is still there.
func (e *Engine) Stop() {
	e.once.Do(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.stopLocked()
	})
}

func (e *Engine) stopLocked() {
	if e.cmd == nil && e.reap == nil {
		return
	}

	// Everything snug runs itself is excluded from the sweep, or teardown would
	// find its own cleanup and call it a leak.
	exclude := map[int]bool{os.Getpid(): true}
	if e.reap != nil && e.reap.cmd.Process != nil {
		exclude[e.reap.cmd.Process.Pid] = true
	}

	// 1. Containers. They are not the engine's children either, and they
	//    outlive it, so this has to happen before anything is killed.
	if e.podman != "" {
		stop := exec.Command(e.podman, "--root", e.store, "--runroot", e.runroot,
			"stop", "--all", "--time", "5")
		stop.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		_ = stop.Run()
	}

	// 2. Drop the keepalive. From here the engine is on its own idle timeout
	//    even if every kill below misses.
	e.life.Close()
	e.life = nil

	// 3. Kill what we can reach directly. The group kill is right when podman
	//    is a real binary; the sweep by socket path is what reaches the engine
	//    when podman is a wrapper and the group kill only hits the shim.
	if e.cmd != nil && e.cmd.Process != nil {
		pgid := -e.cmd.Process.Pid
		_ = syscall.Kill(pgid, syscall.SIGTERM)
	}
	signalOwned(e.paths(), exclude, syscall.SIGTERM)

	if e.cmd != nil && e.cmd.Process != nil {
		done := make(chan struct{})
		go func() { _, _ = e.cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-e.cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
	}

	// 4. Verify. "The kill returned no error" is not evidence that anything
	//    died — that assumption is what let the wrapper case leak silently.
	if left := waitQuiet(e.paths(), exclude, quietBudget); len(left) > 0 {
		signalOwned(e.paths(), exclude, syscall.SIGKILL)
		if left = waitQuiet(e.paths(), exclude, 3*time.Second); len(left) > 0 {
			fmt.Fprintf(os.Stderr,
				"snug: WARNING — this sandbox's container engine did not die with it.\n"+
					"      Still running:\n%s"+
					"      Reap them with:\n"+
					"        kill -9 %s\n"+
					"      and check the store with:\n"+
					"        podman --root %s --runroot %s ps\n",
				describe(left), joinPIDs(left), e.store, e.runroot)
		}
	}

	// 5. The reaper's job is done; tell it so and wait, so that snug returning
	//    means teardown has finished.
	e.reap.standDown()
	e.reap = nil

	_ = os.Remove(e.sock)
	e.cmd = nil
}

func joinPIDs(pids []int) string {
	parts := make([]string, 0, len(pids))
	for _, p := range pids {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, " ")
}
