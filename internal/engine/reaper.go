package engine

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// The reaper closes the one gap nothing else can: snug is SIGKILLed, so no
// deferred cleanup and no signal handler ever runs.
//
// The engine itself is covered without help — see lifeline.go, its idle timeout
// fires when snug's socket dies. CONTAINERS are not: conmon is nobody's child,
// it is reparented to init, and it keeps the payload running whether the engine
// is up or not. That is true with a real podman too, so it is not a
// wrapper-specific problem and Pdeathsig never solved it.
//
// So snug arms one helper BEFORE it starts the engine: a shell that blocks
// reading a pipe snug holds the write end of, and stops this engine's
// containers when that pipe reports EOF. Every way snug can die closes the
// pipe, SIGKILL included, because the kernel does it.
//
// It is not a daemon. It has no state, no socket and one job, it outlives snug
// by exactly the time that job takes, and on a clean exit snug does the
// teardown itself and tells the reaper to stand down — so the ordinary path
// spawns it and never uses it.
//
// Two details that are load-bearing:
//
//   - Its own process group. A signal aimed at snug's group — Ctrl-C, a
//     supervisor killing the group — must not take out the thing whose job is
//     to clean up after that.
//   - No Pdeathsig, deliberately, which is the exact opposite of every other
//     helper snug starts.
//
// The paths travel in the ENVIRONMENT, not in argv, so the reaper's own command
// line does not name the socket the sweep in reap.go matches on — otherwise
// teardown would find the reaper and count snug's own cleanup as a leak.
//
// Known and NOT fixed here: `stop --all` is scoped to the STORE, and the store
// is shared by every sandbox with the same profiles on the same target. So a
// sandbox that dies stops a concurrent sibling's containers too. That is the
// original behaviour of this teardown, not something the reaper introduced, and
// closing it needs a per-run label on containers, which lives in the proxy.
const reaperScript = `
read -r tok
[ "$tok" = ok ] && exit 0
echo "snug: the sandbox died without cleaning up; stopping its containers" >&2
"$SNUG_REAP_PODMAN" --root "$SNUG_REAP_STORE" --runroot "$SNUG_REAP_RUNROOT" \
	stop --all --time 5 >/dev/null 2>&1
rm -f "$SNUG_REAP_SOCK"
`

type reaper struct {
	cmd *exec.Cmd
	w   *os.File
}

// startReaper arms the helper. Called before the engine is started, so that a
// snug killed during startup is still covered.
func startReaper(podman, store, runroot, sock string) (*reaper, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("/bin/sh", "-c", reaperScript)
	cmd.Stdin = r
	cmd.Stdout = nil // /dev/null: nothing it prints belongs on the payload's stdout
	cmd.Stderr = os.Stderr
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"SNUG_REAP_PODMAN=" + podman,
		"SNUG_REAP_STORE=" + store,
		"SNUG_REAP_RUNROOT=" + runroot,
		"SNUG_REAP_SOCK=" + sock,
	}
	// Own process group, and NO Pdeathsig. See the comment above.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		return nil, fmt.Errorf("arming the container reaper: %w", err)
	}
	// The child has its own copy; ours would only keep an fd alive.
	r.Close()
	return &reaper{cmd: cmd, w: w}, nil
}

// standDown tells the reaper snug already cleaned up, and waits for it to go.
// Waiting is the point: when snug returns, teardown has finished.
func (r *reaper) standDown() {
	if r == nil {
		return
	}
	_, _ = r.w.WriteString("ok\n")
	r.w.Close()

	done := make(chan struct{})
	go func() { _, _ = r.cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = r.cmd.Process.Kill()
		<-done
	}
}
