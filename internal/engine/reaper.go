package engine

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// The reaper was built to close the one gap nothing else could: snug is
// SIGKILLed, so no deferred cleanup and no signal handler ever runs.
//
// # Read this first: the gap it was built for is closed by something else now
//
// The premise, stated here for two milestones, was: "the engine itself is
// covered without help — lifeline.go's idle timeout fires when snug's socket
// dies. CONTAINERS are not: conmon is nobody's child, it is reparented to
// init, and it keeps the payload running whether the engine is up or not."
// The second half was measured true pre-C0 and is measured FALSE now. Issue
// #125's C0 gave the engine its own pid namespace, conmon's double-forked
// grandchild reparents onto podman (pid 1 of that namespace) rather than onto
// a host init, and killing the engine collapses the namespace and everything
// in it. The A/B numbers are in the package comment in engine.go; the short
// version is that the same isolated "SIGKILL the engine and touch nothing
// else" left the container running past a 10s deadline before C0 and killed
// it inside one 250ms poll tick after.
//
// Combined with the Pdeathsig chain (engine to P1, P1 to P0), that means every
// way snug can die already fells this run's containers, measured at under 70ms
// end to end from a SIGKILL of snug — faster than this helper could ever have
// forked a `podman stop`. So on the paths measured, THIS FILE NO LONGER
// DELIVERS THE OUTCOME; the kernel does.
//
// It stays anyway, and that is a decision rather than an oversight. Removing
// the PROCESS is a maintainer's call and wants its own change with its own
// red-team pass — this correction only establishes that the mechanism is
// redundant, not that it should go. It is free on the clean path (Stop tells
// it to stand down before snug returns).
//
// What did NOT survive that decision (issue #167) is the `podman stop` this
// process used to fork on EOF. It is DELETED, not kept as a best-effort
// fallback, and that changes what the sentence above means: this is no
// longer "the one leg of teardown that does not depend on the kernel having
// torn the pid namespace down the way the measurement says it does" — with a
// renumbered pid namespace it depends on the collapse NOT having happened
// (impossible on the path that triggers this helper at all: EOF on the pipe
// IS snug dying, which is exactly what fells the engine and collapses the
// namespace) AND on pids it cannot read (the runroot's recorded conmon.pid
// and pidfile are numbered in the ENGINE's pid namespace since C0, meaningless
// on the host — see engine.go's stopLocked step 1). Its only remaining
// possible effect was signalling a live HOST process that happened to own a
// small pid number, on a host sharing the boot pid namespace or a container
// with its own. Removing it closes that stray-signal path; it does not retire
// a mechanism, because the mechanism stopped delivering its outcome on this
// path when C0 landed.
//
// So snug arms one helper BEFORE it starts the engine: a shell that blocks
// reading a pipe snug holds the write end of, and on EOF removes this run's
// ENTIRE run directory (containers.conf, registries.conf, auth.json,
// resolv.conf, the generated home/, and the socket itself) — the one thing
// nothing else removes on the SIGKILL path, since the kernel's namespace
// collapse deletes processes, not files.
//
// The directory, not just the socket (red team F4). stopLocked's own step 4
// (`os.RemoveAll(e.runDir)`) does not run on SIGKILL — no Go code runs at
// all on that path — and a leftover empty (or non-empty) directory at
// e.runDir permanently poisons that pid number: engine.New's own existence
// check refuses with "file exists" the next time this uid+pid combination is
// reused for a run, which is not an abstract risk on a host that recycles
// pids quickly. `rm -rf`, not `rmdir` after individually removing each
// generated file: the latter would duplicate, in this three-line shell
// script, Go-side knowledge of exactly what Spec() writes into the
// directory (engine.go's writeContainersConf/writeRegistriesConf/
// writeAuthFile/writeResolvConf/writeEngineHome), and drift the moment that
// list changes. `rm -rf` needs no such list, and it is safe to be this
// blunt specifically BECAUSE the directory is snug's own and nothing else's:
// createRunDir makes it 0700 and uid-checked at creation, under an
// unpredictable pid-derived name, so recursively removing it cannot delete
// anything this run did not itself put there.
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
// Those two are not the whole of it, and the third is easy to lose because it
// lives in another package. snug's signalled-teardown guard sweeps its OWN
// descendant tree and SIGKILLs everything in it
// (internal/sandbox/teardown.go's confirmTeardown), and this process is a
// direct child of snug — so without an explicit exemption the guard kills the
// helper that exists precisely because the guard might not get to run. It is
// exempted by pid, through Engine.ReaperPIDs and
// sandbox.Options.ExcludeFromTeardown, and the exemption covers this process's
// own children too: on EOF it still forks `rm` (below) to remove the run
// directory, and sparing the shell while killing that is worse than sparing
// neither.
//
// Issue #113 is the history. Before that exemption existed the sweep did kill
// this process, and it was harmless for a reason nothing in this file could
// see: internal/cli's `defer ctrCleanup()` runs after sandbox.Run returns and
// performed the teardown itself. Two facts one edit apart from disagreeing.
//
// The path travels in the ENVIRONMENT, not in argv, so the reaper's own
// command line does not name the socket the sweep in reap.go matches on —
// otherwise teardown would find the reaper and count snug's own cleanup as a
// leak.
const reaperScript = `
read -r tok
[ "$tok" = ok ] && exit 0
echo "snug: the sandbox died without cleaning up" >&2
case "$SNUG_REAP_DIR" in
/*/snug-[0-9]*) rm -rf "$SNUG_REAP_DIR" ;;
*) echo "snug: refusing to remove unexpected run directory" >&2 ;;
esac
`

type reaper struct {
	cmd *exec.Cmd
	w   *os.File
}

// startReaper arms the helper. Called before the engine is started, so that a
// snug killed during startup is still covered.
//
// Only sock and runDir, now (issue #167): podman/store/runroot/runLabel
// existed solely to feed the `podman stop` invocation this script no longer
// makes.
//
// runDir is passed EXPLICITLY rather than derived in the shell, and that is a
// safety property, not a tidiness one. The first version of this removal ran
// `rm -rf "$(dirname "$SNUG_REAP_SOCK")"`, which is a different command from
// the `rm -f "$SNUG_REAP_SOCK"` it replaced in one way that matters: `rm -f`
// on an empty variable is a harmless no-op, while `dirname ""` is `.` and
// this process sets no Dir, so it inherits snug's cwd — the user's project
// directory, usually. An empty value would therefore have deleted the
// directory the user was working in, at the exact moment snug is dead and
// cannot supervise. e.sock is non-empty on every path New can return, so it
// was not reachable; it was one refactor away from being so, and the whole
// blast radius sat behind a variable being non-empty.
func startReaper(sock, runDir string) (*reaper, error) {
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
		"SNUG_REAP_SOCK=" + sock,
		"SNUG_REAP_DIR=" + runDir,
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
