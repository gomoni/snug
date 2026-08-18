// Package engine computes the paths and launch spec for a container engine
// that belongs to one sandbox, and tears it down again.
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
// # The engine runs in the sandbox's own network namespace (issue #63, Tier B)
//
// It used to be a plain host process, on the host's own network namespace,
// meaning a container it started reached the internet even from an offline
// sandbox (ENGINE-NETNS.md §0, the finding this tier closes). The engine is
// now forked by internal/stage, EAGERLY, as a second long-lived child of the
// stage (P1) alongside bwrap — this package no longer starts it directly. It
// computes the paths (Engine.New), builds the stage.EngineSpec the stage's
// StartEngine consumes (Engine.Spec), and tears the result down again
// (Engine.Stop) — the fork, the setns into N, the private mount-namespace
// copy and the capability drop all live in internal/stage (EnterEngine,
// __inengine) because they need the stage's own raw-fork machinery and its
// membership in the sandbox's user namespace U.
//
// # Teardown, and why it is not just a kill
//
// The engine process itself dies WITH the stage: it is Pdeathsig'd to P1,
// which is itself Pdeathsig'd (and lifeline-held) to P0, so engine ⊂ P1 ⊂ P0
// and any death of snug cascades down to it. That REPLACES this package's old
// job of killing the engine process directly — Stop below no longer signals
// it at all. What Stop still owns:
//
//  1. lifeline.go — the engine runs with a finite idle timeout and snug holds
//     one streaming request open, dialled at its (now /tmp) socket. This is
//     what keeps a live run's engine up through idle stretches; its old
//     "keep a wrapper engine alive long enough to reap it" role is gone now
//     that preflight P1 refuses a wrapper outright and the engine is always a
//     real stage child.
//  2. reaper.go — a pipe-triggered helper stops this run's CONTAINERS (never
//     the engine process) when snug dies without cleaning up. Containers are
//     not the engine's children — conmon double-forks and its grandchild
//     reparents in the HOST pid namespace, because the engine does not
//     unshare pid — so they outlive the engine and need an explicit stop
//     regardless of how confined the engine itself is.
//  3. reap.go — Stop's own ordinary-path teardown: stop containers by label
//     while the engine's socket is still live, THEN verify by sweeping for
//     processes that still name this run's socket path. "The kill returned
//     no error" is not evidence anything died; the sweep is.
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

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/stage"
)

// idleTimeout is how long the engine outlives its last client. Never
// `--time 0`, which would disable the timeout and make the engine the daemon
// this project says it does not run. Short enough that a hard kill is cleaned
// up while the human is still looking at the terminal; long enough that a
// slow re-dial of the lifeline cannot expire it.
const idleTimeout = 10 * time.Second

// quietBudget bounds how long Stop waits for this run's containers to go away
// before it gives up and says so. It exceeds idleTimeout so that the
// lifeline alone is enough to reach a verified-clean state even when the
// direct filtered stop below could not land.
const quietBudget = idleTimeout + 5*time.Second

// RunLabelKey is the container label snug stamps every container it creates
// with, so that teardown can reach this run's containers and only those.
//
// A dotted, namespaced key rather than a bare word: labels are a flat namespace
// shared with whatever the image and the user set, and `run` alone would be a
// plausible thing for someone else to mean.
const RunLabelKey = "snug.run"

type Engine struct {
	sock     string
	runroot  string
	store    string
	runDir   string
	runLabel string

	// podman and env are what Stop needs to run a HOST-SIDE `podman stop`
	// against this run's store — set once, from the same values Spec() puts
	// into the stage.EngineSpec, so the two never diverge (invariant 6's
	// spirit applied within this package: one source of the engine's own
	// identity).
	podman string
	env    []string

	mu   sync.Mutex
	life *lifeline
	reap *reaper
	once sync.Once
}

// New computes the paths for a sandbox's engine but starts nothing.
//
// The STORE key is derived from the profile set AND the target, so the same
// project with the same profiles reuses its images across runs (a warm
// start) while a different project — or the same project with wider profiles
// — gets a different store. It stays under XDG_DATA_HOME, unaffected by
// issue #63 Tier B: nothing about WHERE the engine runs changes what should
// persist across runs.
//
// The SOCKET lives under /tmp/snug-<uid>-<pid>/ (issue #63, Tier B,
// ENGINE-WIRING.md §3.1), hardened and unique to THIS run — createRunDir
// refuses to reuse an existing entry at that path, the same discipline
// commit dfe6ac8 (#61, #85) applied to snug's own runtime directory. That is
// what teardown matches on (see reap.go): the store is shared with every
// past and concurrent sandbox that resolved to the same key, so killing
// "whatever names the store" would reach into a sibling sandbox that is
// still working.
//
// The RUNROOT, MEASURED, must NOT be pid-unique the way the socket is, and
// that is a correction of what ENGINE-WIRING.md §3.1 assumed: podman's own
// libpod database, which lives IN the persisted store, records the runroot
// path a run used and REFUSES a later run against the same store with a
// DIFFERENT one ("database run root ... does not match"). A store that
// persists across runs (by design, for a warm start) needs a runroot that is
// STABLE across those same runs — exactly like ordinary rootless podman's
// own default ($XDG_RUNTIME_DIR/containers, stable for a login session) — so
// it is keyed by the SAME profiles+target key as the store, not by pid, and
// created with the SAME shared, first-writer-wins MkdirAll the store already
// uses. It still lives under /tmp, not $XDG_RUNTIME_DIR — that half of §3.1's
// reasoning (a root-in-userns podman masks $XDG_RUNTIME_DIR with its own
// tmpfs on /run) is unaffected by this correction.
func New(profiles []policy.ProfileName, target string) (*Engine, error) {
	sorted := policy.NameStrings(profiles)
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

	pid := os.Getpid()
	runDir := filepath.Join(os.TempDir(), runDirName(os.Getuid(), pid))
	if err := createRunDir(runDir); err != nil {
		return nil, err
	}

	e := &Engine{
		// runLabel is what teardown stops, and it identifies THIS RUN rather
		// than the store. The store is shared on purpose — that is what makes
		// a warm start warm — so `stop --all` scoped to it stopped a
		// concurrent sibling's containers as collateral. The proxy stamps
		// this label on every container it creates; Stop and the reaper both
		// filter on it, so a teardown reaches exactly the containers this run
		// started.
		runLabel: fmt.Sprintf("%s=%d", RunLabelKey, pid),

		store:   filepath.Join(dataHome, "snug", "engines", key, "storage"),
		runDir:  runDir,
		runroot: filepath.Join(os.TempDir(), fmt.Sprintf("snug-engines-%d-%s", os.Getuid(), key), "rr"),
		sock:    filepath.Join(runDir, fmt.Sprintf("podman-%d.sock", pid)),
	}
	for _, d := range []string{e.store, e.runroot} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			_ = os.RemoveAll(runDir)
			return nil, err
		}
	}
	return e, nil
}

func (e *Engine) Socket() string { return e.sock }

// RunLabel is the `key=value` this run's containers are stamped with. The proxy
// applies it at create; teardown filters on it.
func (e *Engine) RunLabel() string { return e.runLabel }

// Spec builds the stage.EngineSpec that Stage.StartEngine consumes: exactly
// what this run's engine execs into, chosen entirely by P0. podman is the
// preflight-checked path to a real binary; baseEnv is the explicit, minimal
// environment the caller built (PATH, HOME, and anything a pinned podman
// bundle needs, e.g. CONTAINERS_STORAGE_CONF/CONTAINERS_REGISTRIES_CONF) —
// XDG_RUNTIME_DIR is added here, pointing at this run's own runroot, so the
// caller never has to know that path. cgroupsDisabled is preflight P5's own
// measured selection (ENGINE-WIRING.md §4): when this host's cgroup
// delegation does not survive even the private cgroup namespace __inengine's
// own fork creates, podman needs `cgroups = "disabled"` as its DEFAULT for
// every container it creates. That is a containers.conf setting, not an argv
// flag on `system service` — so it is GENERATED into a file under this run's
// own /tmp directory and pointed at by CONTAINERS_CONF, never handed over
// inline (the same "pointer, not inline value" rule CLAUDE.md states for
// GIT_CONFIG_GLOBAL, PIP_CONFIG_FILE and friends).
//
// Spec also remembers podman and the final env on the Engine itself, so
// Stop's own host-side `podman stop` (reap.go) uses the IDENTICAL values
// rather than a second, potentially-diverging computation.
func (e *Engine) Spec(podman string, baseEnv []string, cgroupsDisabled bool) (stage.EngineSpec, error) {
	finalEnv := append([]string{}, baseEnv...)
	finalEnv = append(finalEnv, "XDG_RUNTIME_DIR="+e.runroot)
	if cgroupsDisabled {
		confPath, err := e.writeCgroupsDisabledConf()
		if err != nil {
			return stage.EngineSpec{}, err
		}
		finalEnv = append(finalEnv, "CONTAINERS_CONF="+confPath)
	}

	e.podman = podman
	e.env = finalEnv

	argv := []string{
		"--root", e.store,
		"--runroot", e.runroot,
		// NOT --time 0. The idle timeout is the engine's own "my client went
		// away", and the lifeline (lifeline.go) is what keeps it from firing
		// while the sandbox lives.
		"system", "service", "--time", strconv.Itoa(int(idleTimeout.Seconds())),
		"unix://" + e.sock,
	}

	return stage.EngineSpec{Podman: podman, Argv: argv, Env: finalEnv, Sock: e.sock}, nil
}

// writeCgroupsDisabledConf generates a minimal containers.conf under this
// run's own (already hardened, 0700, host-uid-owned) /tmp directory, read
// only because Spec points CONTAINERS_CONF at it — never merged with, or
// replacing, any host containers.conf, because the engine's env carries
// nothing else that would make podman look at one.
func (e *Engine) writeCgroupsDisabledConf() (string, error) {
	path := filepath.Join(e.runDir, "containers.conf")
	content := "# snug: generated because preflight P5 measured that this host's cgroup\n" +
		"# delegation does not survive even the engine's own private cgroup namespace.\n" +
		"[containers]\n" +
		"cgroups = \"disabled\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// ArmReaper starts the pipe-triggered teardown helper (reaper.go) that stops
// this run's containers if snug dies without cleaning up.
//
// Called by the caller BEFORE sandbox.Run even begins — deliberately not
// tied to whether the engine has actually started yet, unlike DialLifeline
// below, because arming it early is what covers a snug killed during the
// stage's own startup window (creating U+N, waiting for the network), before
// the engine has been forked at all. It needs only paths and the podman
// binary, all of which Spec has already fixed on the Engine by the time this
// is called; it does not need the engine's socket to exist yet.
func (e *Engine) ArmReaper() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := startReaper(e.podman, e.store, e.runroot, e.sock, e.runLabel)
	if err != nil {
		return err
	}
	e.reap = r
	return nil
}

// DialLifeline opens the keepalive stream (lifeline.go) that ties the
// engine's lifetime to this sandbox. Unlike ArmReaper, this NEEDS the
// engine's socket to already exist, so the caller runs it from
// sandbox.Options.OnEngineReady — after Stage.StartEngine has confirmed the
// socket is there, before the payload is forked. A failure here is fatal to
// the whole run (invariant 5): without the lifeline a hard-killed snug would
// leave a finite-timeout-but-not-yet-expired engine running for up to
// idleTimeout with nothing to shorten it, so snug refuses to hand the
// sandbox an engine it cannot guarantee to reap promptly.
func (e *Engine) DialLifeline() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	life, err := dialLifeline(e.sock)
	if err != nil {
		if e.reap != nil {
			e.reap.standDown()
			e.reap = nil
		}
		return fmt.Errorf("the container engine came up but would not accept the keepalive\n"+
			"      stream that ties its lifetime to this sandbox (%v).\n"+
			"      Without it a hard-killed snug would leave the engine running, so snug\n"+
			"      refuses to hand the sandbox an engine it cannot guarantee to reap", err)
	}
	e.life = life
	return nil
}

// Stop tears the engine's CONTAINERS down and verifies. The engine PROCESS
// itself is not signalled here at all: it is Pdeathsig'd to the stage (P1),
// which is Pdeathsig'd (and lifeline-held) to P0, so it dies with the stage
// on every path — clean exit, panic, SIGKILL. What is left for this to do is
// exactly what Pdeathsig cannot reach: containers are not the engine's
// children, so they outlive it whatever kills it.
func (e *Engine) Stop() {
	e.once.Do(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.stopLocked()
	})
}

func (e *Engine) stopLocked() {
	// Everything snug runs itself is excluded from the sweep, or teardown
	// would find its own cleanup and call it a leak.
	exclude := map[int]bool{os.Getpid(): true}
	if e.reap != nil && e.reap.cmd.Process != nil {
		exclude[e.reap.cmd.Process.Pid] = true
	}

	// 1. Containers. Not the engine's children, and they outlive it, so this
	//    has to happen before the engine's socket goes away.
	if e.podman != "" {
		// --filter, not just --all: the store is shared with any concurrent
		// sandbox that resolved to the same key, and stopping ITS containers
		// because this one is going away is collateral a user cannot predict.
		//
		// Run on the HOST here, unconfined — this is P0 itself, not the
		// engine, invoking podman's CLI directly against the shared store's
		// path (which is host-uid-owned, exactly like every other file this
		// process writes) to STOP, never to run anything new. It needs no
		// network and no namespace of its own.
		stop := exec.Command(e.podman, "--root", e.store, "--runroot", e.runroot,
			"stop", "--all", "--filter", "label="+e.runLabel, "--time", "5")
		stop.Env = e.env
		_ = stop.Run()
	}

	// 2. Drop the keepalive. From here the engine is on its own idle timeout
	//    even if it somehow outlives the stage.
	e.life.Close()
	e.life = nil

	// 3. Verify. "The stop command returned no error" is not evidence anything
	//    died — that assumption is what let a wrapper-engine case leak
	//    silently in the pre-Tier-B design. The sweep is by SOCKET PATH, never
	//    by comm and never by the shared store path (which would reach a
	//    concurrent sibling).
	if left := waitQuiet(e.paths(), exclude, quietBudget); len(left) > 0 {
		signalOwned(e.paths(), exclude, syscall.SIGKILL)
		if left = waitQuiet(e.paths(), exclude, 3*time.Second); len(left) > 0 {
			fmt.Fprintf(os.Stderr,
				"snug: WARNING — this sandbox's containers did not die with it.\n"+
					"      Still running:\n%s"+
					"      Reap them with:\n"+
					"        kill -9 %s\n"+
					"      and check the store with:\n"+
					"        podman --root %s --runroot %s ps\n",
				describe(left), joinPIDs(left), e.store, e.runroot)
		}
	}

	// 4. The reaper's job is done; tell it so and wait, so that snug
	//    returning means teardown has finished.
	e.reap.standDown()
	e.reap = nil

	_ = os.RemoveAll(e.runDir)
}

func joinPIDs(pids []int) string {
	parts := make([]string, 0, len(pids))
	for _, p := range pids {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, " ")
}
