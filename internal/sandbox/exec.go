package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/bwrapinfo"
	"github.com/gomoni/snug/internal/fdseal"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/stage"
)

// Options are the run-time choices a human makes at the CLI. Nothing here is
// expressible in a profile — weakening is the human's prerogative (INDEX §2.5).
type Options struct {
	NoSeccomp bool
	Warn      func(string) // where degradation notices go; never silently dropped

	// HTTPDoors are listening unix sockets the CALLER created on the host, one
	// per name in p.HTTPDoors and in that order, to be handed to the payload as
	// LISTEN_FDS descriptors.
	//
	// Created by the caller and not here, for the reason every host fact in this
	// tree is: the socket needs a path in the run's runtime directory and that
	// path has to be published to run state so `snug proxy` can find it, both of
	// which are internal/cli's job. This package only passes the descriptors.
	//
	// THEY GO FIRST in ExtraFiles, so the payload sees them at fd 3.., which is
	// what LISTEN_FDS=n means. Measured: bwrap closes only the descriptors it
	// consumes and renumbers nothing, so a socket appended after the memfds
	// would arrive at a number LISTEN_FDS cannot name.
	HTTPDoors []*os.File

	// OnInfo, if non-nil, is called exactly once, as soon as bwrap has
	// reported its own info-fd JSON. It is the hook `snug attach`'s run-state
	// file is written through, which is why WHEN it runs is a security
	// question and not a convenience:
	//
	//   unstaged — from a background goroutine, before the payload's own
	//     program has been exec'd, never blocking bwrap's startup.
	//   staged — from the calling goroutine, and on a container run strictly
	//     AFTER the parked payload has been released (issue #125). Publishing
	//     it earlier would make the sandbox attachable while its payload is
	//     still parked, and `snug attach` would then put a process inside a
	//     sandbox the gate exists to keep empty.
	//
	// If bwrap never answers — an old bwrap, a failed start, a topology this
	// package could not wire the descriptor through for — OnInfo is simply
	// never called, and this package warns instead (same rule as every other
	// place this file degrades: named, not silent). A run whose OnInfo is
	// never reached is a run `snug attach` will not find; it is not a run
	// that failed to start.
	OnInfo func(RunInfo)

	// OnInit, if non-nil, is called with the sandbox init's HOST pid the
	// moment bwrap reports it — on the unstaged arm, from
	// reportInfo's goroutine, right after bwrapinfo.Read returns and BEFORE
	// publishInfo; on the staged arm, wired to stage.Config.OnSandboxForked,
	// so it runs the instant P1 forwards bwrap's "forked" event (issue #236)
	// rather than after the mount settle and the engine's cold start
	// "enginestarted" waits out. Both arms funnel through notifyInit, the one
	// place this package turns "bwrap named its init" into the call.
	//
	// It carries a pid and nothing else — it is not OnInfo's early twin:
	// OnInfo is a RunInfo, published (on the staged arm) only after a gated
	// payload is released, and this runs before that release ever happens. A
	// failure inside it is warn-only; the run continues regardless of what it
	// does with the pid.
	OnInit func(pid int)

	// EngineSpec, when non-nil, tells runStaged to fork a container engine
	// into this sandbox's own N — EAGERLY, after the network is confirmed and
	// while bwrap's payload is parked on the gate, as a second long-lived child
	// of the stage alongside bwrap (issue #63, Tier B; ENGINE-WIRING.md §1;
	// issue #125 for the gate). It is ALSO what makes this run a gated one:
	// Run emits --block-fd/--sync-fd if and only if this is non-nil. nil means no
	// engine at all: an ordinary @net (or offline) run with no container
	// profile selected. Only meaningful when p.Topology.NeedsStage() is true;
	// internal/cli/container.go is the only caller that sets it, having
	// already run the P1-P6 preflight this package does not repeat.
	EngineSpec *stage.EngineSpec

	// OnEngineReady, if non-nil, runs once the stage has confirmed the
	// engine's socket exists and BEFORE the payload is released from its gate
	// (issue #125) — so a failure here (dialling the lifeline that ties the
	// engine's lifetime to this sandbox, arming teardown) refuses the WHOLE run
	// rather than letting a payload start behind a container engine this
	// process cannot guarantee to reap. Only ever called when EngineSpec is
	// non-nil, and nothing is running inside the sandbox while it runs.
	OnEngineReady func() error

	// OnPayloadExit, if non-nil, runs after the staged payload has been
	// reaped (st.Wait() returned) and BEFORE the deferred st.Close() collapses
	// the stage. It is the seam for stopping THIS run's containers, by label,
	// while the engine's socket is still reachable — internal/sandbox must
	// not import internal/engine (layering: this package is lower-level), so
	// the actual "stop --filter label=..." call is supplied by the caller as
	// a closure. Never called on the unstaged arm of Run, which
	// has no stage and therefore no engine to have started in the first
	// place.
	OnPayloadExit func()

	// ExcludeFromTeardown names host pids that the signalled-teardown sweep
	// must not kill, together with anything reparented under them. It exists
	// for exactly one caller and one process: internal/engine's container
	// reaper, whose job is to OUTLIVE snug and stop this run's containers if
	// snug died without cleaning up (issue #113). Every other helper snug
	// starts is meant to die with the sandbox and belongs in the sweep.
	//
	// A pid, not a handle, because internal/sandbox must not import
	// internal/engine (layering, the same reason OnPayloadExit is a closure).
	// Snapshotted by the caller before sandbox.Run: the reaper is armed before
	// the stage exists, so its pid is already fixed by then.
	ExcludeFromTeardown []int
}

// RunInfo is what a running sandbox reports about itself, once, at startup:
// bwrap's own --info-fd answer plus whether — and with what identity — a
// seccomp filter actually got installed. "Actually got installed" matters
// more than "was requested": a filter this package could not build (an
// unsupported GOARCH, an assembly failure) degrades to no filter with a
// warning, per invariant 5, and RunInfo reflects what is REALLY running, not
// what the caller asked for.
type RunInfo struct {
	InitPID    int
	Namespaces map[string]uint64 // "mnt", "pid", "net", "ipc", "uts", "cgroup"

	SeccompActive bool
	// SeccompDigest is FilterDigest(prog) over the bytes actually installed.
	// Empty when SeccompActive is false.
	SeccompDigest string
}

// infoFDTimeout bounds how long Run waits for bwrap's --info-fd answer
// before giving up and warning that this run will not be attachable. bwrap
// writes it before exec'ing the payload (measured), so this is generous
// against a slow host rather than against anything the payload could do.
const infoFDTimeout = 10 * time.Second

// Run executes the policy and returns the payload's exit code verbatim, so
// `snug ... -- make test` is usable in a pipeline.
func Run(p *policy.Policy, uid, gid int, opts Options) (int, error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return 0, fmt.Errorf("bubblewrap (bwrap) is not installed — snug cannot run without it")
	}

	var extra []*os.File
	defer func() {
		for _, f := range extra {
			f.Close()
		}
	}()

	// Child fd numbers: exec.Cmd maps ExtraFiles[i] to 3+i.
	nextFD := func() int { return 3 + len(extra) }

	// The door sockets are appended BEFORE anything else, so they occupy fd
	// 3..3+n-1 exactly as LISTEN_FDS promises. See Options.HTTPDoors.
	extra = append(extra, opts.HTTPDoors...)

	// Generated files (resolv.conf today; hosts/passwd/group later) travel as
	// anonymous memfds, so nothing lands on disk.
	dataFDs := map[string]int{}
	for _, m := range p.SortedMounts() {
		if m.Kind != policy.KindData {
			continue
		}
		f, err := memfd("snug-data", m.Content)
		if err != nil {
			return 0, err
		}
		dataFDs[m.Guest] = nextFD()
		extra = append(extra, f)
	}

	flags := p.BwrapFlags(uid, gid, func(guest string) int { return dataFDs[guest] })

	var runInfo RunInfo
	if !opts.NoSeccomp {
		// Built here rather than through FilterFD so the exact bytes that get
		// installed are also the bytes RunInfo.SeccompDigest is computed
		// over — the identity `snug attach` will later rebuild and compare
		// (FilterDigest's doc comment). Two callers hashing two different
		// copies of "the filter" is exactly the kind of drift that would
		// make attach's digest check meaningless.
		prog, ok, ferr := BuildFilter()
		switch {
		case ferr != nil || !ok:
			// The only subsystem permitted to degrade. Loudly: a user who
			// believes a guarantee that no longer holds is worse off than one
			// who got an error. RunInfo.SeccompActive stays false, which is
			// what makes the run-state file honest about a filter this
			// process could not actually install, as opposed to one a human
			// asked to skip (--no-seccomp).
			msg := "seccomp filter unavailable"
			if ferr != nil {
				msg = fmt.Sprintf("seccomp filter unavailable (%v)", ferr)
			} else {
				msg = "no seccomp syscall table for this architecture"
			}
			opts.warn(msg + "; continuing WITHOUT it.\n" +
				"      The namespace boundary is unaffected; ptrace/keyctl/TIOCSTI hardening is not active.")
		default:
			f, ferr := memfd("snug-seccomp", prog)
			if ferr != nil {
				return 0, ferr
			}
			flags = append(flags, "--seccomp", strconv.Itoa(nextFD()))
			extra = append(extra, f)
			runInfo.SeccompActive = true
			runInfo.SeccompDigest = FilterDigest(prog)
		}
	}

	// bwrap's --info-fd answer (§7 of the attach design): one JSON object,
	// written before the payload is exec'd, carrying bwrap's own child pid
	// and six namespace inodes. This is how `snug attach` learns what to
	// join — no procfs scanning, no PPid walking, no race. The descriptor
	// travels exactly like the --seccomp memfd above: through `extra`, via
	// nextFD(), added to `flags` before the args-memfd snapshot below.
	//
	// On the staged (@net) topology this needs NO protocol change: the
	// descriptor rides the same Config.Sandbox pass-through every other
	// entry in `extra` already does, renumbered to the same 3+i bwrap
	// expects either way.
	infoR, infoW, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	flags = append(flags, "--info-fd", strconv.Itoa(nextFD()))
	extra = append(extra, infoW)

	// NETWORKING needs no handshake with bwrap, and that has not changed.
	//
	// bwrap used to be started first and told to park its payload on --block-fd
	// until pasta had attached, because pasta needs a netns and only bwrap could
	// make one. Under the stage the netns exists BEFORE bwrap does, so pasta
	// attaches first and there is nothing to park for the NETWORK's sake. That
	// reason for parking is gone and stays gone; --json-status-fd, readChildPID
	// and the whole `parked` type went with it and are not coming back.
	//
	// --block-fd IS back, for a different reason, on container runs only (issue
	// #125). A container engine has to be confirmed up before the payload
	// exists, and unlike pasta it cannot be started before bwrap: the whole
	// point of Tier C is that the engine's mount view is DERIVED from the
	// sandbox's, which bwrap has to have built first. So the payload is parked
	// again — but the window is bounded by the engine's cold start (1-2s
	// typical, engineSocketWaitTimeout 30s), which is far wider than pasta's
	// ~100ms ever was, and the old defect scales with it.
	//
	// THE OLD DEFECT, re-measured on this host before writing this: bwrap
	// releases a parked payload on EOF exactly as readily as on a byte, and
	// do_exit runs exit_files (closing the pipe) BEFORE exit_notify (delivering
	// PR_SET_PDEATHSIG), so the release always wins that race. SIGKILL the
	// process holding the write end while the payload is parked and it runs:
	// PAYLOAD_RAN 5/5.
	//
	// THE FIX, and the reason these two flags are inseparable: the SAME pipe's
	// write end is handed to bwrap as --sync-fd. bwrap keeps that descriptor
	// open in the sandbox's own pid 1 for the life of the run, so the parked
	// read can never see EOF however violently anything outside dies —
	// measured, same harness, same host: payload_never_ran 0/5, with
	// release-by-byte still running the payload as the positive control.
	//
	// Do not "simplify" this to any other inherited descriptor. An arbitrary
	// extra fd passed to bwrap keeps the pipe open just as well (0/5), and
	// LEAKS INTO THE PAYLOAD: measured, the payload's fd table came out
	// 0,1,2,4,5 with two such descriptors, against exactly 0,1,2 with --sync-fd.
	// bwrap closes the descriptors it was TOLD about and passes through the ones
	// it was not — its behaviour, not ours, so it is asserted in an integration
	// test rather than trusted.
	//
	// Note for anyone adding a flag near here: the args memfd below is a
	// SNAPSHOT of `flags`, so anything appended after it is silently dropped —
	// the same shape as the --seccomp-after-`--` bug.
	var release *os.File // P0's copy of the block pipe's write end; nil ⇒ this run is not gated
	if opts.EngineSpec != nil {
		if !p.Topology.NeedsStage() {
			// Not reachable from internal/cli — every container selection
			// resolves to a stage — and refused rather than assumed, because
			// the failure mode is a payload parked with nothing that will ever
			// release it.
			return 0, fmt.Errorf("refusing to run: a container engine was requested on a topology "+
				"with no stage (%s), so bwrap's payload would be parked with nothing to start "+
				"the engine that releases it", p.Topology.Netns)
		}
		blockR, blockW, perr := os.Pipe()
		if perr != nil {
			return 0, perr
		}
		flags = append(flags, "--block-fd", strconv.Itoa(nextFD()))
		extra = append(extra, blockR)
		flags = append(flags, "--sync-fd", strconv.Itoa(nextFD()))
		extra = append(extra, blockW)
		release = blockW
	}

	// The whole flag list travels through a memfd rather than real argv:
	//   - it sidesteps ARG_MAX for large policies
	//   - the sandbox's own /proc/<pid>/cmdline does not display the policy to
	//     the agent, so the agent cannot read its own boundary out of procfs
	//   - it removes every shell-quoting concern from what --dry-run prints
	//
	// Nothing may be appended to `flags` after this point.
	joined, err := nulJoin(flags)
	if err != nil {
		return 0, err
	}
	argsFile, err := memfd("snug-args", joined)
	if err != nil {
		return 0, err
	}
	argsFD := nextFD()
	extra = append(extra, argsFile)

	argv := []string{"--args", strconv.Itoa(argsFD), "--"}
	argv = append(argv, p.Command...)

	stdin, stdout, stderr, err := safeStdio()
	if err != nil {
		return 0, err
	}

	if p.Topology.NeedsStage() {
		return runStaged(p, bwrap, argv, extra, stdin, stdout, stderr, opts, infoR, release, runInfo)
	}

	cmd := exec.Command(bwrap, argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.ExtraFiles = extra

	// bwrap runs with an EMPTY environment, and this line is load-bearing.
	//
	// exec.Cmd with a nil Env passes os.Environ() — the whole host environment.
	// bwrap then becomes PID 1 of the sandbox's PID namespace, running as the
	// same uid as the payload, so the payload can read every host variable out
	// of /proc/1/environ: SSH_AUTH_SOCK, cloud credentials, tokens. --clearenv
	// only clears the environment handed to the *spawned command*; it says
	// nothing about bwrap's own. Found by the redteam agent, which pulled 106
	// host variables out of a sandbox whose payload env was correctly clean.
	//
	// bwrap needs nothing from the host environment — the payload's environment
	// is rebuilt entirely through --setenv — so empty costs nothing.
	cmd.Env = []string{}

	// No Setpgid anywhere in this chain: the tree stays in the terminal's
	// foreground process group so Ctrl-C reaches the payload and job control
	// works for an interactive shell inside the sandbox.
	if err := fdseal.SealFor(cmd); err != nil {
		return 0, err
	}

	// Armed immediately before the fork, never after it: a signal landing
	// between a live bwrap and an uninstalled handler is issue #13's window,
	// and the only way to close it is not to have it. See teardown.go.
	guard := armTeardown(opts)
	defer guard.stop()

	if err := cmd.Start(); err != nil {
		return 0, err
	}
	reportInfo(infoR, runInfo, opts)

	// THE UNSTAGED ARM, which today means offline: bwrap made its own network
	// namespace and there is no helper to attach, so the payload is already
	// running. Every networked run goes through runStaged above — NetEgress is
	// the only mode deriveTopology maps to NetnsStage, and the only mode that
	// needs a helper. Named for the TOPOLOGY rather than for its one member,
	// because which arm a reader is in is a question about the topology.
	//
	// guard.wait, not a bare wait(cmd): a TERM/INT/HUP arriving in the ~40ms
	// before bwrap's own init arms its pdeathsig used to leave that init
	// running, reparented, holding the payload — issue #13. See teardown.go.
	return guard.wait(cmd.Process.Pid, func() (int, error) {
		return wait(cmd)
	})
}

// runStaged is the NetnsStage arm, and its ORDER is the security property.
//
//	stage.Start   -> N exists, pinned by a descriptor, with nobody in it
//	startPasta    -> pasta attaches to that empty N and configures snug0
//	WaitNetReady  -> the stage confirms snug0 is UP and RUNNING, from inside N
//	StartSandbox  -> bwrap builds the sandbox; on a container run its payload
//	                 PARKS here and the engine starts behind the gate
//	release       -> only NOW does a payload exist
//
// The NETWORK's own ordering problem is gone and stays gone: pasta needs a
// netns, the stage makes one before bwrap exists, so nothing is ever parked
// waiting for the network. --json-status-fd, readChildPID and the entire parked
// type went with that and are not coming back.
//
// The GATE is a different thing wearing the same flag (issue #125). A container
// engine cannot be started before bwrap — Tier C derives its mount view from
// the sandbox's — so on a container run the payload is parked on --block-fd
// until the engine is confirmed. What makes that safe, and what made the
// original parked window a defect, is stated at the flag's own emission point
// in Run: --block-fd is passed ONLY together with --sync-fd on the same pipe,
// so a killed snug cannot release the payload by dying (measured 5/5 -> 0/5).
// A run with no container engine passes neither flag and is not parked at all.
//
// BUT ONLY THE RELEASE HALF. F2 had two clauses — a killed snug released the
// payload AND left an orphaned sandbox — and the reordering closes the first.
// The second was open on both topologies and predates it: between bwrap
// forking the sandbox init and bwrap arming --die-with-parent on it, nothing
// in snug guaranteed the sandbox died, so a signal to snug in that interval
// left an init reparented to the nearest subreaper, holding the payload and
// the netns, with write access to the target. Measured 3/3, all four signals,
// on both topologies. Do not read the deletions above as covering it: what
// covers it is teardown.go's guard, armed around each fork, and issue #13
// carries the measurements and the three refuted candidates.
//
// What remains open is stated as a rule, not as a list of signal names, and
// teardown.go's residual paragraph is where it lives: every termination that
// does not run a Go signal handler — SIGKILL, which never reaches userspace,
// and a genuine panic or runtime throw in P0, which dies on the runtime's own
// crash path. Nothing else; teardownSignals carries every orphaning signal a
// handler can reach. This comment named SIGKILL alone for a milestone while
// the code registered TERM/INT/HUP, which is issue #111 — a `kill -QUIT`
// reproduced issue #13 exactly, in the same window, against three documents
// all saying it could not.
//
// What made the reorder possible, having previously been recorded as a blocker:
// confirming the interface is up needed a process inside N to read
// /proc/<pid>/net/dev, and before bwrap there is none. But a socket's network
// namespace is fixed when the SOCKET is created, not by where its owner later
// goes — so the socket the stage opens in N to bring lo up still answers for N
// after the stage has left, and the stage answers the question over the control
// socket. Both halves measured; see stage.WaitNetReady.
func runStaged(p *policy.Policy, bwrap string, argv []string, extra []*os.File,
	stdin, stdout, stderr *os.File, opts Options, infoR, release *os.File, runInfo RunInfo) (int, error) {
	// The read end of bwrap's --info-fd pipe belongs to the STAGE on this arm,
	// not to this process (issue #125): P1 forks bwrap, so P1 is the process
	// that must be able to kill bwrap's parked init, and it cannot kill a pid it
	// was never told. P0 gets the parsed answer back in the "start" event.
	defer infoR.Close()
	st, err := stage.Start(stage.Config{
		Topology:  p.Topology,
		Sandbox:   extra,
		BwrapInfo: infoR,
		Stdin:     stdin, Stdout: stdout, Stderr: stderr,
		// Wired to the same notifyInit the offline arm calls from
		// reportInfo, so StartSandbox's "forked" event reaches opts.OnInit
		// synchronously, before the mount settle and the engine's cold start
		// "enginestarted" waits out (issue #236).
		OnSandboxForked: func(pid int) { notifyInit(opts, pid) },
	})
	if err != nil {
		return 0, err
	}
	defer st.Close()

	// Two shapes now share this arm (issue #63, Tier B). A NetEgress run
	// attaches pasta to a namespace with NO process in it — measured: it
	// starts, stays up, and its interface is waiting when bwrap arrives — and
	// waits for pasta's own "snug0" interface. A run that needs a stage ONLY
	// because a container profile is selected (offline @podman-socket: the
	// engine needs a stage for its own U even though N carries no egress)
	// starts no pasta at all and waits for "lo" instead, which setup.go
	// already brought up while it was still inside N. Either way, no payload
	// — and, from here on, no engine — exists before this returns: invariant
	// 5 at the exact point it used to be enforced by parking a process that
	// already existed.
	var helper *netHelper
	netIface := "lo"
	if p.Net.Mode == policy.NetEgress {
		netIface = stage.NetIfaceName

		helper, err = startPasta(p, st.Target())
		if err != nil {
			return 0, err
		}
		defer helper.stop()
		helper.watch(opts.warn)
	}

	// Raced against pasta dying (when there is a pasta to race), because the
	// two failures need different messages and very different latencies. A
	// pasta that exits at once — the crashing or OOM-killed shape — would
	// otherwise be reported only when the stage's interface timeout expired,
	// turning a 300ms error into a ten-second one that a human interrupts
	// before reading. An offline podman run has no pasta to race against, so
	// it simply waits.
	ready := make(chan error, 1)
	go func() { ready <- st.WaitNetReady(netReadyTimeout, netIface) }()
	if helper != nil {
		select {
		case err := <-ready:
			if err != nil {
				return 0, err
			}
		case <-helper.died():
			return 0, fmt.Errorf("pasta exited before the network came up: %s", helper.failure())
		}
	} else if err := <-ready; err != nil {
		return 0, err
	}

	// Armed before StartSandbox, and here that is the fork of a GRANDchild:
	// bwrap is forked by the stage, so P0 never learns its pid and st.Pid() is
	// the only lever it has. Everything above this line — the stage, pasta,
	// the engine, the up-to-netReadyTimeout wait for the interface — is
	// deliberately outside the guard: nothing there can be orphaned (the
	// stage and the engine both carry their own PR_SET_PDEATHSIG and no
	// payload exists yet), and a guard held across that wait would swallow a
	// Ctrl-C for as long as fifteen seconds.
	guard := armTeardown(opts)
	defer guard.stop()
	// pasta is a descendant, so confirmTeardown's sweep kills it — and
	// helper.watch is sitting on exactly that death, ready to report the
	// sandbox as degraded. runStaged's `defer helper.stop()` is what normally
	// claims the death, and on the signal path it has not run yet. Claim it
	// here instead, before the first kill (issue #112).
	guard.onSignal(helper.markStopping)

	// ONE request, and on a container run the payload is PARKED when it returns
	// (issue #125). Everything that has to be true before a payload exists is
	// true here and nowhere else: bwrap has built the sandbox, the engine is
	// forked into N and its socket answers. A failure means the stage has
	// already killed bwrap and its init — invariant 5, with the payload never
	// having existed rather than existing briefly on a doomed run.
	info, err := st.StartSandbox(bwrap, argv, opts.EngineSpec, release != nil)
	if err != nil {
		return 0, err
	}

	// Between the engine and the payload, and this is the reason the stage
	// reports twice for one request: the container reaper is armed HERE, while
	// nothing inside the sandbox is running. A failure refuses the run
	// (invariant 5 — an engine snug cannot guarantee to reap is not handed to a
	// payload), and the parked payload dies with it: this function returns, the
	// deferred st.Close() drops the lifeline, and the stage kills bwrap AND its
	// parked init on the way out (internal/stage's watchLifeline).
	if opts.EngineSpec != nil && opts.OnEngineReady != nil {
		if err := opts.OnEngineReady(); err != nil {
			return 0, err
		}
	}

	// THE RELEASE. One byte, and the payload exists from this line on. Written
	// by P0 rather than by the stage on purpose: P0 is the only process that
	// knows every precondition above actually held, and the write end it uses
	// is its own copy — the sandbox's pid 1 holds another, which is what stops
	// P0's death from doing the same job (see the flag's emission point in Run).
	if release != nil {
		if _, werr := release.Write([]byte{0}); werr != nil {
			return 0, fmt.Errorf("releasing the sandbox's parked payload: %w", werr)
		}
	}

	// AFTER the release, never before, and on both shapes. OnInfo publishes the
	// run-state file that makes a run attachable, and attaching to a sandbox
	// whose payload is still parked would put a process inside it before the
	// gate opened — precisely what the gate exists to prevent. On an ungated run
	// this ordering costs nothing: the payload is already running.
	publishInfo(info, runInfo, opts)

	// From here on a payload exists, forked by the STAGE, not by this process.
	// guard.wait is what closes issue #13's window on this topology: the
	// stage's own child (bwrap) can be orphaned exactly as the offline
	// topology's bwrap can, by the same ~40ms pdeathsig-arming gap, and
	// confirmTeardown's sweep is what reaches it once the stage is dead.
	return guard.wait(st.Pid(), func() (int, error) {
		ws, err := st.Wait()
		// Run BEFORE the deferred st.Close() above collapses the stage — and
		// therefore the engine, via its own Pdeathsig cascading from P1 —
		// while the engine's socket is still reachable. That reachability
		// used to be the whole point of this position: it let a filtered
		// `podman stop` run against a still-live engine, before the collapse.
		// Issue #167 deleted that call (the pids it would stop are numbered
		// in the engine's own pid namespace, meaningless to a host-side
		// invocation whether the engine happens to be alive here or already
		// dead on the SIGKILL path — internal/engine's package comment and
		// ENGINE-WIRING.md §6/§12 item 1 carry the argument), so THIS SEAM
		// NOW EXISTS FOR NOTHING SPECIFIC TO ITS POSITION: opts.OnPayloadExit
		// (Engine.Stop) still drops the keepalive, verifies by the socket-
		// path sweep and tears down the reaper, and none of those three
		// needs the engine reachable rather than already collapsed. THAT
		// SEPARATE DECISION HAS SINCE BEEN MADE (issue #344): the hook here
		// now only DETACHES the engine, and the verification moved to the
		// caller's own deferred cleanup, which runs after the st.Close()
		// above. "Leaving it costs nothing observable" was measured false —
		// from this position the engine is alive by construction, so a sweep
		// for it can only go quiet by waiting out the engine's idle timeout,
		// and the sweep did not notice for a milestone only because it was
		// matching a socket spelling no process carries. Called whatever
		// the payload's own outcome, because "did this run have containers
		// to stop" is a question about opts.EngineSpec, not about how the
		// payload exited.
		if opts.OnPayloadExit != nil {
			opts.OnPayloadExit()
		}
		if err != nil {
			return 0, err
		}
		if ws.Exited() {
			return ws.ExitStatus(), nil
		}
		return -1, nil
	})
}

// reportInfo reads bwrap's --info-fd answer in the background and calls
// opts.OnInfo once it has one — NEVER blocking the caller, which by the time
// this is called already has a running payload. base carries the seccomp
// fields Run already computed, since bwrap's own JSON says nothing about the
// filter.
//
// THE UNSTAGED ARM ONLY. On the staged arm the read end lives in
// the stage (issue #125), which parses it and forwards the answer in the
// "start" event; runStaged calls publishInfo below instead. The split is not
// cosmetic: on that arm the answer must be IN HAND before the payload is
// released, so it cannot be read in the background.
//
// infoR is closed here, once, regardless of outcome: this is its only
// reader and its only closer.
func reportInfo(infoR *os.File, base RunInfo, opts Options) {
	go func() {
		defer infoR.Close()
		info, err := bwrapinfo.Read(infoR, infoFDTimeout)
		if err != nil {
			opts.warn(fmt.Sprintf("this run will not be attachable (%v)", err))
			return
		}
		notifyInit(opts, info.InitPID)
		publishInfo(info, base, opts)
	}()
}

// notifyInit is the one place both arms of Run turn "bwrap named its init"
// into opts.OnInit(pid) — the offline arm from reportInfo's goroutine, the
// staged arm through stage.Config.OnSandboxForked (runStaged) — the same
// convergence publishInfo already gives opts.OnInfo. pid <= 1 means bwrap
// never answered or named something that cannot be a host init; OnInit is not
// called for it, same as publishInfo's own InitPID <= 0 guard.
func notifyInit(opts Options, pid int) {
	if opts.OnInit == nil || pid <= 1 {
		return
	}
	opts.OnInit(pid)
}

// publishInfo turns bwrap's answer — however it arrived — into a RunInfo and
// hands it to opts.OnInfo. One place, so that a run's attachability record is
// built identically whichever process read the descriptor.
//
// An InitPID of 0 means bwrap never answered. That is warn-only, and it stays
// warn-only: the run is simply not attachable. On a GATED run it cannot get
// this far — the stage refuses to leave a parked payload it cannot name (see
// internal/stage's runOneSandbox), so the run has already failed by here.
func publishInfo(info bwrapinfo.Info, base RunInfo, opts Options) {
	if info.InitPID <= 0 {
		opts.warn("this run will not be attachable (bwrap did not report its --info-fd answer)")
		return
	}
	// bwrap OMITS a namespace it did not itself unshare, so the staged arm's
	// "net" arrives as 0 and is recovered from /proc here rather than in the
	// stage: it is a read of the host's own procfs about a host pid, which P0
	// can do as well as P1, and keeping it here keeps the recovery rule in one
	// place next to the writeRunState that depends on it.
	fillMissingNamespaceIDs(info.InitPID, info.Namespaces)
	if opts.OnInfo != nil {
		opts.OnInfo(RunInfo{
			InitPID:       info.InitPID,
			Namespaces:    info.Namespaces,
			SeccompActive: base.SeccompActive,
			SeccompDigest: base.SeccompDigest,
		})
	}
}

// fillMissingNamespaceIDs is the fix for a gap the attach design's own §7
// assumed away: bwrap's --info-fd JSON omits a "<kind>-namespace" key
// ENTIRELY for any namespace bwrap did not itself create with its own
// --unshare-* flag — it says nothing about a namespace the process merely
// INHERITED. Measured directly against this host's bwrap: with
// --unshare-net passed, "net-namespace" is present and correct; without it
// (the process already sitting in a private netns handed to it, exactly
// runStaged's own shape — the stage creates the netns and bwrap is forked
// already inside it, never unsharing net itself) the key is absent
// entirely, which json.Decoder silently zero-values. Zero is not a real
// namespace inode on any Linux kernel, so every recorded "net" entry for an
// @net (staged) run was 0 — and since `snug attach`'s own live check reads
// the REAL inode from /proc and refuses on ANY mismatch (§4.1 step 4), this
// silently made every @net sandbox permanently unattachable.
//
// The fix reads whatever bwrap's report left at 0 directly from
// /proc/<pid>/ns/<kind> — fstat on an opened descriptor, never readlink (the
// same reasoning internal/cli/attach.go's own procNamespaceInodes gives: not
// trusting the kernel to have rendered a string consistently with what a
// later setns will actually join). It runs for every kind, not only "net",
// on the same "do not special-case one topology's shape" reasoning the rest
// of this file already follows — if a future bwrap release omits a
// DIFFERENT key for some other reason, this closes that too rather than
// needing a second patch.
func fillMissingNamespaceIDs(pid int, namespaces map[string]uint64) {
	for kind, id := range namespaces {
		if id != 0 {
			continue
		}
		var st unix.Stat_t
		if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, kind), &st); err != nil {
			// Leave it at 0 — the caller (writeRunState) already refuses to
			// publish state without every one of the six ids present and
			// non-zero elsewhere; nothing here should paper over a pid that
			// is already gone by guessing.
			continue
		}
		namespaces[kind] = st.Ino
	}
}

// netReadyTimeout is P0's patience with the STAGE, not with pasta: the stage
// applies its own shorter bound to the interface itself, so exceeding this one
// means the stage is wedged rather than the network being slow.
const netReadyTimeout = 15 * time.Second

func wait(cmd *exec.Cmd) (int, error) {
	err := cmd.Wait()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 0, err
}

// excludeSet renders ExcludeFromTeardown in the form the sweep wants. nil when
// there is nothing to spare, which is the ordinary run.
func (o Options) excludeSet() map[int]bool {
	if len(o.ExcludeFromTeardown) == 0 {
		return nil
	}
	m := make(map[int]bool, len(o.ExcludeFromTeardown))
	for _, pid := range o.ExcludeFromTeardown {
		// A zero or negative pid would be a caller bug, and passing it through
		// is how "exclude nothing" becomes "exclude the process group" in
		// whatever reads this next. Dropped rather than trusted.
		if pid > 1 {
			m[pid] = true
		}
	}
	return m
}

func (o Options) warn(msg string) {
	if o.Warn != nil {
		o.Warn(msg)
		return
	}
	fmt.Fprintln(os.Stderr, "snug: "+msg)
}

// nulJoin renders the flag list in the NUL-separated form bwrap's --args reads,
// and refuses any element that contains the separator.
//
// This code OWNS the separator, so it is the one place entitled to say that no
// element may contain it — and it is the last place the whole argv exists as
// Go values, so a check here holds for every flag whatever authored it, not
// just for the ones whose author was remembered.
//
// It is deliberately the SECOND guard. `checkEnvValue` refuses a NUL in a
// profile-supplied environment value at parse time, where the error can name
// the profile, the verb and the variable; that is the one that will fire in
// practice and the one a human can act on. This one fires when something else
// puts a NUL into a flag — a path, a generated value, a future writer nobody
// has thought of — and it fails the run rather than handing bwrap a flag list
// that means something other than the policy.
//
// The reachable case, measured: an environ.set value carrying a NUL escape
// re-synced bwrap's --args parser onto its own remainder, so
// `--setenv EDITOR "vim\\u0000--ro-bind\\u0000/home/u/.ssh\\u0000/home/u/.ssh"`
// mounted ~/.ssh — a mount no Mount ever existed for, so Validate,
// rejectMasking and --dry-run were all blind to it.
func nulJoin(args []string) ([]byte, error) {
	var b bytes.Buffer
	for i, a := range args {
		if strings.ContainsRune(a, 0) {
			return nil, fmt.Errorf("refusing to run: flag %d of the bwrap argument list "+
				"contains a NUL byte, which is the separator the list is joined with — "+
				"everything after it would be read by bwrap as further flags, and no "+
				"such flag is in the resolved policy. This is a bug in snug unless a "+
				"profile put it there; run `snug --dry-run` and look at the ENVIRONMENT "+
				"block", i)
		}
		b.WriteString(a)
		b.WriteByte(0)
	}
	return b.Bytes(), nil
}

// safeStdio returns the three standard descriptors, with any that is a
// DIRECTORY replaced by /dev/null.
//
// sealInheritedFDs closes the door on inherited fds above 2, for a reason it
// states plainly: an open fd on a host directory is a complete bypass of the
// mount policy, because openat(2) walks from that descriptor's own vfsmount and
// never consults the sandbox's mount namespace. Fds 0/1/2 are exempt from that
// sweep because stdio has to pass through — which left exactly the same hole
// standing on three well-known descriptor numbers.
//
// The redteam agent walked through it:
//
//	snug proj -- sh -c 'cat /proc/self/fd/0/.bashrc'          < /home/user
//	snug proj -- sh -c 'echo x > /proc/self/fd/0/pwned'        0< ./ungranted-dir
//
// Both worked: arbitrary read AND write of a host subtree no profile granted.
// The sandboxed agent cannot set snug's descriptors, so the trigger is the
// launcher rather than the payload — but snug runs under wrappers and
// automation that rewire stdio as a matter of course, and the invariant is one
// the code already claims to enforce.
//
// A directory on stdio is never meaningful for a payload: read(2) on a dirfd
// returns EISDIR. So substituting /dev/null costs nothing real.
func safeStdio() (stdin, stdout, stderr *os.File, err error) {
	out := [3]*os.File{os.Stdin, os.Stdout, os.Stderr}
	names := [3]string{"stdin", "stdout", "stderr"}

	for i, f := range out {
		if f == nil {
			continue
		}
		fi, statErr := f.Stat()
		if statErr != nil || !fi.IsDir() {
			continue
		}
		devnull, openErr := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if openErr != nil {
			return nil, nil, nil, fmt.Errorf("%s is a directory and /dev/null is unavailable: %w", names[i], openErr)
		}
		fmt.Fprintf(os.Stderr, "snug: %s is a directory; replacing it with /dev/null.\n"+
			"      A directory descriptor would let the sandbox reach the host filesystem "+
			"through /proc/self/fd/%d, bypassing every mount grant.\n", names[i], i)
		out[i] = devnull
	}
	return out[0], out[1], out[2], nil
}

// sealInheritedFDs moved to internal/fdseal (SealFor) in Phase 1: the stage
// (P1) is a long-lived process that forks more than once, and a keep-list
// derived from the *exec.Cmd being forked is what stays correct as such a
// process's descriptor table drifts — see that package's doc comment.
