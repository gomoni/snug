package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/fdseal"
	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/stage"
)

// Options are the run-time choices a human makes at the CLI. Nothing here is
// expressible in a profile — weakening is the human's prerogative (INDEX §2.5).
type Options struct {
	NoSeccomp bool
	Warn      func(string) // where degradation notices go; never silently dropped

	// OnInfo, if non-nil, is called exactly once, from a background
	// goroutine, as soon as bwrap has reported its own info-fd JSON — before
	// the payload's own program has been exec'd inside the sandbox, but
	// never blocking bwrap's own startup (see the comment above runStaged
	// for why nothing in this package parks a payload on a handshake any
	// more). It is the hook `snug attach`'s run-state file is written
	// through.
	//
	// If bwrap never answers — an old bwrap, a failed start, a topology this
	// package could not wire the descriptor through for — OnInfo is simply
	// never called, and this package warns instead (same rule as every other
	// place this file degrades: named, not silent). A run whose OnInfo is
	// never reached is a run `snug attach` will not find; it is not a run
	// that failed to start.
	OnInfo func(RunInfo)

	// EngineSpec, when non-nil, tells runStaged to fork a container engine
	// into this sandbox's own N — EAGERLY, after the network is confirmed and
	// before the payload exists, as a second long-lived child of the stage
	// alongside bwrap (issue #63, Tier B; ENGINE-WIRING.md §1). nil means no
	// engine at all: an ordinary @net (or offline) run with no container
	// profile selected. Only meaningful when p.Topology.NeedsStage() is true;
	// internal/cli/container.go is the only caller that sets it, having
	// already run the P1-P6 preflight this package does not repeat.
	EngineSpec *stage.EngineSpec

	// OnEngineReady, if non-nil, runs right after StartEngine has confirmed
	// the engine's socket exists — before StartSandbox, so a failure here
	// (dialling the lifeline that ties the engine's lifetime to this
	// sandbox, arming teardown) refuses the WHOLE run rather than letting a
	// payload start behind a container engine this process cannot guarantee
	// to reap. Only ever called when EngineSpec is non-nil.
	OnEngineReady func() error

	// OnPayloadExit, if non-nil, runs after the staged payload has been
	// reaped (st.Wait() returned) and BEFORE the deferred st.Close() collapses
	// the stage. It is the seam for stopping THIS run's containers, by label,
	// while the engine's socket is still reachable — internal/sandbox must
	// not import internal/engine (layering: this package is lower-level), so
	// the actual "stop --filter label=..." call is supplied by the caller as
	// a closure. Never called on the offline/host-network arm of Run, which
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

	// Networking needs NO handshake with bwrap any more, and the absence is the
	// point.
	//
	// bwrap used to be started first and told to park its payload on --block-fd
	// until pasta had attached, because pasta needs a netns and only bwrap could
	// make one. Under the stage the netns exists BEFORE bwrap does, so pasta
	// attaches first and there is nothing to park. That deletes --block-fd,
	// --json-status-fd, the two pipes, readChildPID and the whole `parked` type
	// along with the SIGKILL window they carried: a payload that has not been
	// forked cannot be released early.
	//
	// Nothing here is conditional on networking any more, which is why this block
	// is gone rather than shortened. Note for anyone adding a flag near here: the
	// args memfd below is a SNAPSHOT of `flags`, so anything appended after it is
	// silently dropped — the same shape as the --seccomp-after-`--` bug.

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
		return runStaged(p, bwrap, argv, extra, stdin, stdout, stderr, opts, infoR, runInfo)
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

	// This arm is the OFFLINE and host-network one: bwrap made its own namespace
	// (or was given the host's) and there is no helper to attach, so the payload
	// is already running. Every networked run goes through runStaged above —
	// NetEgress is the only mode deriveTopology maps to NetnsStage, and the only
	// mode that ever needed a helper.
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
//	StartSandbox  -> only NOW does a payload exist
//
// The previous order was the reverse — bwrap first, its payload parked on
// --block-fd, released once pasta was up — because pasta needs a netns and
// only bwrap could create one. That parked interval was a real defect: bwrap
// releases a parked payload on EOF exactly as readily as on a byte, and snug's
// own death closes the write end, so a SIGKILL of snug inside the window ran
// the payload with no network and left an orphaned sandbox. Measured 5/5.
//
// Reordering does not narrow that window, it removes the thing that had a
// window: there is no payload to release, so there is nothing for a dying snug
// to release. --block-fd, --json-status-fd, readChildPID and the entire parked
// type are gone with it.
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
	stdin, stdout, stderr *os.File, opts Options, infoR *os.File, runInfo RunInfo) (int, error) {
	st, err := stage.Start(stage.Config{
		Topology: p.Topology,
		Sandbox:  extra,
		Stdin:    stdin, Stdout: stdout, Stderr: stderr,
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

	// EAGER, between netready and StartSandbox — a fixed step of the stage's
	// own startup, never lazy (ENGINE-WIRING.md §1): the engine's successful
	// confinement to N is a precondition of the payload existing at all, the
	// same shape WaitNetReady already enforces one level up. A failure here
	// is fatal to the whole run — invariant 5 — and StartSandbox below is
	// never reached on that path.
	if opts.EngineSpec != nil {
		if err := st.StartEngine(*opts.EngineSpec); err != nil {
			return 0, err
		}
		if opts.OnEngineReady != nil {
			if err := opts.OnEngineReady(); err != nil {
				return 0, err
			}
		}
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

	if err := st.StartSandbox(bwrap, argv); err != nil {
		return 0, err
	}
	reportInfo(infoR, runInfo, opts)

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
		// needs the engine reachable rather than already collapsed. Left
		// here rather than moved after st.Close(): moving it is a separate
		// decision, and leaving it costs nothing observable. Called whatever
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
// this is called already has a running (or about-to-run) payload on both
// topologies. base carries the seccomp fields Run already computed, since
// bwrap's own JSON says nothing about the filter.
//
// infoR is closed here, once, regardless of outcome: this is its only
// reader and its only closer.
func reportInfo(infoR *os.File, base RunInfo, opts Options) {
	go func() {
		defer infoR.Close()
		info, err := readRunInfo(infoR, infoFDTimeout)
		if err != nil {
			opts.warn(fmt.Sprintf("this run will not be attachable (%v)", err))
			return
		}
		info.SeccompActive, info.SeccompDigest = base.SeccompActive, base.SeccompDigest
		if opts.OnInfo != nil {
			opts.OnInfo(info)
		}
	}()
}

// readRunInfo decodes bwrap's --info-fd JSON, bounded by timeout.
//
// json.Decoder.Decode, not ReadAll: Decode stops at one complete JSON value
// rather than waiting for EOF, and this process keeps its OWN copy of the
// write end open (in `extra`, for the whole life of the run) — waiting for
// EOF here would then wait forever.
//
// The goroutine+select shape, rather than SetReadDeadline, matches the one
// already used for WaitNetReady above: it is bounded by C's patience with
// bwrap, not by anything the pipe itself can express, and a timeout leaves
// the inner goroutine to exit on its own once infoR is closed by the caller.
func readRunInfo(infoR *os.File, timeout time.Duration) (RunInfo, error) {
	type result struct {
		info RunInfo
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var raw struct {
			ChildPID int    `json:"child-pid"`
			Mnt      uint64 `json:"mnt-namespace"`
			Pid      uint64 `json:"pid-namespace"`
			Net      uint64 `json:"net-namespace"`
			Ipc      uint64 `json:"ipc-namespace"`
			Uts      uint64 `json:"uts-namespace"`
			Cgroup   uint64 `json:"cgroup-namespace"`
		}
		if err := json.NewDecoder(infoR).Decode(&raw); err != nil {
			ch <- result{err: fmt.Errorf("reading bwrap's --info-fd: %w", err)}
			return
		}
		namespaces := map[string]uint64{
			"mnt": raw.Mnt, "pid": raw.Pid, "net": raw.Net,
			"ipc": raw.Ipc, "uts": raw.Uts, "cgroup": raw.Cgroup,
		}
		fillMissingNamespaceIDs(raw.ChildPID, namespaces)
		ch <- result{info: RunInfo{
			InitPID:    raw.ChildPID,
			Namespaces: namespaces,
		}}
	}()
	select {
	case res := <-ch:
		return res.info, res.err
	case <-time.After(timeout):
		return RunInfo{}, fmt.Errorf("bwrap did not answer on --info-fd within %s", timeout)
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
