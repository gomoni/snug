package sandbox

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// This file closes the second half of issue #13: a snug signalled during the
// first tens of milliseconds of a run can leave the sandbox's init alive,
// reparented to whatever subreaper is nearest, holding the payload and (for
// @net) the network namespace, with write access to the target — after snug
// itself is gone.
//
// The root cause, measured (see the issue and .claude/scratchpad's settlement
// on it): bwrap arms --die-with-parent (PR_SET_PDEATHSIG) on the sandbox's
// OWN init late, after that init's own setup. Before that, killing the process
// bwrap runs as (the "outer" process P0 directly forked) does not take the
// init with it: the init has not yet registered to be told. This is true for
// every catchable signal, because nothing installed a handler at all — the
// default disposition just let P0 die.
//
// THE WINDOW IS WIDER THAN THIS COMMENT SAID. It read "roughly 40ms in" for
// several milestones. Re-measured on this host with the payload writing a
// control file at startup, SIGKILL of snug at a fixed offset, 4-6 runs per
// offset, WITHOUT the offline arm's intermediate pid namespace:
//
//	offset  86  90  94 ms -> 0 leaks / 4     (payload has not started yet)
//	offset  98        ms -> 3 leaks / 4
//	offset 102        ms -> 4 leaks / 4
//	offset 110 130 160 ms -> 8 leaks / 8 each
//
// A "leak" is the strong form: the payload RAN — its control file appeared —
// after snug was already dead, and then held the target, writable and
// unsupervised. Payload start latency is ~206ms, measured 5x, which is why the
// low offsets look clean: nothing had started to be left behind.
//
// The fix has never tried to out-guess that window, which is why the number
// being wrong cost nothing. It kills the process P0 itself forked (bwrap for
// the offline topology, the stage for @net) and then actively hunts down and
// kills anything still alive underneath it, rather than hoping the kernel's
// own cascade already armed in time. See confirmTeardown.
//
// ON THE OFFLINE ARM THE WINDOW IS NOW CLOSED OUTRIGHT, by construction rather
// than by the sweep. bwrap is pid 1 of the intermediate pid namespace snug
// forks it into (exec.go's SysProcAttr, issue #101), so bwrap's own
// --die-with-parent SIGKILL fires and zap_pid_ns_processes then SIGKILLs the
// sandbox init before it has forked a payload at all. Measured 0 leaks across
// 18 offsets from 0 to 1200ms, 144+ trials, against the table above on the
// same host in the same session. The sweep is still what the guarantee rests
// on — a construction that happens to win a race is not a boundary — but this
// arm no longer needs it to win.
//
// The sweep is HOST-SIDE — it walks the host's own /proc and the host's own
// PPid values — and therefore crosses PID-namespace boundaries: a pid
// namespace hides its members' view of each other, not the host's view of
// them. Two consequences worth stating, because both have been proposed as
// extra work and neither is needed. Nothing here forwards a signal INWARD, so
// there is no need for a handler inside each namespace (a namespace init
// ignores signals it has no handler for; SIGKILL, which is what this sends, it
// cannot ignore). And if snug ever nests another PID namespace in the chain —
// issue #101's inner init — this code needs no change: the extra level shows
// up as one more ordinary host pid with an ordinary host PPid, well inside
// descendantHopLimit.
//
// THE RESIDUAL, stated as a rule rather than as a list of names. What is left
// open is every termination that does not run a Go signal handler:
//
//   - SIGKILL. It never reaches userspace, so no handler in P0 — however
//     careful — gets a chance to run. Measured, accepted, not an oversight;
//     see the issue for the alternative that was rejected (making the STAGE's
//     own Pdeathsig catchable, which only ever covered the @net topology and
//     would have weakened an unconditional teardown guarantee —
//     TestAFrozenStageTreeStillDiesWithSnug — to close a window that exists
//     identically with no stage at all).
//   - A genuine panic or runtime throw inside P0 itself. The Go runtime dies
//     on its own crash path, which no handler intercepts. Measured: with
//     signal.Notify registered for SIGSEGV, a nil dereference still printed
//     "panic: runtime error: invalid memory address ... [signal SIGSEGV ...
//     code=0x1]" and exited rc=2, and the notified channel never fired —
//     the runtime splits on si_code, so a FAULT crashes while a signal SENT
//     with kill(2) is delivered to the handler.
//
// WHAT THOSE TWO LEAVE BEHIND CHANGED SHAPE WITH ISSUE #125's GATE, on
// container runs only, and it is written down here rather than discovered
// later. During the parked window — bwrap has built the sandbox and its init is
// blocked on --block-fd while the container engine starts, 1-2s typically and
// up to engineSocketWaitTimeout — a SIGKILL of P0 plays out like this,
// MEASURED end to end, 20 runs, with a fake engine that never binds its socket
// so the window is the full 30s:
//
//	P0            dies; its copy of the block pipe's write end closes. NO EOF:
//	              the sandbox's own pid 1 holds another, as --sync-fd.
//	parked init   stays blocked in read(). THE PAYLOAD IS NEVER FORKED — 20/20,
//	              and that clause of the old defect is closed outright.
//	P1            RACES its own death. do_exit closes P0's descriptors
//	              (exit_files) BEFORE it delivers P1's Pdeathsig (exit_notify) —
//	              the very ordering that makes --block-fd-alone unsafe — so P1's
//	              lifeline watcher wakes on the EOF first and kills the parked
//	              init explicitly. Measured 20/20 on this host: zero processes
//	              left, checked 200ms and 1.5s after the kill.
//	              POSITIVE CONTROL, because "nothing was left" is exactly the
//	              assertion that passes when nothing ever started: with that one
//	              kill removed from watchLifeline, exactly one process survives,
//	              5/5 — the parked init.
//	engine        Pdeathsig from P1's death.
//	bwrap (outer) --die-with-parent on P1's death, which does NOT reach the
//	              parked init: bwrap has not armed it on that init yet (measured
//	              — kill the outer bwrap while parked and the init stays alive
//	              AND still releasable).
//
// So the residual is narrower than "a killed snug leaks a sandbox", and it is
// this: a parked init is orphaned whenever P1 cannot run code at all — a
// SIGSTOPped stage tree, where Pdeathsig is the only thing left and Pdeathsig
// kills P1 without running its watcher, or a lost race on a host that schedules
// differently from this one. What is left then holds N and the whole mount tree
// with a payload that does not exist and now never will. Strictly better than
// the orphan this file's own history is about — that one holds a RUNNING
// payload with write access to the target — and still a leak.
//
// Nothing else. Issue #111 is why this paragraph is a rule: the previous
// version named SIGKILL alone, three times, in three files, while the code
// registered exactly TERM/INT/HUP — so `kill -QUIT`, the standard gesture for
// dumping a Go program's goroutines and an ordinary thing for a supervisor to
// send, reproduced issue #13 bit-for-bit in the same startup window. Measured
// one signal at a time: snug orphaned on QUIT ABRT TRAP SEGV BUS FPE ILL SYS
// STKFLT (all the runtime's fatal-throw path, rc=2) and did not on USR1 USR2
// PWR XCPU XFSZ PIPE. teardownSignals now carries every one of those that a
// handler can reach, which — measured, not assumed — is all of them.
//
// One deliberate cost, because it is a behaviour change and not a free win:
// `kill -QUIT snug` no longer dumps snug's own goroutine stacks, since the
// handler consumes the signal that used to produce them. Tearing the sandbox
// down beats debuggability of the wrapper — a hung snug leaves a sandbox
// holding the target either way, and the guard is the only thing that can end
// it. The dump is not lost, only moved: it is what SIGKILL still cannot give
// and what a debugger, or a snug run outside a sandbox's lifetime, still can.
//
// The handler must also stay on the path that RETURNS through the caller, not
// one that exits directly. internal/cli's `defer ctrCleanup()` runs after
// sandbox.Run returns and is what stops a signalled run's containers; an
// os.Exit here would skip it. See confirmTeardown's exclusion list and issue
// #113 — the same dependency, seen from the sweep's side.

// teardownPollBudget bounds how long P0 spends confirming a signalled sandbox
// is actually gone before giving up and exiting anyway with a diagnostic.
// teardownPollInterval is how often it rechecks while doing so.
//
// 250ms is NOT a margin against the arming window above, and the earlier
// version of this comment claimed it was — "by the time this budget is halfway
// spent, bwrap's own init has certainly either armed its pdeathsig or forked
// nothing at all". The measurements in this file's header refute the
// certainty: leaks were still 8/8 at a 160ms offset. What the budget actually
// buys is the only thing it ever bought — time for confirmTeardown's OWN
// sweep-and-kill loop to catch a descendant that was mid-fork at the moment
// bwrap was killed. That loop does not wait for any cascade to arm, which is
// why the wrong number never became a wrong behaviour.
const (
	teardownPollBudget   = 250 * time.Millisecond
	teardownPollInterval = 5 * time.Millisecond
)

// teardownSignals is every termination the guard converts from "die now, leave
// the sandbox behind" into "tear the sandbox down first, then report the
// conventional 128+signal exit code".
//
// The membership rule, and it is the whole point of the list existing as a
// named variable rather than as arguments at the call site: a signal belongs
// here if it can arrive from OUTSIDE this process and would otherwise kill P0
// without running a handler. Not "the signals a supervisor is likely to send"
// — that reasoning is what shipped TERM/INT/HUP alone and left issue #111's
// SIGQUIT hole, and "likely" is not a property an attacker respects.
//
// The last five are the ones that look wrong and are not. SEGV, BUS, FPE, ILL
// and STKFLT name faults, but a fault is not how they get here: the Go runtime
// checks si_code, so a genuine nil dereference still panics and crashes with
// its own traceback (measured — see the residual paragraph at the top of this
// file), while the same signal number SENT with kill(2) is delivered to this
// handler like any other. Registering them therefore costs nothing in crash
// reporting and closes the last externally-reachable members of the orphaning
// class. Issue #111 proposed leaving them out on the grounds that catching
// them would suppress the runtime's crash reporting; that was measured false
// before this list was written.
//
// Adding to this list is cheap and safe. REMOVING from it reopens issue #13
// for whatever is removed, silently — which is why two tests guard it rather
// than one: TestTeardownSignalsCoversEveryMeasuredOrphaningSignal checks
// membership against a table written independently of this variable, and
// TestTheTeardownGuardCatchesEverySignalItRegisters checks, in a subprocess,
// that each one is really delivered to a handler.
var teardownSignals = []os.Signal{
	syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP,
	syscall.SIGQUIT, syscall.SIGABRT, syscall.SIGTRAP, syscall.SIGSYS,
	syscall.SIGSEGV, syscall.SIGBUS, syscall.SIGFPE, syscall.SIGILL, syscall.SIGSTKFLT,
}

var (
	subreaperOnce sync.Once
	subreaperErr  error
)

// becomeSubreaper marks THIS process as the reaper for any orphan produced
// anywhere in its own descendant tree (PR_SET_CHILD_SUBREAPER, prctl(2)),
// however many fork/exec hops down.
//
// Without it, a descendant orphaned mid-chain — bwrap's own forked init, or
// (staged) the bwrap the stage forks — reparents to the NEAREST subreaper
// further up the process tree instead of to snug. Measured on the host this
// was written on: that is the surrounding container's own pid 1, not snug —
// issue #13's own reproduction shows exactly this ("ppid=6392", the
// container's subreaper, not snug's pid). Once reparented there,
// descendantsOf can no longer reach it by walking ancestry back to P0, so a
// process snug just orphaned would be invisible to the very sweep meant to
// clean it up.
//
// Idempotent and process-wide: called once per snug process, harmless with no
// sandbox running, and it does not change how a normally-exiting sandbox is
// reaped (cmd.Wait already does that; this only matters for what is left
// AFTER an intermediate ancestor dies unexpectedly).
//
// Called BEFORE the fork it protects, which is the spelling the kernel
// documents: a task inherits has_child_subreaper at copy_process() time, so
// the ordering is a contract rather than a preference. Measured on this host,
// setting it AFTER the fork also captured the orphan (three-way probe: before,
// after, and never — only "never" escaped, to the container's own subreaper at
// pid 6392, reproducing issue #13's own trace). Do not read that as licence to
// move this later: it is one kernel agreeing with the loose spelling, and the
// arrangement here costs nothing to keep correct.
func becomeSubreaper() error {
	subreaperOnce.Do(func() {
		subreaperErr = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
	})
	return subreaperErr
}

// confirmTeardown kills directChild — the process P0 itself forked for this
// run, bwrap for the offline topology or the stage for @net — and then does
// NOT trust any automatic cascade to finish the job. It repeatedly scans this
// process's OWN descendant tree and SIGKILLs everything still in it, until
// nothing is left or teardownPollBudget runs out.
//
// This is deliberately active rather than passive. Merely killing directChild
// and waiting is exactly the experiment issue #13 measured as failing 3/3 in
// the arming window (see this file's header for its measured width): bwrap's
// own init has not yet armed the pdeathsig that
// would make it notice directChild's death, so killing directChild alone
// leaves it running, indefinitely, with no further signal ever arriving.
// warn is called at most once, only if something outlived the whole budget.
//
// directChild is passed as a PIDFD, not as a pid, and the sweep signals through
// a pidfd too. See killPinned: this code chooses what to SIGKILL by parsing
// /proc, and "the pid you read is the pid you kill" stops being true the moment
// the process behind it is reaped.
//
// exclude names host pids this sweep must NOT kill, and it covers their whole
// subtrees (see descendantsOf). Today it holds exactly one thing: the container
// reaper (internal/engine/reaper.go), whose entire job is to outlive snug and
// stop this run's containers if snug died without cleaning up — which is why it
// is the one helper snug starts with no Pdeathsig and its own process group.
// Sweeping it up is a contradiction: the guard would kill the process that
// exists because the guard might not get to run.
//
// It has been harmless up to now for a reason that is one edit away from
// stopping being true (issue #113): internal/cli's `defer ctrCleanup()` runs
// after sandbox.Run returns and does the container teardown itself, so a
// reaper killed here was never needed. An early os.Exit anywhere on the signal
// path — and #111's fix reshapes exactly that path — turns "the sweep kills
// the reaper" into "a signalled @podman-socket run leaks its containers". The
// exclusion removes the dependency rather than documenting it.
//
// A nil or empty exclude is the ordinary case: no container profile selected,
// no reaper, nothing to spare.
//
// The exclusion is by PID, and killPinned three functions below exists because
// a pid is not a stable name for a process — "the pid you read is the pid you
// kill" stops being true the moment something is reaped. An exclusion is that
// same claim facing the other way ("the pid you spare"), so it deserves the
// same scepticism, and a red-team pass gave it one. It is sound today for a
// structural reason rather than a lucky one: the reaper blocks reading a pipe
// whose write end snug holds until ctr.cleanup(), which runs AFTER sandbox.Run
// returns — that is, after this function has finished — so the reaper cannot
// exit, be reaped, and have its number recycled DURING the sweep. Nothing
// inside the sandbox can signal it either; it is a host process in a different
// pid namespace.
//
// The residual, stated rather than fixed: if that ordering ever changes, this
// becomes a real pid-reuse hole. The fix then is the one killPinned already
// models — hold a pidfd for the excluded process and honour the exclusion only
// while /proc/self/fdinfo/<fd>'s Pid: still names it.
func confirmTeardown(directChild *os.File, exclude map[int]bool, warn func(string)) {
	if directChild != nil {
		_ = unix.PidfdSendSignal(int(directChild.Fd()), unix.SIGKILL, nil, 0)
	}

	root := os.Getpid()
	deadline := time.Now().Add(teardownPollBudget)
	for {
		pids := descendantsOf(root, exclude)
		if len(pids) == 0 {
			return
		}
		for _, pid := range pids {
			killPinned(pid, root, exclude)
		}
		if time.Now().After(deadline) {
			warn(fmt.Sprintf("snug was signalled and killed the sandbox, but %d process(es) "+
				"(pid(s) %v) were still alive after %s of trying to confirm they were gone. "+
				"They may be wedged in uninterruptible sleep, or reparented somewhere this "+
				"process cannot see (see internal/sandbox/teardown.go's becomeSubreaper). "+
				"Check `ps` for orphans under those pids.", len(pids), pids, teardownPollBudget))
			return
		}
		time.Sleep(teardownPollInterval)
	}
}

// teardownGuard is P0's promise that no signal in teardownSignals will return
// until the sandbox it is responsible for is confirmed gone.
//
// It is armed and disarmed around ONE fork, and the placement is the whole
// design:
//
//	arm()          <- signal disposition changes here, and not one line earlier
//	fork the sandbox
//	wait()         <- races the payload's exit against a caught signal
//	stop()
//
// Arming BEFORE the fork rather than after it closes a window that no offset
// sweep could reliably hit: between a bwrap that already exists and a
// signal.Notify that has not run yet, the default disposition still applies,
// so the signal would kill snug outright and leave exactly the orphan this
// file is about. Sub-millisecond, and structural to close.
//
// Arming no EARLIER than that is equally deliberate. Everything before the
// fork — resolving a policy, starting the stage, waiting up to netReadyTimeout
// for pasta's interface — has nothing that can be orphaned (the stage carries
// its own PR_SET_PDEATHSIG and there is no payload yet), and a guard held
// across it would swallow the user's Ctrl-C and make snug appear to hang for
// as long as that wait lasts.
type teardownGuard struct {
	sig  chan os.Signal
	opts Options

	// beforeSweep runs on a caught signal, before confirmTeardown kills
	// anything, and never on the ordinary path. It is for state that says
	// "this death was ours" to something watching a helper — the sweep kills
	// helpers that have watchers, and a watcher cannot tell an orderly
	// teardown from a helper crashing unless somebody tells it first.
	//
	// Registered rather than fixed, because the offline topology has no
	// helpers at all and must stay a pass-through. Ordered, and run to
	// completion before the first kill: a claim made after the kill is a
	// claim made too late, which is issue #112 exactly.
	beforeSweep []func()
}

// onSignal registers a function to run on a caught signal, before the sweep.
// See teardownGuard.beforeSweep. Must be called before the fork it protects,
// like everything else about the guard.
func (g *teardownGuard) onSignal(fn func()) {
	if fn != nil {
		g.beforeSweep = append(g.beforeSweep, fn)
	}
}

// armTeardown installs the guard. It must be called immediately before the
// fork whose child it will tear down.
func armTeardown(opts Options) *teardownGuard {
	if err := becomeSubreaper(); err != nil {
		opts.warn(fmt.Sprintf("could not become a child-subreaper (%v). A snug killed by "+
			"TERM/INT/HUP during startup may still leave an orphaned sandbox behind: an "+
			"orphan reparents to the nearest subreaper above it instead of to snug, and "+
			"snug can only sweep its own descendants. Nothing else about the sandbox is "+
			"affected. prctl(PR_SET_CHILD_SUBREAPER) has been available since Linux 3.4 "+
			"and takes no privilege, so a failure here means a seccomp filter or an LSM "+
			"in whatever started snug is refusing it.", err))
	}

	g := &teardownGuard{sig: make(chan os.Signal, 1), opts: opts}
	signal.Notify(g.sig, teardownSignals...)
	return g
}

func (g *teardownGuard) stop() { signal.Stop(g.sig) }

// wait races `wait` — however a topology blocks until its sandbox is done —
// against a caught signal.
//
// On the ordinary path nothing here changes anything: the select picks up
// wait's own result and this is a pass-through, byte-identical to calling wait
// directly.
//
// On a caught signal it does the opposite of what the default disposition
// would (die immediately, as snug did with no handler at all, leaving the
// window open): it confirms via confirmTeardown that the sandbox is actually
// gone before returning, then reports the conventional signal-death exit code
// (128+signal, the same number a shell would have reported for the old
// unhandled death) so scripts checking $? see no behavioural difference.
//
// rootChildPid is the pid this process directly forked for the run — bwrap
// itself (offline) or the stage (staged) — which is what confirmTeardown kills
// first.
func (g *teardownGuard) wait(rootChildPid int, wait func() (int, error)) (int, error) {
	// Pinned HERE, before the goroutine below can reap it. A pid is only a
	// stable name for a process until something wait()s on it, and the
	// goroutine below is exactly that something; pinning first means the
	// descriptor cannot come to name some other process that inherited the
	// number. See killPinned for the same argument applied to the sweep.
	//
	// A failure is not fatal: on a kernel without pidfd_open the sweep still
	// reaches this process, because it is a descendant of snug like everything
	// else it forked.
	var pinned *os.File
	if fd, err := unix.PidfdOpen(rootChildPid, 0); err == nil {
		pinned = os.NewFile(uintptr(fd), "pidfd-sandbox")
		defer pinned.Close()
	}

	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		code, err := wait()
		done <- result{code, err}
	}()

	select {
	case r := <-done:
		return r.code, r.err
	case sig := <-g.sig:
		// BEFORE the sweep, not after: the sweep is what kills the helpers
		// these callbacks are claiming responsibility for, and a claim made
		// afterwards has already lost the race with the watcher goroutine
		// that fires on the helper's death (issue #112).
		for _, fn := range g.beforeSweep {
			fn()
		}
		confirmTeardown(pinned, g.opts.excludeSet(), g.opts.warn)
		// The kill inside confirmTeardown makes wait's own goroutine return
		// promptly — it is blocked on reaping rootChildPid (or being told
		// about it), and that process is now dead. Drain rather than race it:
		// this is not a second confirmation, just collecting the goroutine so
		// nothing here leaks.
		<-done
		return 128 + int(sig.(syscall.Signal)), nil
	}
}

// killPinned SIGKILLs pid, having first PINNED it with a pidfd and then
// re-confirmed — through that pin — that it is still a descendant of root.
//
// The order is the point, and the hazard is pid reuse. This code chooses what
// to kill by parsing /proc, and between reading a pid and signalling it the
// process behind it can be reaped and the number handed to something else
// entirely. The sequence here cannot kill a stranger:
//
//	pidfd_open(pid)      pins whatever process holds pid RIGHT NOW
//	re-read ancestry     names the process the pidfd pinned, because a live
//	                     (or zombie) process still holds its own pid
//	pidfd_send_signal    signals the pinned process, never the number
//
// If the original process died and the number was recycled, the pin names the
// NEW occupant and the ancestry re-read describes it too — so an unrelated
// process is skipped rather than killed, and the dead one needs no signal.
//
// The fallback is a plain kill(2), which is what this whole function is
// avoiding, and it is reached only where pidfd_open does not exist at all
// (before Linux 5.3). Racy there, and it was the only option snug had.
func killPinned(pid, root int, exclude map[int]bool) {
	if exclude[pid] {
		return
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		if err == unix.ENOSYS {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		// Anything else — ESRCH above all — means it is already gone.
		return
	}
	defer unix.Close(fd)

	// The re-read is what makes the pin safe against pid reuse, and it is also
	// where the exclusion is re-applied: descendantsOf's snapshot chose this
	// candidate, and between then and now the process could have been reparented
	// UNDER an excluded pid (the reaper forking its podman on EOF is exactly
	// that shape). Deciding twice, from fresh reads, is cheaper than being wrong
	// once.
	if !isDescendantOf(pid, root, exclude) {
		return
	}
	_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
}

// ── /proc process-tree walking ───────────────────────────────────────────
//
// No /proc/<pid>/task/<tid>/children here, and the reason is NOT the one this
// comment used to give. It said the file was "measured absent on the
// development host (CONFIG_CHECKPOINT_RESTORE not set)". Re-measured: this
// host has CONFIG_CHECKPOINT_RESTORE=y and `cat /proc/$$/task/$$/children`
// returns children. The claim was also self-refuting, since internal/initwalk
// reads that exact file and issue #236's measurements show it working.
//
// The real reason is a difference in what the two callers owe. initwalk NAMES
// an init and has a fallback when it cannot — the run is merely not
// attachable. This sweep is the teardown GUARANTEE and has none, so it is
// built on ancestry walked UP from every candidate pid, which needs no kernel
// config option at all, exactly as the integration suite's own findDescendant
// does. With becomeSubreaper active this needs very few hops for a reparented
// orphan (it lands on root directly); the bound below is generous for a
// genuinely deep, still-live process tree instead.

const descendantHopLimit = 32

// descendantsOf returns every pid, owned by this uid, whose ancestry (walking
// PPid upward) reaches root within descendantHopLimit hops. root itself is
// never included.
//
// A pid named in exclude is omitted, and so is anything whose walk to root
// passes THROUGH an excluded pid — the exclusion is a subtree, not a single
// process. That is the useful shape rather than the tidy one: the container
// reaper is a shell that forks `podman stop` when its pipe reports EOF, so an
// exclusion covering only the shell would spare the reaper and kill the
// cleanup it exists to perform.
func descendantsOf(root int, exclude map[int]bool) []int {
	ppids := allPPIDs()
	var out []int
	for pid := range ppids {
		if pid == root || exclude[pid] {
			continue
		}
		p := pid
		for hop := 0; hop < descendantHopLimit; hop++ {
			parent, ok := ppids[p]
			if !ok || parent == p {
				break
			}
			if exclude[parent] {
				break
			}
			if parent == root {
				out = append(out, pid)
				break
			}
			if parent <= 1 {
				break
			}
			p = parent
		}
	}
	return out
}

// isDescendantOf walks PPid upward from pid, one /proc read per hop, and
// reports whether it reaches root. Separate from descendantsOf because it
// answers about ONE pid with FRESH reads: descendantsOf's snapshot is what
// chooses candidates, and this is what re-confirms a candidate after
// killPinned has pinned it.
func isDescendantOf(pid, root int, exclude map[int]bool) bool {
	if exclude[pid] {
		return false
	}
	p := pid
	for hop := 0; hop < descendantHopLimit; hop++ {
		parent, _, ok := readStatus(p)
		if !ok || parent == p || parent <= 1 || exclude[parent] {
			return false
		}
		if parent == root {
			return true
		}
		p = parent
	}
	return false
}

// allPPIDs builds a pid->ppid map for every process on the host owned by this
// uid. Restricted by uid for the same reason the integration suite's own
// allPIDs is: this process has no business signalling anything it does not
// own, and a shared host may have plenty of unrelated processes to skip past.
//
// The uid filter is the natural place to worry that snug is filtering away
// something it needs to kill, because a MISSING INTERMEDIATE is worse than a
// missing leaf: descendantsOf walks UP through this map, so a node absent from
// it dead-ends the walk and hides everything below it too. A red-team pass
// raised exactly that, on two grounds. Both were measured and neither holds,
// and the measurements are recorded here so the next reader does not have to
// repeat them:
//
//   - PR_SET_DUMPABLE=0 does NOT hide a process from this map. It reassigns
//     the FILES under /proc/<pid> to uid 0 — `stat` reports `status` and
//     `cmdline` as uid=0 — while /proc/<pid> itself, the DIRECTORY, keeps the
//     real uid. os.ReadDir plus Info() stats the directory entry, so a
//     non-dumpable child stays in the map and in descendantsOf's output.
//     Measured directly against these two functions.
//   - The stage is not uid-0 on the HOST. It is root inside its own user
//     namespace, which maps 0 to this uid, so its /proc directory reads 1000
//     like everything else. Measured across a whole `-p @net` run: the stage,
//     the /proc/self/exe setns shim, both bwraps, pasta and the payload all
//     read uid 1000.
//
// So the filter drops other users' processes and nothing of snug's own. If a
// future topology ever does put a genuinely differently-owned process INSIDE
// the chain, this comment is the thing that is now wrong.
func allPPIDs() map[int]int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	uid := uint32(os.Getuid())
	out := map[int]int{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uid {
			continue
		}
		ppid, zombie, ok := readStatus(pid)
		if !ok {
			continue
		}
		// A zombie holds no resources beyond its exit status — no running
		// code, no fds, no netns membership — and it does not respond to
		// signals. Counting it as "still needs killing" would make
		// confirmTeardown spin for its whole budget and warn on every
		// ordinary run: reaping a genuinely dead child is cmd.Wait's job,
		// not this sweep's, and this sweep exists to find processes that
		// can still DO something, not pids that merely still exist in the
		// process table.
		if zombie {
			continue
		}
		out[pid] = ppid
	}
	return out
}

// readStatus reads a process's parent pid and run state from
// /proc/<pid>/status, far easier to parse reliably than /proc/<pid>/stat
// (comm can contain spaces and parens, which shift every fixed-position field
// after it).
func readStatus(pid int) (ppid int, zombie bool, ok bool) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, false, false
	}
	defer f.Close()
	havePPid := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if v, cut := strings.CutPrefix(line, "State:"); cut {
			zombie = strings.HasPrefix(strings.TrimSpace(v), "Z")
		}
		if v, cut := strings.CutPrefix(line, "PPid:"); cut {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return 0, false, false
			}
			ppid, havePPid = n, true
		}
	}
	if sc.Err() != nil {
		// A truncated read means the fields below were never seen. Reporting
		// "not a descendant" on a partial parse would silently shrink the
		// sweep, which is the one direction that turns this file into a test
		// that cannot fail.
		return 0, false, false
	}
	return ppid, zombie, havePPid
}
