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
// OWN init late, after that init's own setup — roughly 40ms in. Before that,
// killing the process bwrap runs as (the "outer" process P0 directly forked)
// does not take the init with it: the init has not yet registered to be told.
// This is true on BOTH topologies snug has (a bare `snug <dir>` and `-p @net`
// alike), for every catchable signal, because nothing in either topology
// installed a handler at all — the default disposition just let P0 die.
//
// The fix does not try to out-guess that 40ms window. It kills the process P0
// itself forked (bwrap for the offline topology, the stage for @net) and then
// actively hunts down and kills anything still alive underneath it, rather
// than hoping the kernel's own cascade already armed in time. See
// confirmTeardown.
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
// SIGKILL is NOT handled here and cannot be: it never reaches userspace, so no
// handler in P0 — however careful — gets a chance to run. The window this
// closes for TERM/INT/HUP remains open for a SIGKILLed snug. That is a
// measured, accepted residual, not an oversight — see the issue for the
// alternative that was rejected (making the STAGE's own Pdeathsig catchable,
// which only ever covered the @net topology and would have weakened an
// unconditional teardown guarantee — TestAFrozenStageTreeStillDiesWithSnug —
// to close a window that exists identically with no stage at all).

// teardownPollBudget bounds how long P0 spends confirming a signalled sandbox
// is actually gone before giving up and exiting anyway with a diagnostic.
// teardownPollInterval is how often it rechecks while doing so.
//
// 250ms is generous against the ~40ms window above: by the time this budget
// is halfway spent, bwrap's own init has certainly either armed its pdeathsig
// (in which case killing bwrap directly already closed it) or forked nothing
// at all (in which case there was nothing to leak). What the budget actually
// buys is time for confirmTeardown's OWN sweep-and-kill loop to catch a
// descendant that was mid-fork at the moment bwrap was killed.
const (
	teardownPollBudget   = 250 * time.Millisecond
	teardownPollInterval = 5 * time.Millisecond
)

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
// the ~5-40ms window: bwrap's own init has not yet armed the pdeathsig that
// would make it notice directChild's death, so killing directChild alone
// leaves it running, indefinitely, with no further signal ever arriving.
// warn is called at most once, only if something outlived the whole budget.
//
// directChild is passed as a PIDFD, not as a pid, and the sweep signals through
// a pidfd too. See killPinned: this code chooses what to SIGKILL by parsing
// /proc, and "the pid you read is the pid you kill" stops being true the moment
// the process behind it is reaped.
func confirmTeardown(directChild *os.File, warn func(string)) {
	if directChild != nil {
		_ = unix.PidfdSendSignal(int(directChild.Fd()), unix.SIGKILL, nil, 0)
	}

	root := os.Getpid()
	deadline := time.Now().Add(teardownPollBudget)
	for {
		pids := descendantsOf(root)
		if len(pids) == 0 {
			return
		}
		for _, pid := range pids {
			killPinned(pid, root)
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

// teardownGuard is P0's promise that a TERM, INT or HUP will not return until
// the sandbox it is responsible for is confirmed gone.
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
	signal.Notify(g.sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
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
		confirmTeardown(pinned, g.opts.warn)
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
func killPinned(pid, root int) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		if err == unix.ENOSYS {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		// Anything else — ESRCH above all — means it is already gone.
		return
	}
	defer unix.Close(fd)

	if !isDescendantOf(pid, root) {
		return
	}
	_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
}

// ── /proc process-tree walking ───────────────────────────────────────────
//
// No /proc/<pid>/task/<tid>/children here: measured absent on the development
// host (CONFIG_CHECKPOINT_RESTORE not set), so descendantsOf walks ancestry
// UP from every candidate pid instead, exactly as the integration suite's own
// findDescendant does. With becomeSubreaper active this needs very few hops
// for a reparented orphan (it lands on root directly); the bound below is
// generous for a genuinely deep, still-live process tree instead.

const descendantHopLimit = 32

// descendantsOf returns every pid, owned by this uid, whose ancestry (walking
// PPid upward) reaches root within descendantHopLimit hops. root itself is
// never included.
func descendantsOf(root int) []int {
	ppids := allPPIDs()
	var out []int
	for pid := range ppids {
		if pid == root {
			continue
		}
		p := pid
		for hop := 0; hop < descendantHopLimit; hop++ {
			parent, ok := ppids[p]
			if !ok || parent == p {
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
func isDescendantOf(pid, root int) bool {
	p := pid
	for hop := 0; hop < descendantHopLimit; hop++ {
		parent, _, ok := readStatus(p)
		if !ok || parent == p || parent <= 1 {
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
