//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This file is issue #13's second half: signalling snug during the first tens
// of milliseconds of a run leaves the sandbox's init alive — reparented away
// from snug, holding the payload, holding the network namespace, and still
// writing to the target directory — after snug itself is gone.
//
// It exists as a NEW test rather than as an extension of
// TestKillingSnugDuringStartupNeverRunsThePayload because that test
// structurally cannot see this defect, and the issue says so: its fake pasta
// hangs forever, so bwrap is never forked and there is nothing to orphan — its
// own precondition asserts bwrap's ABSENCE. Two earlier fixes for #13 were
// agreed against that test and both were wrong. What follows is what makes the
// next attempt falsifiable.
//
// Three properties are deliberate:
//
//   - It sweeps the kill OFFSET rather than picking one. The window is a race
//     against bwrap arming PR_SET_PDEATHSIG on its own init, so a single offset
//     measures one point on a curve whose shape differs per topology — measured
//     against the unfixed code, offline orphans at 20 and 50ms while the stage
//     orphans at 50 and 100ms, so an offset chosen for one topology can be
//     clean on the other. Which offsets, and why only four, is in
//     orphanSweepOffsets.
//   - It does NOT gate on the payload having appeared. Requiring bwrap or the
//     payload to exist before signalling is exactly the precondition that makes
//     the older test green; an offset that lands before the payload exists is a
//     legitimate pass here, not a skip.
//   - It finds the orphan by a per-run TOKEN in /proc/<pid>/cmdline, host-wide,
//     never by walking down from snug's pid. An orphan has by definition been
//     reparented — measured on this host, onto the surrounding container's own
//     subreaper, not onto snug — so any ancestry-based sweep would report a
//     clean tree for the one process it was written to find.

// orphanSweepOffsets is where the signal lands, measured from the fork.
//
// Issue #13 asks for a uniform 20ms step across 0-300ms. That is sixteen
// offsets, and once signals and topologies are counted, 96 real sandbox
// launches for a suite whose speed is a feature. Each of these four was kept
// because it CATCHES something, measured against the unfixed code — not
// because it tiles a range:
//
//	 20ms  offline orphans; stage has not forked bwrap yet
//	 50ms  BOTH topologies orphan — the one offset that would do on its own
//	100ms  stage orphans; offline is already clean
//	250ms  catches nothing today, and is the only one kept on an argument
//	       rather than a measurement — see below
//
// So each topology is hit TWICE by the first three, which is the margin worth
// paying for on a race: a single point can be missed by a host that is faster
// or slower than this one, two adjacent points cannot be missed by a small
// shift in either direction.
//
// Dropped, with reasons, because "it might catch something" is how a 96-launch
// test happens: 0ms signals before either topology has forked anything, so
// there is nothing to orphan and it asserts only that snug dies, which every
// other test already does; 200ms and 300ms are past both windows, where the
// sandbox is fully up and its teardown is the ordinary path other tests cover.
//
// 250ms is the exception and is deliberate. The windows do not start at zero —
// the stage's opens at 40ms rather than 0ms purely because the stage and pasta
// have to run first — so a change that makes startup SLOWER moves the window
// right rather than widening it, and the first three offsets would then all
// land before it. One late offset is the tripwire for that, and it is cheap.
//
// The signal that this sampling has gone stale is a failure at one offset with
// its neighbours green: that means the window has narrowed, and the offsets
// have to follow it.
var orphanSweepOffsets = []time.Duration{
	20 * time.Millisecond, 50 * time.Millisecond,
	100 * time.Millisecond, 250 * time.Millisecond,
}

// orphanConfirmedOffsets is the reduced sweep, and the reduction is measured
// rather than chosen: 50ms is the one offset at which issue #111 reproduced an
// orphan on BOTH topologies, and 100ms is where the staged one still did. A
// signal that leaks at any offset leaks at these two.
var orphanConfirmedOffsets = []time.Duration{
	50 * time.Millisecond, 100 * time.Millisecond,
}

// orphanSignals is every signal measured to leave an orphaned sandbox behind,
// with how much of the offset window each is swept across.
//
// fullSweep is the four-offset sweep, and it is spent where the offset
// dimension can still teach us something: the three signals the guard has
// always carried, plus SIGQUIT, which is issue #111's own reproduction and the
// one a human is most likely to send by hand.
//
// The rest get orphanConfirmedOffsets. That is a real reduction in coverage
// and it is stated rather than hidden: after signal.Notify accepts them, all
// twelve travel one code path (teardownGuard.wait's select), so the offset
// dimension is measuring the WINDOW, which is a property of the topology and
// not of the signal number. What is signal-specific — whether os/signal
// delivers this number to a handler at all, rather than letting the runtime
// die on it — is asserted per signal, exhaustively, and much more cheaply, by
// TestTheTeardownGuardCatchesEverySignalItRegisters in internal/sandbox.
var orphanSignals = []struct {
	sig       syscall.Signal
	fullSweep bool
}{
	{syscall.SIGTERM, true},
	{syscall.SIGINT, true},
	{syscall.SIGHUP, true},
	{syscall.SIGQUIT, true},

	{syscall.SIGABRT, false},
	{syscall.SIGTRAP, false},
	{syscall.SIGSYS, false},
	{syscall.SIGSEGV, false},
	{syscall.SIGBUS, false},
	{syscall.SIGFPE, false},
	{syscall.SIGILL, false},
	{syscall.SIGSTKFLT, false},
}

const (
	// orphanMarkerPeriod is how often the payload REWRITES its marker. The
	// evidence is the marker's mtime, never its existence — see orphanRun.
	orphanMarkerPeriod = 100 * time.Millisecond

	// orphanSettle is how long to wait after snug has exited before deciding
	// nothing survived it. Several marker periods, so a live orphan has had
	// many chances to touch the file: a check made too early would pass
	// because the orphan had not got round to writing yet, which is the "test
	// that cannot fail" shape this suite exists to avoid.
	orphanSettle = 700 * time.Millisecond
)

// TestSignallingSnugDuringStartupLeavesNoOrphanedSandbox is the regression for
// issue #13, and — since the signal set below grew — for issue #111.
//
// SIGKILL is deliberately NOT in the signal set. It never reaches userspace, so
// no handler in snug gets a chance to run and no fix expressible in snug can
// close it; the residual is documented on the issue rather than papered over
// here. TestKillingSnugDuringStartupNeverRunsThePayload still asserts SIGKILL
// for the property that IS closed — that no payload exists to be released.
//
// Everything else that can orphan a sandbox IS here. The set used to be
// TERM/INT/HUP, chosen as "what a supervisor sends", and issue #111 measured
// the cost of that reasoning: `kill -QUIT` — the standard gesture for dumping
// a Go program's goroutines — reproduced issue #13 bit-for-bit, in the same
// startup window, on both topologies, while three separate documents said
// SIGKILL was the only residual. The nine added here are every signal measured
// to kill snug through the Go runtime's fatal-throw path. Written out rather
// than imported from internal/sandbox on purpose: a test that reads its
// expectations from the code under test cannot fail.
//
// Cost: one real sandbox per offset per signal per topology. 24 launches took
// 21s measured; the full 12x4x2 does not fit in the suite's outermost 4m, so
// the offset dimension is sampled per signal — see orphanSignals. Dropping a
// DIMENSION is not where to save that time: one offset, or one signal, or one
// topology is exactly what let this defect through twice. Sampling within the
// offset dimension is where it was saved, on measurements rather than on
// taste; see orphanSweepOffsets.
func TestSignallingSnugDuringStartupLeavesNoOrphanedSandbox(t *testing.T) {
	budget(t, 150*time.Second)
	requireSandbox(t)
	requirePasta(t)

	for _, topo := range []struct {
		name string
		args []string
	}{
		{"offline", nil},
		{"stage", []string{"-p", "@net"}},
	} {
		t.Run(topo.name, func(t *testing.T) {
			// The positive control runs FIRST, and the rest of this topology's
			// subtests are meaningless without it: it proves that a sandbox
			// started exactly this way is visible to exactly this sweep and
			// does write exactly this marker. A pidsWithToken that always
			// returned nothing would otherwise make every assertion below pass.
			orphanPositiveControl(t, topo.args)

			for _, s := range orphanSignals {
				t.Run(s.sig.String(), func(t *testing.T) {
					offsets := orphanSweepOffsets
					if !s.fullSweep {
						offsets = orphanConfirmedOffsets
					}
					for _, off := range offsets {
						t.Run(fmt.Sprintf("%dms", off.Milliseconds()), func(t *testing.T) {
							orphanRun(t, topo.args, s.sig, off)
						})
					}
				})
			}
		})
	}
}

// orphanRun starts one sandbox, signals snug `off` after the fork, waits for
// snug to be gone, and then asserts that nothing of that run survived it.
func orphanRun(t *testing.T, args []string, sig syscall.Signal, off time.Duration) {
	t.Helper()
	proj, _ := target(t)
	tok := orphanToken()
	marker := filepath.Join(proj, "m-"+tok)

	cmd := orphanCmd(t, args, proj, tok)
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if wait := off - time.Since(start); wait > 0 {
		time.Sleep(wait)
	}
	if err := cmd.Process.Signal(sig); err != nil {
		// The run finished before the signal landed — impossible with a payload
		// that sleeps for 30s unless snug failed to start at all.
		t.Fatalf("could not signal snug: %v\n%s", err, orphanLog(t, cmd))
	}
	_ = cmd.Wait()
	// Taken AFTER Wait returns, so it is genuinely "snug is gone". Everything
	// below compares against this instant rather than against the existence of
	// a file.
	died := time.Now()

	time.Sleep(orphanSettle)

	survivors := pidsWithToken(tok, cmd.Process.Pid)
	defer killAll(survivors)

	if len(survivors) != 0 {
		t.Errorf("%s to snug %dms into startup left %d process(es) of this run alive after "+
			"snug itself was gone: %s. That is issue #13: the sandbox's init outlives the "+
			"process that was supposed to own it, still holding the payload and its "+
			"namespaces.\n%s",
			sig, off.Milliseconds(), len(survivors), describePIDs(survivors), orphanLog(t, cmd))
	}
	// The marker's MTIME, not its existence. An earlier version of this test
	// asserted the file was absent and CI was right to fail it: at 280ms and
	// 300ms the payload had already run and written it BEFORE the signal
	// landed, so a correct teardown looked like a leak. What no correct
	// teardown can produce is a write dated after snug's own death — which is
	// why the payload rewrites the marker every orphanMarkerPeriod for as long
	// as it lives, and why this compares against `died`.
	if fi, err := os.Stat(marker); err == nil && fi.ModTime().After(died) {
		t.Errorf("%s to snug %dms into startup left something that WROTE to the target "+
			"directory %s %s AFTER snug was gone. An orphaned sandbox keeps the write "+
			"access it was granted, which is the half of issue #13 that outlives the "+
			"process tree.\n%s", sig, off.Milliseconds(), marker,
			fi.ModTime().Sub(died).Round(time.Millisecond), orphanLog(t, cmd))
	}
}

// orphanPositiveControl runs the identical command and does NOT signal it, then
// requires both detectors to fire: the token sweep must see the sandbox, and the
// payload must write the marker.
//
// Without this every negative assertion in this file would be satisfied by a
// snug that failed to start, a payload that never ran, or a sweep that cannot
// see a process it is looking straight at.
func orphanPositiveControl(t *testing.T, args []string) {
	t.Helper()
	t.Run("positive-control", func(t *testing.T) {
		proj, _ := target(t)
		tok := orphanToken()
		marker := filepath.Join(proj, "m-"+tok)

		cmd := orphanCmd(t, args, proj, tok)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		snug := cmd.Process.Pid
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			killAll(pidsWithToken(tok, snug))
		})

		// `since` is what makes this a control for the REAL assertion. The
		// negative arm does not ask whether the marker exists, it asks whether
		// it was written after a given instant — so this must prove exactly
		// that detector fires on a sandbox that is genuinely alive, not merely
		// that a file appeared.
		since := time.Now()

		var seen []int
		var fresh bool
		deadline := time.Now().Add(20 * time.Second)
		for {
			seen = pidsWithToken(tok, snug)
			fi, statErr := os.Stat(marker)
			fresh = statErr == nil && fi.ModTime().After(since)
			if len(seen) > 0 && fresh {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("PRECONDITION: an UNSIGNALLED run never produced both detectors — "+
					"sweep found %d process(es) %s; marker %s written after the run started: "+
					"%v. Every negative assertion in this test is vacuous until this "+
					"passes.\n%s", len(seen), describePIDs(seen), marker, fresh,
					orphanLog(t, cmd))
			}
			time.Sleep(25 * time.Millisecond)
		}
	})
}

// orphanCmd builds the snug invocation both arms share.
//
// The payload sleeps, writes the marker, then sleeps for a long time, so an
// orphan announces itself twice: once as a live process carrying the token in
// its argv, and once as a file written to the target AFTER snug's death.
func orphanCmd(t *testing.T, args []string, proj, tok string) *exec.Cmd {
	t.Helper()
	// A LOOP, not a single delayed write. A one-shot marker makes the evidence
	// "does this file exist", which is true for any run whose payload got far
	// enough — including a run torn down perfectly. Rewriting it makes the
	// evidence "is this file still being written", which only a live process
	// can produce.
	payload := fmt.Sprintf(
		`while :; do echo %s > "$SNUG_TARGET/m-%s"; sleep %.2f; done`,
		payloadMarker, tok, orphanMarkerPeriod.Seconds())

	argv := append(append([]string{}, args...), proj, "--", "/bin/sh", "-c", payload)
	cmd := exec.Command(snugBin, argv...)
	cmd.Env = baseEnv()

	// A real file, never the default pipe. os/exec's pipe stays open as long as
	// ANY process holds its write end — and an orphaned sandbox is precisely a
	// process that inherited it, so cmd.Wait() would block on the very thing
	// this test is measuring and report it as a two-second WaitDelay rather
	// than as a finding.
	log, err := os.CreateTemp(t.TempDir(), "snug-out")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	cmd.Stdout, cmd.Stderr = log, log
	return cmd
}

func orphanLog(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()
	f, ok := cmd.Stdout.(*os.File)
	if !ok {
		return ""
	}
	b, err := os.ReadFile(f.Name())
	if err != nil || len(b) == 0 {
		return "      (snug wrote nothing to stdout/stderr)"
	}
	return "      snug said: " + strings.ReplaceAll(strings.TrimSpace(string(b)), "\n", "\n      ")
}

// orphanToken returns a string unique to one run, safe inside a shell
// double-quoted string and inside a filename.
func orphanToken() string {
	return "snug13tok" + strconv.Itoa(os.Getpid()) + "x" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

// pidsWithToken returns every live process on this host, owned by this uid,
// whose argv contains tok — excluding the pids in `except`.
//
// By ARGV and host-wide, for the reason at the top of this file: the process
// this is hunting has been reparented out of snug's subtree by definition, so
// findDescendant cannot reach it. A zombie never matches: /proc/<pid>/cmdline
// is empty once a process is dead, so a killed-but-unreaped child cannot be
// mistaken for a survivor.
func pidsWithToken(tok string, except ...int) []int {
	skip := map[int]bool{}
	for _, p := range except {
		skip[p] = true
	}
	var out []int
	for _, pid := range allPIDs() {
		if skip[pid] {
			continue
		}
		for _, arg := range cmdlineOf(pid) {
			if strings.Contains(arg, tok) {
				out = append(out, pid)
				break
			}
		}
	}
	return out
}

func describePIDs(pids []int) string {
	if len(pids) == 0 {
		return "(none)"
	}
	var b strings.Builder
	for i, pid := range pids {
		if i > 0 {
			b.WriteString(", ")
		}
		ppid, _ := ppidOf(pid)
		fmt.Fprintf(&b, "pid %d (%s, ppid %d)", pid, commOf(pid), ppid)
	}
	return b.String()
}

func killAll(pids []int) {
	for _, pid := range pids {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}
