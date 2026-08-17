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
//     at HEAD, offline orphans at 0-60ms and the stage at 20-100ms, so either
//     one alone would have called the other topology clean.
//   - It does NOT gate on the payload having appeared. Requiring bwrap or the
//     payload to exist before signalling is exactly the precondition that makes
//     the older test green; an offset that lands before the payload exists is a
//     legitimate pass here, not a skip.
//   - It finds the orphan by a per-run TOKEN in /proc/<pid>/cmdline, host-wide,
//     never by walking down from snug's pid. An orphan has by definition been
//     reparented — measured on this host, onto the surrounding container's own
//     subreaper, not onto snug — so any ancestry-based sweep would report a
//     clean tree for the one process it was written to find.

const (
	// orphanSweepEnd and orphanSweepStep are the window from issue #13's own
	// measurements with an order of magnitude of headroom: bwrap's init arms
	// its pdeathsig at roughly 40ms, both topologies were measured clean from
	// 200ms, and the sweep runs to 300ms so a regression that merely MOVES the
	// window later still lands inside it.
	orphanSweepEnd  = 300 * time.Millisecond
	orphanSweepStep = 20 * time.Millisecond

	// orphanMarkerDelay is how long the payload waits before writing to the
	// target. It must outlast snug's own death, or a marker written before the
	// signal would be indistinguishable from one written by an orphan.
	orphanMarkerDelay = 250 * time.Millisecond

	// orphanSettle is how long to wait after snug has exited before deciding
	// nothing survived it. Comfortably longer than orphanMarkerDelay: a check
	// made too early would pass because the orphan had not got round to writing
	// yet, which is the "test that cannot fail" shape this suite exists to
	// avoid.
	orphanSettle = 700 * time.Millisecond
)

// TestSignallingSnugDuringStartupLeavesNoOrphanedSandbox is the regression for
// issue #13.
//
// SIGKILL is deliberately NOT in the signal set. It never reaches userspace, so
// no handler in snug gets a chance to run and no fix expressible in snug can
// close it; the residual is documented on the issue rather than papered over
// here. TestKillingSnugDuringStartupNeverRunsThePayload still asserts SIGKILL
// for the property that IS closed — that no payload exists to be released.
//
// Cost: it starts a real sandbox once per offset per signal per topology, which
// is why its budget is minutes rather than seconds. The alternative — one
// offset, or one signal, or one topology — is what let this defect through
// twice.
func TestSignallingSnugDuringStartupLeavesNoOrphanedSandbox(t *testing.T) {
	budget(t, 5*time.Minute)
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

			for _, sig := range []syscall.Signal{
				syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP,
			} {
				t.Run(sig.String(), func(t *testing.T) {
					for off := time.Duration(0); off <= orphanSweepEnd; off += orphanSweepStep {
						t.Run(fmt.Sprintf("%dms", off.Milliseconds()), func(t *testing.T) {
							orphanRun(t, topo.args, sig, off)
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
	if _, err := os.Stat(marker); err == nil {
		t.Errorf("%s to snug %dms into startup left something that WROTE to the target "+
			"directory %s after snug was gone. An orphaned sandbox keeps the write access "+
			"it was granted, which is the half of issue #13 that outlives the process "+
			"tree.\n%s", sig, off.Milliseconds(), marker, orphanLog(t, cmd))
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

		var seen []int
		deadline := time.Now().Add(20 * time.Second)
		for {
			seen = pidsWithToken(tok, snug)
			_, statErr := os.Stat(marker)
			if len(seen) > 0 && statErr == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("PRECONDITION: an UNSIGNALLED run never produced both detectors — "+
					"sweep found %d process(es) %s, marker %s exists: %v. Every negative "+
					"assertion in this test is vacuous until this passes.\n%s",
					len(seen), describePIDs(seen), marker, statErr == nil, orphanLog(t, cmd))
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
	payload := fmt.Sprintf(`sleep %.2f; echo %s > "$SNUG_TARGET/m-%s"; sleep 30`,
		orphanMarkerDelay.Seconds(), payloadMarker, tok)

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
