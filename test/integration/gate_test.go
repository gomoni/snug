//go:build integration

package integration

// gate_test.go is issue #125's Tier C "C2-gate" piece: the payload of a
// CONTAINER run is parked (bwrap's --block-fd) until the engine is confirmed
// up, and P0 alone holds the byte that releases it (--sync-fd on the same
// pipe). Every number these tests turn into assertions came from probes that
// were run once and then deleted — nothing else in the repo checks any of
// them, so a later "simplify --block-fd back to just --block-fd" or "drop the
// explicit init kill" would go green here without this file.
//
// Every test drives a REAL sandbox and a REAL bwrap, through the real
// stage/gate machinery internal/stage/gate.go implements — never a
// mock of the control protocol. What is NOT real is podman: $SNUG_PODMAN
// (containerpreflight.go's preflightPodmanBinary trusts it outright, never
// re-resolving it through PATH) is pointed at testdata/fakepodman, a small
// stand-in that does the one thing these tests need controlled — WHEN its
// socket appears and what its first HTTP response is — without a real
// engine's uncontrollable 1-2s cold start. Nothing here is testing whether a
// real container runs; that is containerengine_test.go's job. subuid
// delegation, a private cgroup namespace and CLONE_NEWPID are all still real:
// this file needs requireSandbox and a host with a delegated subuid/subgid
// range for this uid, exactly like a real @podman-socket run.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	fakePodmanBinOnce sync.Once
	fakePodmanBinPath string
	fakePodmanBinErr  error
)

// fakePodmanBin builds testdata/fakepodman once for the whole process — it
// never touches a container, so unlike netprobeBin/holderBin/confprobeBin
// (which are scoped to the calling test's own t.TempDir(), rebuilt per
// caller) it is safe to keep at one fixed path for every test in this file,
// the same way pidfdProbeBin (TestMain, sandbox_test.go) is.
func fakePodmanBin(t *testing.T) string {
	t.Helper()
	fakePodmanBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "snug-fakepodman")
		if err != nil {
			fakePodmanBinErr = err
			return
		}
		bin := filepath.Join(dir, "fakepodman")
		cmd := exec.Command("go", "build", "-o", bin, "./testdata/fakepodman")
		cmd.Dir = "."
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			fakePodmanBinErr = fmt.Errorf("building test/integration/testdata/fakepodman: %w: %s",
				err, out.String())
			return
		}
		fakePodmanBinPath = bin
	})
	if fakePodmanBinErr != nil {
		t.Fatal(fakePodmanBinErr)
	}
	return fakePodmanBinPath
}

// writeFakePodmanConfig sets the ONE compiled fakepodman binary's behaviour
// for the NEXT run: see testdata/fakepodman's own doc comment for the format.
// Safe to call between runs because this whole suite is deliberately not
// parallel (sandbox_test.go's package doc) — there is never a second snug
// invocation reading this file while a new one is being written.
func writeFakePodmanConfig(t *testing.T, bin string, delay time.Duration, status int) {
	t.Helper()
	content := fmt.Sprintf("delay=%s\nstatus=%d\n", delay, status)
	if err := os.WriteFile(bin+".cfg", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ── TestAKilledSnugCannotReleaseTheParkedPayload ────────────────────────────

// TestAKilledSnugCannotReleaseTheParkedPayload is the M4 harness (host-bridge's
// design review, §0/§2.2) in tree: SIGKILL of snug while a container run's
// payload is parked on --block-fd must never release it. Measured, before the
// fix landed: PAYLOAD_RAN 5/5 with --block-fd alone; payload_never_ran 0/5
// with --sync-fd on the same pipe. Five runs here, matching that harness.
//
// Two things make the five kills mean something, in the same test rather than
// nearby:
//
//   - POSITIVE CONTROL: an ordinary, unsignalled gated run really does run the
//     payload once released. Without this, "payload never ran" 5/5 would be
//     equally true of a --sync-fd gate that releases NOTHING, ever.
//   - ADJACENT NEGATIVE: that same positive-control payload's own descriptor
//     table is exactly stdio (0,1,2) plus `ls`'s own directory handle. This is
//     the failure mode --sync-fd was chosen over an arbitrary extra inherited
//     descriptor to avoid (measured: an arbitrary fd survives the parked read
//     exactly as well, 0/5, but LEAKS into the payload — fds 0,1,2,4,5 against
//     exactly 0,1,2). Asserting the gate held without also checking this would
//     miss that leak entirely.
//
// Mutation-checked, and the result is worth recording rather than only the
// pass: removing --sync-fd ALONE (leaving internal/stage/gate.go's own
// explicit pidfd kill of the init in place) does NOT make the five kills
// below fail — watchLifeline's kill(), armed for a different reason
// (TestKillingOnlyBwrapLeavesAReleasableInit, below), independently reaches
// the init fast enough to win the race that used to matter. The two
// mechanisms overlap for THIS failure mode (SIGKILL of P0) by construction:
// the explicit kill covers "the process that can still release it" for
// every abort, of which "P0 died" is one. Removing --sync-fd AND disabling
// that explicit kill together reproduces PAYLOAD_RAN 5/5, exactly the
// pre-fix measurement — verified by hand, reverted by hand. Removing only
// the explicit kill (leaving --sync-fd) does not fail HERE either, for the
// same reason in reverse: --sync-fd alone already keeps the write end held
// inside the sandbox's own pid 1 (measured, M3), so P0's death produces no
// EOF regardless. That asymmetric case — an abort that kills only the outer
// bwrap while --sync-fd is intact — is exactly what
// TestKillingOnlyBwrapLeavesAReleasableInit isolates instead: it does not
// touch --sync-fd at all and fails on the explicit kill alone.
func TestAKilledSnugCannotReleaseTheParkedPayload(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)

	fp := fakePodmanBin(t)

	t.Run("positive-control-and-adjacent-negative", func(t *testing.T) {
		proj, _ := target(t)
		writeFakePodmanConfig(t, fp, 0, 200)
		env := append(baseEnv(), "SNUG_PODMAN="+fp,
			// SNUG_PODMAN_ROOT is what the toolchain graft is built from since
			// Tier C: the engine's view is derived from the sandbox's, so a
			// binary in a temp directory reaches it only through a graft, and
			// snug refuses the run rather than exec a path the engine cannot
			// see. The fake engine is self-contained, so its own directory is
			// the whole toolchain.
			"SNUG_PODMAN_ROOT="+filepath.Dir(fp))

		r := runEnv(t, env, []string{"-p", "@podman-socket"}, proj,
			"echo GATE-RELEASED; ls -l /proc/self/fd/")
		if !r.ran {
			t.Fatalf("PRECONDITION: the gated payload never ran at all (snug exited %d), so "+
				"neither half of this test means anything:\n%s", r.code, r.out)
		}
		if r.code != 0 {
			t.Fatalf("PRECONDITION: the gated run exited %d:\n%s", r.code, r.out)
		}
		if !strings.Contains(r.out, "GATE-RELEASED") {
			t.Fatalf("PRECONDITION: the payload ran but never printed its own marker:\n%s", r.out)
		}

		var stdio, suspicious []string
		for _, ln := range strings.Split(r.out, "\n") {
			fd, tgt, ok := parseFdLine(ln)
			if !ok {
				continue
			}
			if fd <= 2 {
				stdio = append(stdio, ln)
				continue
			}
			// fd 3 belongs to `ls` itself, exactly as
			// TestThePayloadInheritsNothingButStdio's own classifier notes: the
			// open directory handle that produced this listing necessarily
			// names that same path.
			if fd == 3 && strings.HasSuffix(tgt, "/fd") {
				continue
			}
			suspicious = append(suspicious, ln)
		}
		if len(stdio) == 0 {
			t.Fatalf("PRECONDITION: no stdio descriptors were listed at all, so this is not a "+
				"real descriptor table and the check below would pass vacuously:\n%s", r.out)
		}
		if len(suspicious) > 0 {
			t.Errorf("the gated payload's descriptor table carries more than stdio: %v\n"+
				"--sync-fd exists precisely so the block pipe's write end stays in the "+
				"sandbox's own pid 1 and never reaches here (measured: an arbitrary extra "+
				"inherited fd does, at fds 0,1,2,4,5). Any descriptor beyond stdio and ls's "+
				"own is exactly that leak.\n%s", suspicious, r.out)
		}
	})

	for i := 0; i < 5; i++ {
		t.Run(fmt.Sprintf("kill-%d", i), func(t *testing.T) {
			proj, _ := target(t)
			tok := orphanToken()
			marker := filepath.Join(proj, "marker-"+tok)
			script := fmt.Sprintf(`echo PAYLOAD-RAN-%s > "$SNUG_TARGET/marker-%s"`, tok, tok)

			// A generous delay: bwrap parks near-instantly after building the
			// mount tree (measured M1), so this only has to comfortably outlast
			// the 500ms we sleep below before killing snug, not the engine's
			// own real-world cold start.
			writeFakePodmanConfig(t, fp, 3*time.Second, 200)
			env := append(baseEnv(), "SNUG_PODMAN="+fp,
				// SNUG_PODMAN_ROOT is what the toolchain graft is built from since
				// Tier C: the engine's view is derived from the sandbox's, so a
				// binary in a temp directory reaches it only through a graft, and
				// snug refuses the run rather than exec a path the engine cannot
				// see. The fake engine is self-contained, so its own directory is
				// the whole toolchain.
				"SNUG_PODMAN_ROOT="+filepath.Dir(fp))

			argv := []string{"-p", "@podman-socket", proj, "--", "/bin/sh", "-c", script}
			cmd := exec.Command(snugBin, argv...)
			cmd.Env = env
			log, err := os.CreateTemp(t.TempDir(), "snug-gate-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { log.Close() })
			cmd.Stdout, cmd.Stderr = log, log

			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				killAll(pidsWithToken(tok, cmd.Process.Pid))
			})

			// PRECONDITION: the payload is genuinely PARKED — the stage exists
			// and has forked bwrap — before snug is killed. Without this,
			// "the payload never ran" would be equally true of a run that
			// never got anywhere near the gate.
			stagePID, ok := findDescendant(cmd.Process.Pid, isStageProcess, 15*time.Second)
			if !ok {
				t.Fatalf("PRECONDITION: the stage never appeared under snug\n%s", orphanLog(t, cmd))
			}
			if _, ok := findDescendant(stagePID, isComm("bwrap"), 15*time.Second); !ok {
				t.Fatalf("PRECONDITION: bwrap never appeared under the stage, so the payload "+
					"never got PARKED\n%s", orphanLog(t, cmd))
			}

			// Comfortably inside fakepodman's own 3s delay.
			time.Sleep(500 * time.Millisecond)

			if err := cmd.Process.Kill(); err != nil {
				t.Fatalf("SIGKILL snug: %v", err)
			}
			_ = cmd.Wait()

			// Give a released payload every chance to run before looking — a
			// check made too early would pass for the wrong reason.
			time.Sleep(1 * time.Second)

			if _, err := os.Stat(marker); err == nil {
				t.Errorf("the gated payload RAN after snug was SIGKILLed while it was parked. "+
					"This is the exact defect --sync-fd exists to close (measured 5/5 without "+
					"it, 0/5 with it): a killed snug must never release a parked payload.\n%s",
					orphanLog(t, cmd))
			}
		})
	}
}

// ── TestKillingOnlyBwrapLeavesAReleasableInit ───────────────────────────────

// TestKillingOnlyBwrapLeavesAReleasableInit is the "explicit init kill" test
// (review §2.3, §9): while the payload is parked, bwrap has NOT yet armed
// --die-with-parent on its own init (measured — killing the outer bwrap
// alone left the init alive, still parked, and STILL RELEASABLE afterwards).
// So an abort of a gated run that killed only bwrap and trusted the kernel's
// own cascade would leave exactly that: an orphaned, permanently parked
// sandbox init holding the network namespace and the mount tree. Nothing in
// snug may rely on --die-with-parent here; internal/stage/gate.go's
// parked.kill() explicitly SIGKILLs the init too, via a pidfd learned from
// bwrap's own --info-fd answer.
//
// The abort is triggered through a REAL failure path, not a fault injected
// into snug's own code: fakepodman is configured to answer the first
// connection with a non-200 status, so internal/engine's dialLifeline (P0's
// own OnEngineReady) fails immediately, exactly as it would if a real engine
// refused the keepalive stream. runStaged then returns the error without
// ever writing the release byte, st.Close() drops the lifeline, and the
// stage's watchLifeline goroutine (internal/stage/serve.go) is what calls
// parked.kill() and exits — the SAME function
// TestAKilledSnugCannotReleaseTheParkedPayload's SIGKILL scenario depends on,
// exercised here from its OTHER caller.
//
// Positive control that the abort really happened: a non-zero exit and the
// specific named error, so "nothing survived" cannot pass on a run that
// never even reached the gate.
func TestKillingOnlyBwrapLeavesAReleasableInit(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)

	fp := fakePodmanBin(t)
	proj, _ := target(t)
	tok := orphanToken()
	marker := filepath.Join(proj, "marker-"+tok)
	script := fmt.Sprintf(`echo PAYLOAD-RAN-%s > "$SNUG_TARGET/marker-%s"`, tok, tok)

	// status=503: the socket appears (so StartSandbox/"enginestarted"
	// succeeds and the payload is confirmed PARKED, not merely never having
	// reached the gate at all), but the FIRST connection — dialLifeline's own
	// keepalive dial, sandbox.Options.OnEngineReady — is refused at once.
	// delay=300ms: not for pacing the abort (that still happens as soon as
	// the socket exists and dialLifeline is tried), but to hold the window
	// open long enough for the PRECONDITION scan below to reliably catch the
	// real bwrap pid(s) of THIS run before the abort tears them down.
	writeFakePodmanConfig(t, fp, 300*time.Millisecond, 503)
	env := append(baseEnv(), "SNUG_PODMAN="+fp,
		// SNUG_PODMAN_ROOT is what the toolchain graft is built from since
		// Tier C: the engine's view is derived from the sandbox's, so a
		// binary in a temp directory reaches it only through a graft, and
		// snug refuses the run rather than exec a path the engine cannot
		// see. The fake engine is self-contained, so its own directory is
		// the whole toolchain.
		"SNUG_PODMAN_ROOT="+filepath.Dir(fp))

	argv := []string{"-p", "@podman-socket", proj, "--", "/bin/sh", "-c", script}
	cmd := exec.Command(snugBin, argv...)
	cmd.Env = env
	log, err := os.CreateTemp(t.TempDir(), "snug-gate-abort-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	cmd.Stdout, cmd.Stderr = log, log

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// PRECONDITION: catch THIS run's own bwrap pid(s) — the outer bwrap AND,
	// if it has forked by the time this scan runs, the parked init, which is
	// its own distinct process with identical comm and cmdline (a fork
	// changes neither) — while they are known-good descendants of THIS
	// snug's own stage. This is what lets the check below name the EXACT
	// pids that must be gone afterward, rather than sweeping the whole host
	// (which this development host's own ambient bwrap traffic — other
	// terminals, other sandboxes — makes far too noisy to use as a signal).
	stagePID, ok := findDescendant(cmd.Process.Pid, isStageProcess, 15*time.Second)
	if !ok {
		t.Fatalf("PRECONDITION: the stage never appeared under snug\n%s", readAll(log.Name()))
	}
	bwrapPIDs, ok := waitForBwrapDescendants(stagePID, 15*time.Second)
	if !ok {
		t.Fatalf("PRECONDITION: no bwrap-comm descendant of the stage ever appeared, so the "+
			"payload never got PARKED and this test would be measuring nothing\n%s",
			readAll(log.Name()))
	}

	if err := cmd.Wait(); err == nil {
		t.Fatalf("snug exited 0 against a fakepodman that refuses the keepalive stream — "+
			"the abort this test depends on never happened, so nothing below is testing "+
			"anything:\n%s", readAll(log.Name()))
	}

	out := readAll(log.Name())
	// POSITIVE CONTROL: the abort really happened, and happened for the
	// reason this test means. A generic non-zero exit is not enough — snug
	// could have failed for an unrelated reason (a preflight refusal, say)
	// before ever reaching the gate at all, which would make "nothing
	// survived" vacuous.
	if !strings.Contains(out, "would not accept the keepalive") {
		t.Fatalf("PRECONDITION: snug's own output does not name the keepalive-stream refusal "+
			"this test depends on — it may have failed for an unrelated reason before "+
			"reaching the gate at all:\n%s", out)
	}

	if _, err := os.Stat(marker); err == nil {
		t.Errorf("the payload ran despite the engine refusing OnEngineReady — invariant 5: a "+
			"payload must not exist behind an engine snug could not confirm\n%s", out)
	}

	// Settle: parked.kill() is a signal, not a synchronous wait — give the
	// kernel a moment to actually deliver it and reap the tree.
	time.Sleep(500 * time.Millisecond)

	if survivors := pidsWithToken(tok); len(survivors) > 0 {
		defer killAll(survivors)
		t.Errorf("%d process(es) belonging to this run are still alive after the abort: %s\n"+
			"%s", len(survivors), describePIDs(survivors), out)
	}

	// THE ASSERTION THIS TEST EXISTS FOR: the EXACT bwrap pid(s) captured
	// above, before the abort, must not still be alive as "bwrap" — checked
	// by pid, never by a host-wide comm sweep (this development host runs
	// plenty of ambient bwrap traffic of its own — other terminals, other
	// sandboxes — that a broad sweep cannot tell apart from a leak here).
	// isDescendantOf reads status fresh per pid, so a NUMBER that got
	// reused by an unrelated process in the interim is not mistaken for a
	// survivor: it is checked against comm AND against still being a
	// descendant of the stage that no longer exists.
	var stillAlive []int
	for _, pid := range bwrapPIDs {
		if commOf(pid) == "bwrap" {
			stillAlive = append(stillAlive, pid)
		}
	}
	if len(stillAlive) > 0 {
		defer killAll(stillAlive)
		t.Errorf("%d of this run's OWN bwrap pid(s), captured while parked (%v), are STILL "+
			"alive as \"bwrap\" after the abort: %s\n"+
			"The parked init has NOT yet armed --die-with-parent while parked (measured), so "+
			"an abort that killed only the outer bwrap and trusted the kernel's own cascade "+
			"would leave exactly this: an orphaned, still-releasable sandbox init.\n%s",
			len(stillAlive), bwrapPIDs, describePIDs(stillAlive), out)
	}
}

// waitForBwrapDescendants polls until at least one "bwrap"-comm descendant of
// root exists, then returns EVERY such descendant found at that moment — the
// outer bwrap and, if it has already forked by then, the parked init, which
// carries the identical comm and cmdline (a fork changes neither).
func waitForBwrapDescendants(root int, timeout time.Duration) ([]int, bool) {
	deadline := time.Now().Add(timeout)
	for {
		var found []int
		for _, pid := range allPIDs() {
			if commOf(pid) != "bwrap" {
				continue
			}
			p := pid
			for hop := 0; hop < 8; hop++ {
				parent, ok := ppidOf(p)
				if !ok {
					break
				}
				if parent == root {
					found = append(found, pid)
					break
				}
				p = parent
			}
		}
		if len(found) > 0 {
			return found, true
		}
		if time.Now().After(deadline) {
			return nil, false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readAll(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return "      (snug wrote nothing to stdout/stderr)"
	}
	return "      snug said: " + strings.ReplaceAll(strings.TrimSpace(string(b)), "\n", "\n      ")
}
