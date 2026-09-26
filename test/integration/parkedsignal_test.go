//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestASignalWhileThePayloadIsParkedNeverReleasesIt is the regression for
// red-team finding F3 on issue #605's fix.
//
// Every @net run (and every container run) parks its payload on bwrap's
// --block-fd until P0 writes one byte. The teardown guard caught TERM/INT/HUP
// in that window but only READ the signal in guard.wait, after the release
// byte — so the payload ran 120-420ms after the user's stop, 3/3 per signal.
//
// Method: SIGSTOP the STAGE the moment the first bwrap exists, wait for the
// sandbox's parked pid 1, then signal a RUNNING snug. A stopped stage cannot
// answer StartSandbox, so the only thing that can wake snug is the signal:
// the run must end on it, with the stage still stopped. Pre-fix, snug sat in
// StartSandbox with the signal caught and unread; the SIGCONT below then lets
// the stage answer and the release byte follow.
//
// The red team's method stopped SNUG instead, and that was not
// deterministic: the stage finished the build during the stop, so at SIGCONT
// its reply and the signal were ready at the same instant, and Go hands a
// caught signal to guard.sig from a separate goroutine. The reply won, the
// last guard.caught() ran before that goroutine had delivered, and the byte
// went out. That is the residual exec.go names at the release, and the stop
// put every attempt inside it: with the test pinned to one CPU
// (taskset -c 0), 5/5 runs failed, 2-3 of the 3 signals each.
func TestASignalWhileThePayloadIsParkedNeverReleasesIt(t *testing.T) {
	budget(t, 180*time.Second)
	requireSandbox(t)
	requirePasta(t)

	shapes := []struct {
		name    string
		profile []string
		env     func(t *testing.T) []string
	}{
		{"net", []string{"-p", "@net"}, func(t *testing.T) []string { return baseEnv() }},
		{"net+podman-socket", []string{"-p", "@net", "-p", "@podman-socket"}, func(t *testing.T) []string {
			env, _ := containerEngineEnv(t)
			requireRealEngine(t, env)
			return env
		}},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			env := shape.env(t)
			proj, _ := target(t)
			for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
				marker := filepath.Join(proj, "RAN-"+sig.String())
				args := append(append([]string{}, shape.profile...), proj, "--",
					"/bin/sh", "-c", fmt.Sprintf("echo ran > %q", marker))
				cmd := exec.Command(snugBin, args...)
				cmd.Env = env
				cmd.WaitDelay = waitDelay
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				p0 := cmd.Process.Pid

				// The stage is the parent of the first bwrap: it forks bwrap, and it
				// is the process that answers StartSandbox. Stopped here, before the
				// sandbox is even built, it cannot have answered yet.
				stage := 0
				deadline := time.Now().Add(30 * time.Second)
				for stage == 0 {
					for _, pid := range descendantsOf(p0) {
						if commOf(pid) == "bwrap" {
							if pp, ok := ppidOf(pid); ok && commOf(pp) != "bwrap" {
								_ = syscall.Kill(pp, syscall.SIGSTOP)
								stage = pp
								break
							}
						}
					}
					if stage == 0 && time.Now().After(deadline) {
						cmd.Process.Kill()
						cmd.Wait()
						t.Fatalf("%s: PRECONDITION: no bwrap ever appeared under snug", sig)
					}
				}
				defer syscall.Kill(stage, syscall.SIGCONT)

				var tree map[int]string
				for {
					bwraps := 0
					for _, pid := range descendantsOf(p0) {
						if commOf(pid) == "bwrap" {
							bwraps++
						}
					}
					if bwraps >= 2 {
						tree = map[int]string{}
						for _, pid := range descendantsOf(p0) {
							tree[pid] = commOf(pid)
						}
						break
					}
					if time.Now().After(deadline) {
						syscall.Kill(stage, syscall.SIGCONT)
						cmd.Process.Kill()
						cmd.Wait()
						t.Fatalf("%s: PRECONDITION: the parked sandbox pid 1 never appeared", sig)
					}
				}

				time.Sleep(500 * time.Millisecond)
				if _, err := os.Stat(marker); err == nil {
					syscall.Kill(p0, syscall.SIGKILL)
					syscall.Kill(stage, syscall.SIGCONT)
					cmd.Wait()
					t.Fatalf("%s: PRECONDITION: the payload ran before the signal was sent, so it was "+
						"never parked and this measured nothing", sig)
				}
				_ = syscall.Kill(p0, sig)
				done := make(chan struct{})
				go func() { _ = cmd.Wait(); close(done) }()
				select {
				case <-done:
				case <-time.After(15 * time.Second):
					t.Errorf("%s: snug did not end on the signal while the stage could not answer "+
						"(F3: the signal is only read after the release)", sig)
					_ = syscall.Kill(stage, syscall.SIGCONT)
					<-done
				}
				code := cmd.ProcessState.ExitCode()
				time.Sleep(700 * time.Millisecond)

				if _, err := os.Stat(marker); err == nil {
					t.Errorf("%s: the payload ran after snug caught %s while it was parked (F3)", sig, sig)
				}
				if code != 128+int(sig) {
					t.Errorf("%s: exit %d, want %d", sig, code, 128+int(sig))
				}
				for pid, comm := range tree {
					if commOf(pid) == comm && comm != "" {
						t.Errorf("%s: pid %d (%s) from the sandbox tree survived", sig, pid, comm)
					}
				}
			}
		})
	}
}
