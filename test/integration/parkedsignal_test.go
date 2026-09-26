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
// Method (the red team's): SIGSTOP snug the moment a second bwrap (the
// sandbox's own pid 1, parked) exists, confirm the payload has not run, send
// the signal, SIGCONT. Stopping snug is what makes this deterministic: the
// signal is pending before snug can take another step.
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

				deadline := time.Now().Add(30 * time.Second)
				var tree map[int]string
				for {
					bwraps := 0
					for _, pid := range descendantsOf(p0) {
						if commOf(pid) == "bwrap" {
							bwraps++
						}
					}
					if bwraps >= 2 {
						_ = syscall.Kill(p0, syscall.SIGSTOP)
						tree = map[int]string{}
						for _, pid := range descendantsOf(p0) {
							tree[pid] = commOf(pid)
						}
						break
					}
					if time.Now().After(deadline) {
						cmd.Process.Kill()
						cmd.Wait()
						t.Fatalf("%s: PRECONDITION: the parked sandbox pid 1 never appeared", sig)
					}
				}

				time.Sleep(500 * time.Millisecond)
				if _, err := os.Stat(marker); err == nil {
					syscall.Kill(p0, syscall.SIGKILL)
					syscall.Kill(p0, syscall.SIGCONT)
					cmd.Wait()
					t.Fatalf("%s: PRECONDITION: the payload ran while snug was stopped, so it was "+
						"never parked and this measured nothing", sig)
				}
				_ = syscall.Kill(p0, sig)
				_ = syscall.Kill(p0, syscall.SIGCONT)
				_ = cmd.Wait()
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
