//go:build integration

package integration

// stageptracegate_test.go is issue #61 part (a)'s live regression: the stage
// (P1) now drops CAP_SYS_PTRACE from its own capability BOUNDING set at the
// __stage-setup -> __stage-serve execve (internal/policy/stagecaps.go,
// internal/stage/capdrop.go). internal/stage's own tests prove the drop
// survives the re-exec and reaches every thread; this file proves it on a
// REAL `-p @net` run, sweeping every process that shares P1's own user
// namespace (U) the way an attacker would have to — from outside the
// process, by namespace identity, not by asking the stage what it believes
// about itself.
import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// readCapWords parses CapBnd/CapPrm/CapEff out of /proc/<pid>/status. Unlike
// internal/stage's own readCapField (HOSTREAD-EXEMPT: it only ever reads the
// calling process's OWN /proc/self/task/*/status), this reads an ARBITRARY
// other process's status by pid — exactly what a peer in U would have to do,
// which is the point of running this check from a separate process tree
// entirely rather than from inside the stage.
func readCapWords(pid int) (bnd, prm, eff uint64, err error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, 0, 0, err
	}
	get := func(field string) uint64 {
		for _, line := range strings.Split(string(data), "\n") {
			name, value, ok := strings.Cut(line, ":")
			if !ok || name != field {
				continue
			}
			n, _ := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
			return n
		}
		return 0
	}
	return get("CapBnd"), get("CapPrm"), get("CapEff"), nil
}

// userNSOf reads /proc/<pid>/ns/user's target ("user:[<inode>]"), the same
// shape threadNetnsIDs already uses for "net" — comparing two of these by
// plain string equality is what identifies two processes as sharing one user
// namespace.
func userNSOf(pid int) (string, error) {
	return os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/user")
}

// TestNothingSnugPutsInUHoldsCapSysPtrace sweeps every process on the host
// that shares P1's own user namespace (U) — P1 itself and the outer bwrap
// process, on this topology with no engine running — and fails if ANY of
// them still holds CAP_SYS_PTRACE in CapBnd, CapPrm or CapEff. This is the
// gate issue #61's 2026-08-17 settlement identified as case G, read the way a
// peer-in-U attacker would have to read it: by namespace membership, from a
// process outside the stage entirely.
func TestNothingSnugPutsInUHoldsCapSysPtrace(t *testing.T) {
	budget(t, 15*time.Second)
	requireSandbox(t)
	requirePasta(t)
	proj, _ := target(t)

	cmd := exec.Command(snugBin, "-p", "@net", proj, "--", "/bin/sleep", "10")
	cmd.Env = baseEnv()
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	stagePID, ok := findDescendant(cmd.Process.Pid, isStageProcess, 5*time.Second)
	if !ok {
		t.Fatal("PRECONDITION: the stage (P1) never appeared")
	}
	// Wait for the actual payload too, not just P1 — the same readiness bar
	// TestTheStageLeavesNoNamespaceObjectAfterSIGKILL uses, so the sandbox
	// this sweep looks at is fully built rather than mid-setup.
	if _, ok := findDescendant(cmd.Process.Pid, isComm("sleep"), 5*time.Second); !ok {
		t.Fatal("PRECONDITION: the payload ('sleep') never appeared")
	}

	u, err := userNSOf(stagePID)
	if err != nil {
		t.Fatalf("reading P1's own user namespace: %v", err)
	}

	type member struct {
		pid           int
		comm          string
		bnd, prm, eff uint64
		readErr       error
	}
	var members []member
	for _, pid := range allPIDs() {
		link, err := userNSOf(pid)
		if err != nil || link != u {
			continue
		}
		bnd, prm, eff, err := readCapWords(pid)
		members = append(members, member{pid: pid, comm: commOf(pid), bnd: bnd, prm: prm, eff: eff, readErr: err})
	}

	// Classified before the kill, for the same reason
	// TestOnlyBwrapAndTheSandboxAreInN reads ancestry before it kills: once
	// snug dies the tree collapses and pids can no longer be attributed.
	cmd.Process.Kill()
	cmd.Wait()
	killed = true

	// POSITIVE CONTROL 1: a run that never actually formed U (a broken stage,
	// a policy that silently fell back to the offline topology) would sweep
	// to an empty set and this test would otherwise pass having checked
	// nothing.
	if len(members) == 0 {
		t.Fatal("PRECONDITION: the sweep by user-namespace identity found NOTHING, not even " +
			"P1 itself — the sweep found no U to check, not an empty U")
	}
	sawStage := false
	ptraceBit := uint64(1) << unix.CAP_SYS_PTRACE
	adminBit := uint64(1) << unix.CAP_SYS_ADMIN
	for _, m := range members {
		if m.pid == stagePID {
			sawStage = true
		}
		if m.readErr != nil {
			// Gone between the sweep and the read (a transient helper P1 or
			// bwrap forks and reaps during setup) — not a finding, the same
			// tolerance TestOnlyBwrapAndTheSandboxAreInN gives a vanished comm.
			continue
		}
		for name, mask := range map[string]uint64{"CapBnd": m.bnd, "CapPrm": m.prm, "CapEff": m.eff} {
			if mask&ptraceBit != 0 {
				t.Errorf("pid %d (comm %q, in U) holds CAP_SYS_PTRACE: %s=%#x", m.pid, m.comm, name, mask)
			}
		}
		// POSITIVE CONTROL 2: an all-zero capability set would also read as
		// "no CAP_SYS_PTRACE" while actually meaning this member is not a
		// full-capability occupant of U at all (a bug in the sweep, or a
		// process caught mid-exit with its credentials already torn down).
		if m.bnd&adminBit == 0 {
			t.Errorf("pid %d (comm %q, in U) CapBnd=%#x holds no CAP_SYS_ADMIN — its lack of "+
				"CAP_SYS_PTRACE proves nothing unless it is otherwise a full-capability "+
				"member of U", m.pid, m.comm, m.bnd)
		}
	}
	if !sawStage {
		t.Fatal("PRECONDITION: P1 itself was not among the members found by its own user-" +
			"namespace id — the sweep methodology is broken, not U")
	}
}
