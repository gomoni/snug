//go:build integration

package integration

// enginec3_test.go holds issue #125's C3 assertions about the DERIVED VIEW
// itself — the ones C2-view's own test does not make, each with the positive
// control the issue's "what C3 owes" list names.
//
// C2-view asserted the set relation: every mount in the engine's namespace is
// either the sandbox's or one snug added. That leaves three questions it does
// not answer, and all three are about DIRECTION rather than about membership:
//
//  1. the grafts go one way. The engine sees them; the PAYLOAD must not, and
//     the mechanism is a propagation flag (MS_REC|MS_PRIVATE on /) rather than
//     anything the mount set records — so the set relation cannot see it.
//  2. AccessRO in the model is read-only in the KERNEL. Tier C attaches the
//     config graft with mount_setattr(MOUNT_ATTR_RDONLY); a graft recorded
//     read-only and attached writable would pass every unit test in the repo.
//  3. `snug attach` joins the payload's namespaces, and the engine's pid
//     namespace is not among them (issue #145). #125's design pass calls this
//     criterion 2's residual: the window is smaller, not closed.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
)

// engineGraftGuests is the set of destinations Tier C attaches into the
// engine's view. Read from the policy package rather than spelled here, so a
// destination that moves moves in one place.
func engineGraftGuests() []string {
	return []string{
		policy.EngineStoreGuest, policy.EngineRunrootGuest,
		policy.EngineSockGuest, policy.EngineConfGuest,
	}
}

// startEngineRun starts a background @podman-socket run whose payload parks,
// and returns the payload's own pid and the engine's, both host-side. Both are
// found by matching a real process rather than by arithmetic on snug's pid:
// the payload is bwrap's child through a pid namespace, and the engine is the
// stage's, so neither is a fixed hop from anything.
func startEngineRun(t *testing.T, marker string) (proj string, payloadPID, enginePID int) {
	t.Helper()
	env, _ := containerEngineEnv(t)
	requireSandbox(t)
	proj, _ = target(t)

	cmd := exec.Command(snugBin, "-p", "@podman-socket", proj, "--",
		// The trailing `true` is load-bearing: a shell EXECS the last command
		// of a -c script in place, so `echo M; sleep 60` leaves a process whose
		// argv is `sleep 60` and carries no marker at all — the payload then
		// looks absent (measured, 15s of timeout).
		"/bin/sh", "-c", "echo "+marker+"; sleep 60; true")
	cmd.Env = env
	log, err := os.CreateTemp(t.TempDir(), "snug-c3-")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = log, log
	proc := startBgProc(t, cmd)

	enginePID, ok := findDescendant(proc.pid(), isEngineProcess, 30*time.Second)
	if !ok {
		b, _ := os.ReadFile(log.Name())
		t.Fatalf("PRECONDITION: no engine process appeared under a @podman-socket run, so there "+
			"is no derived view to make any assertion about:\n%s", b)
	}
	// COMMIT POINT for the run-count floor (issue #393 §4): the fatal check
	// above already proved a real engine process exists, for every caller of
	// this shared helper.
	markEngineRan(t, enginePathFromEnv(env))
	payloadPID, ok = findDescendant(proc.pid(), func(pid int) bool {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return false
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		// argv[0] must be the SHELL, not snug. snug's own command line ends
		// with the payload it was asked to run, so a match on the marker
		// alone finds the outer process — whose mount table is the HOST's,
		// and every "the payload cannot see X" assertion against it is then
		// being made about the wrong namespace (measured: 794 mounts).
		return len(args) > 2 && args[0] == "/bin/sh" &&
			strings.Contains(args[len(args)-1], marker)
	}, 15*time.Second)
	if !ok {
		b, _ := os.ReadFile(log.Name())
		t.Fatalf("PRECONDITION: the payload never appeared under this run:\n%s", b)
	}
	return proj, payloadPID, enginePID
}

// mountLinesOf returns mountinfo's mount-point -> options field for one pid.
// Field 5 is the mount point and field 6 the per-mount options, which is where
// mount_setattr(MOUNT_ATTR_RDONLY) shows up — and it is the per-MOUNT field,
// not the per-superblock one, which matters here: two mounts of one superblock
// can differ, and it is the mount Tier C sets.
func mountLinesOf(t *testing.T, pid int) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		t.Fatalf("reading the mount table of pid %d: %v", pid, err)
	}
	out := map[string]string{}
	for _, ln := range strings.Split(string(raw), "\n") {
		f := strings.Fields(ln)
		if len(f) > 5 && strings.HasPrefix(f[4], "/") {
			out[f[4]] = f[5]
		}
	}
	return out
}

// TestThePayloadCannotSeeAnyGraft is C3's first assertion. The engine's mount
// namespace is created from the SANDBOX's by setns, so without
// `mount(MS_REC|MS_PRIVATE)` on / first, every graft __inengine attaches
// propagates straight back into the namespace the payload is sitting in — and
// the payload would hold the container store, the runroot and the engine's
// socket directory, none of which any profile grants.
//
// THE POSITIVE CONTROL IS THAT THE GRAFT EXISTS. Issue #125's design pass says
// so in terms: a test that the payload cannot see a graft "passes on an engine
// that never grafted anything". So each destination is required in the ENGINE's
// table before it is forbidden in the payload's, and the two tables are read
// within milliseconds of each other from the same running run.
//
// MUTATION-CHECKED, and the mutation that works is not the one that looks
// likely. Removing __inengine's `unshare(CLONE_NEWNS)` — step 5, the engine's
// own copy of the sandbox's view — makes this fail with the payload's mount
// table holding all 53 of the engine's, grafts included. Changing the
// propagation flag on / does NOT: neither MS_SLAVE nor MS_SHARED in place of
// MS_PRIVATE propagates anything back, because the engine's namespace is fresh
// and marking / shared there starts a new peer group rather than joining the
// sandbox's. Worth knowing which line is load-bearing for THIS property: the
// MS_PRIVATE call is load-bearing for two others (overlay, and podman's
// per-container nsfs binds) and its own comment says so.
func TestThePayloadCannotSeeAnyGraft(t *testing.T) {
	budget(t, 90*time.Second)
	_, payloadPID, enginePID := startEngineRun(t, payloadMarker)

	engine := mountLinesOf(t, enginePID)
	payload := mountLinesOf(t, payloadPID)
	if len(payload) < 5 {
		t.Fatalf("PRECONDITION: the payload's mount table has %d entries; a comparison against "+
			"it would be vacuous", len(payload))
	}

	for _, guest := range engineGraftGuests() {
		if _, ok := engine[guest]; !ok {
			t.Fatalf("CONTROL: the engine's own view has no mount at %s, so the assertion that "+
				"the payload cannot see one would be true of a run that grafted nothing", guest)
		}
		if _, ok := payload[guest]; ok {
			t.Errorf("the PAYLOAD has a mount at %s. That is a graft snug attached in the "+
				"engine's namespace, propagating back into the sandbox's — the payload then "+
				"holds a host directory no profile granted it, and neither Validate nor "+
				"--dry-run knows about it (issue #125, C3).", guest)
		}
	}
}

// TestAReadOnlyGraftIsReadOnlyInTheKernel is C3's second assertion, and it is
// about the gap between the model and the mount: policy.AccessRO is a field,
// mount_setattr(MOUNT_ATTR_RDONLY) is what makes it true, and every unit test
// in this repo would pass if the second were never called.
//
// It matters for exactly one destination and that is the point of the control:
// the config graft holds the containers.conf, storage.conf, registries.conf and
// signature policy snug generated and started the engine under. Writable, the
// engine could rewrite what it was started under — and it is root-in-U with the
// full delegated subuid range.
//
// THE POSITIVE CONTROL IS AN RW GRAFT: the store, the runroot and the socket
// directory must read `rw` in the same table, from the same parse. A test that
// only looked for `ro` would pass just as well against a table where every
// mount was read-only, which is a different broken engine.
func TestAReadOnlyGraftIsReadOnlyInTheKernel(t *testing.T) {
	budget(t, 90*time.Second)
	_, _, enginePID := startEngineRun(t, payloadMarker)
	engine := mountLinesOf(t, enginePID)

	opts, ok := engine[policy.EngineConfGuest]
	if !ok {
		t.Fatalf("the engine's view has no mount at %s at all", policy.EngineConfGuest)
	}
	if !hasOpt(opts, "ro") {
		t.Errorf("the config graft at %s is mounted %q — snug records it AccessRO and Tier C "+
			"attaches it with mount_setattr(MOUNT_ATTR_RDONLY). Writable, the engine can rewrite "+
			"the containers.conf, storage.conf and signature policy it was started under.",
			policy.EngineConfGuest, opts)
	}

	// CONTROL: the writable grafts really are writable in the same table.
	for _, guest := range []string{policy.EngineStoreGuest, policy.EngineRunrootGuest,
		policy.EngineSockGuest} {
		opts, ok := engine[guest]
		if !ok {
			t.Errorf("CONTROL: no mount at %s", guest)
			continue
		}
		if !hasOpt(opts, "rw") {
			t.Errorf("CONTROL: the graft at %s is mounted %q, not rw — the engine cannot write "+
				"its own store, and the `ro` assertion above then proves nothing about "+
				"mount_setattr because everything here is read-only", guest, opts)
		}
	}
}

// hasOpt reads one flag out of mountinfo's comma-separated options field.
// Substring matching would be wrong in both directions here: "ro" occurs inside
// "relatime", and "rw" inside no current option but nothing guarantees that.
func hasOpt(opts, want string) bool {
	for _, o := range strings.Split(opts, ",") {
		if o == want {
			return true
		}
	}
	return false
}

// TestAttachCannotReachTheEngineChildsProcFD is C3's last assertion, and it is
// the residual the design pass names rather than a boundary it closes: `snug
// attach` joins the payload's namespaces, and CLAUDE.md's own list records that
// /proc/<pid>/fd reaches a sibling's files and /proc/<pid>/mem its memory,
// neither of them syscall-shaped, so no seccomp filter can name them. What
// stops attach reaching the engine is that the engine is in a PID NAMESPACE the
// payload's /proc does not enumerate (issue #145).
//
// TWO CONTROLS, because there are two ways this could pass for the wrong
// reason. The engine must be reachable from the HOST at the same instant (so
// the process really exists and really has an fd table), and attach's own
// /proc must be readable (so a refusal is not simply attach failing to start).
//
// The assertion is by IDENTITY, not by absence of a number: the engine's HOST
// pid can legitimately name a different process inside the sandbox's own pid
// namespace, and asserting "/proc/<hostpid> does not exist" would then be
// asserting a coincidence. What must be true is that no process attach can see
// is the engine.
func TestAttachCannotReachTheEngineChildsProcFD(t *testing.T) {
	budget(t, 120*time.Second)
	marker := "snugc3attach"
	proj, _, enginePID := startEngineRun(t, marker)

	// CONTROL A: from the host, this pid has a readable fd table. Without it,
	// "attach cannot read it" is a statement about a dead process.
	if _, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", enginePID)); err != nil {
		t.Fatalf("CONTROL: the engine's own /proc/%d/fd is not readable from the HOST either "+
			"(%v), so the assertion below is about a process that is not there", enginePID, err)
	}

	// CONTROL B: the needle the probe greps for really does match the engine.
	// Asserted against the engine's OWN cmdline, host-side, so a probe that
	// finds nothing is finding nothing because it cannot SEE the engine — not
	// because it is looking for the wrong string.
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", enginePID))
	if err != nil {
		t.Fatalf("CONTROL: reading the engine's cmdline: %v", err)
	}
	joined := strings.Join(strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00"), " ")
	if !strings.Contains(joined, "system service") {
		t.Fatalf("CONTROL: the engine's own cmdline (%q) does not contain the string the probe "+
			"below greps for, so the probe would report nothing whatever it could see", joined)
	}

	env, _ := containerEngineEnv(t)
	// The needle is assembled from two variables rather than written out, and
	// that is not style: this script is the probe's own argv, so a literal
	// `system service` in it makes the probe match ITSELF. Measured — the
	// first version of this test reported the attach shell as the engine.
	script := fmt.Sprintf(`
a=sys; b=tem; c=ser; d=vice
echo "SELFFD=$(ls /proc/self/fd 2>&1 | wc -l)"
echo "NPROC=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)"
echo "ENGINEFD=$(ls /proc/%d/fd 2>&1 | head -1)"
for p in /proc/[0-9]*; do
  [ "$p" = "/proc/$$" ] && continue
  tr '\0' ' ' < $p/cmdline 2>/dev/null | grep -q "$a$b $c$d" && echo "SAWENGINE=$p"
done
echo DONE
`, enginePID)
	out, code := cli(t, env, "attach", proj, "--", "/bin/sh", "-c", script)
	if !strings.Contains(out, "DONE") {
		t.Fatalf("PRECONDITION: `snug attach` did not run the probe (exit %d):\n%s", code, out)
	}

	// CONTROL C: attach's own procfs works, so a negative below is a boundary
	// rather than an unreadable /proc.
	// CONTROL D: the sweep had processes to walk. `for p in /proc/[0-9]*`
	// finding nothing would make the negative below trivially true.
	if strings.Contains(out, "NPROC=0") {
		t.Fatalf("CONTROL: the probe enumerated no processes at all in the sandbox's /proc, so "+
			"its identity sweep never ran:\n%s", out)
	}
	if strings.Contains(out, "SELFFD=0") {
		t.Fatalf("CONTROL: attach cannot read its OWN /proc/self/fd, so it could not read the "+
			"engine's for reasons that have nothing to do with the engine:\n%s", out)
	}

	if strings.Contains(out, "SAWENGINE=") {
		t.Errorf("`snug attach` can see the container engine's own process. The engine holds "+
			"CAP_SYS_ADMIN in U and the full delegated subuid range, and /proc/<pid>/fd and "+
			"/proc/<pid>/mem are not syscall-shaped, so a process that can see it can read its "+
			"files and its memory (issue #125's criterion 2, issue #145):\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "ENGINEFD=")
		if !ok {
			continue
		}
		// A readable fd table at that number is only a finding if the process
		// AT that number is the engine, which SAWENGINE above already covers.
		// What must never appear is a successful listing plus the engine being
		// visible; a bare ENOENT here is the ordinary case.
		if rest != "" && !strings.Contains(rest, "No such file") &&
			!strings.Contains(rest, "cannot access") {
			t.Logf("note: /proc/%d/fd inside the sandbox listed %q — a different process holds "+
				"that number in the sandbox's own pid namespace; the identity sweep above is "+
				"what decides", enginePID, rest)
		}
	}
}
