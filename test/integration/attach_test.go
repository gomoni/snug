//go:build integration

package integration

// attach_test.go is .claude/scratchpad/ATTACH-SHAPE.md §13.3-§13.6 (and the
// bwrap-argv half of §13.7): `snug attach` against a REALLY running sandbox.
// §13.1/§13.2's pure tests (the state file, the confinement plan) live in
// internal/cli and internal/attach — this file is everything that needs a
// real, live sandbox to attach to.
//
// Every negative here has the positive control the working agreement
// demands: a marker the payload emits before anything else, a process
// checked ALIVE before the kill that is supposed to end it, and — where the
// property is "X is not visible/reachable" — a companion assertion that the
// detector genuinely CAN see X when X is really there.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// attachTopologies is the two shapes `snug attach` has to work identically
// against (design §6.4: "on BOTH topologies the pid snug knows is useless",
// which is exactly why there is no per-topology branch in attach at all —
// this table is what proves that claim rather than assuming it).
var attachTopologies = []struct {
	name string
	args []string
}{
	{"offline", nil},
	{"net", []string{"-p", "@net"}},
}

// attachEnv gives one test its own isolated $XDG_RUNTIME_DIR, so `snug
// attach`'s discovery only ever sees runs THIS test started — the same
// isolation baseEnv already gives XDG_CONFIG_HOME, applied to the directory
// state.json now lives under.
func attachEnv(t *testing.T) (env []string, xdgRuntime string) {
	t.Helper()
	xdgRuntime = t.TempDir()
	return baseEnv("XDG_RUNTIME_DIR=" + xdgRuntime), xdgRuntime
}

// bgProc is a background process this test starts and must both be able to
// wait for AND kill+wait for in cleanup, without the "exec: Wait was already
// called" panic that a bare *exec.Cmd gives a caller who does both.
type bgProc struct {
	cmd  *exec.Cmd
	once sync.Once
	err  error
}

func startBgProc(t *testing.T, cmd *exec.Cmd) *bgProc {
	t.Helper()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &bgProc{cmd: cmd}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		p.wait()
	})
	return p
}

func (p *bgProc) wait() error {
	p.once.Do(func() { p.err = p.cmd.Wait() })
	return p.err
}

func (p *bgProc) pid() int { return p.cmd.Process.Pid }

// attachSandbox is a background `snug <dir> -- <payload>` this test can
// attach to. Unlike run()/cli(), it does not block: the payload is expected
// to outlive this test's own assertions.
type attachSandbox struct {
	proc    *bgProc
	logPath string
	proj    string
}

func startAttachSandbox(t *testing.T, env []string, args []string, proj, payload string) *attachSandbox {
	t.Helper()
	argv := append(append([]string{}, args...), proj, "--", "/bin/bash", "-c",
		"printf '%s\\n' "+payloadMarker+"\n"+payload)
	cmd := exec.Command(snugBin, argv...)
	cmd.Env = env

	log, err := os.CreateTemp(t.TempDir(), "snug-bg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	cmd.Stdout, cmd.Stderr = log, log

	proc := startBgProc(t, cmd)
	return &attachSandbox{proc: proc, logPath: log.Name(), proj: proj}
}

func (s *attachSandbox) log() string {
	b, _ := os.ReadFile(s.logPath)
	return string(b)
}

func (s *attachSandbox) pid() int { return s.proc.pid() }

// ready is the combined positive control every test below needs before its
// own assertions: the payload actually STARTED (payloadMarker) and the run
// PUBLISHED its state (state.json), so `snug attach` has something to find.
// Without both, every assertion downstream would be equally true of a
// sandbox that never came up.
func (s *attachSandbox) ready(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if strings.Contains(s.log(), payloadMarker) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the background sandbox's payload never started:\n%s", s.log())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// statePath is where THIS run's state.json lives, given the xdgRuntime this
// test isolated it under.
func (s *attachSandbox) statePath(xdgRuntime string) string {
	return filepath.Join(xdgRuntime, "snug", fmt.Sprintf("run-%d", s.pid()), "state.json")
}

func (s *attachSandbox) waitForState(t *testing.T, xdgRuntime string) {
	t.Helper()
	p := s.statePath(xdgRuntime)
	deadline := time.Now().Add(15 * time.Second)
	for {
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("state.json never appeared at %s:\n%s", p, s.log())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// runDir is this run's own runtime directory (the parent of state.json).
func (s *attachSandbox) runDir(xdgRuntime string) string {
	return filepath.Dir(s.statePath(xdgRuntime))
}

// attachScript runs `snug attach proj -- bash -c script` and returns it in
// the same sandboxRun shape run()/mustRun already use, so every existing
// convention (mustRun's "the payload never ran" guard) applies here too.
func attachScript(t *testing.T, env []string, proj, script string) sandboxRun {
	t.Helper()
	out, code := cli(t, env, "attach", proj, "--", "/bin/bash", "-c",
		"printf '%s\\n' "+payloadMarker+"\n"+script)
	ran := false
	var kept []string
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == payloadMarker {
			ran = true
			continue
		}
		kept = append(kept, line)
	}
	return sandboxRun{out: strings.Join(kept, "\n"), ran: ran, code: code}
}

// ── §13.3: it works ──────────────────────────────────────────────────────

// TestAttachRunsInsideTheRunningSandbox is design tests 12+13 (both
// topologies) plus 14 and 21, folded into one sandbox launch per topology —
// the same "one sandbox for all N checks, not N" economy
// TestRootSkeletonIsReadOnly already argues for in sandbox_test.go.
func TestAttachRunsInsideTheRunningSandbox(t *testing.T) {
	budget(t, 40*time.Second)
	requireSandbox(t)

	for _, topo := range attachTopologies {
		t.Run(topo.name, func(t *testing.T) {
			if topo.name == "net" {
				requirePasta(t)
			}
			env, xdg := attachEnv(t)
			proj, secret := target(t)

			bg := startAttachSandbox(t, env, topo.args, proj,
				`echo IN-SANDBOX-TMPFS-HOME > "$HOME/home-marker"; sleep 300`)
			bg.ready(t)
			bg.waitForState(t, xdg)

			// CONTROL for test 12: the marker lives ONLY in the sandbox's own
			// tmpfs $HOME, which has no host-filesystem counterpart at all —
			// finding it below is attributable to attach joining the mount
			// namespace, not to some coincidental host path.
			if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), "home-marker")); err == nil {
				t.Fatal("test setup is broken: the marker exists on the host's own $HOME")
			}

			r := attachScript(t, env, proj, fmt.Sprintf(`
cat "$HOME/home-marker" 2>&1
echo ---PID1---
cat /proc/1/comm 2>&1
echo "MY-PID=$$"
echo ---ADJACENT---
ls ~/.ssh 2>&1
cat %s 2>&1
ls %s 2>&1
ls %s 2>&1
touch ./attach-write-ok 2>&1 && echo TARGET-WRITABLE
`, secret, filepath.Dir(secret), filepath.Join(filepath.Dir(proj), "sibling"))).mustRun(t)

			// test 12/13: really inside the sandbox.
			if !strings.Contains(r.out, "IN-SANDBOX-TMPFS-HOME") {
				t.Errorf("[%s] attach did not see the sandbox's own tmpfs $HOME:\n%s", topo.name, r.out)
			}

			// test 14: A is in the sandbox's OWN pid namespace — pid 1 there
			// is bwrap's own init, and A's own pid is small (the sandbox's pid
			// namespace has had at most a handful of processes in it).
			if !strings.Contains(r.out, "bwrap") {
				t.Errorf("[%s] /proc/1/comm is not bwrap from inside the attached session:\n%s",
					topo.name, r.out)
			}
			if idx := strings.Index(r.out, "MY-PID="); idx >= 0 {
				line, _, _ := strings.Cut(r.out[idx+len("MY-PID="):], "\n")
				pid, err := strconv.Atoi(strings.TrimSpace(line))
				if err != nil {
					t.Errorf("[%s] could not parse the attached shell's own pid from %q", topo.name, line)
				} else if pid > 1000 {
					t.Errorf("[%s] the attached shell's own pid inside is %d, which is not the "+
						"small number a freshly created pid namespace should still be at:\n%s",
						topo.name, pid, r.out)
				}
			} else {
				t.Errorf("[%s] the attached shell never printed its own pid:\n%s", topo.name, r.out)
			}

			// test 21: adjacent-still-closed. ~/.ssh absent, the host's SECRET
			// (above the target's parent) unreachable, the parent's sibling
			// directory of the TARGET's parent unreachable, while the target
			// itself IS writable — the same shape as
			// TestUngrantedPathsAreAbsent/TestDotdotGrantsTheParentAndNothingAbove,
			// asked of the ATTACHED session rather than the payload's own.
			if strings.Contains(r.out, "must-not-be-readable") {
				t.Errorf("[%s] the attached session read the host secret above the target:\n%s",
					topo.name, r.out)
			}
			if !strings.Contains(r.out, "TARGET-WRITABLE") {
				t.Errorf("[%s] the target itself was not writable from the attached session:\n%s",
					topo.name, r.out)
			}
		})
	}
}

// TestAttachedProcessCarriesNoHostEnvironmentVariable is design test 15.
// REGRESSION-SHAPED: the same class of finding as
// TestNoHostEnvironmentViaPid1 in sandbox_test.go, one layer further out —
// here the leak this checks for would be from the ATTACH CLIENT's own host
// environment into the attached session, which §5.3 says must never happen
// (the recorded, snug-authored environment only).
func TestAttachedProcessCarriesNoHostEnvironmentVariable(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	env, xdg := attachEnv(t)
	proj, _ := target(t)

	bg := startAttachSandbox(t, env, nil, proj, `sleep 300`)
	bg.ready(t)
	bg.waitForState(t, xdg)

	clientEnv := append(append([]string{}, env...), "SNUG_ATTACH_HOST_CANARY=leak-canary-value")
	// PRECONDITION: the canary really is in the client's own environment,
	// or the absence check below would be trivially true.
	found := false
	for _, kv := range clientEnv {
		if kv == "SNUG_ATTACH_HOST_CANARY=leak-canary-value" {
			found = true
		}
	}
	if !found {
		t.Fatal("precondition: the canary is not in the attach client's own environment")
	}

	r := attachScript(t, clientEnv, proj, `printenv`).mustRun(t)
	if strings.Contains(r.out, "leak-canary-value") {
		t.Errorf("a host environment variable from the ATTACH CLIENT leaked into the attached "+
			"session:\n%s", r.out)
	}
}

// TestAttachedProcessHasTheRunsSeccompFilterInstalled is design test 16.
// Requested is not the same as active (TestSeccompIsActuallyInstalled's own
// reasoning, applied here): both the kernel's own status line AND a
// behavioural probe.
func TestAttachedProcessHasTheRunsSeccompFilterInstalled(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	env, xdg := attachEnv(t)
	proj, _ := target(t)

	bg := startAttachSandbox(t, env, nil, proj, `sleep 300`)
	bg.ready(t)
	bg.waitForState(t, xdg)

	r := attachScript(t, env, proj, `
grep '^Seccomp:' /proc/self/status
command -v unshare >/dev/null && (unshare -U /bin/true && echo NESTED-USERNS-CREATED || echo REFUSED) || echo NO-UNSHARE
`).mustRun(t)

	if !strings.Contains(r.out, "Seccomp:\t2") && !strings.Contains(r.out, "Seccomp: 2") {
		t.Errorf("the attached session's own Seccomp status line is not 2 (filter installed and "+
			"active):\n%s", r.out)
	}
	if strings.Contains(r.out, "NO-UNSHARE") {
		skipOrFail(t, "util-linux's unshare is not available inside the sandbox")
	}
	if strings.Contains(r.out, "NESTED-USERNS-CREATED") {
		t.Errorf("the attached session could create a nested user namespace — the filter is not "+
			"actually denying it:\n%s", r.out)
	}
}

// TestAttachedProcessHasAnEmptyCapabilityBoundingSet is design test 17. The
// CONTROL IS THE TEST, per the design's own note: without a genuinely
// unconfined comparison, "CapBnd: 0" passes just as well on a process that
// never joined anything.
func TestAttachedProcessHasAnEmptyCapabilityBoundingSet(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	env, xdg := attachEnv(t)
	proj, _ := target(t)

	bg := startAttachSandbox(t, env, nil, proj, `sleep 300`)
	bg.ready(t)
	bg.waitForState(t, xdg)

	// CONTROL: this test PROCESS's own (unconfined, host) CapBnd. An ordinary
	// process keeps a FULL bounding set even unprivileged — dropping bits
	// from it needs an explicit PR_CAPBSET_DROP loop, which nothing here has
	// done — so this must NOT read as all-zero.
	hostStatus, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	hostCapBnd := ""
	for _, line := range strings.Split(string(hostStatus), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "CapBnd:" {
			hostCapBnd = f[1]
		}
	}
	if hostCapBnd == "" || hostCapBnd == "0000000000000000" {
		t.Fatalf("control: this test process's own CapBnd is %q — that is not a usable "+
			"unconfined baseline, so the assertion below would prove nothing", hostCapBnd)
	}

	r := attachScript(t, env, proj, `grep '^CapBnd:' /proc/self/status`).mustRun(t)
	if !strings.Contains(r.out, "CapBnd:\t0000000000000000") && !strings.Contains(r.out, "0000000000000000") {
		t.Errorf("the attached session's CapBnd is not all-zero:\n%s (host control was %s)",
			r.out, hostCapBnd)
	}
}

// TestAttachedProcessCannotReachHostLoopback is design test 18 (M19). Only
// the @net topology has a real network stack to probe in the first place —
// offline's netns has nothing but lo, which would make a refusal there
// ambiguous between "isolated" and "nothing to isolate".
func TestAttachedProcessCannotReachHostLoopback(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	requirePasta(t)
	env, xdg := attachEnv(t)
	proj, _ := target(t)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveBanner(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port

	// PRECONDITION: the host can reach its own listener.
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("precondition: the host cannot reach its own listener: %v", err)
	}
	c.Close()

	bg := startAttachSandbox(t, env, []string{"-p", "@net"}, proj, `sleep 300`)
	bg.ready(t)
	bg.waitForState(t, xdg)

	r := attachScript(t, env, proj, fmt.Sprintf(
		`timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/%d' 2>&1 && echo REACHED || echo REFUSED-OR-TIMEDOUT`,
		port)).mustRun(t)

	if strings.Contains(r.out, "REACHED") {
		t.Errorf("the attached session reached the HOST's own 127.0.0.1 listener:\n%s", r.out)
	}
	if !strings.Contains(r.out, "REFUSED-OR-TIMEDOUT") {
		t.Errorf("the probe did not report a verdict at all:\n%s", r.out)
	}
}

// ── §13.4: the negatives, each with its control ─────────────────────────

// selfNamespaceInodes reads THIS process's own six namespace ids, for
// forging a state.json that legitimately points at this very process —
// duplicated locally rather than imported from internal/cli, per this
// package's own rule (package doc, sandbox_test.go): drive the built binary,
// never link against it.
func selfNamespaceInodes(t *testing.T) map[string]uint64 {
	t.Helper()
	out := map[string]uint64{}
	for _, k := range []string{"mnt", "pid", "net", "ipc", "uts", "cgroup"} {
		var st unix.Stat_t
		if err := unix.Stat("/proc/self/ns/"+k, &st); err != nil {
			t.Fatal(err)
		}
		out[k] = st.Ino
	}
	return out
}

// selfStartTime is field 22 of /proc/self/stat, the same parsing
// internal/cli/runstate.go's procStartTime does — duplicated here for the
// same reason as selfNamespaceInodes above.
func selfStartTime(t *testing.T) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	fields := strings.Fields(s[i+2:])
	const starttimeIndex = 22 - 3
	v, err := strconv.ParseUint(fields[starttimeIndex], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// plantForgedRunState hand-writes a run directory that will pass
// discoverLiveRuns' structural checks (owned, 0700, lock HELD, well-formed
// state.json) and only fail — or not — at the LIVE-process checks §4.1
// makes, which is exactly the seam tests 19 and 20 need to isolate. The lock
// is held for the life of the test via t.Cleanup.
func plantForgedRunState(t *testing.T, xdgRuntime, target string, initPID int, initStarttime uint64,
	namespaces map[string]uint64) {
	t.Helper()

	dir := filepath.Join(xdgRuntime, "snug", fmt.Sprintf("run-%d", initPID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		lock.Close()
	})

	state := map[string]any{
		"schema": 1,
		"target": target,
		"chdir":  target,
		"sandbox": map[string]any{
			"init_pid":       initPID,
			"init_starttime": initStarttime,
			"namespaces":     namespaces,
		},
		"seccomp": map[string]any{"state": "none"},
		"env":     [][2]string{{"SHELL", "/bin/sh"}, {"HOME", "/tmp"}},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAttachRefusesAPidWhoseUserNamespaceIsOurOwn is design test 19. Points
// a forged, otherwise well-formed state.json at THIS TEST PROCESS's own pid
// — same namespaces as this process by construction, so every earlier check
// (pid exists, starttime matches, all six namespace ids match) passes, and
// only the userns-is-ours refusal is left to fire. No real sandbox is
// needed: the property under test is entirely in attach's own pre-fork
// checks (§4.1 steps 2-5).
func TestAttachRefusesAPidWhoseUserNamespaceIsOurOwn(t *testing.T) {
	budget(t)
	requireSandbox(t)
	env, xdg := attachEnv(t)
	target := t.TempDir()

	plantForgedRunState(t, xdg, target, os.Getpid(), selfStartTime(t), selfNamespaceInodes(t))

	out, code := cli(t, env, "attach", target)
	if code == 0 {
		t.Fatalf("attach should have refused to join a pid in its own user namespace:\n%s", out)
	}
	if !strings.Contains(out, "your own") {
		t.Errorf("refused, but the message does not name the situation (should say the target's "+
			"user namespace IS the caller's own, not surface a bare EINVAL):\n%s", out)
	}
}

// TestAttachRefusesAfterPidReuse is design test 20: a forged state.json with
// a WRONG init_starttime (everything else — namespaces — correct and
// pointing at this test's own process) must be refused specifically as a
// pid-reuse mismatch, distinguishable by message from the userns refusal
// test 19 exercises. The control is the identical setup with the TRUE start
// time, which must NOT be refused for the "reused" reason (it still refuses
// downstream — this pid genuinely is not inside a sandbox — but that is
// message 19 covers, not this one, and the distinction is exactly the point:
// this test isolates the starttime check specifically).
func TestAttachRefusesAfterPidReuse(t *testing.T) {
	budget(t)
	requireSandbox(t)
	env, xdg := attachEnv(t)
	target := t.TempDir()

	realStart := selfStartTime(t)
	ns := selfNamespaceInodes(t)

	plantForgedRunState(t, xdg, target, os.Getpid(), realStart+123456, ns)
	out, code := cli(t, env, "attach", target)
	if code == 0 {
		t.Fatalf("attach should have refused a start-time mismatch:\n%s", out)
	}
	if !strings.Contains(out, "reused") {
		t.Errorf("refused, but not for pid reuse specifically:\n%s", out)
	}

	// CONTROL: the TRUE start time does not trip the "reused" branch — it
	// trips the (different) userns-is-ours branch instead, exactly as test 19
	// measures directly. Without this, "refused, and says reused" above could
	// be satisfied by a build that refuses EVERY attach for the same reason
	// regardless of the recorded start time.
	xdg2 := t.TempDir()
	env2 := baseEnv("XDG_RUNTIME_DIR=" + xdg2)
	plantForgedRunState(t, xdg2, target, os.Getpid(), realStart, ns)
	out2, code2 := cli(t, env2, "attach", target)
	if code2 == 0 {
		t.Fatalf("control: expected SOME refusal (this pid is not inside a real sandbox):\n%s", out2)
	}
	if strings.Contains(out2, "reused") {
		t.Errorf("control: the TRUE start time was still refused as a REUSE mismatch, so the "+
			"refusal above is not attributable to the wrong start time specifically:\n%s", out2)
	}
}

// ── §13.5: the residual, asserted rather than hoped ─────────────────────

// attachFindMarker is the in-sandbox choreography tests 22/22b share: find
// the attached process's OWN pid, as the SANDBOX'S OWN /proc names it (a
// namespaced, small number — nothing the host side can hand in, since the
// whole point of attach's pid namespace membership is that the two numbering
// spaces disagree). It is found by scanning /proc for a cmdline containing a
// marker unique to this test's own attach invocation.
//
// THE QUINE TRAP, found running this exact test: bwrap re-execs itself as
// pid 1 with the payload's own COMMAND LINE appended verbatim after `--`
// (measured: /proc/1/cmdline literally reads "bwrap --args N -- /bin/bash -c
// <the whole payload script source>"). So if the SEARCH script's own source
// contains the marker as a contiguous literal (because it greps for it),
// that source text — reflected whole into pid 1's own cmdline — matches
// ITSELF, and the scan finds pid 1 before it ever finds the real target. The
// fix is the same one every quine-avoidance trick uses: the marker is
// assembled at RUN TIME from two halves that never appear concatenated
// anywhere in this script's own source, so grepping for the whole string can
// never match the string that greps for it. Excluding pid 1 outright is a
// second, independent guard for the same hazard — bwrap's own argv
// reflection is not limited to this one shape and pid 1 is never a
// legitimate answer regardless.
func attachFindMarkerScript(marker string) string {
	half := len(marker) / 2
	return fmt.Sprintf(`
M1=%q
M2=%q
for i in $(seq 1 500); do
  for p in /proc/[0-9]*; do
    [ "$p" = /proc/1 ] && continue
    if tr '\0' '\n' < "$p/cmdline" 2>/dev/null | grep -qF "$M1$M2"; then
      APID=$(basename "$p")
      break 2
    fi
  done
  sleep 0.02
done
echo "APID=$APID"
`, marker[:half], marker[half:])
}

// TestKnownOpenResidualPayloadReachesAnAttachedProcessDescriptor is design
// test 22: the payload can list /proc/<attached>/fd, read its environ, and
// reopen a relayed pipe — all EXPECTED to succeed (M24). This is a
// known-open-residual test in the shape the existing
// TestKnownOpenResidualSiblingReadWritesProcPidMem uses: it asserts the
// finding, not a fix.
func TestKnownOpenResidualPayloadReachesAnAttachedProcessDescriptor(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	env, xdg := attachEnv(t)
	proj, _ := target(t)

	marker := "snugattachmarker" + strconv.Itoa(os.Getpid()) + strconv.FormatInt(time.Now().UnixNano(), 36)

	bg := startAttachSandbox(t, env, nil, proj, attachFindMarkerScript(marker)+`
ls /proc/$APID/fd 2>&1
echo ---ENVIRON---
tr '\0' '\n' < /proc/$APID/environ 2>&1
echo ---REOPEN---
echo REOPENED-VIA-PROC-FD1 > /proc/$APID/fd/1 2>&1 && echo REOPEN-WRITE-OK || echo REOPEN-WRITE-FAILED
sleep 60
`)
	bg.ready(t)
	bg.waitForState(t, xdg)

	// Non-terminal stdio on the attach client, deterministically, so the pipe
	// relay path is used regardless of how this test binary itself was
	// invoked (newStdioRelay decides pty-or-pipes from whether ITS OWN stdin
	// is a terminal).
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	outLog, err := os.CreateTemp(t.TempDir(), "attach-client-")
	if err != nil {
		t.Fatal(err)
	}
	defer outLog.Close()

	attachCmd := exec.Command(snugBin, "attach", proj, "--", "/bin/sh", "-c",
		fmt.Sprintf("echo %s; while :; do sleep 1; done", marker))
	attachCmd.Env = env
	attachCmd.Stdin = devNull
	attachCmd.Stdout, attachCmd.Stderr = outLog, outLog
	client := startBgProc(t, attachCmd)

	// PRECONDITION: the attach client's OWN output shows the marker — proof
	// the relay itself works and A really started — before asking the
	// payload to have found it via /proc.
	deadline := time.Now().Add(15 * time.Second)
	for {
		b, _ := os.ReadFile(outLog.Name())
		if strings.Contains(string(b), marker) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the attach client never printed its own marker:\n%s", string(b))
		}
		time.Sleep(25 * time.Millisecond)
	}

	deadline = time.Now().Add(15 * time.Second)
	for {
		if strings.Contains(bg.log(), "APID=") && strings.Contains(bg.log(), "REOPEN-WRITE") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the payload never finished its /proc probe of the attached process:\n%s", bg.log())
		}
		time.Sleep(25 * time.Millisecond)
	}

	out := bg.log()
	if strings.Contains(out, "APID=\n") || !strings.Contains(out, "APID=") {
		t.Fatalf("the payload never found the attached process's own pid via /proc:\n%s", out)
	}
	if !strings.Contains(out, "ENVIRON") || strings.Count(out, "=") < 3 {
		t.Errorf("the payload's read of /proc/<attached>/environ does not look populated:\n%s", out)
	}
	if !strings.Contains(out, "REOPEN-WRITE-OK") {
		t.Errorf("the payload could not reopen and write into the attached process's fd 1 (a "+
			"relayed pipe) — this is the KNOWN OPEN residual (M24) and this test's whole point "+
			"is that it succeeds:\n%s", out)
	}

	// And the write really reached the relay: the attach CLIENT's own
	// captured output shows what the payload wrote via /proc.
	deadline = time.Now().Add(10 * time.Second)
	for {
		b, _ := os.ReadFile(outLog.Name())
		if strings.Contains(string(b), "REOPENED-VIA-PROC-FD1") {
			break
		}
		if time.Now().After(deadline) {
			b2, _ := os.ReadFile(outLog.Name())
			t.Fatalf("the payload's write via /proc/<attached>/fd/1 never reached the attach "+
				"client's own output — the relay is not actually connected:\n%s", string(b2))
		}
		time.Sleep(25 * time.Millisecond)
	}

	_ = client
}

// TestRelayedStdioKeepsTheHostInodeOutOfTheSandbox is design test 22b: the
// narrowing the pipe relay actually buys. §5.4's own claim is precise —
// reading through the reopened descriptor must NOT reveal what was already
// in the redirected HOST FILE — and the control is a plain, unsandboxed,
// same-uid sibling read of a REAL file through /proc/<pid>/fd/1, which must
// succeed, so "did not reveal the marker" above is attributable to the
// relay and not to /proc/<pid>/fd reads being broken in general (the exact
// M24 shape: sibling-to-sibling, same uid, no sandbox).
func TestRelayedStdioKeepsTheHostInodeOutOfTheSandbox(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)

	// ── HOST CONTROL: no sandbox at all ──────────────────────────────────
	hostFile := filepath.Join(t.TempDir(), "host-marker-file")
	const hostMarker = "HOST-SIBLING-READBACK-MARKER"
	if err := os.WriteFile(hostFile, []byte(hostMarker+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hf, err := os.OpenFile(hostFile, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer hf.Close()
	sibling := exec.Command("/bin/sleep", "10")
	sibling.Stdout = hf
	siblingProc := startBgProc(t, sibling)

	readBack, err := os.ReadFile(fmt.Sprintf("/proc/%d/fd/1", siblingProc.pid()))
	if err != nil {
		t.Fatalf("precondition (control technique itself): could not reopen a plain sibling's "+
			"fd 1 via /proc at all: %v", err)
	}
	if !strings.Contains(string(readBack), hostMarker) {
		t.Fatalf("precondition: the plain host-sibling /proc/<pid>/fd/1 reopen technique did not "+
			"reveal the marker (%q) — if this fails, the assertion below proves nothing about "+
			"the SANDBOX's relay specifically, because the technique itself is not shown to work:\n"+
			"got: %q", hostMarker, string(readBack))
	}

	// ── SANDBOX CASE ──────────────────────────────────────────────────────
	env, xdg := attachEnv(t)
	proj, _ := target(t)
	marker := "snugattach22b" + strconv.Itoa(os.Getpid()) + strconv.FormatInt(time.Now().UnixNano(), 36)

	// timeout, not a bare cat: reopening a pipe's WRITE end for reading
	// SUCCEEDS (M24 — "pipe: OK, both ends"), so this does not fail with
	// EBADF. It blocks waiting for data/EOF that will never come, because
	// the pipe's write end (A's own fd 1, and the relay's copy of it) stays
	// open for the whole session. A bounded timeout is what turns "blocks
	// forever" into a verdict; a timeout with NO output is itself part of
	// the finding (there is nothing here to read AT ALL), not a test bug.
	bg := startAttachSandbox(t, env, nil, proj, attachFindMarkerScript(marker)+`
READBACK=$(timeout 2 cat /proc/$APID/fd/1 2>&1)
echo "READBACK=[$READBACK]"
sleep 60
`)
	bg.ready(t)
	bg.waitForState(t, xdg)

	attachFile := filepath.Join(t.TempDir(), "attach-marker-file")
	const attachMarker = "SANDBOX-MUST-NOT-SEE-THIS-HOST-CONTENT"
	if err := os.WriteFile(attachFile, []byte(attachMarker+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	af, err := os.OpenFile(attachFile, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer af.Close()

	attachCmd := exec.Command(snugBin, "attach", proj, "--", "/bin/sh", "-c",
		fmt.Sprintf("echo %s; while :; do sleep 1; done", marker))
	attachCmd.Env = env
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	attachCmd.Stdin = devNull
	attachCmd.Stdout = af
	attachCmd.Stderr = af
	client := startBgProc(t, attachCmd)
	_ = client

	deadline := time.Now().Add(15 * time.Second)
	for {
		if strings.Contains(bg.log(), "READBACK=") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the payload never finished its readback attempt:\n%s", bg.log())
		}
		time.Sleep(25 * time.Millisecond)
	}

	out := bg.log()
	if strings.Contains(out, attachMarker) {
		t.Errorf("the payload read the HOST FILE's pre-existing content back through the "+
			"attached process's fd 1 — the relay did not keep the host inode out of the "+
			"sandbox:\n%s", out)
	}
}

// ── §13.6: teardown, one test per row of §11 ────────────────────────────

// findAttachedByComm locates A (the attached command) as a host-visible
// descendant of the attach client's own pid, by COMM — A execs, so its comm
// is the exec'd program's own basename, unlike B, which never execs and
// keeps the client's own comm. C -> B -> A is at most two hops.
func findAttachedByComm(clientPID int, comm string, timeout time.Duration) (int, bool) {
	return findDescendant(clientPID, isComm(comm), timeout)
}

// TestAttachedProcessDiesWithASIGKILLedSnug is design test 23 / §11's second
// row (M20).
func TestAttachedProcessDiesWithASIGKILLedSnug(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	env, xdg := attachEnv(t)
	proj, _ := target(t)

	bg := startAttachSandbox(t, env, nil, proj, `sleep 300`)
	bg.ready(t)
	bg.waitForState(t, xdg)

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	attachCmd := exec.Command(snugBin, "attach", proj, "--", "/bin/sleep", "60")
	attachCmd.Env = env
	attachCmd.Stdin = devNull
	client := startBgProc(t, attachCmd)

	apid, ok := findAttachedByComm(client.pid(), "sleep", 15*time.Second)
	if !ok {
		t.Fatal("the attached process never appeared as a host-visible descendant of the attach client")
	}
	// POSITIVE CONTROL: it really is alive right now.
	if err := unix.Kill(apid, 0); err != nil {
		t.Fatalf("precondition: the attached process %d does not appear to be alive: %v", apid, err)
	}

	if err := bg.proc.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	bg.proc.wait()

	select {
	case <-waitDone(client):
	case <-time.After(15 * time.Second):
		t.Fatal("the attach client did not exit within 15s of the sandbox itself being SIGKILLed")
	}

	if err := unix.Kill(apid, 0); err == nil {
		t.Errorf("the attached process %d is still alive after the sandbox it was joined to "+
			"was SIGKILLed — this is issue #61's own teardown claim (M20), broken", apid)
	}
}

// waitDone wraps bgProc.wait in a channel so a SIGKILL test can select
// against it with a timeout rather than blocking indefinitely.
func waitDone(p *bgProc) <-chan struct{} {
	ch := make(chan struct{})
	go func() { p.wait(); close(ch) }()
	return ch
}

// TestAttachedProcessDiesWithASIGKILLedAttachClient is design test 24 / §11
// (M21): the mirror image of the test above — B dies on its PDEATHSIG, A
// dies on its own, and — the other half this test is really for — the
// SANDBOX AND ITS PAYLOAD ARE UNTOUCHED.
func TestAttachedProcessDiesWithASIGKILLedAttachClient(t *testing.T) {
	budget(t, 30*time.Second)
	requireSandbox(t)
	env, xdg := attachEnv(t)
	proj, _ := target(t)

	// A payload that keeps proving liveness AFTER the kill, the same
	// heartbeat shape orphan_test.go uses, so "the sandbox is untouched" is
	// checked by an ONGOING write rather than by the mere continued
	// existence of a pid.
	bg := startAttachSandbox(t, env, nil, proj,
		`while :; do date +%s%N > "$SNUG_TARGET/heartbeat"; sleep 0.1; done`)
	bg.ready(t)
	bg.waitForState(t, xdg)

	heartbeat := filepath.Join(proj, "heartbeat")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(heartbeat); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("precondition: the payload's heartbeat file never appeared")
		}
		time.Sleep(25 * time.Millisecond)
	}

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	attachCmd := exec.Command(snugBin, "attach", proj, "--", "/bin/sleep", "60")
	attachCmd.Env = env
	attachCmd.Stdin = devNull
	client := startBgProc(t, attachCmd)

	apid, ok := findAttachedByComm(client.pid(), "sleep", 15*time.Second)
	if !ok {
		t.Fatal("the attached process never appeared as a host-visible descendant of the attach client")
	}
	if err := unix.Kill(apid, 0); err != nil {
		t.Fatalf("precondition: the attached process %d does not appear to be alive: %v", apid, err)
	}

	if err := client.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	client.wait()

	// A must die (PDEATHSIG on B, then on A itself). Poll rather than assume
	// instant propagation.
	deadline = time.Now().Add(10 * time.Second)
	for {
		if unix.Kill(apid, 0) != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Errorf("the attached process %d is still alive %s after the ATTACH CLIENT was "+
				"SIGKILLed", apid, 10*time.Second)
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// THE POINT: the sandbox and its payload are untouched. Fresh heartbeat
	// writes, dated after the kill, prove the payload is still a LIVE
	// process rather than merely a file that happened to survive.
	since := time.Now()
	time.Sleep(500 * time.Millisecond)
	fi, err := os.Stat(heartbeat)
	if err != nil {
		t.Fatalf("the sandbox's heartbeat file disappeared after the attach client was "+
			"SIGKILLed: %v", err)
	}
	if !fi.ModTime().After(since) {
		t.Errorf("the sandbox's heartbeat stopped being written after the attach client was " +
			"SIGKILLed — the sandbox itself was affected, which §11/M21 says must not happen")
	}
}

// TestAttachLeavesNoProcessAndNoFileBehind is design test 25 / §11's last
// row: after an ORDINARY, successfully-completed attach session, nothing of
// it survives — no process (host-wide sweep, not just "not a child of
// anything this test still holds a handle to"), and no file appears in the
// run directory beyond what the RUN itself (not attach) put there.
func TestAttachLeavesNoProcessAndNoFileBehind(t *testing.T) {
	budget(t, 20*time.Second)
	requireSandbox(t)
	env, xdg := attachEnv(t)
	proj, _ := target(t)

	bg := startAttachSandbox(t, env, nil, proj, `sleep 300`)
	bg.ready(t)
	bg.waitForState(t, xdg)

	before, err := os.ReadDir(bg.runDir(xdg))
	if err != nil {
		t.Fatal(err)
	}

	tok := "snugattach25tok" + strconv.Itoa(os.Getpid()) + strconv.FormatInt(time.Now().UnixNano(), 36)
	r := attachScript(t, env, proj, `echo `+tok+`; true`).mustRun(t)
	if !strings.Contains(r.out, tok) {
		t.Fatalf("the attached command never ran, so this test proves nothing:\n%s", r.out)
	}

	survivors := pidsWithToken(tok)
	if len(survivors) != 0 {
		t.Errorf("%d process(es) matching this attach session's own token are still alive after "+
			"it completed: %s", len(survivors), describePIDs(survivors))
	}

	after, err := os.ReadDir(bg.runDir(xdg))
	if err != nil {
		t.Fatal(err)
	}
	names := func(es []os.DirEntry) []string {
		var out []string
		for _, e := range es {
			out = append(out, e.Name())
		}
		return out
	}
	if strings.Join(names(before), ",") != strings.Join(names(after), ",") {
		t.Errorf("the run directory's contents changed after an attach session: before=%v after=%v — "+
			"attach must create no files of its own (§11's last row)", names(before), names(after))
	}
}

// TestAttachSurvivesGoRuntimeThreadChurn is design test 26: the
// runtime.LockOSThread regression. Without the lock, PR_SET_PDEATHSIG fires
// on the death of the OS THREAD that created B, not merely the process —
// so an unlocked forking goroutine whose thread the Go runtime later retires
// kills the attached session for no reason. This is inherently a
// best-effort reproduction (there is no way to force the Go scheduler's hand
// from outside the attach binary's own process), so it maximises the odds by
// running MANY concurrent, longer-lived attach sessions against the same
// running sandbox with GOMAXPROCS constrained on each — concurrency and
// contention are what make thread retirement likely within a test's
// lifetime. Every one of them must survive its FULL sleep, not just start.
func TestAttachSurvivesGoRuntimeThreadChurn(t *testing.T) {
	budget(t, 60*time.Second)
	requireSandbox(t)
	env, xdg := attachEnv(t)
	proj, _ := target(t)

	bg := startAttachSandbox(t, env, nil, proj, `sleep 300`)
	bg.ready(t)
	bg.waitForState(t, xdg)

	const n = 12
	const sleepSecs = 3
	var wg sync.WaitGroup
	results := make([]string, n)
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			marker := fmt.Sprintf("churn-marker-%d", i)
			sessEnv := append(append([]string{}, env...), "GOMAXPROCS=1")
			out, code := cli(t, sessEnv, "attach", proj, "--", "/bin/sh", "-c",
				fmt.Sprintf("echo %s-start; sleep %d; echo %s-end", marker, sleepSecs, marker))
			results[i] = out
			codes[i] = code
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		start := fmt.Sprintf("churn-marker-%d-start", i)
		end := fmt.Sprintf("churn-marker-%d-end", i)
		if !strings.Contains(results[i], start) {
			t.Errorf("session %d never even started (no %q in output):\n%s", i, start, results[i])
			continue
		}
		if !strings.Contains(results[i], end) {
			t.Errorf("session %d started but did not survive its full %ds sleep (missing %q) — "+
				"this is the LockOSThread regression's signature, a session killed partway "+
				"through by its own attach client's forking thread being retired:\n%s",
				i, sleepSecs, end, results[i])
		}
		if codes[i] != 0 {
			t.Errorf("session %d exited %d, want 0:\n%s", i, codes[i], results[i])
		}
	}
}

// ── §13.7: golden / screen ───────────────────────────────────────────────

// TestBwrapFlagsCarryInfoFdBeforeTheSeparator is design test 27: the
// `--seccomp`-after-bwrap's-`--` bug (a flag PASSED but never installed,
// exit code 0) is the reason this asserts the ARGV SHAPE against the real
// bwrap invocation, not just that attach later manages to work. A PATH-shim
// standing in for bwrap logs its own exact argv (one element per line, no
// shell-quoting ambiguity) and which fds above 2 are open at the moment it
// is about to exec the real bwrap, then really execs it — so the sandbox
// this test launches actually runs.
func TestBwrapFlagsCarryInfoFdBeforeTheSeparator(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	realBwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatal(err)
	}
	shimDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "bwrap-argv.log")
	// The OUTER argv this shim receives is just "--args N --" plus the
	// payload command (internal/sandbox/exec.go's own comment: "the whole
	// flag list travels through a memfd rather than real argv"). The flags
	// this test actually cares about — --info-fd among them — are NUL-joined
	// bytes bwrap itself reads from fd N via --args, per bwrap's own
	// documented behaviour of inserting that fd's content in place of
	// "--args N". So the shim expands it: everything read from
	// /proc/self/fd/$argsfd (a FRESH, independent open of a real memfd — not
	// a dup of fd $argsfd itself, so it does not disturb the seek position
	// bwrap will read from moments later) counts as flags BEFORE the literal
	// "--" that follows "--args N" in the outer argv.
	script := "#!/bin/sh\n" +
		"argsfd=\"\"\nprev=\"\"\n" +
		"for a in \"$@\"; do\n" +
		"  if [ \"$prev\" = \"--args\" ]; then argsfd=\"$a\"; fi\n" +
		"  prev=\"$a\"\n" +
		"done\n" +
		": > " + shQuote(logPath) + ".tmp\n" +
		"if [ -n \"$argsfd\" ]; then tr '\\0' '\\n' < \"/proc/self/fd/$argsfd\" >> " + shQuote(logPath) + ".tmp; fi\n" +
		"skip=1\n" +
		"for a in \"$@\"; do\n" +
		"  if [ \"$a\" = \"--\" ]; then skip=0; fi\n" +
		"  if [ \"$skip\" = 0 ]; then printf '%s\\n' \"$a\" >> " + shQuote(logPath) + ".tmp; fi\n" +
		"done\n" +
		"printf -- '---FDS---\\n' >> " + shQuote(logPath) + ".tmp\n" +
		"for fd in /proc/self/fd/*; do\n" +
		"  n=$(basename \"$fd\")\n" +
		"  case \"$n\" in 0|1|2) ;; *) printf 'OPENFD:%s\\n' \"$n\" >> " + shQuote(logPath) + ".tmp ;; esac\n" +
		"done\n" +
		"mv " + shQuote(logPath) + ".tmp " + shQuote(logPath) + "\n" +
		"exec " + shQuote(realBwrap) + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shimDir, "bwrap"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	shimEnv := baseEnv("PATH=" + shimDir + ":" + os.Getenv("PATH"))
	out, code := cli(t, shimEnv, proj, "--", "/bin/true")
	if code != 0 {
		t.Fatalf("the shimmed run itself failed (code %d), so the log below cannot be trusted:\n%s",
			code, out)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("the bwrap shim never wrote its log — it may never have been exec'd at all: %v", err)
	}
	argvPart, fdsPart, ok := strings.Cut(string(data), "---FDS---\n")
	if !ok {
		t.Fatalf("the shim's log has no ---FDS--- marker:\n%s", string(data))
	}
	lines := strings.Split(strings.TrimRight(argvPart, "\n"), "\n")

	sepIdx, infoFdIdx := -1, -1
	for i, l := range lines {
		if l == "--" && sepIdx == -1 {
			sepIdx = i
		}
		if l == "--info-fd" && infoFdIdx == -1 {
			infoFdIdx = i
		}
	}
	if infoFdIdx == -1 {
		t.Fatalf("bwrap's argv never carries --info-fd at all:\n%s", strings.Join(lines, "\n"))
	}
	if sepIdx == -1 {
		t.Fatalf("bwrap's argv has no `--` separator at all:\n%s", strings.Join(lines, "\n"))
	}
	if infoFdIdx > sepIdx {
		t.Fatalf("--info-fd appears AFTER bwrap's `--` separator (at %d, separator at %d) — this "+
			"is exactly the --seccomp-after-`--` shape: a flag PASSED but never actually parsed "+
			"by bwrap:\n%s", infoFdIdx, sepIdx, strings.Join(lines, "\n"))
	}
	if infoFdIdx+1 >= len(lines) {
		t.Fatalf("--info-fd has no following argument:\n%s", strings.Join(lines, "\n"))
	}
	fdNum, err := strconv.Atoi(lines[infoFdIdx+1])
	if err != nil {
		t.Fatalf("the token after --info-fd (%q) is not a number", lines[infoFdIdx+1])
	}

	// THE ARGV IS NOT ENOUGH. Prove the descriptor was actually open at exec
	// time — a flag naming a number nothing backs is exactly what the
	// historical bug looked like from the argv alone.
	if !strings.Contains(fdsPart, fmt.Sprintf("OPENFD:%d\n", fdNum)) {
		t.Errorf("fd %d (named by --info-fd) was NOT among the open descriptors at the moment "+
			"bwrap was about to be exec'd:\n%s", fdNum, fdsPart)
	}
}
