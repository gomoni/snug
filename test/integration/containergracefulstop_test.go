//go:build integration

package integration

// containergracefulstop_test.go is issue #174's own integration layer: a
// clean payload exit now stops THIS run's containers, through the engine's
// own socket, on a bounded timeout that is snug's number rather than the
// payload's (internal/runstop's own package comment carries the full design
// and the measurements it rests on — the step itself runs in P1, not P0; see
// internal/stage/serve.go's runOneSandbox). That code is already unit-tested
// against a fake engine (internal/runstop/runstop_test.go); what only a real
// engine can prove is the properties below, each against podman actually
// delivering (or not delivering) a signal to a real container's real pid 1.
import (
	"errors"
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

// termtrapprobeBin builds testdata/termtrapprobe for the host architecture,
// the same way holderBin builds testdata/holder and for the same reasons (see
// that function's own doc comment) — built fresh per call into this test's
// OWN t.TempDir() rather than cached in a process-wide sync.Once, which is
// the shape netprobeBin/resolvprobeBin/egressprobeBin use and which broke
// under a full-suite run (a t.TempDir() from whichever test ran the build
// FIRST is gone by the time a LATER test's cached path is read). holderBin
// already sidesteps that; this does the same.
func termtrapprobeBin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "termtrapprobe")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/termtrapprobe")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("building test/integration/testdata/termtrapprobe: %v: %s", err, out.String())
	}
	return bin
}

// ignoretermBin builds testdata/ignoresterm, the same way termtrapprobeBin
// builds testdata/termtrapprobe and for the same reasons — a fresh
// t.TempDir() build rather than a process-wide cache. See that probe's own
// doc comment (red-team finding F5) for why it exists at all: holder's
// absence of a signal handler is not the same fact as "this container
// ignores its stop signal" for a Go binary, and a test whose premise is the
// second one needs a probe that actually is the second one.
func ignoretermBin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "ignoresterm")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/ignoresterm")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("building test/integration/testdata/ignoresterm: %v: %s", err, out.String())
	}
	return bin
}

// TestCleanExitStopsATermTrappingContainerGracefully is issue #174's central
// claim made concrete: a payload that exits cleanly causes THIS run's
// container to receive SIGTERM — not merely to die — before snug's own
// process ends.
//
// termtrapprobe (testdata/termtrapprobe) is the instrument that makes this
// observable at all: it installs a SIGTERM handler and drops a flag file the
// moment that handler runs, into a bind mount the host can read straight off
// disk once the container's own namespace is gone. holder, used elsewhere in
// this suite, installs no handler and so cannot tell "received SIGTERM" apart
// from "was SIGKILLed when the pid namespace collapsed" — both just make it
// stop existing.
//
// THE POSITIVE CONTROL is the second half of this test: the identical
// container, under a SIGNALLED run of snug. A signalled run's teardown sweep
// SIGKILLs the stage before runstop.Stop can ever run (that ordering is
// TestASignalledRunWhosePayloadIgnoresItSendsNoGracefulStop's own subject); the pid namespace then
// collapses and the container dies WITHOUT ever being asked to stop. If the
// flag file appeared there too, the clean-exit half above would only be
// proving the container exited, which is true of both paths — the control is
// what turns "the flag exists" into "the flag exists BECAUSE OF snug's own
// stop request".
func TestCleanExitStopsATermTrappingContainerGracefully(t *testing.T) {
	budget(t, 180*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	probeBin := termtrapprobeBin(t)

	// ── half 1: a CLEAN exit — the flag must appear ──────────────────────

	proj, _ := target(t)
	if err := os.WriteFile(filepath.Join(proj, "termtrapprobe"), mustRead(t, probeBin), 0o755); err != nil {
		t.Fatal(err)
	}
	flagDir := filepath.Join(proj, "flags")
	if err := os.Mkdir(flagDir, 0o755); err != nil {
		t.Fatal(err)
	}

	const tagClean = "snugtest-termtrap-clean:1"
	tokenClean := "snug174-clean-" + orphanToken()
	scriptClean := buildScratchProbeImageFor(tagClean, "termtrapprobe") + fmt.Sprintf(`
token = %[2]q
projdir = %[3]q
if build_scratch_probe():
    # The bind SOURCE is the target directory itself, not the "flags"
    # subdirectory under it: the anchored-source rule
    # (policy.CheckEngineBindSource, issue #284) refuses a plain name inside a
    # read-write bind as swappable, and its own remedy is exactly this — bind
    # the anchored ancestor and address the subdirectory inside the container.
    body = json.dumps({"Image": "localhost/%[1]s", "Cmd": [token, "/proj/flags"],
                        "HostConfig": {"NetworkMode": "host",
                                       "Binds": [projdir + ":/proj:rw"]}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        cid = json.loads(resp)["Id"]
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% cid)
        print("START: %%d" %% status, flush=True)
        status, j = req("GET", "/v1.41/containers/%%s/json" %% cid)
        print("RUNNING: %%s" %% json.loads(j).get("State", {}).get("Running"), flush=True)
print("PROBE-READY", flush=True)
`, tagClean, tokenClean, proj)
	if err := os.WriteFile(filepath.Join(proj, "termtrap_clean.py"), []byte(scriptClean), 0o644); err != nil {
		t.Fatal(err)
	}

	rc := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 termtrap_clean.py`).mustRun(t)
	if !strings.Contains(rc.out, fmt.Sprintf("BUILD %s: 200", tagClean)) {
		t.Fatalf("control: the clean-exit image did not even build:\n%s", rc.out)
	}
	if !strings.Contains(rc.out, "CREATE: 201") {
		t.Fatalf("control: the clean-exit container was never created:\n%s", rc.out)
	}
	if !strings.Contains(rc.out, "START: 204") && !strings.Contains(rc.out, "START: 200") {
		t.Fatalf("control: the clean-exit container never started:\n%s", rc.out)
	}
	if !strings.Contains(rc.out, "RUNNING: True") {
		t.Fatalf("control: the clean-exit container was never observed running, so there was "+
			"nothing for a graceful stop to reach:\n%s", rc.out)
	}
	if !strings.Contains(rc.out, "PROBE-READY") {
		t.Fatalf("the clean-exit payload did not run to the end:\n%s", rc.out)
	}

	cleanFlag := filepath.Join(flagDir, tokenClean+".stopped")
	data, err := os.ReadFile(cleanFlag)
	if err != nil {
		t.Fatalf("after a CLEAN snug exit, the container's own SIGTERM-handler flag %s was not "+
			"written (%v) — the graceful stop did not reach this run's container:\n%s",
			cleanFlag, err, rc.out)
	}
	if !strings.Contains(string(data), tokenClean) {
		t.Errorf("the flag file %s does not name this run's own token %q: %q",
			cleanFlag, tokenClean, data)
	}

	// ── half 2: the SAME container, under a SIGNALLED run — no flag ─────

	const tagSig = "snugtest-termtrap-sig:1"
	tokenSig := "snug174-sig-" + orphanToken()
	scriptSig := buildScratchProbeImageFor(tagSig, "termtrapprobe") + fmt.Sprintf(`
token = %[2]q
projdir = %[3]q
if build_scratch_probe():
    # Same anchored-source fix as the clean-exit half above.
    body = json.dumps({"Image": "localhost/%[1]s", "Cmd": [token, "/proj/flags"],
                        "HostConfig": {"NetworkMode": "host",
                                       "Binds": [projdir + ":/proj:rw"]}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        cid = json.loads(resp)["Id"]
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% cid)
        print("START: %%d" %% status, flush=True)
        status, j = req("GET", "/v1.41/containers/%%s/json" %% cid)
        print("RUNNING: %%s" %% json.loads(j).get("State", {}).get("Running"), flush=True)
print("CONTAINER-RUNNING", flush=True)
# IGNORES SIGTERM ON PURPOSE, and that is what makes the assertion below a
# control rather than a coincidence. Since issue #595 the payload gets a
# bounded grace on a catchable signal, and a payload that EXITS inside it
# exits NORMALLY — which reaches the stage's clean-path graceful stop and
# writes the flag. This half's subject is the other case: a payload that does
# not take the offer, so the budget expires, confirmTeardown SIGKILLs the
# stage, and no stop is ever asked for.
import signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
print("IGNORING-SIGTERM", flush=True)
time.sleep(300)
`, tagSig, tokenSig, proj)
	if err := os.WriteFile(filepath.Join(proj, "termtrap_sig.py"), []byte(scriptSig), 0o644); err != nil {
		t.Fatal(err)
	}

	bg := startBgSandbox(t, env, []string{"-p", "@podman-build"}, proj, `python3 termtrap_sig.py`)
	bg.ready(t)
	bg.waitForState(t)

	deadline := time.Now().Add(60 * time.Second)
	for !strings.Contains(bg.log(), "CONTAINER-RUNNING") {
		if time.Now().After(deadline) {
			t.Fatalf("the signalled run's container never reached CONTAINER-RUNNING:\n%s", bg.log())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(bg.log(), fmt.Sprintf("BUILD %s: 200", tagSig)) {
		t.Fatalf("control: the signalled run's own image did not build:\n%s", bg.log())
	}
	if !strings.Contains(bg.log(), "CREATE: 201") {
		t.Fatalf("control: the signalled run's own container was never created:\n%s", bg.log())
	}
	if !strings.Contains(bg.log(), "RUNNING: True") {
		t.Fatalf("control: the signalled run's own container was never observed running:\n%s", bg.log())
	}

	if err := syscall.Kill(bg.pid(), syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM snug (pid %d): %v", bg.pid(), err)
	}
	waitErr := bg.proc.wait()
	code := 0
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		code = ee.ExitCode()
	} else if waitErr != nil {
		t.Fatalf("waiting for the signalled snug: %v\n%s", waitErr, bg.log())
	}
	if code != 128+int(syscall.SIGTERM) {
		t.Fatalf("a SIGTERMed snug exited %d, not %d (128+SIGTERM); this test's own precondition "+
			"— that it really took the signal-teardown path — does not hold:\n%s",
			code, 128+int(syscall.SIGTERM), bg.log())
	}

	sigFlag := filepath.Join(flagDir, tokenSig+".stopped")
	// A short grace window, not a race with teardown: the pid namespace
	// collapse behind a SIGKILL is on the order of milliseconds (issue #113's
	// own measurement, "container token pids gone at 50.19 ms"), so polling
	// briefly is only insurance against a slow filesystem, never against a
	// stop that fires late.
	deadline = time.Now().Add(3 * time.Second)
	var sigFlagExists bool
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sigFlag); err == nil {
			sigFlagExists = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if sigFlagExists {
		t.Errorf("after a SIGNALLED snug exit whose payload IGNORED the signal, the "+
			"container's SIGTERM-handler flag %s WAS written — once the payload has "+
			"declined its grace (issue #595) the budget expires and confirmTeardown "+
			"SIGKILLs the stage, so the clean-path graceful stop must never be reached "+
			"(issue #174, TestASignalledRunWhosePayloadIgnoresItSendsNoGracefulStop's own "+
			"subject); without this control the clean-exit flag above would prove only "+
			"that the container exited, not that it received snug's own stop", sigFlag)
	}
}

// TestASignalledRunWhosePayloadIgnoresItSendsNoGracefulStop is issue #174's
// other half of the same claim, checked at the MECHANISM rather than at the
// container's own behaviour.
//
// THE NAME CARRIES A CONDITION THAT USED TO BE UNNECESSARY. It read
// "TestSignalledRunSendsNoGracefulStop", and that was the whole truth while a
// signalled snug SIGKILLed the sandbox instantly. Since issue #595 a catchable
// signal gives the payload a bounded grace, and a payload that EXITS inside it
// exits NORMALLY — so st.Wait returns an ordinary status, the stage reaches
// its clean-path graceful stop, and this run's containers ARE stopped
// gracefully. That is a capability, not a leak, and it is the composition
// stated at payloadGraceBudget: an operator holding Ctrl-C on a container run
// pays both budgets, up to ~2s.
//
// So the payload here IGNORES the signal, which is what leaves the mechanism
// below as the one that runs: a snug process whose payload declined the grace
// must never even attempt the graceful stop, because the graceful stop runs
// in P1 (internal/stage's own
// runOneSandbox, refs the ordering
// TestGracefulStopRunsAfterTheReapAndBeforeTheExitedEventLeaves in
// test/guard/enginereapordering_test.go pins from inside the process), and
// confirmTeardown pidfd-SIGKILLs P1 before P1 ever reaches that step — not
// because a P0-side closure was blocked and skipped, which was true of an
// earlier shape of this code and is no longer where the stop lives at all.
//
// holder (no signal handler at all) is enough here: this test never asks
// whether the CONTAINER reacted to a stop, only whether snug's own audit
// trail — visible with -v, since containerAudit is the one sink every
// dockerproxy audit call reaches (internal/cli/container.go) — ever names a
// graceful stop on the signalled path.
//
// The positive control is a CLEAN exit of the identical setup, which must
// show a "graceful stop: " line: without it, an absent line on the signalled
// path would be equally explained by -v not working at all, or by this run's
// container never existing to begin with. It asserts the EXACT wording the
// clean path produces ("graceful stop: 1 of 1 container(s) stopped", red-team
// finding F3) rather than the bare "graceful stop: " prefix — the earlier
// shape of this control checked for the substring "gracefully", which no
// audit line this package emits has ever contained, so it was failing on its
// own precondition rather than measuring the signalled path at all.
//
// This test is ALSO red-team finding F2's regression, on the same run: F2
// was internal/sandbox/exec.go calling OnGracefulStop with a ZERO StopReport
// whenever st.Wait itself returned an error — which a signalled run's
// pidfd-SIGKILLed stage does, every time, since it dies before ever sending
// "exited" — rendering "graceful stop: none ran before this run reported its
// exit" on a run that never reported anything at all. OnGracefulStop is now
// called only `if err == nil`, and the negative assertion below (no
// "graceful stop: " substring on the signalled path, matching ALL FOUR
// shapes the audit switch can produce, "none ran" included) is what would
// catch that line reappearing.
func TestASignalledRunWhosePayloadIgnoresItSendsNoGracefulStop(t *testing.T) {
	budget(t, 180*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	if err := os.WriteFile(filepath.Join(proj, "holder"), mustRead(t, holderBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}

	// ── control: a CLEAN exit DOES audit a graceful stop ─────────────────

	const tagClean = "snugtest-nostop-clean:1"
	tokenClean := "snug174-nostop-clean-" + orphanToken()
	scriptClean := buildScratchProbeImageFor(tagClean, "holder") + fmt.Sprintf(`
token = %[2]q
if build_scratch_probe():
    body = json.dumps({"Image": "localhost/%[1]s", "Cmd": [token],
                        "HostConfig": {"NetworkMode": "host"}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        cid = json.loads(resp)["Id"]
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% cid)
        print("START: %%d" %% status, flush=True)
print("PROBE-READY", flush=True)
`, tagClean, tokenClean)
	if err := os.WriteFile(filepath.Join(proj, "nostop_clean.py"), []byte(scriptClean), 0o644); err != nil {
		t.Fatal(err)
	}

	rc := runEnv(t, env, []string{"-p", "@podman-build", "-v"}, proj, `python3 nostop_clean.py`).mustRun(t)
	if !strings.Contains(rc.out, fmt.Sprintf("BUILD %s: 200", tagClean)) {
		t.Fatalf("control: the clean-exit image did not even build:\n%s", rc.out)
	}
	if !strings.Contains(rc.out, "CREATE: 201") {
		t.Fatalf("control: the clean-exit container was never created:\n%s", rc.out)
	}
	if !strings.Contains(rc.out, "START: 204") && !strings.Contains(rc.out, "START: 200") {
		t.Fatalf("control: the clean-exit container never started:\n%s", rc.out)
	}
	if !strings.Contains(rc.out, "PROBE-READY") {
		t.Fatalf("the clean-exit payload did not run to the end:\n%s", rc.out)
	}
	// The exact clean-path wording, not merely the shared "graceful stop: "
	// prefix (red-team finding F3): holder installs no signal handling of
	// its own, so the Go runtime's default table terminates it on SIGTERM,
	// and the one container this run created IS stopped — the default case
	// in onGracefulStop's switch (internal/cli/container.go), "%d of %d
	// container(s) stopped". A control that accepted any "graceful stop: "
	// line at all would still pass if that switch's OTHER cases (a Note, or
	// "none ran") were what actually fired here, which would say nothing
	// true about the wording the test BELOW forbids on the signalled path.
	if !strings.Contains(rc.out, "graceful stop: 1 of 1 container(s) stopped") {
		t.Fatalf("control: a CLEAN snug exit did not audit \"graceful stop: 1 of 1 container(s) "+
			"stopped\" — the absence this test measures on the signalled path below would then "+
			"prove nothing, since the exact wording it forbids there never fires on ANY path:\n%s",
			rc.out)
	}

	// ── the signalled run: no graceful stop may be audited at all ────────

	const tagSig = "snugtest-nostop-sig:1"
	tokenSig := "snug174-nostop-sig-" + orphanToken()
	scriptSig := buildScratchProbeImageFor(tagSig, "holder") + fmt.Sprintf(`
token = %[2]q
if build_scratch_probe():
    body = json.dumps({"Image": "localhost/%[1]s", "Cmd": [token],
                        "HostConfig": {"NetworkMode": "host"}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        cid = json.loads(resp)["Id"]
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% cid)
        print("START: %%d" %% status, flush=True)
print("CONTAINER-RUNNING", flush=True)
# Declines the grace issue #595 gives it, for the reason the other signalled
# half states: a payload that EXITS inside the window exits normally, which
# reaches the stage's clean-path graceful stop. The mechanism this test is
# about — confirmTeardown SIGKILLing P1 before P1 reaches the stop — is what
# happens once the budget expires instead.
import signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
print("IGNORING-SIGTERM", flush=True)
time.sleep(300)
`, tagSig, tokenSig)
	if err := os.WriteFile(filepath.Join(proj, "nostop_sig.py"), []byte(scriptSig), 0o644); err != nil {
		t.Fatal(err)
	}

	bg := startBgSandbox(t, env, []string{"-p", "@podman-build", "-v"}, proj, `python3 nostop_sig.py`)
	bg.ready(t)
	bg.waitForState(t)

	deadline := time.Now().Add(60 * time.Second)
	for !strings.Contains(bg.log(), "CONTAINER-RUNNING") {
		if time.Now().After(deadline) {
			t.Fatalf("the signalled run's container never reached CONTAINER-RUNNING:\n%s", bg.log())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(bg.log(), fmt.Sprintf("BUILD %s: 200", tagSig)) {
		t.Fatalf("control: the signalled run's own image did not build:\n%s", bg.log())
	}
	if !strings.Contains(bg.log(), "CREATE: 201") {
		t.Fatalf("control: the signalled run's own container was never created:\n%s", bg.log())
	}

	if err := syscall.Kill(bg.pid(), syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM snug (pid %d): %v", bg.pid(), err)
	}
	waitErr := bg.proc.wait()
	code := 0
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		code = ee.ExitCode()
	} else if waitErr != nil {
		t.Fatalf("waiting for the signalled snug: %v\n%s", waitErr, bg.log())
	}
	if code != 128+int(syscall.SIGTERM) {
		t.Fatalf("a SIGTERMed snug exited %d, not %d (128+SIGTERM); this test's own precondition "+
			"— that it really took the signal-teardown path — does not hold:\n%s",
			code, 128+int(syscall.SIGTERM), bg.log())
	}

	if strings.Contains(bg.log(), "graceful stop: ") {
		t.Errorf("a SIGTERMed snug's own -v output names a graceful stop — every shape "+
			"containerAudit's onGracefulStop closure can print starts \"graceful stop: \", so "+
			"this one substring catches all of them: the step (runstop.Stop, called from "+
			"internal/stage/serve.go's runOneSandbox) must never even be REACHED once "+
			"confirmTeardown has pidfd-SIGKILLed the stage before it gets there (issue #174):\n%s",
			bg.log())
	}
}

// TestContainerIgnoringUSR1StopSignalDoesNotDelaySnugsExitPastBudget is
// issue #174's DoS bound: a container that names its OWN stop signal
// (HostConfig-adjacent top-level StopSignal, a payload choice per
// containerProcessChoice in internal/dockerproxy/toplevel.go) and then
// ignores it must not be able to make snug's own exit expensive.
//
// holder is what this test uses, and SIGUSR1 is the reason that is not the
// F5 mistake it looks like (red-team finding against this file's own earlier
// claim, which cited signal(7)'s pid-1 rule — "a process running as pid 1
// silently discards any signal it has not installed a handler for" — as
// though it applied to a Go binary; it does not, because the Go runtime
// installs its OWN handler for every signal at process start, and that
// table's entry for SIGTERM terminates the process). SIGUSR1 is different:
// it is one of the few signals the Go runtime's default table does NOT act
// on, so holder — with no signal.Notify of its own — genuinely ignores it.
// TestContainerIgnoringItsDefaultStopSignalDoesNotDelaySnugsExitPastBudget,
// below, is the same bound against the REALISTIC default (an unspecified
// StopSignal, which defaults to SIGTERM) using ignoresterm, a probe built to
// ignore it on purpose rather than by accident of which signal was picked.
//
// What is measured is NOT snug's whole wall-clock time — this suite's engine
// cold start alone varies with host load by seconds, which would make a fixed
// cap on the total either flaky or too loose to mean anything. Instead the
// PAYLOAD prints its own exit timestamp as its last action, and the interval
// from THAT instant to this process observing `run()` return is what the cap
// bounds: exactly the interval runstop.Stop plus teardown owns. Assert
// snug's exit is inside that cap — never that the container died, which the
// namespace collapse guarantees regardless of whether this bound holds at all.
func TestContainerIgnoringUSR1StopSignalDoesNotDelaySnugsExitPastBudget(t *testing.T) {
	budget(t, 180*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	if err := os.WriteFile(filepath.Join(proj, "holder"), mustRead(t, holderBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}

	const tag = "snugtest-usr1-budget:1"
	token := "snug174-usr1-" + orphanToken()
	script := buildScratchProbeImageFor(tag, "holder") + fmt.Sprintf(`
token = %[2]q
if build_scratch_probe():
    body = json.dumps({"Image": "localhost/%[1]s", "Cmd": [token], "StopSignal": "SIGUSR1",
                        "HostConfig": {"NetworkMode": "host"}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        cid = json.loads(resp)["Id"]
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% cid)
        print("START: %%d" %% status, flush=True)
        status, j = req("GET", "/v1.41/containers/%%s/json" %% cid)
        info = json.loads(j)
        print("RUNNING: %%s" %% info.get("State", {}).get("Running"), flush=True)
        print("STOPSIGNAL: %%s" %% info.get("Config", {}).get("StopSignal"), flush=True)
import time
print("EXIT-EPOCH-NS:%%d" %% int(time.time() * 1e9), flush=True)
`, tag, token)
	if err := os.WriteFile(filepath.Join(proj, "usr1_budget.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 usr1_budget.py`)
	hostAfter := time.Now()
	r = r.mustRun(t)

	if !strings.Contains(r.out, fmt.Sprintf("BUILD %s: 200", tag)) {
		t.Fatalf("control: the image did not even build:\n%s", r.out)
	}
	if !strings.Contains(r.out, "CREATE: 201") {
		t.Fatalf("control: the container was never created:\n%s", r.out)
	}
	if !strings.Contains(r.out, "START: 204") && !strings.Contains(r.out, "START: 200") {
		t.Fatalf("control: the container never started:\n%s", r.out)
	}
	if !strings.Contains(r.out, "RUNNING: True") {
		t.Fatalf("control: the container was never observed running — there was nothing here "+
			"for an ignored stop signal to delay:\n%s", r.out)
	}

	epochLine, ok := lineAfterPrefix(r.out, "EXIT-EPOCH-NS:")
	if !ok {
		t.Fatalf("the payload never printed its own exit timestamp, so the interval this test "+
			"bounds cannot be measured:\n%s", r.out)
	}
	epochNs, err := strconv.ParseInt(epochLine, 10, 64)
	if err != nil {
		t.Fatalf("the payload's exit timestamp %q did not parse: %v\n%s", epochLine, err, r.out)
	}
	payloadExit := time.Unix(0, epochNs)

	took := hostAfter.Sub(payloadExit)
	// A small negative reading is possible clock-skew noise between the
	// sandboxed payload's clock read and this process's own — both are the
	// same host's CLOCK_REALTIME, so a large negative would mean the
	// timestamps were not measuring what this test thinks they measure.
	if took < -500*time.Millisecond {
		t.Fatalf("control: the measured interval is %s, which is negative by more than clock "+
			"skew can explain — this test's own timestamps are not trustworthy", took)
	}
	// The cap: well under podman's own measured 10.059s default wait for a
	// container that never answers a stop signal at all (#174's own
	// measurement), which is what an UNBOUNDED wait would cost here. It
	// leaves slack for a loaded host over the ~1s this step's own budget
	// (runstop.Budget, internal/runstop/runstop.go) plus teardown, while
	// still failing if snug ever waited out the container's own default.
	const budgetCap = 8 * time.Second
	if took > budgetCap {
		t.Errorf("a container ignoring its own SIGUSR1 stop signal delayed snug's exit by %s "+
			"(cap %s) — a hostile payload can choose a stop signal nothing handles and must "+
			"not thereby set how long snug takes to exit (issue #174)", took, budgetCap)
	}
}

// TestContainerIgnoringItsDefaultStopSignalDoesNotDelaySnugsExitPastBudget is
// TestContainerIgnoringUSR1StopSignalDoesNotDelaySnugsExitPastBudget's own
// positive control and red-team finding F5's regression test: the SAME DoS
// bound, but against the REALISTIC pathological case runstop.go's own package
// comment describes — "the case that consumes the budget is one that
// explicitly ignores its stop signal" — with no StopSignal override at all
// (the OCI default is SIGTERM) and ignoresterm, a probe built to
// signal.Ignore its stop signal on purpose rather than one that merely
// happens not to install a handler for it.
//
// Without this test, the USR1 test above is the only evidence this bound
// holds at all, and it holds there for a reason (SIGUSR1 being one of the
// few signals the Go runtime's own default table leaves unhandled) that does
// NOT generalise to SIGTERM — the signal an OCI container actually gets by
// default, and the one runstop.go's own budget reasoning is written about.
func TestContainerIgnoringItsDefaultStopSignalDoesNotDelaySnugsExitPastBudget(t *testing.T) {
	budget(t, 180*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	if err := os.WriteFile(filepath.Join(proj, "ignoresterm"), mustRead(t, ignoretermBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}

	const tag = "snugtest-defaultsig-budget:1"
	token := "snug174-defaultsig-" + orphanToken()
	script := buildScratchProbeImageFor(tag, "ignoresterm") + fmt.Sprintf(`
token = %[2]q
if build_scratch_probe():
    body = json.dumps({"Image": "localhost/%[1]s", "Cmd": [token],
                        "HostConfig": {"NetworkMode": "host"}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        cid = json.loads(resp)["Id"]
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% cid)
        print("START: %%d" %% status, flush=True)
        status, j = req("GET", "/v1.41/containers/%%s/json" %% cid)
        info = json.loads(j)
        print("RUNNING: %%s" %% info.get("State", {}).get("Running"), flush=True)
        print("STOPSIGNAL: %%s" %% info.get("Config", {}).get("StopSignal"), flush=True)
import time
print("EXIT-EPOCH-NS:%%d" %% int(time.time() * 1e9), flush=True)
`, tag, token)
	if err := os.WriteFile(filepath.Join(proj, "defaultsig_budget.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 defaultsig_budget.py`)
	hostAfter := time.Now()
	r = r.mustRun(t)

	if !strings.Contains(r.out, fmt.Sprintf("BUILD %s: 200", tag)) {
		t.Fatalf("control: the image did not even build:\n%s", r.out)
	}
	if !strings.Contains(r.out, "CREATE: 201") {
		t.Fatalf("control: the container was never created:\n%s", r.out)
	}
	if !strings.Contains(r.out, "START: 204") && !strings.Contains(r.out, "START: 200") {
		t.Fatalf("control: the container never started:\n%s", r.out)
	}
	if !strings.Contains(r.out, "RUNNING: True") {
		t.Fatalf("control: the container was never observed running — there was nothing here "+
			"for an ignored stop signal to delay:\n%s", r.out)
	}

	epochLine, ok := lineAfterPrefix(r.out, "EXIT-EPOCH-NS:")
	if !ok {
		t.Fatalf("the payload never printed its own exit timestamp, so the interval this test "+
			"bounds cannot be measured:\n%s", r.out)
	}
	epochNs, err := strconv.ParseInt(epochLine, 10, 64)
	if err != nil {
		t.Fatalf("the payload's exit timestamp %q did not parse: %v\n%s", epochLine, err, r.out)
	}
	payloadExit := time.Unix(0, epochNs)

	took := hostAfter.Sub(payloadExit)
	if took < -500*time.Millisecond {
		t.Fatalf("control: the measured interval is %s, which is negative by more than clock "+
			"skew can explain — this test's own timestamps are not trustworthy", took)
	}
	const budgetCap = 8 * time.Second
	if took > budgetCap {
		t.Errorf("a container ignoring its own (default, SIGTERM) stop signal delayed snug's "+
			"exit by %s (cap %s) — a hostile payload does not even need to NAME a stop signal "+
			"to make snug wait out the engine's own default before teardown fells it "+
			"(issue #174)", took, budgetCap)
	}
}

// TestPaddedContainersDoNotSuppressTheGracefulStopOfAVictim is red-team
// finding F1's integration-level regression: two throwaway containers,
// created and started SOLELY to carry a large label each, must not be able
// to make runstop's own /v1.41/containers/json read cut BEFORE it reaches a
// genuine victim container's id — silently suppressing this run's ENTIRE
// graceful stop, victim included, for the price of two containers the
// payload does not otherwise use.
//
// A SINGLE oversized container does not reach this attack at all:
// dockerproxy's ownership gate reads a container's OWN inspect body through
// the SAME 1 MiB limit (internal/dockerproxy/ownership.go) to confirm a
// create body's declared image matches what the engine actually ran, and a
// container whose inspect it cannot decode is refused with 403 before its
// create ever completes. The attack needs at least two containers, each
// individually UNDER that per-container limit, whose COMBINED entries in one
// LIST answer exceed runstop's SEPARATE 1 MiB list-read limit — which is
// exactly what padValue's size below is chosen for: 600 KiB is comfortably
// under 1 MiB alone, and two of them together in one JSON array are not.
func TestPaddedContainersDoNotSuppressTheGracefulStopOfAVictim(t *testing.T) {
	budget(t, 180*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	probeBin := termtrapprobeBin(t)

	proj, _ := target(t)
	if err := os.WriteFile(filepath.Join(proj, "termtrapprobe"), mustRead(t, probeBin), 0o755); err != nil {
		t.Fatal(err)
	}
	flagDir := filepath.Join(proj, "flags")
	if err := os.Mkdir(flagDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "holder"), mustRead(t, holderBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}

	const tagVictim = "snugtest-f1-victim:1"
	const tagPad = "snugtest-f1-pad:1"
	tokenVictim := "snug174-f1-victim-" + orphanToken()
	padValue := strings.Repeat("A", 600*1024)

	script := buildScratchProbeImageFor(tagVictim, "termtrapprobe") +
		buildScratchProbeImageForNamed("build_pad_probe", tagPad, "holder") + fmt.Sprintf(`
token = %[2]q
projdir = %[3]q
pad = %[4]q
if build_scratch_probe() and build_pad_probe():
    # The victim is created FIRST and the padding AFTER — podman's own
    # /v1.41/containers/json answers oldest-created-first (MEASURED: with
    # the padding created first instead, the victim's own flag never
    # appeared at all, because it sat past the 1 MiB cut in every run),
    # so this is what makes the padding the thing that gets cut rather than
    # the victim this attack is aimed at.
    # The anchored-source rule (policy.CheckEngineBindSource, issue #284)
    # again: bind the target directory itself, address the subdirectory
    # inside the container, exactly as TestCleanExitStopsATermTrappingContainerGracefully does.
    body = json.dumps({"Image": "localhost/%[1]s", "Cmd": [token, "/proj/flags"],
                        "HostConfig": {"NetworkMode": "host",
                                       "Binds": [projdir + ":/proj:rw"]}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("VICTIM-CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        cid = json.loads(resp)["Id"]
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% cid)
        print("VICTIM-START: %%d" %% status, flush=True)
        status, j = req("GET", "/v1.41/containers/%%s/json" %% cid)
        print("VICTIM-RUNNING: %%s" %% json.loads(j).get("State", {}).get("Running"), flush=True)
    for i in range(2):
        body = json.dumps({"Image": "localhost/%[5]s", "Cmd": ["pad-%%d" %% i],
                            "Labels": {"pad": pad},
                            "HostConfig": {"NetworkMode": "host"}}).encode()
        status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
        print("PAD-CREATE %%d: %%d %%s" %% (i, status, resp.decode(errors="replace")[:200]), flush=True)
        if status == 201:
            cid = json.loads(resp)["Id"]
            status, _ = req("POST", "/v1.41/containers/%%s/start" %% cid)
            print("PAD-START %%d: %%d" %% (i, status), flush=True)
print("PROBE-READY", flush=True)
`, tagVictim, tokenVictim, proj, padValue, tagPad)
	if err := os.WriteFile(filepath.Join(proj, "f1_padded.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	rc := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 f1_padded.py`).mustRun(t)
	if !strings.Contains(rc.out, fmt.Sprintf("BUILD %s: 200", tagVictim)) ||
		!strings.Contains(rc.out, fmt.Sprintf("BUILD %s: 200", tagPad)) {
		t.Fatalf("control: one of the two images did not even build:\n%s", rc.out)
	}
	for i := 0; i < 2; i++ {
		if !strings.Contains(rc.out, fmt.Sprintf("PAD-CREATE %d: 201", i)) {
			t.Fatalf("control: pad container %d was never created:\n%s", i, rc.out)
		}
		if !strings.Contains(rc.out, fmt.Sprintf("PAD-START %d: 204", i)) &&
			!strings.Contains(rc.out, fmt.Sprintf("PAD-START %d: 200", i)) {
			t.Fatalf("control: pad container %d never started:\n%s", i, rc.out)
		}
	}
	if !strings.Contains(rc.out, "VICTIM-CREATE: 201") {
		t.Fatalf("control: the victim container was never created:\n%s", rc.out)
	}
	if !strings.Contains(rc.out, "VICTIM-START: 204") && !strings.Contains(rc.out, "VICTIM-START: 200") {
		t.Fatalf("control: the victim container never started:\n%s", rc.out)
	}
	if !strings.Contains(rc.out, "VICTIM-RUNNING: True") {
		t.Fatalf("control: the victim was never observed running — there was nothing here for "+
			"a graceful stop to reach:\n%s", rc.out)
	}
	if !strings.Contains(rc.out, "PROBE-READY") {
		t.Fatalf("the payload did not run to the end:\n%s", rc.out)
	}

	flag := filepath.Join(flagDir, tokenVictim+".stopped")
	data, err := os.ReadFile(flag)
	if err != nil {
		t.Fatalf("after a clean snug exit with two padding containers present, the victim's own "+
			"SIGTERM-handler flag %s was not written (%v) — the padding suppressed the graceful "+
			"stop for this run's genuine container, which is red-team finding F1 reopened:\n%s",
			flag, err, rc.out)
	}
	if !strings.Contains(string(data), tokenVictim) {
		t.Errorf("the flag file %s does not name the victim's own token %q: %q",
			flag, tokenVictim, data)
	}
}
