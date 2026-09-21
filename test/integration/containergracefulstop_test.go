//go:build integration

package integration

// containergracefulstop_test.go is issue #174's own integration layer: a
// clean payload exit now stops THIS run's containers, through the engine's
// own socket, on a bounded timeout that is snug's number rather than the
// payload's (internal/dockerproxy/stoprun.go's own doc comment carries the
// full design and the measurements it rests on). That code is already
// unit-tested against a fake engine (internal/dockerproxy/stoprun_test.go);
// what only a real engine can prove is the three properties below, each
// against podman actually delivering (or not delivering) a signal to a real
// container's real pid 1.
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
// SIGKILLs the stage before StopRunContainers can ever run (that ordering is
// TestSignalledRunSendsNoGracefulStop's own subject); the pid namespace then
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
import time
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
		t.Errorf("after a SIGNALLED snug exit, the container's SIGTERM-handler flag %s WAS "+
			"written — snug's clean-path graceful stop must not run once a signal has "+
			"reached it (issue #174, TestSignalledRunSendsNoGracefulStop's own subject); "+
			"without this control the clean-exit flag above would prove only that the "+
			"container exited, not that it received snug's own stop", sigFlag)
	}
}

// TestSignalledRunSendsNoGracefulStop is issue #174's other half of the same
// claim, checked at the MECHANISM rather than at the container's own
// behaviour: a snug process that takes a signal must never even attempt
// StopRunContainers, because confirmTeardown has already SIGKILLed the stage
// the closure holding it was blocked in — the ordering
// TestContainerRunWiresStopAtCleanupNotAtPayloadExit
// (test/guard/enginereapordering_test.go) pins from the other side, inside
// the process.
//
// holder (no signal handler at all) is enough here: this test never asks
// whether the CONTAINER reacted to a stop, only whether snug's own audit
// trail — visible with -v, since containerAudit is the one sink every
// dockerproxy audit call reaches (internal/cli/container.go) — ever names a
// graceful stop on the signalled path.
//
// The positive control is a CLEAN exit of the identical setup, which must
// show the "stopped … gracefully" line: without it, an absent line on the
// signalled path would be equally explained by -v not working at all, or by
// this run's container never existing to begin with.
func TestSignalledRunSendsNoGracefulStop(t *testing.T) {
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
	if !strings.Contains(rc.out, "gracefully") {
		t.Fatalf("control: a CLEAN snug exit produced no graceful-stop audit line at all — the "+
			"absence this test measures on the signalled path below would then prove nothing, "+
			"since the line never fires on ANY path:\n%s", rc.out)
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
import time
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

	if strings.Contains(bg.log(), "gracefully") {
		t.Errorf("a SIGTERMed snug's own -v output names a graceful stop — the clean-path stop "+
			"(StopRunContainers) must never run once the teardown sweep has already SIGKILLed "+
			"the stage it would have run from (issue #174):\n%s", bg.log())
	}
	if strings.Contains(bg.log(), "graceful stop skipped") {
		t.Errorf("a SIGTERMed snug even ATTEMPTED the graceful stop and had it fail — it must "+
			"never be reached at all on the signal path:\n%s", bg.log())
	}
}

// TestContainerIgnoringUSR1StopSignalDoesNotDelaySnugsExitPastBudget is
// issue #174's DoS bound: a container that names its OWN stop signal
// (HostConfig-adjacent top-level StopSignal, a payload choice per
// containerProcessChoice in internal/dockerproxy/toplevel.go) and then
// ignores it must not be able to make snug's own exit expensive. holder
// installs no handler for anything, so as this container's pid 1 it ignores
// SIGUSR1 for the same kernel reason it ignores SIGTERM (signal(7): a pid-1
// process silently discards any signal it has not installed a handler for,
// whatever that signal's default disposition would otherwise be).
//
// What is measured is NOT snug's whole wall-clock time — this suite's engine
// cold start alone varies with host load by seconds, which would make a fixed
// cap on the total either flaky or too loose to mean anything. Instead the
// PAYLOAD prints its own exit timestamp as its last action, and the interval
// from THAT instant to this process observing `run()` return is what the cap
// bounds: exactly the interval StopRunContainers plus teardown owns. Assert
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
	// (stopBudget, internal/dockerproxy/stoprun.go) plus teardown, while
	// still failing if snug ever waited out the container's own default.
	const budgetCap = 8 * time.Second
	if took > budgetCap {
		t.Errorf("a container ignoring its own SIGUSR1 stop signal delayed snug's exit by %s "+
			"(cap %s) — a hostile payload can choose a stop signal nothing handles and must "+
			"not thereby set how long snug takes to exit (issue #174)", took, budgetCap)
	}
}
