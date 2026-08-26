//go:build integration

package integration

// containerownership_test.go is issue #386's own integration layer: the
// container ownership gate (internal/dockerproxy/ownership.go) is now
// universal — it runs on every request addressed to a specific container or
// exec instance, not merely on DELETE — and it is placed BEFORE isHijack, so
// that the exact route measured in #386 (`POST .../start` carrying
// `Upgrade:`) is covered too. That code is already unit-tested against
// recorded podman bodies (internal/dockerproxy/ownership_test.go); this file
// is the end-to-end proof against a REAL, shared engine store, because the
// property under test — "a container an EARLIER run created is not this
// run's to act on" — only exists once two real runs have shared one store.
//
// # Why two real runs on one target, sequentially
//
// The engine's store is keyed on the target directory and persists across
// runs (ownership.go's own package comment; VERIFY.md §9's "warm start"
// language). Two runs on the SAME target directory therefore share one
// store, which is the only way to produce "another run's container" at all.
// snug refuses a second LIVE run on one target
// (internal/cli/targetlock.go, .claude/design/ONE-SANDBOX-PER-DIR.md), so the
// two runs here are sequential: run() blocks until the first snug process has
// fully exited (and released its flock) before the second is even started.
// That sequencing is also the real threat shape #386 is about — the store
// outlives any one run, and whatever an earlier run left in it is still
// there the next time this target is opened.
//
// # The row-3 trap this test exists to avoid
//
// A container created WITHOUT `NetworkMode: host` fails `start` in run B with
// a 500 at networking — the engine holds no CAP_NET_ADMIN — which reads
// identically to an ownership refusal on every assertion that checks only
// "not 2xx". Measured against podman 5.8.4 during the redteam round that
// filed #386: WITH `NetworkMode: host`, the pre-fix `start` answered **204**.
// So run A's leftover container is created with `HostConfig.NetworkMode:
// "host"` baked in, and every attack assertion below checks the exact 403 and
// the exact "not created by this sandbox run" substring — never merely "not
// 2xx" — so a 500 from a different cause cannot read as a pass.
//
// # The positive control
//
// In the SAME run B, after the six attack routes: B creates, starts, execs
// into and removes its OWN container, and every step must answer 2xx.
// Without this, the whole test passes on a proxy that refuses the entire
// container API — CLAUDE.md's "a test that cannot fail is worse than no
// test", applied to a security gate rather than to a sandbox boundary.
import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestContainerOwnershipGateRefusesAnotherRunsContainer is issue #386's
// permanent regression test: a container run A created, started and let
// exit is untouchable by run B — a separate `snug` invocation against the
// SAME target directory, carrying its own `snug.run` label — on every route
// that addresses that one container by id, while run B's own container is
// fully usable end to end.
func TestContainerOwnershipGateRefusesAnotherRunsContainer(t *testing.T) {
	budget(t, 240*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)

	// ONE target for both runs — see the package doc above for why that is
	// what makes this property observable at all.
	proj, _ := target(t)

	// ── run A: create, start, let exit; the record OUTLIVES this process ──

	const tagA = "snugtest-ownership-a:1"
	if err := os.WriteFile(filepath.Join(proj, "buildmarker"), mustRead(t, buildMarkerBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}
	scriptA := buildScratchProbeImageFor(tagA, "buildmarker") + fmt.Sprintf(`
if build_scratch_probe():
    # NetworkMode "host" baked in on purpose: without it, run B's own attempt
    # to /start this container fails at networking (the engine holds no
    # CAP_NET_ADMIN) with a 500 that reads identically to an ownership
    # refusal on any assertion weaker than the exact 403 + message this test
    # checks (issue #386's own measurement, podman 5.8.4).
    body = json.dumps({"Image": "localhost/%[1]s",
                        "HostConfig": {"NetworkMode": "host"}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("A-CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        cid = json.loads(resp)["Id"]
        print("A-CONTAINER-ID:" + cid, flush=True)
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% cid)
        print("A-START: %%d" %% status, flush=True)
        status, w = req("POST", "/v1.41/containers/%%s/wait" %% cid)
        print("A-WAIT: %%d %%s" %% (status, w.decode(errors="replace")), flush=True)
        # The marker inside the container: it printed BUILT-INSIDE-SNUG to its
        # own stdout and exited, which /logs recovers.
        status, logs = req("GET", "/v1.41/containers/%%s/logs?stdout=1&stderr=1" %% cid)
        print("A-LOGS-BEGIN", flush=True)
        print(logs.decode(errors="replace"), flush=True)
        print("A-LOGS-END", flush=True)
print("A-SCRIPT-COMPLETE", flush=True)
`, tagA)
	if err := os.WriteFile(filepath.Join(proj, "ownership_a.py"), []byte(scriptA), 0o644); err != nil {
		t.Fatal(err)
	}

	runA := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 ownership_a.py`).mustRun(t)

	if !strings.Contains(runA.out, "A-SCRIPT-COMPLETE") {
		t.Fatalf("run A's payload did not run to the end:\n%s", runA.out)
	}
	if !strings.Contains(runA.out, fmt.Sprintf("BUILD %s: 200", tagA)) {
		t.Fatalf("control: run A's scratch image did not even build, so no container ever "+
			"existed for run B to find:\n%s", runA.out)
	}
	if !strings.Contains(runA.out, "A-CREATE: 201") {
		t.Fatalf("control: run A could not create its own leftover container:\n%s", runA.out)
	}
	if !strings.Contains(runA.out, "BUILT-INSIDE-SNUG") {
		t.Fatalf("control: run A's container never printed its own marker in its logs, so it "+
			"did not really run — there is nothing here for run B to attack:\n%s", runA.out)
	}
	cid, ok := lineAfterPrefix(runA.out, "A-CONTAINER-ID:")
	if !ok || len(cid) != 64 {
		t.Fatalf("could not recover run A's container id (a 64-hex string) from its output:\n%s", runA.out)
	}

	// ── run A has fully exited (runEnv/cli block on it); run B starts next ──

	const tagB = "snugtest-ownership-b:1"
	if err := os.WriteFile(filepath.Join(proj, "holder"), mustRead(t, holderBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}
	scriptB := buildScratchProbeImageForNamed("build_scratch_holder", tagB, "holder") + fmt.Sprintf(`
attack_cid = %[1]q

# ── THE ATTACK: six routes against run A's leftover container ──
routes = [
    ("start",  "POST",   "/v1.41/containers/%%s/start" %% attack_cid, None),
    ("exec",   "POST",   "/v1.41/containers/%%s/exec" %% attack_cid,
     json.dumps({"Cmd": ["/holder", "should-never-run"]}).encode()),
    ("rename", "POST",   "/v1.41/containers/%%s/rename?name=stolen" %% attack_cid, None),
    ("logs",   "GET",    "/v1.41/containers/%%s/logs?stdout=1&stderr=1" %% attack_cid, None),
    ("json",   "GET",    "/v1.41/containers/%%s/json" %% attack_cid, None),
    ("rm",     "DELETE", "/v1.41/containers/%%s" %% attack_cid, None),
]
for label, method, path, rbody in routes:
    headers = {"Content-Type": "application/json"} if rbody else {}
    status, resp = req(method, path, rbody, headers)
    print("ATTACK-%%s: %%d %%s" %% (label, status, resp.decode(errors="replace")[:400]), flush=True)

# ── POSITIVE CONTROL: run B's OWN create -> start -> exec -> rm round trip ──
if build_scratch_holder():
    body = json.dumps({"Image": "localhost/%[2]s", "Cmd": ["own-token"],
                        "HostConfig": {"NetworkMode": "host"}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("B-CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        bcid = json.loads(resp)["Id"]
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% bcid)
        print("B-START: %%d" %% status, flush=True)
        ebody = json.dumps({"Cmd": ["/holder", "exec-token"], "Detach": True}).encode()
        status, eresp = req("POST", "/v1.41/containers/%%s/exec" %% bcid, ebody, {"Content-Type": "application/json"})
        print("B-EXEC-CREATE: %%d %%s" %% (status, eresp.decode(errors="replace")[:300]), flush=True)
        if status == 201:
            eid = json.loads(eresp)["Id"]
            sbody = json.dumps({"Detach": True}).encode()
            status, sresp = req("POST", "/exec/%%s/start" %% eid, sbody, {"Content-Type": "application/json"})
            print("B-EXEC-START: %%d" %% status, flush=True)
        status, _ = req("DELETE", "/v1.41/containers/%%s?force=1" %% bcid)
        print("B-RM: %%d" %% status, flush=True)
print("B-SCRIPT-COMPLETE", flush=True)
`, cid, tagB)
	if err := os.WriteFile(filepath.Join(proj, "ownership_b.py"), []byte(scriptB), 0o644); err != nil {
		t.Fatal(err)
	}

	runB := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 ownership_b.py`).mustRun(t)

	if !strings.Contains(runB.out, "B-SCRIPT-COMPLETE") {
		t.Fatalf("run B's payload did not run to the end:\n%s", runB.out)
	}

	// ── the six negatives, each against the EXACT status and message ──
	const wantSubstring = "not created by this sandbox run"
	for _, tc := range []struct{ label, why string }{
		{"start", "starting another run's container"},
		{"exec", "creating an exec instance inside another run's container"},
		{"rename", "renaming another run's container"},
		{"logs", "reading another run's container logs"},
		{"json", "inspecting another run's container"},
		{"rm", "removing another run's container"},
	} {
		got, ok := lineAfterPrefix(runB.out, "ATTACK-"+tc.label+": ")
		if !ok {
			t.Fatalf("no ATTACK-%s line in run B's output — %s was never even attempted:\n%s",
				tc.label, tc.why, runB.out)
		}
		if !strings.HasPrefix(got, "403 ") {
			t.Errorf("%s (route %q) should be refused with 403, got %q:\n%s",
				tc.why, tc.label, got, runB.out)
			continue
		}
		if !strings.Contains(got, wantSubstring) {
			t.Errorf("%s (route %q) was refused, but its body does not carry %q:\n%s",
				tc.why, tc.label, wantSubstring, got)
		}
	}

	// ── the positive control: without this, a proxy refusing EVERYTHING passes too ──
	if !strings.Contains(runB.out, fmt.Sprintf("BUILD %s: 200", tagB)) {
		t.Fatalf("control: run B's OWN scratch image did not even build, so the round trip "+
			"below proves nothing about ownership specifically:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-CREATE: 201") {
		t.Errorf("control: run B could not create its OWN container — the six refusals above "+
			"would pass identically on a proxy that refuses the entire container API:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-START: 204") && !strings.Contains(runB.out, "B-START: 200") {
		t.Errorf("control: run B could not start its OWN container:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-EXEC-CREATE: 201") {
		t.Errorf("control: run B could not create an exec instance in its OWN container:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-EXEC-START: 200") {
		t.Errorf("control: run B could not start its OWN exec instance:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-RM: 204") && !strings.Contains(runB.out, "B-RM: 200") {
		t.Errorf("control: run B could not remove its OWN container:\n%s", runB.out)
	}
}

// lineAfterPrefix returns the text of the first line in out that starts with
// prefix, with the prefix stripped, or ("", false) if no such line exists.
func lineAfterPrefix(out, prefix string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix), true
		}
	}
	return "", false
}

// buildScratchProbeImageForNamed is buildScratchProbeImageFor with the
// python function it defines given a caller-chosen name, so a script that
// needs TWO different `FROM scratch` images (run B here: one to attack, one
// of its own) does not define `build_scratch_probe` twice under one name.
func buildScratchProbeImageForNamed(fn, tag, bin string) string {
	return strings.Replace(buildScratchProbeImageFor(tag, bin), "def build_scratch_probe():", "def "+fn+"():", 1)
}
