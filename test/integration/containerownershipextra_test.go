//go:build integration

package integration

// containerownershipextra_test.go is issue #386's own gate
// (internal/dockerproxy/ownership.go), attacked on four routes a `redteam`
// round against 902cf53 fixed at 49ab112 confirmed LIVE but that
// containerownership_test.go's own six-route sweep does not reach:
//
//  1. the hijacked routes with the exact header spellings a real client sends
//     (attach in four shapes, plus `start` carrying `Upgrade:`, which the
//     committed unit test only exercises against a fake engine);
//  2. the libpod-native spelling of a read (`/v5.0.0/libpod/containers/{id}
//     /json|logs`), which has no live coverage at all — the committed
//     integration test uses only the docker-compat spelling;
//  3. a 12-hex PREFIX of a foreign container's id, which must resolve through
//     the engine and refuse on the RESOLVED 64-hex id — proving
//     canonicalisation rather than a lucky refusal on the client's own
//     string;
//  4. the odd-shape spellings (doubled slashes, a trailing slash, a
//     percent-encoded verb segment, a missing version prefix) that only a
//     hand-written request LINE can produce — `http.Client` (and Python's
//     `http.client`, used everywhere else in this package) normalises every
//     one of them away before the bytes leave the process.
//
// Every one of the four tests below reuses the shared two-sequential-run,
// one-target-directory, shared-store shape containerownership_test.go
// establishes (see its own package doc for why the runs must be sequential
// and why NetworkMode:"host" is baked into every container that starts), and
// every foreign refusal is paired with the SAME run's own container
// succeeding on a related route — the standing rule that a refusal proves
// nothing next to a proxy that simply refuses the whole API.
import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// spawnForeignLeftoverContainer is run A of the two-run ownership shape,
// shared by all four tests below: build a `FROM scratch` image around
// testdata/buildmarker, create a container from it with
// HostConfig.NetworkMode:"host" baked in (the row-3 trap
// containerownership_test.go's own doc comment names — without it a later
// `start` attempt fails at networking with a 500 that reads identically to an
// ownership refusal), start it, wait for it to exit, and return the target
// directory (for run B to reuse) and the container's full 64-hex id.
//
// The container is left to exit rather than kept running — every attack this
// file makes is refused by the ownership gate before the engine is ever
// asked to act on the id, so nothing here depends on the leftover container
// still being alive.
func spawnForeignLeftoverContainer(t *testing.T, env []string, tag string) (proj, cid string) {
	t.Helper()
	proj, _ = target(t)
	if err := os.WriteFile(filepath.Join(proj, "buildmarker"), mustRead(t, buildMarkerBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}
	script := buildScratchProbeImageFor(tag, "buildmarker") + fmt.Sprintf(`
if build_scratch_probe():
    body = json.dumps({"Image": "localhost/%[1]s",
                        "HostConfig": {"NetworkMode": "host"}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("A-CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        cid = json.loads(resp)["Id"]
        print("A-CONTAINER-ID:" + cid, flush=True)
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% cid)
        print("A-START: %%d" %% status, flush=True)
        status, _ = req("POST", "/v1.41/containers/%%s/wait" %% cid)
        print("A-WAIT: %%d" %% status, flush=True)
print("A-SCRIPT-COMPLETE", flush=True)
`, tag)
	if err := os.WriteFile(filepath.Join(proj, "spawn_a.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	runA := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 spawn_a.py`).mustRun(t)
	if !strings.Contains(runA.out, "A-SCRIPT-COMPLETE") {
		t.Fatalf("run A's payload did not run to the end:\n%s", runA.out)
	}
	if !strings.Contains(runA.out, fmt.Sprintf("BUILD %s: 200", tag)) {
		t.Fatalf("control: run A's scratch image did not even build, so there is nothing here "+
			"for run B to attack:\n%s", runA.out)
	}
	if !strings.Contains(runA.out, "A-CREATE: 201") {
		t.Fatalf("control: run A could not create its own leftover container:\n%s", runA.out)
	}
	id, ok := lineAfterPrefix(runA.out, "A-CONTAINER-ID:")
	if !ok || len(id) != 64 {
		t.Fatalf("could not recover run A's container id (a 64-hex string) from its output:\n%s", runA.out)
	}
	return proj, id
}

// ── 1. hijacked routes, real headers, against a real engine ────────────────

// TestForeignHijackedRoutesAreRefusedWithA403NotAStream is issue #386's own
// measurement, beyond the one route (`start` + `Upgrade:`) the committed unit
// test exercises against a fake engine: every hijack-shaped route the round
// tried against run A's leftover container answered 403 with the ownership
// message and NEVER reached isHijack's raw byte-copy — measured live against
// podman, not asserted from a mock.
//
// Why the exact status matters more here than anywhere else in this package:
// `hijack()` (internal/dockerproxy/proxy.go) takes over the TCP connection
// and copies raw bytes both ways with no framing. A refusal that arrived as a
// hang, or as an upgraded connection carrying no data, would be
// indistinguishable from a stream nobody is writing to yet — this test reads
// the response the way an ordinary HTTP client does (via Python's
// `http.client`, which cannot complete a read on a genuinely hijacked
// connection) and asserts a normal, prompt, parseable 403 JSON body. If the
// gate ever stopped running before isHijack, this test would not fail
// cleanly with a wrong status — it would hang, which `req`'s own per-call
// timeout converts into a labelled EXC line rather than a silent budget
// expiry.
func TestForeignHijackedRoutesAreRefusedWithA403NotAStream(t *testing.T) {
	budget(t, 240*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)

	const tagA = "snugtest-ownership-hijack-a:1"
	proj, attackCid := spawnForeignLeftoverContainer(t, env, tagA)

	const tagB = "snugtest-ownership-hijack-b:1"
	if err := os.WriteFile(filepath.Join(proj, "holder"), mustRead(t, holderBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}
	script := buildScratchProbeImageForNamed("build_scratch_holder", tagB, "holder") + fmt.Sprintf(`
attack_cid = %[1]q

def attack(label, method, path, headers):
    try:
        status, body = req(method, path, headers=headers, timeout=10)
        print("ATTACK-" + label + ": " + str(status) + " " +
              body.decode(errors="replace")[:400], flush=True)
    except Exception as e:
        # A hang, a refused upgrade half-way through, or anything else that
        # is not a prompt HTTP response lands here rather than wedging the
        # whole test — see the doc comment above for why that distinction is
        # the point of this test.
        print("ATTACK-" + label + ": EXC " + repr(e), flush=True)

# GET .../attach carrying the pair a real 'docker attach' / 'docker run'
# sends: Upgrade + an explicit Connection: Upgrade.
attack("attach-get-tcp", "GET",
       "/v1.41/containers/" + attack_cid + "/attach?stream=1&stdout=1",
       {"Upgrade": "tcp", "Connection": "Upgrade"})

# POST .../attach, Connection as a comma-separated list with Upgrade in it —
# upgradeRequested's own reason for splitting on "," rather than testing
# equality.
attack("attach-post-tcp", "POST", "/v1.41/containers/" + attack_cid + "/attach",
       {"Connection": "keep-alive, Upgrade", "Upgrade": "tcp"})

# A non-tcp Upgrade token. isHijack decides by PATH, not by what the token
# names, so this must refuse identically.
attack("attach-get-h2c", "GET", "/v1.41/containers/" + attack_cid + "/attach",
       {"Upgrade": "h2c"})

# The /attach/ws spelling a browser-shaped client uses.
attack("attach-ws-websocket", "GET",
       "/v1.41/containers/" + attack_cid + "/attach/ws",
       {"Upgrade": "websocket"})

# The exact route measured in issue #386: foreground docker run's /start
# carrying Upgrade:. The unit test (ownership_test.go,
# TestTheOwnershipGateRunsBeforeTheHijackBranch) proves this against a fake
# engine; this is the same route against a real one.
attack("start-upgrade-tcp", "POST", "/v1.41/containers/" + attack_cid + "/start",
       {"Upgrade": "tcp"})

# The libpod spelling of attach, with an Upgrade header present but empty —
# isHijack matches on path alone, so an empty token must refuse exactly the
# same way a real one does.
attack("libpod-attach-empty", "GET",
       "/v5.0.0/libpod/containers/" + attack_cid + "/attach?stream=1",
       {"Upgrade": ""})

# ── positive control: run B's OWN container, an ordinary (non-hijacked)
# start — proves the six refusals above are not a proxy refusing the whole
# API.
if build_scratch_holder():
    body = json.dumps({"Image": "localhost/%[2]s", "Cmd": ["own-token"],
                        "HostConfig": {"NetworkMode": "host"}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("B-CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        bcid = json.loads(resp)["Id"]
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% bcid)
        print("B-START: %%d" %% status, flush=True)
        status, _ = req("DELETE", "/v1.41/containers/%%s?force=1" %% bcid)
        print("B-RM: %%d" %% status, flush=True)
print("B-SCRIPT-COMPLETE", flush=True)
`, attackCid, tagB)
	if err := os.WriteFile(filepath.Join(proj, "hijack_b.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	runB := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 hijack_b.py`).mustRun(t)
	if !strings.Contains(runB.out, "B-SCRIPT-COMPLETE") {
		t.Fatalf("run B's payload did not run to the end:\n%s", runB.out)
	}

	const wantSubstring = "not created by this sandbox run"
	for _, tc := range []struct{ label, why string }{
		{"attach-get-tcp", "GET .../attach with Upgrade: tcp + Connection: Upgrade"},
		{"attach-post-tcp", "POST .../attach with Connection: keep-alive, Upgrade + Upgrade: tcp"},
		{"attach-get-h2c", "GET .../attach with Upgrade: h2c"},
		{"attach-ws-websocket", "GET .../attach/ws with Upgrade: websocket"},
		{"start-upgrade-tcp", "POST .../start with Upgrade: tcp — issue #386's own measured route"},
		{"libpod-attach-empty", "GET the libpod spelling of attach with an empty Upgrade:"},
	} {
		got, ok := lineAfterPrefix(runB.out, "ATTACK-"+tc.label+": ")
		if !ok {
			t.Fatalf("no ATTACK-%s line in run B's output — %s was never even attempted:\n%s",
				tc.label, tc.why, runB.out)
		}
		if !strings.HasPrefix(got, "403 ") {
			t.Errorf("%s should be refused with a prompt 403, not hijacked or hung; got %q:\n%s",
				tc.why, got, runB.out)
			continue
		}
		if !strings.Contains(got, wantSubstring) {
			t.Errorf("%s was refused, but its body does not carry %q: %q", tc.why, wantSubstring, got)
		}
	}

	// ── the positive control ──
	if !strings.Contains(runB.out, fmt.Sprintf("BUILD %s: 200", tagB)) {
		t.Fatalf("control: run B's OWN scratch image did not even build, so the round trip "+
			"below proves nothing about ownership specifically:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-CREATE: 201") {
		t.Errorf("control: run B could not create its OWN container — the six refusals above "+
			"would pass identically on a proxy that refuses the entire container API:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-START: 204") && !strings.Contains(runB.out, "B-START: 200") {
		t.Errorf("control: run B could not start its OWN container (ordinary, no Upgrade:):\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-RM: 204") && !strings.Contains(runB.out, "B-RM: 200") {
		t.Errorf("control: run B could not remove its OWN container:\n%s", runB.out)
	}
}

// ── 2. the libpod-native spelling of a read ─────────────────────────────────

// TestLibpodSpelledForeignReadsAreGated is the live counterpart of
// ownership.go's own reasoning for running the gate AFTER the libpod schema
// gate rather than before it: a libpod GET passes the schema gate
// (safeMethod), so `GET /libpod/containers/{id}/json` and `.../logs`
// normalise to the same segments as their docker-compat spelling and must be
// refused identically. The committed integration test
// (containerownership_test.go) drives only the compat spelling
// (/v1.41/containers/...); this is the spelling that has no live coverage at
// all.
func TestLibpodSpelledForeignReadsAreGated(t *testing.T) {
	budget(t, 240*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)

	const tagA = "snugtest-ownership-libpod-a:1"
	proj, attackCid := spawnForeignLeftoverContainer(t, env, tagA)

	const tagB = "snugtest-ownership-libpod-b:1"
	if err := os.WriteFile(filepath.Join(proj, "holder"), mustRead(t, holderBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}
	script := buildScratchProbeImageForNamed("build_scratch_holder", tagB, "holder") + fmt.Sprintf(`
attack_cid = %[1]q

for label, method, path in [
    ("libpod-json", "GET", "/v5.0.0/libpod/containers/" + attack_cid + "/json"),
    ("libpod-logs", "GET", "/v5.0.0/libpod/containers/" + attack_cid + "/logs?stdout=1&stderr=1"),
]:
    status, resp = req(method, path)
    print("ATTACK-" + label + ": " + str(status) + " " + resp.decode(errors="replace")[:400], flush=True)

# ── positive control: run B's OWN container, addressed the libpod way ──
if build_scratch_holder():
    body = json.dumps({"Image": "localhost/%[2]s", "Cmd": ["own-token"],
                        "HostConfig": {"NetworkMode": "host"}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("B-CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        bcid = json.loads(resp)["Id"]
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% bcid)
        print("B-START: %%d" %% status, flush=True)
        status, _ = req("GET", "/v5.0.0/libpod/containers/%%s/json" %% bcid)
        print("B-LIBPOD-JSON: %%d" %% status, flush=True)
        status, _ = req("GET", "/v5.0.0/libpod/containers/%%s/logs?stdout=1&stderr=1" %% bcid)
        print("B-LIBPOD-LOGS: %%d" %% status, flush=True)
        status, _ = req("DELETE", "/v1.41/containers/%%s?force=1" %% bcid)
        print("B-RM: %%d" %% status, flush=True)
print("B-SCRIPT-COMPLETE", flush=True)
`, attackCid, tagB)
	if err := os.WriteFile(filepath.Join(proj, "libpod_b.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	runB := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 libpod_b.py`).mustRun(t)
	if !strings.Contains(runB.out, "B-SCRIPT-COMPLETE") {
		t.Fatalf("run B's payload did not run to the end:\n%s", runB.out)
	}

	const wantSubstring = "not created by this sandbox run"
	for _, tc := range []struct{ label, why string }{
		{"libpod-json", "GET /v5.0.0/libpod/containers/{id}/json on another run's container"},
		{"libpod-logs", "GET /v5.0.0/libpod/containers/{id}/logs on another run's container"},
	} {
		got, ok := lineAfterPrefix(runB.out, "ATTACK-"+tc.label+": ")
		if !ok {
			t.Fatalf("no ATTACK-%s line in run B's output — %s was never even attempted:\n%s",
				tc.label, tc.why, runB.out)
		}
		if !strings.HasPrefix(got, "403 ") {
			t.Errorf("%s (libpod spelling) should be refused with 403, got %q:\n%s", tc.why, got, runB.out)
			continue
		}
		if !strings.Contains(got, wantSubstring) {
			t.Errorf("%s was refused, but its body does not carry %q: %q", tc.why, wantSubstring, got)
		}
	}

	// ── the positive control: B's OWN container, same (libpod) spelling ──
	if !strings.Contains(runB.out, fmt.Sprintf("BUILD %s: 200", tagB)) {
		t.Fatalf("control: run B's OWN scratch image did not even build, so the round trip "+
			"below proves nothing about ownership specifically:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-CREATE: 201") {
		t.Errorf("control: run B could not create its OWN container:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-START: 204") && !strings.Contains(runB.out, "B-START: 200") {
		t.Errorf("control: run B could not start its OWN container:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-LIBPOD-JSON: 200") {
		t.Errorf("control: run B could not read its OWN container over the libpod-spelled "+
			"json route — the two refusals above would pass identically on a proxy that "+
			"refuses the whole libpod-spelled read path:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-LIBPOD-LOGS: 200") {
		t.Errorf("control: run B could not read its OWN container's logs over the "+
			"libpod-spelled route:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-RM: 204") && !strings.Contains(runB.out, "B-RM: 200") {
		t.Errorf("control: run B could not remove its OWN container:\n%s", runB.out)
	}
}

// ── 3. a short prefix of a foreign id must canonicalise, not just refuse ───

// TestShortPrefixForeignContainerRefusalNamesTheResolvedId is
// canonicalID's own reasoning (ownership.go) made live: a 12-hex PREFIX of a
// container id resolves through the engine exactly as the full id does
// (measured there against podman 5.8.4: `GET /containers/08cfc5d47cf3/json`
// answers 200), so a client spelling a foreign container by prefix must be
// refused on the id the ENGINE resolved it to, not merely refused somehow.
// The message is asserted to carry BOTH the client's prefix and the full
// 64-hex id it resolved to — proving canonicalisation happened rather than
// the request being refused for some unrelated reason (a lucky 403 would
// pass a weaker assertion just as well).
//
// Paired with the OWN-prefix control: run B addresses its OWN container by
// its own 12-hex prefix and is served (200) — without this, the refusals
// below would pass identically on a proxy that refuses every short id,
// canonicalisation or not.
func TestShortPrefixForeignContainerRefusalNamesTheResolvedId(t *testing.T) {
	budget(t, 240*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)

	const tagA = "snugtest-ownership-prefix-a:1"
	proj, attackCid := spawnForeignLeftoverContainer(t, env, tagA)
	attackPrefix := attackCid[:12]

	const tagB = "snugtest-ownership-prefix-b:1"
	if err := os.WriteFile(filepath.Join(proj, "holder"), mustRead(t, holderBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}
	script := buildScratchProbeImageForNamed("build_scratch_holder", tagB, "holder") + fmt.Sprintf(`
attack_prefix = %[1]q

for label, method, path in [
    ("json",  "GET",    "/v1.41/containers/" + attack_prefix + "/json"),
    ("start", "POST",   "/v1.41/containers/" + attack_prefix + "/start"),
    ("rm",    "DELETE", "/v1.41/containers/" + attack_prefix),
]:
    status, resp = req(method, path)
    print("ATTACK-" + label + ": " + str(status) + " " + resp.decode(errors="replace")[:400], flush=True)

# ── positive control: run B's OWN container, addressed by ITS OWN 12-hex
# prefix ──
if build_scratch_holder():
    body = json.dumps({"Image": "localhost/%[2]s", "Cmd": ["own-token"],
                        "HostConfig": {"NetworkMode": "host"}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("B-CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        bcid = json.loads(resp)["Id"]
        own_prefix = bcid[:12]
        status, resp = req("GET", "/v1.41/containers/" + own_prefix + "/json")
        print("B-OWN-PREFIX-JSON: %%d" %% status, flush=True)
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% bcid)
        print("B-START: %%d" %% status, flush=True)
        status, _ = req("DELETE", "/v1.41/containers/%%s?force=1" %% bcid)
        print("B-RM: %%d" %% status, flush=True)
print("B-SCRIPT-COMPLETE", flush=True)
`, attackPrefix, tagB)
	if err := os.WriteFile(filepath.Join(proj, "prefix_b.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	runB := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 prefix_b.py`).mustRun(t)
	if !strings.Contains(runB.out, "B-SCRIPT-COMPLETE") {
		t.Fatalf("run B's payload did not run to the end:\n%s", runB.out)
	}

	const wantSuffix = "was not created by this sandbox run"
	// The exact substring the round measured: "container <prefix> (<full
	// 64-hex id>)" — the prefix as the client spelled it, the full id in
	// parentheses is what the ENGINE resolved that prefix to.
	wantResolved := fmt.Sprintf("container %s (%s)", attackPrefix, attackCid)
	for _, tc := range []struct{ label, why string }{
		{"json", "GET a foreign container by a 12-hex prefix"},
		{"start", "POST start on a foreign container by a 12-hex prefix"},
		{"rm", "DELETE a foreign container by a 12-hex prefix"},
	} {
		got, ok := lineAfterPrefix(runB.out, "ATTACK-"+tc.label+": ")
		if !ok {
			t.Fatalf("no ATTACK-%s line in run B's output — %s was never even attempted:\n%s",
				tc.label, tc.why, runB.out)
		}
		if !strings.HasPrefix(got, "403 ") {
			t.Errorf("%s should be refused with 403, got %q:\n%s", tc.why, got, runB.out)
			continue
		}
		if !strings.Contains(got, wantSuffix) {
			t.Errorf("%s was refused, but its body does not carry %q: %q", tc.why, wantSuffix, got)
		}
		if !strings.Contains(got, wantResolved) {
			t.Errorf("%s was refused, but its body does not carry %q — the message must name "+
				"the id the ENGINE resolved the prefix to, proving canonicalisation happened "+
				"rather than a refusal on the client's own short string: %q",
				tc.why, wantResolved, got)
		}
	}

	// ── the positive control ──
	if !strings.Contains(runB.out, fmt.Sprintf("BUILD %s: 200", tagB)) {
		t.Fatalf("control: run B's OWN scratch image did not even build, so the round trip "+
			"below proves nothing about ownership specifically:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-CREATE: 201") {
		t.Errorf("control: run B could not create its OWN container:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-OWN-PREFIX-JSON: 200") {
		t.Errorf("control: run B could not read its OWN container addressed by its OWN "+
			"12-hex prefix — the three refusals above would pass identically on a proxy "+
			"that refuses every short id:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-START: 204") && !strings.Contains(runB.out, "B-START: 200") {
		t.Errorf("control: run B could not start its OWN container:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-RM: 204") && !strings.Contains(runB.out, "B-RM: 200") {
		t.Errorf("control: run B could not remove its OWN container:\n%s", runB.out)
	}
}

// ── 4. odd-shape spellings need a hand-written request line ────────────────

// oddShapeRawHelpers is plain Python, concatenated rather than passed through
// fmt.Sprintf — it contains no Go template substitutions, and every literal
// '%' in it must stay a single '%' on the wire.
//
// raw_req writes the request LINE itself, byte for byte, over the AF_UNIX
// socket $CONTAINER_HOST names. That is the point: Python's http.client (like
// Go's http.Client, which the round used and which CLAUDE.md's own note on
// this test records) normalises a doubled slash, a trailing slash and a
// percent-escape out of a path before the request ever leaves the process, so
// a test built on either client's convenience methods would send the proxy an
// already-cleaned path and prove nothing about the odd shape at all.
const oddShapeRawHelpers = `
def raw_req(method, raw_path):
    sock_path = os.environ["CONTAINER_HOST"].replace("unix://", "")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock_path)
    line = "%s %s HTTP/1.1\r\nHost: engine\r\nConnection: close\r\n\r\n" % (method, raw_path)
    s.sendall(line.encode())
    chunks = []
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    except socket.timeout:
        pass
    s.close()
    return b"".join(chunks)

def status_line(raw):
    nl = raw.find(b"\r\n")
    return raw[:nl].decode(errors="replace") if nl >= 0 else raw.decode(errors="replace")
`

// TestOddShapeForeignRoutesAreGatedOnARawRequestLine is the round's
// canonicalisation-adjacent measurement: a doubled slash
// (/v1.41//containers/{id}//json), a trailing slash
// (/v1.41/containers/{id}/json/), a percent-encoded verb segment
// (/v1.41/containers/{id}/lo%67s?stdout=1) and two ways of omitting the
// version/libpod prefix (/containers/{id}/json,
// /libpod/containers/{id}/json) must all still resolve to the SAME gated
// route and refuse a foreign container — normaliseFull's own doc comment
// explains why each one does (split-and-skip-empty absorbs the slashes, Go's
// request-line parser percent-decodes the path before ownership.go ever sees
// it, and the version/libpod prefix is optional to normaliseFull by
// construction). This is the live proof, over a hand-written request line
// so nothing on the way there can normalise the shape away first.
func TestOddShapeForeignRoutesAreGatedOnARawRequestLine(t *testing.T) {
	budget(t, 240*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)

	const tagA = "snugtest-ownership-oddshape-a:1"
	proj, attackCid := spawnForeignLeftoverContainer(t, env, tagA)

	const tagB = "snugtest-ownership-oddshape-b:1"
	if err := os.WriteFile(filepath.Join(proj, "holder"), mustRead(t, holderBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}
	script := buildScratchProbeImageForNamed("build_scratch_holder", tagB, "holder") +
		oddShapeRawHelpers + fmt.Sprintf(`
attack_cid = %[1]q
tag_b = %[2]q

routes = [
    ("double-slash",      "GET", "/v1.41//containers/" + attack_cid + "//json"),
    ("trailing-slash",    "GET", "/v1.41/containers/" + attack_cid + "/json/"),
    ("percent-verb",      "GET", "/v1.41/containers/" + attack_cid + "/lo%%67s?stdout=1"),
    ("no-version",        "GET", "/containers/" + attack_cid + "/json"),
    ("no-version-libpod", "GET", "/libpod/containers/" + attack_cid + "/json"),
]
for label, method, path in routes:
    raw = raw_req(method, path)
    sl = status_line(raw)
    body = raw.decode(errors="replace")
    print("ATTACK-" + label + ": " + sl + " || REFUSAL=" +
          str("not created by this sandbox run" in body), flush=True)

# ── positive control: the SAME raw_req plumbing, against run B's OWN
# container, with no odd shape — proves raw_req itself works and that the
# five refusals above are not an artefact of a broken raw request.
if build_scratch_holder():
    body = json.dumps({"Image": "localhost/" + tag_b, "Cmd": ["own-token"],
                        "HostConfig": {"NetworkMode": "host"}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("B-CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status == 201:
        bcid = json.loads(resp)["Id"]
        raw = raw_req("GET", "/v1.41/containers/" + bcid + "/json")
        print("B-RAW-JSON: " + status_line(raw), flush=True)
        status, _ = req("POST", "/v1.41/containers/%%s/start" %% bcid)
        print("B-START: %%d" %% status, flush=True)
        status, _ = req("DELETE", "/v1.41/containers/%%s?force=1" %% bcid)
        print("B-RM: %%d" %% status, flush=True)
print("B-SCRIPT-COMPLETE", flush=True)
`, attackCid, tagB)
	if err := os.WriteFile(filepath.Join(proj, "oddshape_b.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	runB := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 oddshape_b.py`).mustRun(t)
	if !strings.Contains(runB.out, "B-SCRIPT-COMPLETE") {
		t.Fatalf("run B's payload did not run to the end:\n%s", runB.out)
	}

	for _, tc := range []struct{ label, why string }{
		{"double-slash", "GET /v1.41//containers/{id}//json"},
		{"trailing-slash", "GET /v1.41/containers/{id}/json/"},
		{"percent-verb", "GET /v1.41/containers/{id}/lo%67s?stdout=1"},
		{"no-version", "GET /containers/{id}/json (no version prefix)"},
		{"no-version-libpod", "GET /libpod/containers/{id}/json (no version prefix)"},
	} {
		got, ok := lineAfterPrefix(runB.out, "ATTACK-"+tc.label+": ")
		if !ok {
			t.Fatalf("no ATTACK-%s line in run B's output — %s was never even attempted:\n%s",
				tc.label, tc.why, runB.out)
		}
		if !strings.HasPrefix(got, "HTTP/1.1 403") {
			t.Errorf("%s should be refused with 403, got status line %q:\n%s", tc.why, got, runB.out)
			continue
		}
		if !strings.Contains(got, "REFUSAL=True") {
			t.Errorf("%s was refused with 403 but its body does not carry the ownership "+
				"message %q: %q", tc.why, "not created by this sandbox run", got)
		}
	}

	// ── the positive control: raw_req itself, against B's own container ──
	if !strings.Contains(runB.out, fmt.Sprintf("BUILD %s: 200", tagB)) {
		t.Fatalf("control: run B's OWN scratch image did not even build, so the round trip "+
			"below proves nothing about ownership specifically:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-CREATE: 201") {
		t.Errorf("control: run B could not create its OWN container:\n%s", runB.out)
	}
	got, ok := lineAfterPrefix(runB.out, "B-RAW-JSON: ")
	if !ok {
		t.Fatalf("no B-RAW-JSON line — the raw request against run B's OWN container was "+
			"never even attempted:\n%s", runB.out)
	}
	if !strings.HasPrefix(got, "HTTP/1.1 200") {
		t.Errorf("control: raw_req against run B's OWN container (no odd shape) should answer "+
			"200 — the five refusals above would pass identically on a raw_req that is simply "+
			"broken, or on a proxy refusing the whole API: got status line %q:\n%s", got, runB.out)
	}
	if !strings.Contains(runB.out, "B-START: 204") && !strings.Contains(runB.out, "B-START: 200") {
		t.Errorf("control: run B could not start its OWN container:\n%s", runB.out)
	}
	if !strings.Contains(runB.out, "B-RM: 204") && !strings.Contains(runB.out, "B-RM: 200") {
		t.Errorf("control: run B could not remove its OWN container:\n%s", runB.out)
	}
}
