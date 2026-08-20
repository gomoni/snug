//go:build integration

package integration

// containerengine_test.go is issue #63 Tier B's own integration layer: the
// engine now runs INSIDE the sandbox's own network namespace N, forked by the
// stage as root-in-U and reduced to policy.EngineCapBounding immediately
// before it execs. go-implementer built and wired the mechanism (the commits
// on this branch under "refs #63") and specified exactly what this file must
// assert without writing the assertions — the engine-in-N property can only
// be tested now that the engine is actually wired into internal/cli. Every
// test below is one of those seven assertions, named for the property, with
// its own positive control per CLAUDE.md's standing rule: "a test that cannot
// fail is worse than no test".
//
// # Why every real-engine test drives $SNUG_PODMAN at a pinned static bundle
//
// This development host's own `podman` resolves to distrobox-host-exec (a
// host-escape shim — see internal/cli/podmanshim.go's hostEscapeShims list),
// which preflight P1 (containerpreflight.go) correctly refuses before
// anything is created. Testing this tier at all, on this host, needs a real,
// non-shim engine pinned explicitly — the static bundle host-bridge
// provisioned at ~/.local/opt/podman-static (.claude/design/PODMAN-STATIC.md)
// — via its own `snug-podman` wrapper script, which sets the CONTAINERS_CONF/
// STORAGE_CONF/REGISTRIES_CONF/HOME env the bundle needs to find its own
// pinned helper binaries (conmon, crun, netavark, pasta) rather than
// whatever a bare exec of the pinned podman binary would fall back to.
// containerpreflight.go's own preflightPodmanBinary trusts $SNUG_PODMAN
// outright and never re-resolves it through PATH, which is exactly what lets
// this wrapper be handed to it directly.
//
// containerEngineEnv skips CLEANLY (never fails, even under
// SNUG_REQUIRE_SANDBOX — the same convention requireEngine already uses in
// sandbox_test.go) when the bundle is not present, so a host without it — any
// CI runner today — degrades to a skip rather than either a false pass or a
// hard failure for a capability nobody promised it.
import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/policy"
)

// podmanStaticRootRel is where host-bridge's provisioning left the pinned
// engine bundle, relative to $HOME (.claude/design/PODMAN-STATIC.md §1/§5).
const podmanStaticRootRel = ".local/opt/podman-static"

// containerEngineEnv is baseEnv (via attachEnv's own isolation, so
// $XDG_RUNTIME_DIR never collides with another test's live run) plus
// $SNUG_PODMAN pointed at a freshly provisioned wrapper (provisionEngineWrapper).
// Every test in this file that starts a real engine uses it.
func containerEngineEnv(t *testing.T) (env []string, xdgRuntime string) {
	t.Helper()
	wrapper := provisionEngineWrapper(t)
	base, xdg := attachEnv(t)
	return append(base, "SNUG_PODMAN="+wrapper), xdg
}

// provisionEngineWrapper builds a small shell wrapper around the pinned
// static podman binary, the way both go-implementer and redteam actually ran
// it while measuring this tier — copying the SHAPE of the working wrapper
// redteam left behind, not the path (that one lived under a redteam-only
// scratchpad and is not something this suite may depend on existing).
//
// The bundle's OWN etc/snug/containers.conf and storage.conf pin
// graphroot/runroot/static_dir/tmp_dir/volume_path to the BUNDLE's own
// store, which COLLIDES with the PER-RUN --root/--runroot
// internal/engine.Engine.Spec passes — podman's libpod database then refuses
// with "database run root ... does not match our run root". This strips
// exactly those keys from a COPY of the bundle's own config (the bundle
// itself is never touched) and forces cgroups=disabled, matching
// preflight P5's own default choice for a host in this shape
// (containerpreflight.go's preflightCgroupsWritable): __inengine's own
// private-cgroup-namespace remount is non-fatal-but-failing here (EBUSY),
// and disabling cgroup management avoids relying on it actually working.
// Measured NOT to be what a real container run needed on this development
// host, though — see requireRealEngine's own doc comment for what was.
//
// Skips cleanly (never fails, even under SNUG_REQUIRE_SANDBOX) if the bundle
// itself is not present, for the same reason containerEngineEnv's own doc
// gives.
func provisionEngineWrapper(t *testing.T) string {
	t.Helper()
	return provisionEngineWrapperWithHome(t, "")
}

// provisionEngineWrapperWithHome is provisionEngineWrapper with the engine's
// $HOME under the caller's control. It exists for issue #132's regression
// test and for nothing else, so read the reason rather than the signature:
//
// podman reads a USER containers.conf from $XDG_CONFIG_HOME/containers/ and,
// when that variable is unset, from $HOME/.config/containers/. The engine's
// environment is built by engine.Engine.Spec from PATH, HOME and
// XDG_RUNTIME_DIR alone — no XDG_CONFIG_HOME — so on a real run the file
// podman reads is the HOST USER's own, under their real home. Measured, and
// it is the whole channel:
//
//	$ env -u CONTAINERS_CONF -u XDG_CONFIG_HOME HOME=$D podman run --rm alpine:3.20 cat /leak/token
//	HOST-SECRET-MARKER
//
// A test cannot plant a hostile config in the developer's own
// ~/.config/containers, so it points the engine's HOME at a temporary one
// instead. homeOverride == "" keeps the bundle's own home, which is what
// every other test wants.
func provisionEngineWrapperWithHome(t *testing.T, homeOverride string) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("SKIP: cannot determine $HOME to look for a static podman bundle: " + err.Error())
	}
	root := filepath.Join(home, podmanStaticRootRel)
	podmanBin := filepath.Join(root, "usr", "local", "bin", "podman")
	if fi, statErr := os.Stat(podmanBin); statErr != nil || fi.IsDir() {
		t.Skip("SKIP: no static podman bundle at " + podmanBin + " (.claude/design/PODMAN-STATIC.md); " +
			"this suite never points SNUG_PODMAN at whatever the host's OWN `podman` resolves to")
	}

	dir := t.TempDir()

	containersConf := stripConfigLines(t, filepath.Join(root, "etc", "snug", "containers.conf"),
		"static_dir", "tmp_dir", "volume_path")
	containersConf = forceCgroupsDisabled(containersConf)
	if err := os.WriteFile(filepath.Join(dir, "containers.conf"), []byte(containersConf), 0o644); err != nil {
		t.Fatal(err)
	}

	storageConf := stripConfigLines(t, filepath.Join(root, "etc", "snug", "storage.conf"),
		"graphroot", "runroot")
	if err := os.WriteFile(filepath.Join(dir, "storage.conf"), []byte(storageConf), 0o644); err != nil {
		t.Fatal(err)
	}

	// NOT `export CONTAINERS_CONF` (issue #133). It used to, and that had two
	// costs, both measured rather than reasoned about:
	//
	//  1. snug's own generated containers.conf was never the file under test.
	//     Only CONTAINERS_CONF_OVERRIDE reached the engine, so preflight P5's
	//     cgroups remedy — the reason that file first existed — was verified
	//     by a suite in which it was not loaded.
	//  2. It MASKED the channel issue #132 is about. podman ignores the system
	//     and user containers.conf whenever CONTAINERS_CONF is set, by
	//     ANYONE — so the wrapper was suppressing the host's files itself, and
	//     TestHostContainersConfAuthorsNothingInAContainer passed identically
	//     with snug's own CONTAINERS_CONF deleted. A regression test the
	//     harness satisfies on snug's behalf proves nothing about snug.
	//
	// The copied containers.conf is still written above and still stripped and
	// cgroups-forced; it is simply not pointed at any more, so the file the
	// engine reads is the one snug generates. Storage and registries keep
	// their own variables, which name different files and are not part of this.
	// NOT `export CONTAINERS_REGISTRIES_CONF` either, and for issue #133's
	// reason applied to issue #137's file: snug now generates a registries.conf
	// and points that variable at it, so a wrapper exporting its own would be
	// the harness deciding image provenance on snug's behalf and the
	// regression test would pass with snug's variable deleted.
	//
	// HOME is exported ONLY when a caller planted one. snug now sets HOME
	// itself (to a run-private home carrying the generated policy.json), which
	// is what the default case must exercise. The override case keeps the
	// export deliberately: it stands in for the HOST USER's own home — which a
	// test cannot plant into — so that what is under test there stays
	// CONTAINERS_CONF closing the channel, rather than snug's HOME making the
	// planted file unreachable.
	homeLine := ""
	if homeOverride != "" {
		homeLine = fmt.Sprintf("export HOME=%s\n", homeOverride)
	}
	wrapper := filepath.Join(dir, "snug-test-podman")
	script := fmt.Sprintf("#!/bin/sh\n"+
		"export CONTAINERS_STORAGE_CONF=%s\n"+
		"%s"+
		"exec %s \"$@\"\n",
		filepath.Join(dir, "storage.conf"), homeLine, podmanBin)
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return wrapper
}

// stripConfigLines copies path with every line whose (trimmed) text starts
// with one of dropPrefixes followed by a space or "=" removed — a plain
// textual filter, not a TOML parser, which is enough for the small,
// hand-authored files this reads and keeps this test file from taking on a
// TOML dependency of its own.
func stripConfigLines(t *testing.T, path string, dropPrefixes ...string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skip("SKIP: reading " + path + ": " + err.Error())
	}
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		drop := false
		for _, p := range dropPrefixes {
			if strings.HasPrefix(trimmed, p+" ") || strings.HasPrefix(trimmed, p+"=") {
				drop = true
				break
			}
		}
		if !drop {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// forceCgroupsDisabled overwrites whatever the bundle's own `cgroups = ...`
// line said (measured "enabled" in the bundle as provisioned) with
// "disabled" — see provisionEngineWrapper's own doc comment for why.
func forceCgroupsDisabled(conf string) string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "cgroups") {
			out = append(out, `cgroups = "disabled"`)
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// ── the shared "is there a REAL, working engine" gate ───────────────────────

// realEngineResults memoizes probeRealEngine per distinct env: standing a
// working engine up (subuid delegation, a private cgroup namespace, crun,
// a real image pull) costs real wall-clock time, and every test in this file
// needs the same host-capability answer.
var (
	realEngineMu      sync.Mutex
	realEngineResults = map[string]string{}
)

// requireRealEngine gates on a container engine PROVEN to run a container end
// to end in exactly this env — not merely found on PATH, and not merely
// accepted by preflight.
//
// LookPath("podman") — requireEngine's own check in sandbox_test.go — answers
// "is a podman binary there". It does not answer "does a container engine
// forked into this sandbox's own N, reduced to policy.EngineCapBounding, in
// its own private mount and cgroup namespaces, actually run a payload here".
// Those are different questions on at least two hosts measured: this
// development host's own `podman` is a distrobox shim (P1 refuses it before
// anything is created — see TestPreflightRefusesUnconfinableEngine, which
// tests THAT refusal deliberately, on THIS property), and a GitHub-hosted
// ubuntu-latest CI runner's real, non-shim podman still failed
// TestPodmanBuildIsFilteredEndToEnd outright instead of skipping: the build
// itself returned 200 while its RUN step never executed.
//
// TWO candidate causes were visible in that failure's own output, and only
// ONE of them was real — worth recording because the wrong one is the more
// obvious-looking of the two. `__inengine`'s private-cgroup-namespace remount
// hit EBUSY ("could not remount /sys/fs/cgroup ... — continuing") right next
// to the failure, which looks like the culprit and is not: it is explicitly
// non-fatal by design (inengine.go's own comment), and MEASURED here (a real
// build, driven directly against a real static bundle, outside snug) to
// succeed end to end despite that exact warning. The REAL cause, found by
// reading the build's own streamed body rather than trusting the two markers
// this file already prints: `FROM alpine` (a short name) resolves through
// containers/image's short-name-alias machinery, which picks the SYSTEM
// cache path (/var/cache/containers) over a user one because __inengine's
// process reports euid 0 (root-in-U, not a real host root) — "creating build
// container: mkdir /var/cache/containers: permission denied". buildProbe
// (sandbox_test.go) now uses a fully qualified reference
// (docker.io/library/alpine:3.20), which skips short-name resolution
// entirely; see that constant's own comment for the measurement. Never trust
// "podman is installed", or even "preflight accepted it", as a proxy for "a
// container will actually run here" — and never trust the error message
// sitting closest to the symptom over reading what the engine itself
// actually said.
//
// A plain, unconditional t.Skip on failure — never skipOrFail — for the same
// reason requireEngine's own doc gives: no CI lane promises a working engine
// today, so a green run that never got one is a developer-machine fact, not
// a regression.
func requireRealEngine(t *testing.T, env []string) {
	t.Helper()
	requireSandbox(t)
	requirePython(t)
	requireInternet(t)

	key := strings.Join(env, "\x00")
	realEngineMu.Lock()
	reason, cached := realEngineResults[key]
	realEngineMu.Unlock()
	if !cached {
		reason = probeRealEngine(t, env)
		realEngineMu.Lock()
		realEngineResults[key] = reason
		realEngineMu.Unlock()
	}
	if reason != "" {
		t.Skip("SKIP: no usable real container engine in this environment: " + reason)
	}
}

// probeRealEngine drives the exact "ordinary build" leg
// TestPodmanBuildIsFilteredEndToEnd asserts, in a throwaway target of its
// own, and reports WHY the engine is not usable rather than letting whichever
// test happened to need it first fail with a confusing, unrelated message.
func probeRealEngine(t *testing.T, env []string) string {
	t.Helper()
	proj, _ := target(t)
	if err := os.WriteFile(filepath.Join(proj, "probe.py"), []byte(buildProbe), 0o644); err != nil {
		t.Fatal(err)
	}
	r := runEnv(t, env, []string{"-p", "@podman-build", "-p", "@net"}, proj, `python3 probe.py`)
	if !r.ran {
		return fmt.Sprintf("the probe payload never ran (snug exited %d): %s", r.code, r.out)
	}
	if !strings.Contains(r.out, "ordinary build: 200") {
		return "an ordinary build did not even return 200: " + r.out
	}
	if !strings.Contains(r.out, "BUILT-INSIDE-SNUG") {
		return "a build succeeded but its RUN step never actually executed a container -- this " +
			"host's engine cannot really run one: " + r.out
	}
	return ""
}

// pyPreamble is the http.client-over-AF_UNIX plumbing every python payload in
// this file needs to talk to the proxy at $CONTAINER_HOST, plus a `req`
// helper that returns (status, body). Shared rather than repeated, the same
// reasoning buildProbe's own doc comment in sandbox_test.go gives for the
// query-parameter sets it pins.
const pyPreamble = `import http.client, socket, os, json

class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self.path = path
    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.path)
        self.sock = s

_sock = os.environ["CONTAINER_HOST"].replace("unix://", "")

def req(method, path, body=None, headers=None):
    c = UnixHTTP(_sock)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    return r.status, data
`

// ── 1. egress follows @net, both directions ─────────────────────────────────

// TestContainerEgressFollowsNetProfile is the property Tier B exists for:
// the container engine now lives in the SANDBOX's own network namespace N,
// so a container's egress is governed by whether @net was selected for the
// SANDBOX, not by the engine having its own (formerly the host's) route out.
//
// Both directions in one test, per the implementer's own spec: without @net,
// a pull fails on a network marker while the engine itself still answers
// locally (so the failure is "no network", not "no engine" — the control
// that makes the negative meaningful); with @net, the identical pull
// succeeds.
func TestContainerEgressFollowsNetProfile(t *testing.T) {
	budget(t, 120*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)

	pull := pyPreamble + `
status, _ = req("GET", "/v1.41/version")
print("version: %d" % status, flush=True)

status, body = req("POST", "/v1.41/images/create?fromImage=alpine&tag=3.20")
print("pull-http: %d" % status, flush=True)
print("pull-body-tail: %s" % body[-300:].decode(errors="replace").replace("\n", " "), flush=True)

status, _ = req("GET", "/v1.41/images/alpine:3.20/json")
print("inspect: %d" % status, flush=True)
print("PULLED" if status == 200 else "NOT-PULLED", flush=True)
print("PROBE-COMPLETE", flush=True)
`
	run := func(withNet bool) sandboxRun {
		proj, _ := target(t)
		if err := os.WriteFile(filepath.Join(proj, "pull.py"), []byte(pull), 0o644); err != nil {
			t.Fatal(err)
		}
		args := []string{"-p", "@podman-socket"}
		if withNet {
			args = append(args, "-p", "@net")
		}
		return runEnv(t, env, args, proj, `python3 pull.py`).mustRun(t)
	}

	offline := run(false)
	if !strings.Contains(offline.out, "PROBE-COMPLETE") {
		t.Fatalf("offline probe did not run to the end:\n%s", offline.out)
	}
	// CONTROL: the engine answers locally even with no egress at all — so the
	// failure below is "no network", not "no engine".
	if !strings.Contains(offline.out, "version: 200") {
		t.Fatalf("control: the engine did not even answer /version without @net, so the pull "+
			"failure below proves nothing about egress specifically:\n%s", offline.out)
	}
	if strings.Contains(offline.out, "PULLED") && !strings.Contains(offline.out, "NOT-PULLED") {
		t.Errorf("a container pull SUCCEEDED without @net — the engine has egress an offline "+
			"sandbox must not have:\n%s", offline.out)
	}
	if !strings.Contains(offline.out, "NOT-PULLED") {
		t.Errorf("expected the offline pull to fail (NOT-PULLED), got:\n%s", offline.out)
	}

	withNet := run(true)
	if !strings.Contains(withNet.out, "PROBE-COMPLETE") {
		t.Fatalf("@net probe did not run to the end:\n%s", withNet.out)
	}
	if !strings.Contains(withNet.out, "version: 200") {
		t.Fatalf("control: the engine did not answer /version with @net either:\n%s", withNet.out)
	}
	if !strings.Contains(withNet.out, "PULLED") || strings.Contains(withNet.out, "NOT-PULLED") {
		t.Errorf("the SAME pull, with @net selected, must succeed — egress follows the profile "+
			"in both directions or this tier does not do what it claims:\n%s", withNet.out)
	}
}

// ── shared: build a from-scratch image around the static netprobe binary ────

// netprobeBinPath is built once, lazily, the same way TestMain builds snugBin
// and pidfdProbeBin — but only when a test in this file actually needs it,
// since most hosts running `make integration` locally will skip every test
// here at containerEngineEnv's own gate before ever reaching this.
var (
	netprobeBinOnce sync.Once
	netprobeBinPath string
	netprobeBinErr  error
)

func netprobeBin(t *testing.T) string {
	t.Helper()
	netprobeBinOnce.Do(func() {
		dir := t.TempDir()
		// t.TempDir() is scoped to THIS test and removed on cleanup, but the
		// binary is small and the build is fast (a few hundred ms), so paying
		// it once per calling test rather than truly once per process is a
		// deliberate simplicity trade, not an oversight — unlike snugBin, this
		// is never on a hot path.
		bin := filepath.Join(dir, "netprobe")
		cmd := exec.Command("go", "build", "-o", bin, "./testdata/netprobe")
		cmd.Dir = "."
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			netprobeBinErr = fmt.Errorf("building test/integration/testdata/netprobe: %w: %s", err, out.String())
			return
		}
		netprobeBinPath = bin
	})
	if netprobeBinErr != nil {
		t.Fatal(netprobeBinErr)
	}
	return netprobeBinPath
}

// buildScratchProbeImage builds a `FROM scratch` image whose entrypoint is
// the static netprobe binary, over the SAME proxy this test's sandbox is
// using — no base layer, so no registry pull, which is what lets this run in
// a sandbox that has NO egress at all (the whole point of
// TestContainerEgressFollowsNetProfile's offline half, reused here for
// TestHostLoopbackClosedFromContainer's offline half).
func buildScratchProbeImage(tag string) string {
	return buildScratchProbeImageFor(tag, "netprobe")
}

// runContainerAndCollect creates, starts, waits for and removes a container
// from tag, returning its stdout/stderr (Tty=true, so the compat logs
// endpoint needs no stream-framing decode). network is HostConfig.NetworkMode
// verbatim — "host" is the ONLY mode this tier actually supports (see
// internal/dockerproxy/create.go's own doc comment on the inversion), so
// every caller in this file passes it explicitly rather than relying on
// podman's own default.
const runContainerAndCollectFn = `
def run_and_collect(tag, cmd, network):
    # A freshly built LOCAL image is tagged "localhost/<tag>", not "<tag>" --
    # podman's own default short-name resolution otherwise expands the bare
    # tag to "docker.io/library/<tag>" and 404s ("image not known") on a
    # perfectly real image this same run just built.
    body = json.dumps({"Image": "localhost/" + tag, "Cmd": cmd, "Tty": True,
                        "HostConfig": {"NetworkMode": network}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("CREATE: %d %s" % (status, resp.decode(errors="replace")[:300]), flush=True)
    if status != 201:
        return
    cid = json.loads(resp)["Id"]
    status, _ = req("POST", "/v1.41/containers/%s/start" % cid)
    print("START: %d" % status, flush=True)
    status, w = req("POST", "/v1.41/containers/%s/wait" % cid)
    print("WAIT: %d %s" % (status, w.decode(errors="replace")), flush=True)
    status, logs = req("GET", "/v1.41/containers/%s/logs?stdout=1&stderr=1" % cid)
    print("LOGS-BEGIN", flush=True)
    print(logs.decode(errors="replace"), flush=True)
    print("LOGS-END", flush=True)
    req("DELETE", "/v1.41/containers/%s?force=1" % cid)
`

// ── 2. host loopback closed from a container, with and without @net ────────

// TestHostLoopbackClosedFromContainer is issue #63 Tier B's central risk made
// concrete: before this tier the engine — and every container it started —
// ran on the HOST's own network namespace, so `NetworkMode=host` reached the
// REAL host loopback. Now the engine (and, via NetworkMode=host, a
// container) lives in N, so it must get the identical closure the ordinary
// sandboxed payload already gets (TestHostLoopbackIsUnreachable) — and this
// is the first time a CONTAINER, rather than the payload bwrap execs
// directly, has ever been able to reach into N at all.
func TestHostLoopbackClosedFromContainer(t *testing.T) {
	budget(t, 120*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	probeBin := netprobeBin(t)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveBanner(t, ln)
	port := ln.Addr().(*net.TCPAddr).Port

	// CONTROL: the host can reach its own listener.
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("precondition: the host cannot reach its own listener: %v", err)
	}
	c.Close()

	probeOnce := func(withNet bool, tag string) string {
		proj, _ := target(t)
		if err := os.WriteFile(filepath.Join(proj, "netprobe"), mustRead(t, probeBin), 0o755); err != nil {
			t.Fatal(err)
		}
		script := buildScratchProbeImage(tag) + runContainerAndCollectFn + fmt.Sprintf(`
if build_scratch_probe():
    run_and_collect(%q, ["/netprobe", "%d"], "host")
print("PROBE-COMPLETE", flush=True)
`, tag, port)
		if err := os.WriteFile(filepath.Join(proj, "loopback.py"), []byte(script), 0o644); err != nil {
			t.Fatal(err)
		}
		// @podman-build, not @podman-socket alone: this test builds an image
		// (the /build endpoint requires policy.PodmanBuild — see
		// dockerproxy.handleBuild's own gate), and @podman-socket alone
		// deny()s the build without draining the multi-MB context tar the
		// client is still sending, which surfaced as a python-side
		// BrokenPipeError rather than as a readable refusal the first time
		// this test was written.
		args := []string{"-p", "@podman-build"}
		if withNet {
			args = append(args, "-p", "@net")
		}
		r := runEnv(t, env, args, proj, `python3 loopback.py`).mustRun(t)
		if !strings.Contains(r.out, "PROBE-COMPLETE") {
			t.Fatalf("the container-loopback probe did not run to the end (withNet=%v):\n%s", withNet, r.out)
		}
		if !strings.Contains(r.out, fmt.Sprintf("BUILD %s: 200", tag)) {
			t.Fatalf("the from-scratch image did not build (withNet=%v) — this test proves "+
				"nothing about a container it never ran:\n%s", withNet, r.out)
		}
		if !strings.Contains(r.out, "LOGS-BEGIN") || !strings.Contains(r.out, "RESULT") {
			t.Fatalf("the container never produced its own RESULT lines (withNet=%v) — it did "+
				"not actually run:\n%s", withNet, r.out)
		}
		return r.out
	}

	for _, tc := range []struct {
		withNet bool
		tag     string
	}{
		{false, "snugtest-loopback-offline:1"},
		{true, "snugtest-loopback-net:1"},
	} {
		out := probeOnce(tc.withNet, tc.tag)
		if strings.Contains(out, hostBanner) {
			t.Errorf("a container (NetworkMode=host, @net=%v) READ the host's loopback banner:\n%s",
				tc.withNet, out)
		}
		if strings.Contains(out, "RESULT v4-loop REACHED") {
			t.Errorf("a container (NetworkMode=host, @net=%v) REACHED the host's 127.0.0.1 listener:\n%s",
				tc.withNet, out)
		}
		if strings.Contains(out, "RESULT gw REACHED") {
			t.Errorf("a container (NetworkMode=host, @net=%v) REACHED the gateway address — the "+
				"one --map-host-loopback actually controls:\n%s", tc.withNet, out)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ── 3. no abstract sockets, and the engine's pid is not in the sandbox's pidns ─

// TestNoAbstractSocketsWithEngineInN checks the ordinary sandboxed PAYLOAD's
// own view (not a container's) while a real engine is running: `ss -xl`
// inside the sandbox must report zero abstract sockets, and the engine's own
// host-visible pid must not appear in the sandbox's private pid namespace.
//
// The parenthetical here used to justify "host-visible" with "the stage does
// not use CLONE_NEWPID, so nothing under it does either". The stage still does
// not, but issue #125's C0 put CLONE_NEWPID on the ENGINE's own clone
// (internal/stage/enginefork.go), so the second half is false. The pid this
// test hands the payload is host-visible for a different and stronger reason:
// a nested pid namespace does not hide its members from an ANCESTOR's procfs,
// so the engine is still enumerable under its host pid — which is also why
// internal/engine/reap.go's socket-path sweep is unaffected by C0. What the
// assertion means is unchanged: that host pid must not resolve inside the
// SANDBOX's own pid namespace, which is a sibling of neither.
func TestNoAbstractSocketsWithEngineInN(t *testing.T) {
	budget(t, 60*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	bg := startAttachSandbox(t, env, []string{"-p", "@podman-socket"}, proj, `sleep 300`)
	bg.ready(t)
	bg.waitForState(t)

	enginePID := findEnginePID(t, os.Getuid(), bg.pid())

	script := fmt.Sprintf(`
python3 - <<'EOF'
import http.client, socket, os
class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost"); self.path = path
    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(self.path); self.sock = s
sock = os.environ["CONTAINER_HOST"].replace("unix://", "")
c = UnixHTTP(sock); c.request("GET", "/v1.41/version"); r = c.getresponse(); r.read()
print("version: %%d" %% r.status)
EOF
echo "---SS---"
ss -xl
echo "---PROC---"
ls -d /proc/%d 2>&1
echo DONE
`, enginePID)

	r := attachScript(t, env, proj, script)
	if !strings.Contains(r.out, "DONE") {
		t.Fatalf("the probe did not run to the end:\n%s", r.out)
	}
	// CONTROL: the engine actually answers, so this is a live-engine
	// observation and not a probe that ran against nothing.
	if !strings.Contains(r.out, "version: 200") {
		t.Fatalf("control: the engine did not answer /version from inside the sandbox:\n%s", r.out)
	}

	_, ssSection, procSection := cutTwice(r.out, "---SS---", "---PROC---")
	// Abstract sockets are rendered by ss as "@name" in the local-address
	// column. Any "@" in this section is an abstract listener the sandbox can
	// see, which must be none.
	for _, line := range strings.Split(ssSection, "\n") {
		if strings.Contains(line, "@") {
			t.Errorf("`ss -xl` inside the sandbox shows an abstract socket while a real engine "+
				"is running:\n%s", ssSection)
			break
		}
	}
	if strings.TrimSpace(ssSection) == "" {
		t.Errorf("`ss -xl` produced no output at all — this test cannot tell an empty listing "+
			"from a broken probe:\n%s", r.out)
	}

	if !strings.Contains(procSection, "No such file or directory") {
		t.Errorf("the engine's own pid (%d, host-visible: a nested pid namespace does not hide "+
			"its members from an ancestor's procfs) IS visible in the sandbox's own /proc — the "+
			"sandbox's pid namespace does not actually exclude it:\n%s", enginePID, r.out)
	}
}

func cutTwice(s, a, b string) (before, mid, after string) {
	i := strings.Index(s, a)
	if i < 0 {
		return s, "", ""
	}
	rest := s[i+len(a):]
	j := strings.Index(rest, b)
	if j < 0 {
		return s[:i], rest, ""
	}
	return s[:i], rest[:j], rest[j+len(b):]
}

// ── shared: find the engine's own pid from the HOST side, by socket path ────

// engineSocketPath is what internal/engine.New computes: New's own doc
// comment pins the shape — /tmp/snug-<uid>-<pid>/sock/podman-<pid>.sock, where
// pid is the SNUG PROCESS's own pid (the first Engine.New call in that
// process; a real run only ever makes one). Recomputed here rather than
// imported, deliberately: this is the HOST's own view of a path a container
// never sees (TestContainerSocketNeverExposesEngineSocketDir, internal/cli, is
// the guard that it never reaches the sandbox), so a test that wants to
// observe it from outside has to know the same shape independently.
//
// The `sock/` element arrived with issue #125's C2b split, and the drift was
// caught by the failure message findEnginePID already carried — "either the
// engine never started, or this test's own path computation has drifted from
// internal/engine.New's". An independent restatement is only worth its
// duplication if it says which of the two happened when it disagrees; this
// one did.
func engineSocketPath(uid, snugPID int) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("snug-%d-%d", uid, snugPID),
		"sock", fmt.Sprintf("podman-%d.sock", snugPID))
}

// findEnginePID polls /proc for a process whose cmdline names sock — the
// SAME identify-by-path discipline internal/engine/reap.go uses for
// teardown, reimplemented here (that function is unexported) rather than
// trusted blind: this file's own positive controls are what confirm it
// actually finds something.
func findEnginePID(t *testing.T, uid, snugPID int) int {
	t.Helper()
	sock := engineSocketPath(uid, snugPID)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if pids := pidsNamingCmdlineSubstring(sock); len(pids) > 0 {
			return pids[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no process ever named the engine's own socket path %s in its cmdline "+
				"within 30s — either the engine never started, or this test's own path "+
				"computation has drifted from internal/engine.New's", sock)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// pidsNamingCmdlineSubstring is ownedPIDs from internal/engine/reap.go,
// reimplemented for the same reason findEnginePID's own doc gives.
func pidsNamingCmdlineSubstring(substr string) []int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, ent := range ents {
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + ent.Name() + "/cmdline")
		if err != nil || len(raw) == 0 {
			continue
		}
		cmdline := strings.ReplaceAll(string(raw), "\x00", " ")
		if strings.Contains(cmdline, substr) {
			out = append(out, pid)
		}
	}
	return out
}

// ── 4. the engine's netns/process does not survive a SIGKILL ───────────────

// TestEngineNetnsReapedOnSIGKILL is the standing gate applied to Tier B: a
// hard-killed snug must leave nothing behind that still names this run's
// engine socket, exactly as internal/stage's own SIGKILL tests already
// guard for the sandbox and the stage itself (TestTheStageLeavesNoNamespaceObjectAfterSIGKILL) —
// this is the same property one layer further out, now that a SECOND
// long-lived process (the engine) exists per run.
//
// Asserted by SOCKET-PATH substring in /proc/*/cmdline, never by `comm` (the
// CLAUDE.md-documented pasta.avx2 lesson: a dispatched or renamed binary's
// `comm` need not match anything you searched for) and never by the shared
// store path (which would also match a concurrent sibling sandbox's engine —
// see internal/engine/reap.go's own "accident sentence").
func TestEngineNetnsReapedOnSIGKILL(t *testing.T) {
	budget(t, 60*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	bg := startAttachSandbox(t, env, []string{"-p", "@podman-socket"}, proj, `sleep 300`)
	bg.ready(t)
	bg.waitForState(t)

	sock := engineSocketPath(os.Getuid(), bg.pid())

	// CONTROL: it DID exist before the kill.
	before := pidsNamingCmdlineSubstring(sock)
	if len(before) == 0 {
		t.Fatalf("no process named the engine's socket path %s before the kill — this test "+
			"would prove nothing about teardown", sock)
	}

	if err := syscall.Kill(bg.pid(), syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL snug (pid %d): %v", bg.pid(), err)
	}

	deadline := time.Now().Add(20 * time.Second)
	var left []int
	for {
		left = pidsNamingCmdlineSubstring(sock)
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(left) > 0 {
		t.Errorf("after SIGKILL, %d process(es) still name the engine's socket path %s in "+
			"their cmdline: %v", len(left), sock, left)
	}
}

// ── 5. no host nsfs bind under /run/user/<uid>/netns/ survives a real run ───

// TestHostNsfsBindsDoNotLeak is the negative half of the same finding
// ENGINE-NETNS.md §1 fixed with MS_REC|MS_PRIVATE in __inengine: a container
// engine that is not careful about mount propagation can leave a network
// namespace filesystem bind visible on the HOST under
// /run/user/<uid>/netns/, which survives the sandbox's own teardown. This
// drives an actual, complete container lifecycle (build with a RUN step,
// same as probeRealEngine's own control) and diffs the host's netns
// directory by NAME before and after.
func TestHostNsfsBindsDoNotLeak(t *testing.T) {
	budget(t, 120*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)

	netnsDir := fmt.Sprintf("/run/user/%d/netns", os.Getuid())
	before := readDirNamesOrEmpty(netnsDir)

	proj, _ := target(t)
	if err := os.WriteFile(filepath.Join(proj, "probe.py"), []byte(buildProbe), 0o644); err != nil {
		t.Fatal(err)
	}
	// CONTROL: the run really did build AND run a container (BUILT-INSIDE-SNUG
	// only appears if the RUN step actually executed).
	r := runEnv(t, env, []string{"-p", "@podman-build", "-p", "@net"}, proj, `python3 probe.py`).mustRun(t)
	if !strings.Contains(r.out, "ordinary build: 200") || !strings.Contains(r.out, "BUILT-INSIDE-SNUG") {
		t.Fatalf("control: the real container run this test's leak-check depends on did not "+
			"actually happen:\n%s", r.out)
	}

	after := readDirNamesOrEmpty(netnsDir)
	beforeSet := map[string]bool{}
	for _, n := range before {
		beforeSet[n] = true
	}
	var newEntries []string
	for _, n := range after {
		if !beforeSet[n] {
			newEntries = append(newEntries, n)
		}
	}
	if len(newEntries) > 0 {
		t.Errorf("%s gained new entries after a real container run + teardown: %v — a network "+
			"namespace filesystem bind survived on the host", netnsDir, newEntries)
	}
}

func readDirNamesOrEmpty(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// ── 6. preflight refuses an unconfinable engine, and starts NO stage at all ─

// TestPreflightRefusesUnconfinableEngine is P1/P2/P3 (containerpreflight.go):
// every refusal must name the fix and, per invariant 5 ("no silent
// downgrade") and the design's own repeated emphasis, must refuse BEFORE a
// single namespace exists — never fall back to a host-netns engine. "No
// stage at all" is asserted the same way the rest of this suite asserts a
// negative process-tree claim: nothing in /proc names this run once snug has
// exited.
//
// P6 (ptrace_scope) is a real host sysctl this test does not mock (it would
// need either root to flip it or a mount-namespace trick riskier than the
// property is worth); it is left to redteam/by-hand per the working
// agreement's own escape hatch for exactly this shape.
//
// Positive control, shared by all three cases: on THIS host, with nothing
// faked, the engine starts (the same lightweight bg-start-and-ready pattern
// TestNoAbstractSocketsWithEngineInN uses, without needing a full image
// pull).
func TestPreflightRefusesUnconfinableEngine(t *testing.T) {
	budget(t, 60*time.Second)
	env, _ := containerEngineEnv(t)
	requireSandbox(t)

	t.Run("control: engine starts when nothing is faked", func(t *testing.T) {
		proj, _ := target(t)
		bg := startAttachSandbox(t, env, []string{"-p", "@podman-socket"}, proj, `sleep 5`)
		bg.ready(t)
		bg.waitForState(t)
		// bg's own t.Cleanup kills it; reaching here means the payload started,
		// which (per Engine.DialLifeline's own doc) only happens after the
		// engine reported ready.
	})

	t.Run("P1: podman resolves to a host-escape shim", func(t *testing.T) {
		fakePATH := t.TempDir()
		shim := filepath.Join(fakePATH, "distrobox-host-exec")
		if err := os.WriteFile(shim, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(shim, filepath.Join(fakePATH, "podman")); err != nil {
			t.Fatal(err)
		}
		realPATH := os.Getenv("PATH")
		fakeEnv := append(append([]string{}, env...), "PATH="+fakePATH+":"+realPATH)
		// SNUG_PODMAN must NOT be set here — this case is specifically about
		// what an UNSET override falls back to (PATH resolution), so strip it
		// rather than let the earlier SNUG_PODMAN= entry from containerEngineEnv
		// win by being later.
		fakeEnv = dropEnv(fakeEnv, "SNUG_PODMAN")

		proj, _ := target(t)
		r := runEnv(t, fakeEnv, []string{"-p", "@podman-socket"}, proj, `echo SHOULD-NOT-RUN`)
		assertPreflightRefusal(t, r, proj, "distrobox-host-exec")
	})

	t.Run("P3: newuidmap/newgidmap missing from PATH", func(t *testing.T) {
		fakePATH := t.TempDir() // deliberately empty: nothing needed reaches this refusal
		fakeEnv := append(append([]string{}, env...), "PATH="+fakePATH)
		proj, _ := target(t)
		r := runEnv(t, fakeEnv, []string{"-p", "@podman-socket"}, proj, `echo SHOULD-NOT-RUN`)
		assertPreflightRefusal(t, r, proj, "newuidmap")
	})

	t.Run("P2: /etc/subuid has no range for this uid", func(t *testing.T) {
		if _, err := exec.LookPath("bwrap"); err != nil {
			t.Skip("SKIP: bwrap not found")
		}
		proj, _ := target(t)
		out, code := runUnderMaskedSubuid(t, env, "-p", "@podman-socket", proj, "--", "/bin/echo", "SHOULD-NOT-RUN")
		if strings.Contains(out, "SHOULD-NOT-RUN") {
			t.Fatalf("the payload ran despite a masked /etc/subuid:\n%s", out)
		}
		if code == 0 {
			t.Errorf("snug exited 0 with a masked /etc/subuid, want a refusal:\n%s", out)
		}
		if !strings.Contains(strings.ToLower(out), "subuid") {
			t.Errorf("the refusal does not name subuid, the actual fix:\n%s", out)
		}
		assertNoStageStarted(t, proj)
	})
}

// dropEnv removes every "KEY=..." entry whose key is name, keeping the last
// remaining assignment (os/exec's own "last duplicate wins" rule) undisturbed
// for every other key.
func dropEnv(env []string, name string) []string {
	prefix := name + "="
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// assertPreflightRefusal is the common shape P1/P3 both check: the payload
// marker never appears (the payload never ran), snug exits non-zero, the
// message names fix, and no stage-shaped process is left behind.
func assertPreflightRefusal(t *testing.T, r sandboxRun, proj, wantInMessage string) {
	t.Helper()
	if r.ran {
		t.Fatalf("the payload RAN despite the faulted preflight condition:\n%s", r.out)
	}
	if r.code == 0 {
		t.Errorf("snug exited 0, want a refusal:\n%s", r.out)
	}
	if !strings.Contains(r.out, wantInMessage) {
		t.Errorf("the refusal does not mention %q, so it does not name the fix:\n%s", wantInMessage, r.out)
	}
	assertNoStageStarted(t, proj)
}

// assertNoStageStarted is invariant 5 applied to this refusal specifically:
// preflight must refuse BEFORE a single namespace exists, so nothing in
// /proc may still reference this target directory once snug (already exited
// by the time this runs, since cli()/runEnv() waited for it) is gone.
func assertNoStageStarted(t *testing.T, proj string) {
	t.Helper()
	if pids := pidsNamingCmdlineSubstring(proj); len(pids) > 0 {
		t.Errorf("a preflight refusal left process(es) still naming the target directory: %v", pids)
	}
}

// runUnderMaskedSubuid execs snugBin inside a throwaway bwrap wrapper that
// bind-mounts /dev/null over /etc/subuid, so the REAL host file is never
// touched. bwrap is already a requireSandbox precondition; this reuses it as
// the harness rather than the production `unshare`/mount machinery
// containerpreflight.go itself has no injection point for (CheckSubuidDelegation
// reads a hardcoded /etc/subuid path — deliberately, per its own doc comment
// on why that check is not overridable — so this is the only clean way to
// mock "empty" without editing a real system file).
func runUnderMaskedSubuid(t *testing.T, env []string, args ...string) (string, int) {
	t.Helper()
	full := []string{
		"--unshare-user", "--unshare-pid",
		"--bind", "/", "/",
		"--dev-bind", "/dev", "/dev",
		"--proc", "/proc",
		"--ro-bind", "/dev/null", "/etc/subuid",
		"--die-with-parent",
		"--", snugBin,
	}
	full = append(full, args...)

	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bwrap", full...)
	cmd.Env = env
	cmd.WaitDelay = waitDelay
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("runUnderMaskedSubuid did not finish within %s:\n%s", cmdTimeout, out)
	}
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			t.Fatalf("running snug under a masked-subuid bwrap wrapper: %v\n%s", err, out)
		}
	}
	return string(out), code
}

// ── 7. the running engine's capability set is EXACTLY the bounding set ─────

// TestEngineCapBoundingInU is the "verify the security feature is ACTIVE, not
// merely requested" assertion for the capability drop — the `--seccomp`-
// after-`--` lesson (CLAUDE.md) applied to PR_CAPBSET_DROP/capset.
// internal/stage/capdrop_test.go already proves the MECHANISM
// (dropCapsToExactly) produces the right numbers in a synthetic fresh
// userns; this proves the REAL stage-forked engine — root-in-U, inheriting
// the sandbox's own user namespace, in its own private cgroup namespace,
// immediately before its execve into podman — actually has it, by reading
// the RUNNING engine's own /proc/<enginepid>/status from the host. Reading
// the child pre-exec (as capdrop_test.go's synthetic case does) would mean
// instrumenting the production EnterEngine path itself, which is out of
// scope for a test-only change (CLAUDE.md's "do not touch feature code");
// this is the documented fallback the task's own spec names.
func TestEngineCapBoundingInU(t *testing.T) {
	budget(t, 60*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	bg := startAttachSandbox(t, env, []string{"-p", "@podman-socket"}, proj, `sleep 300`)
	bg.ready(t)
	bg.waitForState(t)

	enginePID := findEnginePID(t, os.Getuid(), bg.pid())

	// CONTROL: it really is running and answering, not a stale pid reused by
	// something else.
	r := attachScript(t, env, proj, `
python3 - <<'EOF'
import http.client, socket, os
class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost"); self.path = path
    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(self.path); self.sock = s
sock = os.environ["CONTAINER_HOST"].replace("unix://", "")
c = UnixHTTP(sock); c.request("GET", "/v1.41/version"); r = c.getresponse(); r.read()
print("version: %d" % r.status)
EOF
`)
	if !strings.Contains(r.out, "version: 200") {
		t.Fatalf("control: the engine at pid %d does not answer /version:\n%s", enginePID, r.out)
	}

	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", enginePID))
	if err != nil {
		t.Fatalf("reading /proc/%d/status: %v", enginePID, err)
	}
	capEff, capBnd := parseCapStatus(t, string(status))

	wantMask := engineCapMask()
	if capEff != wantMask {
		t.Errorf("running engine (pid %d) CapEff = %#x, want %#x (policy.EngineCapBounding)",
			enginePID, capEff, wantMask)
	}
	if capBnd != wantMask {
		t.Errorf("running engine (pid %d) CapBnd = %#x, want %#x — the BOUNDING set must be "+
			"reduced too, not just Effective", enginePID, capBnd, wantMask)
	}
	ptraceBit := uint64(1) << uint(unix.CAP_SYS_PTRACE)
	if capEff&ptraceBit != 0 || capBnd&ptraceBit != 0 {
		t.Errorf("CAP_SYS_PTRACE is present on the RUNNING engine (pid %d): CapEff=%#x CapBnd=%#x",
			enginePID, capEff, capBnd)
	}
	netAdminBit := uint64(1) << uint(unix.CAP_NET_ADMIN)
	if capEff&netAdminBit != 0 || capBnd&netAdminBit != 0 {
		t.Errorf("CAP_NET_ADMIN is present on the RUNNING engine (pid %d): CapEff=%#x CapBnd=%#x",
			enginePID, capEff, capBnd)
	}
}

// engineCapMask independently re-derives the expected bit mask from
// policy.EngineCapBounding using golang.org/x/sys/unix's own CAP_* constants
// — the same externally-stable kernel ABI internal/stage/capdrop.go's private
// engineCapBit map uses, not a read of that map itself (which
// TestEngineCapBoundingCapsAllHaveAKnownBit already guards is complete and
// correct, independently of this file).
func engineCapMask() uint64 {
	bit := map[string]int{
		"CAP_CHOWN": unix.CAP_CHOWN, "CAP_DAC_OVERRIDE": unix.CAP_DAC_OVERRIDE,
		"CAP_FOWNER": unix.CAP_FOWNER, "CAP_FSETID": unix.CAP_FSETID,
		"CAP_KILL": unix.CAP_KILL, "CAP_SETGID": unix.CAP_SETGID,
		"CAP_SETUID": unix.CAP_SETUID, "CAP_SETPCAP": unix.CAP_SETPCAP,
		"CAP_NET_BIND_SERVICE": unix.CAP_NET_BIND_SERVICE, "CAP_SYS_CHROOT": unix.CAP_SYS_CHROOT,
		"CAP_SETFCAP": unix.CAP_SETFCAP, "CAP_SYS_ADMIN": unix.CAP_SYS_ADMIN,
	}
	var mask uint64
	for _, name := range engineCapBoundingNames {
		if b, ok := bit[name]; ok {
			mask |= 1 << uint(b)
		}
	}
	return mask
}

// engineCapBoundingNames mirrors policy.EngineCapBounding's 12 names. Not
// imported directly to keep this file's build tag (integration) independent
// of importing internal/policy just for this one slice — TestEngineCapBoundingIsTheMeasuredTwelve
// (internal/policy) is the drift guard that keeps this list honest; if it
// ever diverges, that test's own count assertion is what will catch it, not
// this file silently computing a stale mask.
var engineCapBoundingNames = []string{
	"CAP_SYS_ADMIN", "CAP_SYS_CHROOT", "CAP_CHOWN", "CAP_DAC_OVERRIDE",
	"CAP_FOWNER", "CAP_FSETID", "CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP",
	"CAP_SETFCAP", "CAP_KILL", "CAP_NET_BIND_SERVICE",
}

func parseCapStatus(t *testing.T, status string) (eff, bnd uint64) {
	t.Helper()
	for _, ln := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(ln, "CapEff:\t"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				t.Fatalf("parsing CapEff line %q: %v", ln, err)
			}
			eff = n
		}
		if v, ok := strings.CutPrefix(ln, "CapBnd:\t"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				t.Fatalf("parsing CapBnd line %q: %v", ln, err)
			}
			bnd = n
		}
	}
	return eff, bnd
}

// ── 8. a container's /etc/resolv.conf is snug's generated one, never the ─────
//      HOST's real one (issue #126)

// resolvprobeBinOnce/resolvprobeBinPath/resolvprobeBinErr mirror
// netprobeBinOnce/netprobeBinPath/netprobeBinErr above — same lazy,
// per-calling-test build, same reasoning.
var (
	resolvprobeBinOnce sync.Once
	resolvprobeBinPath string
	resolvprobeBinErr  error
)

func resolvprobeBin(t *testing.T) string {
	t.Helper()
	resolvprobeBinOnce.Do(func() {
		dir := t.TempDir()
		bin := filepath.Join(dir, "resolvprobe")
		cmd := exec.Command("go", "build", "-o", bin, "./testdata/resolvprobe")
		cmd.Dir = "."
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			resolvprobeBinErr = fmt.Errorf("building test/integration/testdata/resolvprobe: %w: %s", err, out.String())
			return
		}
		resolvprobeBinPath = bin
	})
	if resolvprobeBinErr != nil {
		t.Fatal(resolvprobeBinErr)
	}
	return resolvprobeBinPath
}

// buildScratchResolvProbeImage is buildScratchProbeImage's own shape, copying
// resolvprobe instead of netprobe — a `FROM scratch` image needs no base
// layer and therefore no registry pull, so this builds with the sandbox's
// egress CLOSED, exactly what the offline half of
// TestContainerGetsGeneratedResolvConfNotTheHosts needs.
func buildScratchResolvProbeImage(tag string) string {
	return buildScratchProbeImageFor(tag, "resolvprobe")
}

// buildScratchProbeImage is the same thing for any probe binary the payload
// has already written into its target directory — resolvprobe for issue #126,
// confprobe for issue #132. The image is `FROM scratch` with nothing but the
// binary, so it builds with the sandbox's egress CLOSED and needs no registry.
func buildScratchProbeImageFor(tag, bin string) string {
	return pyPreamble + fmt.Sprintf(`
import tarfile, io, urllib.parse

def build_scratch_probe():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        dockerfile = ("FROM scratch\nCOPY %[2]s /%[2]s\nENTRYPOINT [\"/%[2]s\"]\n").encode()
        ti = tarfile.TarInfo("Dockerfile"); ti.size = len(dockerfile)
        tf.addfile(ti, io.BytesIO(dockerfile))
        with open(%[2]q, "rb") as f:
            data = f.read()
        ti2 = tarfile.TarInfo(%[2]q); ti2.size = len(data); ti2.mode = 0o755
        tf.addfile(ti2, io.BytesIO(data))
    ctx = buf.getvalue()
    q = {"dockerfile": '["Dockerfile"]', "t": %[1]q, "output": %[1]q,
         "networkmode": "0", "nsoptions": '[{"Name":"user","Host":true,"Path":""}]',
         "isolation": "0", "rm": "1", "layers": "1", "pullpolicy": "missing",
         "seccomp": "/usr/share/containers/seccomp.json", "shmsize": "67108864",
         "nocache": "1"}
    status, body = req("POST", "/v5.0.0/libpod/build?" + urllib.parse.urlencode(q), ctx,
                        {"Content-Type": "application/x-tar"})
    print("BUILD %%s: %%d" %% (%[1]q, status), flush=True)
    if status != 200:
        print("BUILD-BODY-TAIL: %%s" %% body[-500:].decode(errors="replace"), flush=True)
    return status == 200
`, tag, bin)
}

// section extracts the text strictly between a "LABEL-BEGIN" and "LABEL-END"
// marker LINE pair, as resolvprobe (testdata/resolvprobe/main.go) prints
// them. Line-anchored — matching a whole line, not a bare substring — on
// purpose: "RESOLV-BEGIN" is a SUFFIX of "PAYLOAD-RESOLV-BEGIN" (this file's
// own marker for the sandbox payload's own /etc/resolv.conf, printed earlier
// in the same script's output), so a plain strings.Index(out, "RESOLV-BEGIN")
// finds that unrelated line first and silently extracts the wrong section —
// measured, the first version of this helper did exactly that. Returns
// ("", false) if either marker is missing, so a caller can distinguish "empty
// content" from "the probe never even produced this section" — the same
// distinction CLAUDE.md's own "a test that cannot fail" rule cares about
// elsewhere in this file.
func section(out, label string) (string, bool) {
	// TrimRight "\r": run_and_collect's own container is created with
	// Tty=true (runContainerAndCollectFn's doc comment — "so the compat
	// logs endpoint needs no stream-framing decode"), and a tty gives every
	// line a trailing \r before the \n. An exact-line match against
	// "RESOLV-END" would otherwise never fire, and did not the first time
	// this was measured: every line here carried it.
	lines := strings.Split(out, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	begin, end := -1, -1
	for i, ln := range lines {
		if ln == label+"-BEGIN" {
			begin = i
			break
		}
	}
	if begin < 0 {
		return "", false
	}
	for i := begin + 1; i < len(lines); i++ {
		if lines[i] == label+"-END" {
			end = i
			break
		}
	}
	if end < 0 {
		return "", false
	}
	return strings.Join(lines[begin+1:end], "\n"), true
}

// hostRealResolvConf reads THIS TEST PROCESS's own (host, unsandboxed)
// /etc/resolv.conf and returns the "nameserver X" addresses it names — the
// exact strings issue #126 measured leaking into a container verbatim
// (`nameserver 192.168.1.1`, a ULA `nameserver fdde:...`). A real value on
// the CI/dev host running this test, not a literal pinned here, so the
// assertion holds on any host's own LAN shape rather than only the one this
// fix was found on.
func hostRealResolvConfNameservers(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Skip("SKIP: cannot read this host's own /etc/resolv.conf to know what a leak would look " +
			"like: " + err.Error())
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "nameserver "); ok {
			servers = append(servers, strings.TrimSpace(v))
		}
	}
	return servers
}

// TestContainerGetsGeneratedResolvConfNotTheHosts is the regression test for
// issue #126: EnterEngine used to mount a private COPY of the host's own
// mount tree (internal/stage/inengine.go step 4) with nothing done to
// /etc/resolv.conf in it, so podman generated every container's own
// /etc/resolv.conf FROM the HOST's real one — an offline sandbox's container
// learned the host LAN's nameservers, a channel the proxy's bind filter
// (internal/dockerproxy/create.go) never sees because it is not a
// client-requested mount.
//
// Two assertions, per the fix's own spec:
//
//  1. THE FIX ITSELF: an offline (@podman-build, no @net) container's
//     /etc/resolv.conf does not contain any address this test's own host
//     /etc/resolv.conf names as a nameserver — the literal leak measured in
//     issue #126, expressed host-agnostically so it holds on whatever LAN
//     shape the machine running this test has, not just the one the bug was
//     found on.
//  2. THE POSITIVE CONTROL: the sandbox PAYLOAD's own /etc/resolv.conf
//     — read directly, inside the very same python process the probe
//     container was built from — equals policy.NetPolicy{Mode:
//     policy.NetIsolated}.ResolvConf() byte for byte. That is what proves
//     the sandbox really is offline and that the generation path ran at all;
//     without it the assertion above could pass on a run that never got as
//     far as producing a policy.
//
// WHICH mechanism the first assertion is testing changed, and the note here
// used to name the wrong one. It said "EnterEngine now bind-mounts the SAME
// generated content over the engine's own /etc/resolv.conf". That bind still
// happens and is still worth having — but it is BEST-EFFORT since #126's
// second half, and on this development host it FAILS outright (issue #128:
// /etc/resolv.conf is itself a bind over a deleted inode, so mounting onto it
// returns ENOENT) while this test passes. What actually keeps the host's
// nameservers out of a container is snug's generated containers.conf —
// `dns_servers`/`dns_searches`/`dns_options`, written from the same resolved
// policy.NetPolicy — which needs no mount to take effect. A container's DNS
// is decided by configuration; the engine's own is decided by the bind.
//
// What this test does NOT do, and why: re-run the identical scenario against
// a build that lacks the fix, to assert the negative directly. There is no
// clean way to flip that mechanism off from inside a single committed test
// binary without reintroducing the very code path issue #126 removed. The
// negative WAS measured by hand, on this branch, before and after the fix
// (commit history + PR #117's own description carry the numbers): the
// offline container's /etc/resolv.conf held this host's real `nameserver
// 192.168.1.1` / `nameserver fdde:...` lines verbatim before the fix, and
// carried none of them after it.
//
// /etc/hosts IS part of this test now, and the reason it once was not has
// been measured wrong. The earlier note here read "podman synthesizes it
// independently of whatever the engine's own /etc/hosts says, so there is
// nothing for EnterEngine to shadow". True of the docker-compat API path this
// test drives — and false of the CLI path, where a planted host entry
// (`10.1.2.3 secret-internal.corp`) reached the container verbatim. So the
// no-leak state this test observed was an accident of which schema the proxy
// happens to allow, not a property snug asserted, and one schema change away
// from silently becoming a leak.
//
// `base_hosts_file = "none"` in snug's generated containers.conf makes it
// structural on both paths, and the assertion below is written to notice a
// leak from EITHER: rather than hunting for one planted string (which needs a
// root-writable /etc/hosts no committed test may assume), it asserts the SET —
// every hostname in the container's /etc/hosts must be one podman itself
// synthesizes. Anything else came from outside.
//
// State plainly what this second assertion can and cannot catch, because it
// looks stronger than it is. MEASURED, by deleting `base_hosts_file` from the
// generated config and re-running: this test still PASSES. Two reasons, and
// neither is that the key does nothing. First, the path this test drives is
// the docker-compat API — the only one the proxy allows — and on that path
// podman synthesizes /etc/hosts rather than copying; the copy was measured on
// the CLI path, which nothing inside a snug sandbox can reach today. Second,
// this development host's own /etc/hosts names nothing but standard localhost
// and ipv6-* entries, so even a copy would carry little to recognise.
//
// So: the key's PRESENCE is held by TestGeneratedContainersConfTakesDNSFromThe
// ResolvedPolicy, a unit test that fails the moment it goes. What this
// assertion adds is the thing no unit test can see — a future schema, proxy
// rule or podman version that reopens a copying path gets caught here, on any
// host whose /etc/hosts names something of its own.
func TestContainerGetsGeneratedResolvConfNotTheHosts(t *testing.T) {
	budget(t, 120*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	hostNameservers := hostRealResolvConfNameservers(t)

	proj, _ := target(t)
	if err := os.WriteFile(filepath.Join(proj, "resolvprobe"), mustRead(t, resolvprobeBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}

	tag := "snugtest-resolvconf-offline:1"
	script := buildScratchResolvProbeImage(tag) + runContainerAndCollectFn + fmt.Sprintf(`
payload_resolv = open("/etc/resolv.conf").read()
print("PAYLOAD-RESOLV-BEGIN", flush=True)
print(payload_resolv, flush=True)
print("PAYLOAD-RESOLV-END", flush=True)
if build_scratch_probe():
    run_and_collect(%q, [], "host")
print("PROBE-COMPLETE", flush=True)
`, tag)
	if err := os.WriteFile(filepath.Join(proj, "resolvconf.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	// @podman-build, not @podman-socket alone, for the same reason
	// TestHostLoopbackClosedFromContainer's own probeOnce gives: this test
	// builds an image, which needs policy.PodmanBuild. No @net: this is the
	// offline case issue #126 was found on.
	r := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 resolvconf.py`).mustRun(t)
	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the resolv.conf probe did not run to the end:\n%s", r.out)
	}
	if !strings.Contains(r.out, fmt.Sprintf("BUILD %s: 200", tag)) {
		t.Fatalf("the from-scratch probe image did not build — this test proves nothing about a "+
			"container it never ran:\n%s", r.out)
	}
	if !strings.Contains(r.out, "LOGS-BEGIN") {
		t.Fatalf("the container never produced logs — it did not actually run:\n%s", r.out)
	}

	// CONTROL 2 first: the generation path itself, proven independently of
	// the container.
	payloadResolv, ok := section(r.out, "PAYLOAD-RESOLV")
	if !ok {
		t.Fatalf("the payload never printed its own /etc/resolv.conf:\n%s", r.out)
	}
	wantPayload := string(policy.NetPolicy{Mode: policy.NetIsolated}.ResolvConf())
	if strings.TrimRight(payloadResolv, "\n") != strings.TrimRight(wantPayload, "\n") {
		t.Fatalf("control: the sandbox PAYLOAD's own /etc/resolv.conf is not the offline-generated "+
			"content this test compares the container against — got %q, want %q", payloadResolv, wantPayload)
	}

	// CONTROL 1: the probe container actually produced a RESOLV section at
	// all, so an absent leak below is a proven negative rather than a probe
	// that silently did not run.
	containerResolv, ok := section(r.out, "RESOLV")
	if !ok {
		t.Fatalf("the container never printed a RESOLV section — it did not actually run "+
			"resolvprobe:\n%s", r.out)
	}

	// THE ASSERTION: no address this test's own host names as a nameserver
	// appears in the offline container's /etc/resolv.conf.
	for _, ns := range hostNameservers {
		if strings.Contains(containerResolv, ns) {
			t.Errorf("an OFFLINE container's /etc/resolv.conf contains this host's real nameserver "+
				"%q — the host LAN topology leak issue #126 fixed:\n%s", ns, r.out)
		}
	}
	if strings.TrimSpace(containerResolv) != "" {
		t.Logf("offline container /etc/resolv.conf was non-empty but held no host nameserver "+
			"(podman writes what snug's generated containers.conf names in dns_servers, which "+
			"offline is a server that resolves nothing): %q", containerResolv)
	}

	// THE SECOND ASSERTION (issue #126's other half): the container's
	// /etc/hosts names nothing the host's own /etc/hosts could have supplied.
	//
	// CONTROL: resolvprobe prints a HOSTS section unconditionally, so an
	// absent section is a probe that did not run rather than a clean result —
	// checked first, exactly as the RESOLV control above is.
	containerHosts, ok := section(r.out, "HOSTS")
	if !ok {
		t.Fatalf("the container never printed a HOSTS section — it did not actually run "+
			"resolvprobe:\n%s", r.out)
	}
	// CONTROL: the file must NAME something, and hostnamesIn must be able to
	// read it. An empty result would make the loop below vacuous — a test that
	// passes because it examined nothing. Measured: `127.0.0.1 localhost` and
	// `::1 localhost`, so `localhost` is the name that must be there.
	names := hostnamesIn(containerHosts)
	if len(names) == 0 {
		t.Fatalf("control: no hostname was read out of the container's /etc/hosts, so the "+
			"assertion below examined nothing:\n%q", containerHosts)
	}
	if !slices.Contains(names, "localhost") {
		t.Errorf("control: the container's /etc/hosts does not even name localhost, which podman "+
			"always writes — hostnamesIn is probably not parsing this file: %q", names)
	}
	for _, name := range names {
		if podmanSynthesizedHostname(name) {
			continue
		}
		t.Errorf("an OFFLINE container's /etc/hosts names %q, which podman does not synthesize — "+
			"it came from the HOST's own hosts table (issue #126):\n%s", name, containerHosts)
	}
}

// ── 6. a SIGNALLED run leaves no container of its own running (issue #113) ──

// holderBin builds testdata/holder for the host architecture, the same way
// netprobeBin builds netprobe and for the same reasons — it is the entrypoint
// of a `FROM scratch` image, so it must be static and it must be built here.
func holderBin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "holder")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/holder")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("building test/integration/testdata/holder: %v: %s", err, out.String())
	}
	return bin
}

// buildAndStartHolder is buildScratchProbeImage's create/start half without
// the wait: it starts a container and LEAVES it running, which is what a test
// about teardown needs and what run_and_collect deliberately does not do.
func buildAndStartHolder(tag, token string) string {
	return buildScratchProbeImage(tag) + fmt.Sprintf(`
def start_holder(tag, token):
    body = json.dumps({"Image": "localhost/" + tag, "Cmd": ["/netprobe", token],
                        "Tty": True, "HostConfig": {"NetworkMode": "host"}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:300]), flush=True)
    if status != 201:
        return
    cid = json.loads(resp)["Id"]
    status, _ = req("POST", "/v1.41/containers/%%s/start" %% cid)
    print("START: %%d %%s" %% (status, cid[:12]), flush=True)

if build_scratch_probe():
    start_holder(%[1]q, %[2]q)
print("HOLDER-LAUNCHED", flush=True)
import time
time.sleep(300)
`, tag, token)
}

// TestASignalledContainerRunLeavesNothingRunning is issue #113's ratchet, and
// it is a ratchet rather than a fix: it passed before the exclusion list
// existed and it passes after, which is exactly its job.
//
// The shape it locks. snug's signalled-teardown sweep (confirmTeardown) kills
// every descendant it finds, and the container reaper — the one helper
// deliberately built to OUTLIVE snug — is a direct child of snug. Before the
// exclusion list the sweep killed it, and that was harmless for a reason
// living in a different file: internal/cli's `defer ctrCleanup()` runs after
// sandbox.Run returns and did the container teardown itself. Two facts one
// edit apart from disagreeing — an early os.Exit on the signal path, and a
// signalled @podman-socket run leaks its containers.
//
// So this asserts the OUTCOME, from the host, with no knowledge of which of
// the two mechanisms delivered it: after a SIGTERM, nothing of this run's
// container is still running. TestConfirmTeardownSparesAnExcludedSubtree in
// internal/sandbox is the other half — it asserts the exclusion mechanism
// itself, which this test cannot see.
//
// The positive control is load-bearing and it is not a formality: the token
// MUST be observed alive on the host before the signal. Without that, a run
// whose container never started at all — a build failure, an engine that
// never came up, a proxy that refused — passes every assertion below, and
// "nothing survived" would be measuring nothing.
func TestASignalledContainerRunLeavesNothingRunning(t *testing.T) {
	budget(t, 180*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	// The holder is copied in as "netprobe" because buildScratchProbeImage's
	// Dockerfile names that path; the image is this test's own tag, so nothing
	// else can pick it up.
	if err := os.WriteFile(filepath.Join(proj, "netprobe"), mustRead(t, holderBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}
	token := "snug113-" + orphanToken()
	script := buildAndStartHolder("snugtest-holder:1", token)
	if err := os.WriteFile(filepath.Join(proj, "holder.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	// @podman-build, not @podman-socket alone: this builds an image, and
	// /build is gated on policy.PodmanBuild — see
	// TestHostLoopbackClosedFromContainer's own note on what @podman-socket
	// alone does to a client mid-upload.
	bg := startAttachSandbox(t, env, []string{"-p", "@podman-build"}, proj, `python3 holder.py`)
	bg.ready(t)
	bg.waitForState(t)

	// POSITIVE CONTROL: the container is genuinely RUNNING on this host, found
	// the same way teardown itself finds things — by cmdline substring, never
	// by comm.
	deadline := time.Now().Add(120 * time.Second)
	var before []int
	for {
		before = pidsNamingCmdlineSubstring(token)
		if len(before) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no process ever carried this run's container token %q: the container "+
				"never started, so a later 'nothing survived the signal' would be measuring "+
				"an absence that was already there.\n%s", token, bg.log())
		}
		time.Sleep(200 * time.Millisecond)
	}

	sock := engineSocketPath(os.Getuid(), bg.pid())
	if len(pidsNamingCmdlineSubstring(sock)) == 0 {
		t.Fatalf("PRECONDITION: no process names this run's engine socket %s while its "+
			"container is running", sock)
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
		t.Errorf("a SIGTERMed snug exited %d, not %d (128+SIGTERM). The teardown guard reports "+
			"the conventional signal-death code so scripts see no change; a different code "+
			"means it exited down some other path — and issue #113 is about exactly which "+
			"path the exit takes, because `defer ctrCleanup()` only runs on this one.\n%s",
			code, 128+int(syscall.SIGTERM), bg.log())
	}

	deadline = time.Now().Add(30 * time.Second)
	var left []int
	for {
		left = pidsNamingCmdlineSubstring(token)
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(left) > 0 {
		t.Errorf("after SIGTERM, %d process(es) of this run's CONTAINER are still running "+
			"(token %q, pids %v). A signalled run must not leak the containers it started — "+
			"either the reaper was killed by the teardown sweep AND ctrCleanup did not run, "+
			"or neither of them stopped this container (issue #113).\n%s",
			len(left), token, left, bg.log())
	}
	if still := pidsNamingCmdlineSubstring(sock); len(still) > 0 {
		t.Errorf("after SIGTERM, %d process(es) still name this run's engine socket %s: %v",
			len(still), sock, still)
	}
}

// hostnamesIn returns every hostname a hosts(5) file names — the second and
// later fields of each non-comment line. The address itself is deliberately
// not returned: a container legitimately names its own address, and it is the
// NAMES that carry a host's internal topology.
func hostnamesIn(hosts string) []string {
	var names []string
	for _, line := range strings.Split(hosts, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		names = append(names, fields[1:]...)
	}
	return names
}

// podmanSynthesizedHostname says whether podman itself writes this name into
// a container's /etc/hosts. Everything else in that file came from outside the
// container, which on a host whose /etc/hosts was copied in is the leak issue
// #126 closes.
//
// The container's own hostname is included because podman names it: with no
// --hostname, that is the container's short id, which is hex. Kept as a shape
// check rather than a lookup of the id, because the test does not know it —
// and a hex-shaped name cannot carry a host's internal topology anyway, which
// is what this assertion is about.
func podmanSynthesizedHostname(name string) bool {
	switch name {
	case "localhost", "localhost.localdomain", "localhost4", "localhost6",
		"localhost4.localdomain4", "localhost6.localdomain6",
		"ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
		"ip6-allnodes", "ip6-allrouters",
		"host.containers.internal", "host.docker.internal":
		return true
	}
	return isHex(name)
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// ── issue #132: the host's containers.conf authors nothing in a container ──

// confprobeBin builds testdata/confprobe for the HOST architecture, the same
// way netprobeBin and resolvprobeBin do and for the same reason: it has to run
// as the entrypoint of a container built and started through the very engine
// under test.
var (
	confprobeBinOnce sync.Once
	confprobeBinPath string
	confprobeBinErr  error
)

func confprobeBin(t *testing.T) string {
	t.Helper()
	confprobeBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "snug-confprobe-")
		if err != nil {
			confprobeBinErr = err
			return
		}
		bin := filepath.Join(dir, "confprobe")
		cmd := exec.Command("go", "build", "-o", bin, "./testdata/confprobe")
		cmd.Dir = "."
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			confprobeBinErr = fmt.Errorf("building test/integration/testdata/confprobe: %w: %s", err, out.String())
			return
		}
		confprobeBinPath = bin
	})
	if confprobeBinErr != nil {
		t.Fatal(confprobeBinErr)
	}
	return confprobeBinPath
}

// hostileContainersConfHome plants a user containers.conf that authors, for
// EVERY container the engine creates, four things nobody asked for: a host
// bind, a host volume, a host device node, and an environment variable. It
// returns the home to point the engine at and the marker string that must not
// appear inside a container.
//
// Each key is one row of issue #132's own measurement table, kept in the same
// spellings, because those are the ones that were confirmed to work rather
// than the ones that look like they should.
func hostileContainersConfHome(t *testing.T) (home, marker string) {
	t.Helper()
	home = t.TempDir()
	secret := t.TempDir()
	marker = "HOST-CONTAINERS-CONF-MARKER"

	// Seed the bundle's own home first. It carries
	// .config/containers/policy.json, which podman needs to decide whether an
	// image may be used at all — without it requireRealEngine reports "a build
	// succeeded but its RUN step never actually executed a container", which
	// looks like a broken host rather than a missing file. Measured, not
	// guessed: the skip appeared the moment $HOME moved and went away when
	// this copy was added.
	copyTree(t, filepath.Join(bundleRoot(t), "home"), home)

	if err := os.WriteFile(filepath.Join(secret, "token"), []byte(marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(home, ".config", "containers")
	if err := os.MkdirAll(conf, 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`[containers]
mounts = ["type=bind,source=%[1]s,destination=/leak,ro=true"]
volumes = ["%[1]s:/leak2:ro"]
devices = ["/dev/fuse:/dev/fuse:rwm"]
env = ["SNUG_HOST_CONF_MARKER=%[2]s"]
env_host = true
default_ulimits = ["nofile=%[3]s:%[3]s"]
`, secret, marker, ulimitMarker)
	if err := os.WriteFile(filepath.Join(conf, "containers.conf"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return home, marker
}

// TestHostContainersConfAuthorsNothingInAContainer is issue #132's regression,
// and it asserts the SET rather than the site, which is what that issue asked
// for: a user containers.conf planted with `mounts`, `volumes`, `devices`,
// `env` and `env_host` must author NOTHING in a container created through
// snug's proxy.
//
// The channel is real and is not client-requested, which is why no existing
// test could see it: the engine adds these mounts itself, AFTER the request,
// so internal/dockerproxy's bind filter — which validates what a client asks
// for — never sees them, and --dry-run renders the resolved Policy and so
// shows them either. Invariant 2's corollary ("every visible path traces to
// exactly one explicit grant") did not hold inside a container.
//
// What closes it is engine.writeContainersConf pointing CONTAINERS_CONF at
// snug's own generated file, which makes podman ignore the system and user
// files entirely. The enumerated keys in that file are the second line, for a
// podman that ever merges instead of replacing (issue #136 carries what that
// enumeration does NOT cover).
//
// CONTROL, and this test is worthless without it: the same planted config,
// read by the same podman binary with CONTAINERS_CONF unset, must actually
// inject. Otherwise "no marker in the container" passes on a plant that was
// never read — the exact shape of a test that cannot fail. The control runs
// host-side against a throwaway store and builds its own `FROM scratch`
// image, so it needs no registry and no cached image.
func TestHostContainersConfAuthorsNothingInAContainer(t *testing.T) {
	budget(t, 180*time.Second)

	home, marker := hostileContainersConfHome(t)
	wrapper := provisionEngineWrapperWithHome(t, home)
	base, _ := attachEnv(t)
	env := append(base, "SNUG_PODMAN="+wrapper)
	requireRealEngine(t, env)

	probe := confprobeBin(t)

	// ── CONTROL: the plant is live on this host and this podman ──────────
	assertHostileConfInjectsWithoutSnug(t, home, probe, marker)

	// ── THE ASSERTION: through snug's proxy, it authors nothing ──────────
	proj, _ := target(t)
	if err := os.WriteFile(filepath.Join(proj, "confprobe"), mustRead(t, probe), 0o755); err != nil {
		t.Fatal(err)
	}

	tag := "snugtest-hostconf:1"
	script := buildScratchProbeImageFor(tag, "confprobe") + runContainerAndCollectFn + fmt.Sprintf(`
if build_scratch_probe():
    run_and_collect(%q, [], "host")
print("PROBE-COMPLETE-OUTER", flush=True)
`, tag)
	if err := os.WriteFile(filepath.Join(proj, "hostconf.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 hostconf.py`).mustRun(t)
	if !strings.Contains(r.out, "PROBE-COMPLETE-OUTER") {
		t.Fatalf("the probe script did not run to the end:\n%s", r.out)
	}
	if !strings.Contains(r.out, fmt.Sprintf("BUILD %s: 200", tag)) {
		t.Fatalf("the from-scratch probe image did not build — this test proves nothing about a "+
			"container it never ran:\n%s", r.out)
	}

	// CONTROL 2: the container really produced every section, so an absent
	// marker below is a proven negative rather than a probe that did not run.
	for _, label := range []string{"ROOT", "LEAK", "ENV", "DEV", "LIMITS"} {
		if _, ok := section(r.out, label); !ok {
			t.Fatalf("the container never printed a %s section — it did not actually run "+
				"confprobe:\n%s", label, r.out)
		}
	}

	if strings.Contains(r.out, marker) {
		t.Errorf("the HOST's containers.conf authored something in a container created through "+
			"snug's proxy — the marker %q reached it (issue #132):\n%s", marker, r.out)
	}
	root, _ := section(r.out, "ROOT")
	for _, unwanted := range []string{"leak", "leak2"} {
		if slices.Contains(strings.Fields(root), unwanted) {
			t.Errorf("the host containers.conf's %q mount destination exists in the container "+
				"(issue #132):\n%s", "/"+unwanted, root)
		}
	}
	dev, _ := section(r.out, "DEV")
	if slices.Contains(strings.Fields(dev), "fuse") {
		t.Errorf("the host containers.conf's `devices` key put /dev/fuse in the container "+
			"(issue #132):\n%s", dev)
	}

	// THE DISCRIMINATOR. Everything above is also closed by the ENUMERATED
	// keys in snug's generated file, so those assertions cannot tell
	// "CONTAINERS_CONF replaced the host's file" from "our file merely won on
	// the keys we thought to name". default_ulimits is deliberately not
	// enumerated (issue #136), so it survives the enumeration and is stopped
	// only by suppression: if this fires, CONTAINERS_CONF is no longer
	// replacing the host and user files, and every key nobody has enumerated
	// is live again.
	limits, _ := section(r.out, "LIMITS")
	if strings.Contains(limits, ulimitMarker) {
		t.Errorf("the host containers.conf's `default_ulimits` reached the container: snug's "+
			"CONTAINERS_CONF is no longer REPLACING the host and user config files, so every "+
			"containers.conf key that is not explicitly enumerated is authored by the host "+
			"again (issues #132, #136):\n%s", limits)
	}
}

// ulimitMarker is an implausible nofile limit — implausible on purpose, so
// that seeing it inside a container cannot be a coincidence of the host's own
// defaults. It is the value hostileContainersConfHome plants in
// default_ulimits and the string
// TestHostContainersConfAuthorsNothingInAContainer looks for.
const ulimitMarker = "13571"

// assertHostileConfInjectsWithoutSnug is the positive control for the test
// above, and it is the whole reason that test means anything: it runs the
// SAME podman binary against the SAME planted config with CONTAINERS_CONF
// unset, and requires the marker to appear. If it does not, the plant is not
// being read — a wrong path, a podman that stopped honouring the key, a
// spelling that no longer works — and "no marker through snug" would be
// proving nothing at all.
//
// It builds its own `FROM scratch` image in a throwaway store rather than
// pulling one, so it needs no registry and no cached image, and it never
// touches the developer's own podman storage.
func assertHostileConfInjectsWithoutSnug(t *testing.T, home, probe, marker string) {
	t.Helper()

	podman := podmanBundleBinary(t)
	ctx := t.TempDir()
	if err := os.WriteFile(filepath.Join(ctx, "confprobe"), mustRead(t, probe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctx, "Containerfile"),
		[]byte("FROM scratch\nCOPY confprobe /confprobe\nENTRYPOINT [\"/confprobe\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	store, runroot := t.TempDir(), t.TempDir()
	// XDG_CONFIG_HOME is REMOVED, not merely left alone: it takes precedence
	// over $HOME/.config, so a developer's own value would silently redirect
	// podman away from the planted file and quietly disarm this control.
	// CONTAINERS_CONF is removed for the obvious reason — its presence is the
	// very thing under test.
	run := func(args ...string) (string, error) {
		cmd := exec.Command(podman, append([]string{"--root", store, "--runroot", runroot}, args...)...)
		cmd.Env = append(dropEnv(dropEnv(os.Environ(), "CONTAINERS_CONF"), "XDG_CONFIG_HOME"),
			"HOME="+home)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	t.Cleanup(func() { run("system", "reset", "--force") })

	tag := "snugtest-hostconf-control:1"
	if out, err := run("build", "-t", tag, ctx); err != nil {
		t.Skipf("SKIP: the control could not build its own from-scratch image with this "+
			"bundle's podman, so issue #132's plant cannot be shown live here: %v: %s", err, out)
	}
	out, err := run("run", "--rm", tag)
	if err != nil {
		t.Fatalf("control: the planted-config container did not run: %v: %s", err, out)
	}
	if !strings.Contains(out, ulimitMarker) {
		t.Fatalf("CONTROL FAILED: the planted default_ulimits (%s) did not reach a container "+
			"even with CONTAINERS_CONF unset. That key is the discriminator for CONTAINERS_CONF's "+
			"SUPPRESSION (issue #136 says why it is not enumerated), so without it the caller's "+
			"assertions only prove the enumeration works:\n%s", ulimitMarker, out)
	}
	if !strings.Contains(out, marker) {
		t.Fatalf("CONTROL FAILED: a user containers.conf planted with mounts/volumes/env "+
			"injected NOTHING into a container even with CONTAINERS_CONF unset. The plant is not "+
			"being read, so the assertion in the caller would pass for the wrong reason "+
			"(issue #132's channel may have moved, or the key spellings changed):\n%s", out)
	}
	t.Logf("control: the planted host containers.conf DOES inject without snug (marker %q seen)", marker)
}

// podmanBundleBinary returns the pinned static podman the whole real-engine
// suite runs on, skipping cleanly if the bundle is absent — the same rule
// provisionEngineWrapper follows, and for the same reason: this suite never
// points anything at whatever the host's own `podman` resolves to.
func podmanBundleBinary(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("SKIP: cannot determine $HOME to look for a static podman bundle: " + err.Error())
	}
	bin := filepath.Join(home, podmanStaticRootRel, "usr", "local", "bin", "podman")
	if fi, statErr := os.Stat(bin); statErr != nil || fi.IsDir() {
		t.Skip("SKIP: no static podman bundle at " + bin + " (.claude/design/PODMAN-STATIC.md)")
	}
	return bin
}

// bundleRoot is the pinned static podman bundle's own root, skipping cleanly
// when it is absent — the same rule the rest of the real-engine suite follows.
func bundleRoot(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("SKIP: cannot determine $HOME to look for a static podman bundle: " + err.Error())
	}
	root := filepath.Join(home, podmanStaticRootRel)
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		t.Skip("SKIP: no static podman bundle at " + root + " (.claude/design/PODMAN-STATIC.md)")
	}
	return root
}

// copyTree copies src's contents into dst, files and directories only. Small
// and deliberately unclever: the one tree it is used on holds a single
// policy.json.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("seeding the engine home from the bundle's own: %v", err)
	}
}

// ── issue #125, C0: the engine holds its own pid namespace ─────────────────
//
// internal/stage/enginefork.go now clones the engine with CLONE_NEWPID and
// internal/stage/inengine.go mounts a fresh procfs bound to it — the
// PREREQUISITE for the rest of issue #125's Tier C: a fresh procfs cannot be
// mounted at all without a pid namespace the caller's own userns owns, and
// the sandbox's own /proc is useless to the engine — it reports no processes
// against a foreign pid namespace's numbering. Three tests, each checking a
// different consequence directly rather than assuming the flag took:
//
//   - TestEngineHasItsOwnPidNamespace: the namespace identity itself.
//   - TestKillingOnlyTheEngineFellsItsContainers: the behavioural payoff,
//     and the exact A/B that flipped under this change — pre-C0 a killed
//     engine left its container running for 10+ seconds; with C0 the
//     namespace collapse takes it down inside one poll tick.
//   - TestConmonPPidIsTheEngine: the structural fact underneath both,
//     read from the HOST's own procfs.
//
// All three reuse holderBin/buildAndStartHolder from
// TestASignalledContainerRunLeavesNothingRunning (issue #113) — a
// `FROM scratch` image whose entrypoint is testdata/holder, built lazily and
// started detached so it stays running past the payload's own control flow,
// which is exactly the shape a teardown test needs.

// findConmonPID polls the host's own procfs for a process named "conmon" —
// comm, not cmdline: conmon does not rewrite argv[0], and "conmon" is short
// enough that /proc/<pid>/comm's 15-byte truncation never bites — whose
// ancestry (by PPid, walking up, findDescendant's own bounded hop count)
// reaches root. Built on findDescendant/isComm/allPIDs/ppidOf, all shared
// with stage_test.go and reimplemented nowhere.
func findConmonPID(t *testing.T, root int, timeout time.Duration) int {
	t.Helper()
	pid, ok := findDescendant(root, isComm("conmon"), timeout)
	if !ok {
		t.Fatalf("no conmon process appeared as a descendant of pid %d within %s — control "+
			"failed: a running container should always have one", root, timeout)
	}
	return pid
}

// startEngineHeldContainer is the shared setup TestKillingOnlyTheEngineFellsItsContainers
// and TestConmonPPidIsTheEngine both need: a real engine, a target directory,
// and a container started via python3 holder.py and left running (never
// waited on), with a unique per-run token in its argv. Returns the live
// background sandbox and the token; the caller still owns the POSITIVE
// CONTROL of confirming the token is actually alive on the host — this
// helper only starts things, per CLAUDE.md's rule that a positive control has
// to sit next to the assertion it backs, not be buried in shared setup.
func startEngineHeldContainer(t *testing.T, env []string, proj, tagSuffix string) (bg *attachSandbox, token string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(proj, "netprobe"), mustRead(t, holderBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}
	token = "snug125c0" + tagSuffix + orphanToken()
	script := buildAndStartHolder("snugtest-holder-c0"+tagSuffix+":1", token)
	if err := os.WriteFile(filepath.Join(proj, "holder.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	bg = startAttachSandbox(t, env, []string{"-p", "@podman-build"}, proj, `python3 holder.py`)
	bg.ready(t)
	bg.waitForState(t)
	return bg, token
}

// waitForToken polls the host for a process naming tok in its cmdline —
// pidsNamingCmdlineSubstring, the same identify-by-cmdline discipline
// internal/engine/reap.go uses for teardown — and fails loudly if none
// appears, per CLAUDE.md's "a test that cannot fail is worse than no test":
// a container that never started must not let a later "nothing survived"
// pass on an absence that was already there.
func waitForToken(t *testing.T, tok string, timeout time.Duration, logf func() string) []int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		pids := pidsNamingCmdlineSubstring(tok)
		if len(pids) > 0 {
			return pids
		}
		if time.Now().After(deadline) {
			t.Fatalf("no process ever carried this run's container token %q within %s: the "+
				"container never started, so an assertion built on top of it would be "+
				"measuring an absence that was already there.\n%s", tok, timeout, logf())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestEngineHasItsOwnPidNamespace is C0's own claim, checked directly:
// /proc/<enginePID>/ns/pid must differ from this TEST PROCESS's own
// (host-side) pid namespace. MEASURED (host-bridge, this fixture):
//
//	pre-C0 : engine /proc/<p>/ns/pid = pid:[4026531836]   (the host's)
//	with C0: engine /proc/<p>/ns/pid = pid:[4026534989]   (its own)
//
// The adjacent negative — that the engine's host-visible pid still does NOT
// resolve inside the SANDBOX's own pid namespace — is
// TestNoAbstractSocketsWithEngineInN's job and is not repeated here; the two
// tests together are "the engine has a pid namespace, and it isn't shared
// with either side it sits between".
func TestEngineHasItsOwnPidNamespace(t *testing.T) {
	budget(t, 60*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	bg := startAttachSandbox(t, env, []string{"-p", "@podman-socket"}, proj, `sleep 300`)
	bg.ready(t)
	bg.waitForState(t)

	enginePID := findEnginePID(t, os.Getuid(), bg.pid())

	// CONTROL: the engine really is running and answering /version, not a
	// stale pid some unrelated process reused.
	r := attachScript(t, env, proj, `
python3 - <<'EOF'
import http.client, socket, os
class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost"); self.path = path
    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(self.path); self.sock = s
sock = os.environ["CONTAINER_HOST"].replace("unix://", "")
c = UnixHTTP(sock); c.request("GET", "/v1.41/version"); r = c.getresponse(); r.read()
print("version: %d" % r.status)
EOF
`)
	if !strings.Contains(r.out, "version: 200") {
		t.Fatalf("control: the engine at pid %d does not answer /version:\n%s", enginePID, r.out)
	}

	engineNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", enginePID))
	if err != nil {
		t.Fatalf("reading /proc/%d/ns/pid: %v", enginePID, err)
	}
	selfNS, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		t.Fatalf("reading /proc/self/ns/pid: %v", err)
	}
	if engineNS == selfNS {
		t.Errorf("the engine (pid %d) shares THIS test process's own pid namespace (%s) — "+
			"CLONE_NEWPID either was not applied to its clone or was applied and then undone "+
			"before the exec into podman (internal/stage/enginefork.go, internal/stage/inengine.go)",
			enginePID, engineNS)
	}
}

// TestKillingOnlyTheEngineFellsItsContainers is C0's central behavioural
// claim and the exact A/B host-bridge measured flipping:
//
//	pre-C0 : container token pids STILL ALIVE 10s after the engine SIGKILL
//	with C0: all container token pids gone 250 ms after the engine SIGKILL
//
// Isolated from TestASignalledContainerRunLeavesNothingRunning (issue #113)
// deliberately: that test signals SNUG itself, so it cannot tell C0's
// namespace-collapse mechanism apart from internal/engine/reaper.go's own
// pipe-triggered cleanup or internal/cli's `defer ctrCleanup()` — both of
// which are armed by snug's own death. This test kills ONLY the engine
// process, by its host-visible pid, and leaves snug running throughout, so
// neither of those fires: the reaper's pipe write happens in snug's own exit
// path and lifeline.go's `hold` loop (which notices the engine died) takes
// no action of its own ("restarting it is not this goroutine's decision" —
// internal/engine/lifeline.go). The POSITIVE CONTROL that makes the
// isolation itself trustworthy is the assertion at the end: snug must still
// be alive and non-zombie after the engine-only kill, or this test has
// silently become a second copy of the #113 one and proves nothing about C0
// specifically.
func TestKillingOnlyTheEngineFellsItsContainers(t *testing.T) {
	budget(t, 180*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	bg, token := startEngineHeldContainer(t, env, proj, "kill")

	// POSITIVE CONTROL: the container is genuinely running on the host BEFORE
	// the kill.
	before := waitForToken(t, token, 120*time.Second, bg.log)
	t.Logf("control: container token %q alive at pids %v before the engine kill", token, before)

	enginePID := findEnginePID(t, os.Getuid(), bg.pid())

	if err := syscall.Kill(enginePID, syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL the engine alone (pid %d): %v", enginePID, err)
	}

	deadline := time.Now().Add(10 * time.Second)
	var left []int
	for {
		left = pidsNamingCmdlineSubstring(token)
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(left) > 0 {
		t.Errorf("after SIGKILLing the ENGINE alone (pid %d), %d process(es) of this run's "+
			"container are still running (token %q, pids %v) within 10s — the engine's own pid "+
			"namespace did not collapse and take them with it (issue #125, C0)",
			enginePID, len(left), token, left)
	}

	// The isolation control: snug itself must still be alive and not a
	// zombie. If it is not, neither this test's "kill the engine ALONE"
	// premise nor its distinction from the #113 SIGTERM-snug test holds, and
	// whatever felled the container might have been snug's own teardown path
	// rather than C0's namespace collapse.
	if state := stateOf(bg.pid()); state == "" || state == "Z" {
		t.Errorf("snug (pid %d, state %q) is gone or zombie after the engine ALONE was "+
			"killed — this test no longer isolates C0's mechanism from snug's own teardown "+
			"path (internal/engine/reaper.go, internal/cli's ctrCleanup)", bg.pid(), state)
	}
}

// TestContainersDieWithTheEngineWithoutAGracefulStop is issue #167's
// regression test: SIGKILLing snug itself (not the engine alone, unlike the
// test above) must still fell this run's containers, WITHOUT a host-side
// `podman stop` ever being attempted — engine.go's stopLocked no longer
// makes that call at all (the pids it would have read are numbered in the
// ENGINE's own pid namespace since #125's C0, meaningless on the host), and
// reaper.go's pipe-triggered helper no longer forks podman either.
//
// SIGKILL of the WHOLE process tree is the important case here, not a signal
// snug can catch: it skips stopLocked entirely (no Go code runs at all on
// this path), so what fells the container is purely the Pdeathsig chain
// (engine ⊂ P1 ⊂ P0) collapsing the engine's pid namespace — exactly the
// mechanism TestKillingOnlyTheEngineFellsItsContainers measures for an
// engine-only kill, now asserted for the path a hard-killed snug actually
// takes.
func TestContainersDieWithTheEngineWithoutAGracefulStop(t *testing.T) {
	budget(t, 180*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	bg, token := startEngineHeldContainer(t, env, proj, "nostop")

	// POSITIVE CONTROL: the container is genuinely running on the host BEFORE
	// the kill — without this, "gone after the kill" is equally true of a
	// container that never started.
	before := waitForToken(t, token, 120*time.Second, bg.log)
	t.Logf("control: container token %q alive at pids %v before SIGKILL", token, before)

	if err := syscall.Kill(bg.pid(), syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL snug (pid %d): %v", bg.pid(), err)
	}

	deadline := time.Now().Add(10 * time.Second)
	var left []int
	for {
		left = pidsNamingCmdlineSubstring(token)
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(left) > 0 {
		t.Errorf("after SIGKILLing snug (pid %d), %d process(es) of this run's container are "+
			"still running (token %q, pids %v) within 10s, with no host-side graceful stop "+
			"ever attempted — the namespace collapse alone must fell them",
			bg.pid(), len(left), token, left)
	}
}

// TestConmonPPidIsTheEngine is the structural fact underneath the other two
// tests in this section, read from the HOST's own procfs — the same view a
// future --pid=host decision (issue #145) would have to re-check, per this
// task's own note. MEASURED (host-bridge, this fixture; pids and paths
// abbreviated):
//
//	pid=1898978 ppid=1898951 pid:[4026534989] .../podman ... system service ...
//	pid=1899295 ppid=1898978 pid:[4026534989] /usr/bin/conmon --api-version 1 -c 0fd4a62e...
//	pid=1899298 ppid=1899295 pid:[4026535001] /netprobe /netprobe c0probe-...
//
// conmon still double-forks (unchanged by C0); what changed is which
// process its own grandchild reparents onto, because pid 1 of the engine's
// own pid namespace is now the engine itself. This test checks the direct
// relationship (conmon's PPid, not just "some ancestor") and, as
// corroboration, that conmon shares the engine's own pid namespace while the
// container's own process — one hop further down, inside crun's nested
// namespace — does not.
func TestConmonPPidIsTheEngine(t *testing.T) {
	budget(t, 180*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	bg, token := startEngineHeldContainer(t, env, proj, "conmon")

	// POSITIVE CONTROL: the container is genuinely running, so a conmon for
	// it genuinely exists to find.
	containerPIDs := waitForToken(t, token, 120*time.Second, bg.log)

	enginePID := findEnginePID(t, os.Getuid(), bg.pid())
	conmonPID := findConmonPID(t, enginePID, 30*time.Second)

	ppid, ok := ppidOf(conmonPID)
	if !ok {
		t.Fatalf("could not read /proc/%d/status for conmon's own PPid", conmonPID)
	}
	if ppid != enginePID {
		t.Errorf("conmon (pid %d) has PPid %d, not the engine (%d) — issue #125's C0 claims "+
			"conmon reparents onto the engine now that the engine is pid 1 of its own pid "+
			"namespace; this is a HOST-procfs read, not a namespace-relative one", conmonPID,
			ppid, enginePID)
	}

	engineNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", enginePID))
	if err != nil {
		t.Fatalf("reading /proc/%d/ns/pid: %v", enginePID, err)
	}
	conmonNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", conmonPID))
	if err != nil {
		t.Fatalf("reading /proc/%d/ns/pid: %v", conmonPID, err)
	}
	if conmonNS != engineNS {
		t.Errorf("conmon (pid %d, ns %s) is not in the engine's own pid namespace (pid %d, "+
			"ns %s) — conmon is an ordinary fork with no CLONE_NEWPID of its own, so it should "+
			"inherit the engine's", conmonPID, conmonNS, enginePID, engineNS)
	}

	containerNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", containerPIDs[0]))
	if err != nil {
		t.Fatalf("reading /proc/%d/ns/pid: %v", containerPIDs[0], err)
	}
	if containerNS == engineNS {
		t.Errorf("the container's own process (pid %d) shares the ENGINE's pid namespace "+
			"(%s) — crun should have given it a nested namespace of its own, one level deeper",
			containerPIDs[0], engineNS)
	}
}

// ── issue #145: PidMode="host" stays refused ────────────────────────────────
//
// TestConmonPPidIsTheEngine's own doc comment named this the "future --pid=host
// decision (issue #145)" this file would have to re-check once the engine had
// a pid namespace of its own. The decision (issue #145) is: it
// stays refused, permanently, because the inversion that turned
// NetworkMode="host" into "joins N" does not transfer to a pid namespace — N
// is a subset of the sandbox's own authority, the engine's pid namespace is a
// superset of it. Three tests, each measuring a different half of that:
//
//   - TestContainerCannotJoinTheEnginesPidNamespace: the refusal itself, with
//     the identical run minus PidMode="host" as its positive control.
//   - TestContainerSeesOnlyItsOwnPids: the negative the refusal preserves —
//     an ORDINARY container's own /proc/1/root and /proc pid listing are its
//     own, never the engine's or the host's.
//   - TestEngineProcfsIsNotBindMountable: the SECOND route to the same
//     reach (`-v /proc:/hostproc`), which issue #145's decision flags as
//     "read from code, not executed" — HostPathVisible matches KindBind
//     only (pinned at the unit level by
//     policy.TestHostPathVisibleRefusesPseudoFilesystems) — so this is what
//     turns that into a measurement.
//
// All three build a `FROM scratch` image around testdata/pidnsprobe, which
// needs no registry pull, so they build and run with the sandbox's own
// egress CLOSED — the same reasoning netprobe/resolvprobe's own doc comments
// give.

// pidnsprobeBin is holderBin's own shape, not netprobeBin's
// sync.Once-memoized one, and deliberately so: THREE tests in this section
// call it (unlike netprobeBin/resolvprobeBin, each called from exactly one),
// and a package-level sync.Once caches the path from a t.TempDir() that
// belongs to whichever test happened to build it FIRST — that directory is
// removed by THAT test's own Cleanup, so the second and third callers would
// get a cached path to a file that no longer exists. Measured: exactly this
// "open .../pidnsprobe: no such file or directory" on the second caller
// before this function took holderBin's shape instead. The build is a few
// hundred milliseconds; paying it three times is cheaper than a shared cache
// with a lifetime bug.
func pidnsprobeBin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "pidnsprobe")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/pidnsprobe")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("building test/integration/testdata/pidnsprobe: %v: %s", err, out.String())
	}
	return bin
}

// TestContainerCannotJoinTheEnginesPidNamespace is the refusal itself,
// measured end to end against a real engine: `podman run --pid=host` (i.e. a
// create body carrying HostConfig.PidMode="host") is refused, naming
// HostConfig.PidMode.
//
// POSITIVE CONTROL, in the SAME test, per CLAUDE.md's rule that a negative
// without one proves nothing: the byte-identical container, minus
// PidMode="host", is actually built and run through the identical real
// engine, and its own stdout is checked for the marker its entrypoint prints
// on completion — so a refusal-shaped bug that accidentally caught every
// create (an engine that never came up, a proxy that denies everything)
// would show up here as the control failing, not as a false pass on the
// refusal alone.
func TestContainerCannotJoinTheEnginesPidNamespace(t *testing.T) {
	budget(t, 120*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	probeBin := pidnsprobeBin(t)
	if err := os.WriteFile(filepath.Join(proj, "pidnsprobe"), mustRead(t, probeBin), 0o755); err != nil {
		t.Fatal(err)
	}

	tag := "snugtest-pidmode-refusal:1"
	script := buildScratchProbeImageFor(tag, "pidnsprobe") + runContainerAndCollectFn + fmt.Sprintf(`
if build_scratch_probe():
    # POSITIVE CONTROL: the identical container, WITHOUT PidMode, actually
    # runs through the real engine.
    run_and_collect(%q, ["/pidnsprobe"], "host")

    # The refusal under test: the same create, PLUS PidMode="host".
    body = json.dumps({"Image": "localhost/%s", "Cmd": ["/pidnsprobe"], "Tty": True,
                        "HostConfig": {"NetworkMode": "host", "PidMode": "host"}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("PIDHOST-CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:400]), flush=True)
print("PROBE-COMPLETE", flush=True)
`, tag, tag)
	if err := os.WriteFile(filepath.Join(proj, "pidmode.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 pidmode.py`).mustRun(t)
	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the probe did not run to the end:\n%s", r.out)
	}
	if !strings.Contains(r.out, fmt.Sprintf("BUILD %s: 200", tag)) {
		t.Fatalf("the from-scratch image did not even build — this test proves nothing about "+
			"either the control or the refusal:\n%s", r.out)
	}

	// POSITIVE CONTROL assertion: the plain run (no PidMode) actually reached
	// a real, running container.
	_, logs, _ := cutTwice(r.out, "LOGS-BEGIN", "LOGS-END")
	if !strings.Contains(logs, "PROBE-COMPLETE") {
		t.Fatalf("control: the container WITHOUT PidMode=host never produced its own "+
			"PROBE-COMPLETE marker — it did not actually run, so the refusal checked below "+
			"proves nothing about a REAL engine:\n%s", r.out)
	}
	if !strings.Contains(r.out, "CREATE: 201") {
		t.Fatalf("control: the plain create (no PidMode) was not even accepted (want 201):\n%s", r.out)
	}

	// The refusal itself.
	if !strings.Contains(r.out, "PIDHOST-CREATE: 403") {
		t.Errorf("HostConfig.PidMode=\"host\" was not refused with 403:\n%s", r.out)
	}
	if !strings.Contains(r.out, "HostConfig.PidMode") {
		t.Errorf("the refusal does not name HostConfig.PidMode:\n%s", r.out)
	}
}

// TestContainerSeesOnlyItsOwnPids is the negative TestContainerCannotJoinTheEnginesPidNamespace's
// refusal exists to preserve: an ORDINARY container (no PidMode at all, so
// podman's own default — a fresh pid namespace per container) sees only
// itself.
//
// Two assertions, both read from the CONTAINER's own stdout (never the
// host's), so what is checked is the view from inside:
//
//   - /proc/1/root lists a tiny, from-scratch root — the pidnsprobe binary
//     plus whatever podman itself bind-mounts (/etc, /dev, /proc) — and
//     specifically none of the ordinary host/sandbox FHS directories
//     (usr, home, root, var) that would appear if /proc/1/root somehow
//     dereferenced into the engine's own private copy of the host tree
//     instead of the container's own.
//   - /proc lists at least two pids — POSITIVE CONTROL: the entrypoint
//     starts a second, short-lived child of itself before listing /proc
//     (testdata/pidnsprobe/main.go), and that child's own "CHILD-MARKER-READY"
//     line must appear in the SAME container's logs, or "only its own pids"
//     would be checked against a /proc listing known to contain just one
//     entry regardless of whether the isolation holds.
func TestContainerSeesOnlyItsOwnPids(t *testing.T) {
	budget(t, 120*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	probeBin := pidnsprobeBin(t)
	if err := os.WriteFile(filepath.Join(proj, "pidnsprobe"), mustRead(t, probeBin), 0o755); err != nil {
		t.Fatal(err)
	}

	tag := "snugtest-ownpids:1"
	script := buildScratchProbeImageFor(tag, "pidnsprobe") + runContainerAndCollectFn + fmt.Sprintf(`
if build_scratch_probe():
    run_and_collect(%q, ["/pidnsprobe"], "host")
print("PROBE-COMPLETE", flush=True)
`, tag)
	if err := os.WriteFile(filepath.Join(proj, "ownpids.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 ownpids.py`).mustRun(t)
	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the probe did not run to the end:\n%s", r.out)
	}
	if !strings.Contains(r.out, fmt.Sprintf("BUILD %s: 200", tag)) {
		t.Fatalf("the from-scratch image did not build:\n%s", r.out)
	}

	_, logs, _ := cutTwice(r.out, "LOGS-BEGIN", "LOGS-END")
	if strings.TrimSpace(logs) == "" {
		t.Fatalf("the container produced no logs at all — this test proves nothing:\n%s", r.out)
	}

	// POSITIVE CONTROL: the child process actually started and printed its
	// own marker, so the pid count checked below is known to be at least two.
	if !strings.Contains(logs, "CHILD-STARTED") || !strings.Contains(logs, "CHILD-MARKER-READY") {
		t.Fatalf("control: the container's own child process never started or never printed its "+
			"marker — the pid listing below proves nothing about isolation:\n%s", logs)
	}

	rootEntries := lineField(logs, "ROOT-ENTRIES")
	if rootEntries == "" {
		t.Fatalf("no ROOT-ENTRIES line in the container's own log:\n%s", logs)
	}
	names := strings.Split(rootEntries, ",")
	nameSet := map[string]bool{}
	for _, n := range names {
		nameSet[strings.TrimSpace(n)] = true
	}
	if !nameSet["pidnsprobe"] {
		t.Errorf("the container's own /proc/1/root does not even list its own entrypoint binary "+
			"(pidnsprobe) — this reading is not of the container's own root at all: %q", rootEntries)
	}
	for _, hostOnly := range []string{"usr", "home", "root", "var"} {
		if nameSet[hostOnly] {
			t.Errorf("the container's own /proc/1/root lists %q — that is an ordinary host/sandbox "+
				"FHS directory a `FROM scratch` container's own root never has; /proc/1/root has "+
				"dereferenced into something OTHER than this container's own rootfs: %q",
				hostOnly, rootEntries)
		}
	}

	pidsLine := lineField(logs, "PIDS")
	pids := strings.FieldsFunc(pidsLine, func(r rune) bool { return r == ',' })
	if len(pids) < 2 {
		t.Errorf("the container's own /proc lists %d pid(s) (%q), want at least 2 (the entrypoint "+
			"plus the child process it started) — either the child never actually ran (control "+
			"already checked above) or /proc itself is reading something other than this "+
			"container's own pid namespace", len(pids), pidsLine)
	}
}

// lineField returns the text after "LABEL " on the first line of logs that
// starts with LABEL, trimmed of the trailing \r a Tty=true container log
// carries (section's own doc comment gives the same reasoning). Returns ""
// if no such line exists.
func lineField(logs, label string) string {
	prefix := label + " "
	for _, line := range strings.Split(logs, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}

// TestEngineProcfsIsNotBindMountable is the SECOND route to the reach
// PidMode="host" is refused for for: `-v /proc:/hostproc` reaches the
// engine's (or, given a different pid, any co-resident process's)
// /proc/<pid>/root the same way, through an entirely different HostConfig
// field. Issue #145's decision names this "read from code, not executed" —
// policy.HostPathVisible matches KindBind mounts only, and /proc is mounted
// as KindProc, so it can never be visible to the bind filter — and this test
// is what turns that into a measurement against a real engine and a real
// container-create request, rather than trusting the code reading alone.
//
// POSITIVE CONTROL, against the SAME real engine: a bind of the sandbox's
// own target directory (which the default profile set already grants
// read-write) is accepted — so the /proc refusal below is a decision about
// /proc specifically, not evidence that every bind request fails, or that
// the engine never came up at all.
func TestEngineProcfsIsNotBindMountable(t *testing.T) {
	budget(t, 120*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	probeBin := pidnsprobeBin(t)
	if err := os.WriteFile(filepath.Join(proj, "pidnsprobe"), mustRead(t, probeBin), 0o755); err != nil {
		t.Fatal(err)
	}

	tag := "snugtest-procbind:1"
	script := buildScratchProbeImageFor(tag, "pidnsprobe") + fmt.Sprintf(`
if build_scratch_probe():
    # The refusal under test.
    body = json.dumps({"Image": "localhost/%s",
                        "HostConfig": {"NetworkMode": "host",
                                       "Mounts": [{"Type": "bind", "Source": "/proc",
                                                    "Target": "/hostproc"}]}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    print("PROCBIND-CREATE: %%d %%s" %% (status, resp.decode(errors="replace")[:400]), flush=True)

    # POSITIVE CONTROL: an ORDINARY bind, of a path the sandbox itself already
    # has read-write, is accepted by the same filter against the same engine.
    body2 = json.dumps({"Image": "localhost/%s",
                         "HostConfig": {"NetworkMode": "host",
                                        "Mounts": [{"Type": "bind", "Source": os.getcwd(),
                                                     "Target": "/hostproj"}]}}).encode()
    status2, resp2 = req("POST", "/v1.41/containers/create", body2, {"Content-Type": "application/json"})
    print("PROJBIND-CREATE: %%d %%s" %% (status2, resp2.decode(errors="replace")[:400]), flush=True)
    if status2 == 201:
        cid = json.loads(resp2)["Id"]
        req("DELETE", "/v1.41/containers/%%s?force=1" %% cid)
print("PROBE-COMPLETE", flush=True)
`, tag, tag)
	if err := os.WriteFile(filepath.Join(proj, "procbind.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 procbind.py`).mustRun(t)
	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the probe did not run to the end:\n%s", r.out)
	}
	if !strings.Contains(r.out, fmt.Sprintf("BUILD %s: 200", tag)) {
		t.Fatalf("the from-scratch image did not even build — this test proves nothing:\n%s", r.out)
	}

	// POSITIVE CONTROL: an ordinary bind against the same real engine and the
	// same filter is accepted.
	if !strings.Contains(r.out, "PROJBIND-CREATE: 201") {
		t.Fatalf("control: an ordinary bind of the sandbox's own read-write target was NOT "+
			"accepted (want 201) — this test's /proc refusal below proves nothing about a "+
			"working bind filter:\n%s", r.out)
	}

	// The refusal itself.
	if !strings.Contains(r.out, "PROCBIND-CREATE: 403") {
		t.Errorf("`-v /proc:/hostproc` was not refused with 403:\n%s", r.out)
	}
	if !strings.Contains(r.out, "cannot see /proc") {
		t.Errorf("the refusal does not say the sandbox cannot see /proc, the actual mechanism:\n%s", r.out)
	}
}
