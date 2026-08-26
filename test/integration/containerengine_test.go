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
// # Which podman this file runs against (issue #393)
//
// The retired static-podman bundle is gone (#398): this suite resolves the
// engine from $SNUG_PODMAN when set, and otherwise from the host's own
// `podman` on PATH — see hostEngine below, the ONE resolver every helper in
// this file goes through. A shim (distrobox-host-exec and friends,
// internal/cli/podmanshim.go's hostEscapeShims) is a t.Fatal, never a skip:
// preflight P1 refuses it for the same reason, and this suite testing a
// capability preflight would refuse is not a legitimate skip. A missing
// engine — no `podman` on PATH and $SNUG_PODMAN unset — is the ONLY skip.
//
// containerEngineEnv therefore degrades to a skip (no engine at all) or a
// fatal (a wrong engine) but never silently measures the wrong binary: on a
// host carrying both a system podman and something else claiming to be one,
// hostEngine's own PATH/$SNUG_PODMAN resolution is the only place that
// decision is made, so it cannot drift from what preflight itself resolves.
import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	snugcli "github.com/gomoni/snug/internal/cli"
	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
)

// ── the single engine resolver (issue #393) ─────────────────────────────────

// engineResolution is hostEngineOnce's cached answer: at most one of path or
// shim is meaningful, decided once for the whole test binary run.
type engineResolution struct {
	path        string // "" means "no engine found"
	versionLine string // `podman --version`'s output, only when path != ""
	shim        policy.HostShim
	isShim      bool
	// named is $SNUG_PODMAN's value when it was set and did NOT resolve. That
	// is a MISCONFIGURATION, not "no engine on this host": somebody named an
	// engine and the name is wrong, so it fails rather than skipping. Letting
	// it skip would reproduce issue #393's own defect one level down — a
	// deliberately pointed-at engine silently not being tested, with a green
	// run to show for it.
	named string
	// unsupported is engine.UnsupportedPodmanReason(versionLine) — "" when the
	// resolved engine is in engine.SupportedPodmanSet. Computed with the
	// resolution rather than at each call site so the answer cannot differ
	// between two tests in one run.
	unsupported string
}

var (
	hostEngineOnce   sync.Once
	hostEngineResult engineResolution

	// versionOnce, engineNoneOnce and engineFailedOnce each print ONE line for
	// the whole run (issue #393 §4's amendment): the healthy case, the "no
	// podman at all" case, and the "podman resolved but could not actually
	// run a container" case are three DIFFERENT facts, and printing the wrong
	// one on the wrong host is exactly how a broken environment reads as an
	// absent one. Makefile's integration-sandbox target greps for these to
	// print "N of 32 ran — <reason>".
	versionOnce      sync.Once
	engineNoneOnce   sync.Once
	engineFailedOnce sync.Once
)

// resolveHostEngineOnce computes engineResolution exactly once per test
// binary run: $SNUG_PODMAN if set, else exec.LookPath("podman"), then the
// same host-escape-shim check preflight's own preflightPodmanBinary applies
// (internal/cli's DetectHostShim, exported for exactly this caller — see its
// own doc comment. Imported here as snugcli: this package already has its
// own unexported `cli` helper in sandbox_test.go, and the two names collide
// at file scope otherwise).
func resolveHostEngineOnce() engineResolution {
	hostEngineOnce.Do(func() {
		name := os.Getenv("SNUG_PODMAN")
		if name == "" {
			p, err := exec.LookPath("podman")
			if err != nil {
				hostEngineResult = engineResolution{}
				return
			}
			name = p
		} else if _, err := exec.LookPath(name); err != nil {
			hostEngineResult = engineResolution{named: name}
			return
		}
		if shim, ok := snugcli.DetectHostShim(name); ok {
			hostEngineResult = engineResolution{path: name, shim: shim, isShim: true}
			return
		}
		abs := name
		if p, err := exec.LookPath(name); err == nil {
			abs = p
		}
		out, _ := exec.Command(abs, "--version").Output()
		line := strings.TrimSpace(string(out))
		hostEngineResult = engineResolution{
			path:        abs,
			versionLine: line,
			unsupported: engine.UnsupportedPodmanReason(line),
		}
	})
	return hostEngineResult
}

// hostEngine resolves the podman this suite runs on. "no engine on this
// host" is the ONLY skip; a wrong engine (a host-escape shim) is a t.Fatal
// naming the shim and how it was named, never a skip — the whole point of
// issue #393 is that this harness must not treat "preflight would refuse
// this" as "there is nothing to test here".
func hostEngine(t *testing.T) string {
	t.Helper()
	r := resolveHostEngineOnce()
	if r.isShim {
		t.Fatalf("podman (named %q) resolves to %s, a host-escape helper (%s) that forwards to "+
			"the HOST's own podman over a channel no network namespace touches. This is exactly "+
			"the configuration preflight P1 refuses, and this suite testing a capability "+
			"preflight would refuse is not a legitimate skip.\n"+
			"      Fix: point $SNUG_PODMAN at a real engine binary, or fix PATH.",
			r.shim.Name, r.shim.Path, filepath.Base(r.shim.Resolved))
	}
	if r.named != "" {
		t.Fatalf("$SNUG_PODMAN=%s does not resolve to an executable on this host. An engine "+
			"somebody NAMED and got wrong is a misconfiguration, not an absent engine, so this "+
			"fails rather than skipping — a skip here would be issue #393's own defect one level "+
			"down, a deliberately pointed-at engine silently going untested with a green run to "+
			"show for it.\n"+
			"      Fix: point $SNUG_PODMAN at a real engine binary, or unset it to use PATH.",
			r.named)
	}
	if r.path == "" {
		engineNoneOnce.Do(func() { t.Logf("snug-engine-none: no podman resolved") })
		t.Skip("SKIP: no podman on PATH and $SNUG_PODMAN unset — no engine on this host to test against")
	}
	// An engine outside engine.SupportedPodmanSet is a WARNING on a developer
	// host and a FAILURE in CI, and the split is the whole point (issue #395).
	// The version floats with the distribution since the pin was retired
	// (#384), so an unconditional fatal would block every developer whose
	// distro moved ahead of or behind the set — the result stays readable and
	// nobody is stopped. A lane that set $SNUG_REQUIRE_ENGINE asked this run to
	// MEAN something, and a green run against an engine nobody supports is the
	// same lie as a green run that skipped everything.
	if r.unsupported != "" {
		if os.Getenv("SNUG_REQUIRE_ENGINE") != "" {
			t.Fatalf("SNUG_REQUIRE_ENGINE is set and the resolved engine is not one snug "+
				"supports: %s\n      Resolved: %q at %s\n"+
				"      Fix: run this lane against %s, or widen "+
				"engine.SupportedPodmanMajor and record the run that justifies it.",
				r.unsupported, r.versionLine, r.path, engine.SupportedPodmanSet)
		}
		versionOnce.Do(func() {
			// The reason rides on the SAME marker line the Makefile already
			// greps, so its "N of 33 ran — <version>" summary carries it with
			// no second marker to teach that recipe about.
			t.Logf("snug-engine-version: %s at %s [UNSUPPORTED: %s]", r.versionLine, r.path, r.unsupported)
		})
		return r.path
	}
	versionOnce.Do(func() {
		t.Logf("snug-engine-version: %s at %s", r.versionLine, r.path)
	})
	return r.path
}

// describeResolvedEngine renders the resolved engine for the negative
// markers below, so a "failed to start" line still names WHICH podman failed.
func describeResolvedEngine() string {
	r := resolveHostEngineOnce()
	if r.named != "" {
		return "$SNUG_PODMAN=" + r.named + " does not resolve"
	}
	if r.path == "" {
		return "no podman resolved"
	}
	return r.versionLine + " at " + r.path
}

// containerEngineEnv is baseEnv (via attachEnv's own isolation, so
// $XDG_RUNTIME_DIR never collides with another test's live run) plus
// $SNUG_PODMAN pointed at hostEngine's resolved binary. Every test in this
// file that starts a real engine uses it.
func containerEngineEnv(t *testing.T) (env []string, xdgRuntime string) {
	t.Helper()
	podman := hostEngine(t)
	base, xdg := attachEnv(t)
	out := append(base, "SNUG_PODMAN="+podman)
	// SNUG_PODMAN_ROOT is passed through from the AMBIENT environment when a
	// developer set it, and never invented (issue #393 spec §1): a system
	// podman at /usr/bin passes G4's first disjunct (@sys already binds
	// /usr), so there is nothing to record, and policy.EngineToolchain("")
	// errors by design. A harness that synthesised a root would be grafting
	// a tree nobody named.
	if root := os.Getenv("SNUG_PODMAN_ROOT"); root != "" {
		out = append(out, "SNUG_PODMAN_ROOT="+root)
	}
	return out, xdg
}

// engineWithHome returns the $SNUG_PODMAN and $SNUG_PODMAN_ROOT a run needs to
// get an engine whose HOME is homeOverride. A tiny exec wrapper is still the
// only way to plant HOME for a process snug starts — everything else
// provisionEngineWrapper used to do (stripping a bundle's own
// storage/containers keys) is gone with the bundle itself.
//
// # Why it returns a ROOT as well, and why the first version was wrong
//
// It returned the wrapper alone, and BOTH gates have to admit that path
// rather than just one. What was measured for #393 was
// internal/cli.preflightPodmanBinary, which only os.Stats the path and
// shim-checks it, so a "#!" wrapper passes — true, and not the question. G4
// asks the OTHER half: can the ENGINE SEE this binary? Since Tier C the
// engine's mount namespace is DERIVED from the sandbox's, so a wrapper in
// t.TempDir() reaches it through nothing at all, and every run through here
// died with
//
//	snug: the container engine cannot see the engine binary (…/snug-test-podman):
//	nothing grafts it into the engine's view and no grant of this sandbox exposes it.
//
// which is the boundary working. $SNUG_PODMAN_ROOT is the seam that names a
// toolchain root for exactly this case (preflight P9, G4's third source), so
// the wrapper's own directory is the root. G4b (#400) does not fire: a
// t.TempDir() is outside every grant of the sandbox under test, so it is not
// payload-writable — the guard refuses a root the PAYLOAD can write, which is
// a different thing from one the test can.
//
// Two gates, and the earlier work measured one. That is the same half-a-rule
// shape CLAUDE.md warns about, so the doc comment names both from now on.
//
// The one caller (TestHostContainersConfAuthorsNothingInAContainer) needs
// this because podman reads a USER containers.conf from
// $XDG_CONFIG_HOME/containers/ and, when that variable is unset, from
// $HOME/.config/containers/ — and the engine's own environment carries no
// XDG_CONFIG_HOME, so on a real run the file podman reads is HOME's. A test
// cannot plant a hostile config into the developer's own ~/.config/containers,
// so it points the engine's HOME at a temporary one instead.
func engineWithHome(t *testing.T, homeOverride string) (wrapper, root string) {
	t.Helper()
	podman := hostEngine(t)
	root = t.TempDir()
	wrapper = filepath.Join(root, "snug-test-podman")
	script := fmt.Sprintf("#!/bin/sh\nexport HOME=%s\nexec %s \"$@\"\n", homeOverride, podman)
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return wrapper, root
}

// seedEngineHome writes the minimum a podman needs to decide an image may be
// used at all, into a home the test owns: $home/.config/containers/policy.json
// = insecureAcceptAnything. The property under test in both callers
// (TestHostContainersConfAuthorsNothingInAContainer,
// TestAHostRegistriesConfDoesNotSteerTheEnginesPull) is that a HOST
// containers.conf/registries.conf does not steer the engine, and that holds
// whatever this host's OWN /etc/containers/policy.json says — measured
// ABSENT on the development host while /usr/share/containers/policy.json is
// present, so generating the seed is what makes the test's result independent
// of undeclared host state rather than a workaround for one missing
// directory in one retired bundle.
func seedEngineHome(t *testing.T, home string) {
	t.Helper()
	dir := filepath.Join(home, ".config", "containers")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	policyJSON := `{"default":[{"type":"insecureAcceptAnything"}]}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(policyJSON), 0o644); err != nil {
		t.Fatal(err)
	}
}

// markEngineRan is the per-test half of issue #393 §4's run-count floor:
// exactly one "snug-engine-ran: <path>" line for every test that is
// COMMITTED to having run with a real engine — never for one that merely
// resolved a binary and then skipped. Makefile's integration-sandbox target
// counts these against SNUG_ENGINE_FLOOR.
func markEngineRan(t *testing.T, enginePath string) {
	t.Helper()
	// The TEST NAME is in the marker, and the Makefile counts DISTINCT names
	// rather than marker lines. Measured, and it is the floor's own version of
	// "a test that cannot fail": some tests reach this twice (requireRealEngine
	// is called per distinct env, and a test driving two envs marks twice), so
	// a bypass run emitted 33 marker LINES from fewer than 32 distinct tests.
	// Counting lines would let 32 lines come from 20 tests and the floor would
	// pass having lost twelve.
	t.Logf("snug-engine-ran: %s %s", t.Name(), enginePath)
}

// enginePathFromEnv reads $SNUG_PODMAN back out of an env slice this file
// built, for markEngineRan's benefit — the env, not hostEngine's own cached
// path, because a caller may have pointed SNUG_PODMAN at engineWithHome's
// wrapper rather than at the resolved binary directly.
func enginePathFromEnv(env []string) string {
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, "SNUG_PODMAN="); ok {
			return rest
		}
	}
	// No explicit SNUG_PODMAN in this env (e.g. TestPodmanBuildIsFilteredEndToEnd's
	// baseEnv()) — the engine actually used is whatever hostEngine already
	// resolved for the whole run, from PATH.
	return resolveHostEngineOnce().path
}

// ── the shared "is there a REAL, working engine" gate ───────────────────────

// realEngineResults memoizes probeRealEngine per distinct env: standing a
// working engine up (subuid delegation, a private cgroup namespace, crun, a
// build that really runs a step) costs real wall-clock time, and every test in
// this file needs the same host-capability answer.
//
// It used to say "a real image pull" and that was true until issue #241: the
// probe built FROM alpine, so this gate — and therefore every test in this
// file — depended on an anonymous Docker Hub pull. It builds FROM scratch now.
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
// A plain t.Skip on failure — never skipOrFail — UNLESS $SNUG_REQUIRE_ENGINE
// is set, for the same reason requireEngine's own doc gives: no CI lane
// promises a working engine today, so a green run that never got one is a
// developer-machine fact, not a regression, and that stays true with the
// variable unset. With it set (issue #393 §4: "an engine that is present but
// cannot run a container is the wrong-engine case"), the same failure is a
// t.Fatal — the caller asked this run to MEAN something.
//
// This is also the ONE place that reaches "committed to running with a real
// engine": markEngineRan fires here, after the skip/fatal decision, never
// before it — a test that resolved an engine and then skipped on this probe
// must NOT count toward the floor (issue #393 §4).
func requireRealEngine(t *testing.T, env []string) {
	t.Helper()
	requireSandbox(t)
	requirePython(t)
	// No requireInternet. This gate carried one until issue #235, from when
	// its probe built FROM alpine, and it put every test in this file behind
	// SNUG_TEST_NET for a pull none of them make any more — the probe is FROM
	// scratch since #241. It still selects @net (see probeRealEngine, which
	// says why), but @net is a network NAMESPACE with pasta attached, not a
	// working route to the internet, and the two were being conflated.

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
		engineFailedOnce.Do(func() {
			t.Logf("snug-engine-failed: %s: engine failed to start: %s", describeResolvedEngine(), reason)
		})
		if os.Getenv("SNUG_REQUIRE_ENGINE") != "" {
			t.Fatalf("SNUG_REQUIRE_ENGINE is set and no usable real container engine is available "+
				"in this environment: %s", reason)
		}
		t.Skip("SKIP: no usable real container engine in this environment: " + reason)
	}
	markEngineRan(t, enginePathFromEnv(env))
}

// probeRealEngine drives the exact "ordinary build" leg
// TestPodmanBuildIsFilteredEndToEnd asserts, in a throwaway target of its
// own, and reports WHY the engine is not usable rather than letting whichever
// test happened to need it first fail with a confusing, unrelated message.
//
// It keeps @net even though the probe needs no egress (issue #235 removed the
// registry the probe used to pull from), because the leg it exists to
// pre-flight is the one TestPodmanBuildIsFilteredEndToEnd runs, and that test
// selects @net. Dropping it here would make the gate pass on a host where the
// @net path is what fails, which is the exact failure requireRealEngine was
// written to convert into a clean skip.
func probeRealEngine(t *testing.T, env []string) string {
	t.Helper()
	proj, _ := target(t)
	writeBuildProbe(t, proj)
	r := runEnv(t, env, []string{"-p", "@podman-build", "-p", "@net"}, proj, `python3 probe.py`)
	if !r.ran {
		// "the probe payload never ran" used to become a skip reason
		// unconditionally, no matter WHY snug refused this fixture's own
		// ordinary run -- issue #369's own measured defect: a test whose
		// XDG_RUNTIME_DIR made the container proxy's socket path exceed
		// AF_UNIX's sun_path limit failed here with exitPolicy (77, "container
		// proxy socket: ... bind: invalid argument"), which this branch folded
		// into the same "no usable engine" SKIP as a genuinely absent
		// capability -- and the suite read green while the regression it
		// existed to catch had never once run.
		//
		// exitUnavail (69, internal/cli/main.go) is the one code this probe's
		// own ordinary, trickery-free fixture can legitimately produce without
		// it being a bug: sandbox.Run itself failed to bring the engine up
		// (the CAP_NET_ADMIN case this file's own header comment names for
		// issue #401). Anything else -- exitPolicy (77, snug REFUSED the run
		// outright), exitUsage (64), exitInternal (70), or any other code --
		// is snug or this harness misbehaving against a fixture that asked for
		// nothing unusual, which is not "there is no engine to test against"
		// and must fail loudly rather than hide behind that skip.
		const exitUnavail = 69
		if r.code != exitUnavail {
			t.Fatalf("probeRealEngine: snug refused this probe's own ordinary run with exit %d, "+
				"which is not exitUnavail (%d) -- that is not \"no usable engine\", it is snug or "+
				"this harness failing for an unrelated reason and must not be swallowed into a "+
				"SKIP:\n%s", r.code, exitUnavail, r.out)
		}
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
    # The timeout is kept in an attribute of our own rather than handed to
    # HTTPConnection: that class stores socket._GLOBAL_DEFAULT_TIMEOUT (a
    # sentinel object, not None and not a number) when none is given, so
    # "if self.timeout is not None: settimeout(self.timeout)" passes the
    # sentinel straight through and raises. Only the ONE caller that talks to a
    # registry sets it -- see TestAnEngineWithNetPullsFromARegistry for why a
    # request that can hang needs its own bound (issue #235).
    def __init__(self, path, timeout=None):
        super().__init__("localhost")
        self.path = path
        self._to = timeout
    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self._to is not None:
            s.settimeout(self._to)
        s.connect(self.path)
        self.sock = s

_sock = os.environ["CONTAINER_HOST"].replace("unix://", "")

def req(method, path, body=None, headers=None, timeout=None):
    c = UnixHTTP(_sock, timeout)
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
// Both directions in one test: without @net a container cannot reach a public
// address the HOST reached moments earlier, while the engine itself still
// answers locally (so the failure is "no network", not "no engine" — the
// control that makes the negative meaningful); with @net the identical
// container reaches it.
//
// # Why this no longer pulls an image (issue #235)
//
// It used to prove both directions with `POST /images/create?fromImage=alpine`
// — an anonymous Docker Hub pull. Docker Hub refuses those ("toomanyrequests:
// You have reached your unauthenticated pull rate limit", measured on this
// development host), and when it does, podman retries internally and the test
// reports nothing but a budget expiring. That failure has been misdiagnosed
// four times, twice with the correction already committed in this repository,
// because the message closest to it names a subsystem that is working. This
// test was the LAST place in the suite that needed a registry.
//
// A local registry of our own cannot replace it, and that is a measurement
// rather than a preference: with @net, `ip -4 addr` inside the sandbox shows
// snug0 carrying the HOST's own address (192.168.1.120/24 here), because that
// is pasta's model. So a listener the test starts on the host's LAN address is
// not reachable from inside — packets to that address stay in the sandbox's
// own netns — and host loopback is closed by design. The only endpoint that is
// reachable with @net and unreachable without it is the real internet, so the
// registry can go and the internet cannot.
//
// What goes with the registry: this no longer proves the engine can complete a
// TLS pull from inside the sandbox's mount view (a CA bundle the engine can
// read is a snug property, not podman's). That leg has its own test —
// TestAnEngineWithNetPullsFromARegistry — which is allowed to SKIP, with the
// registry named, when the registry is the thing refusing.
func TestContainerEgressFollowsNetProfile(t *testing.T) {
	budget(t, 180*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)

	// The host-side positive control AND the address the container is given.
	// internetTarget dials it from here first, so a REFUSED inside the sandbox
	// is a routing answer about snug and cannot be "this laptop is offline" or
	// "DNS is broken" — the container, built FROM scratch, resolves nothing.
	addr := internetTarget(t)

	const tag = "snugegress"
	probeBin := egressprobeBin(t)

	// "host" as the container's NetworkMode, the same as every other container
	// in this file: it means the ENGINE's network namespace, which since Tier B
	// is the sandbox's own N. That is the namespace whose egress is under test.
	script := buildScratchProbeImageFor(tag, "egressprobe") + runContainerAndCollectFn + fmt.Sprintf(`
status, _ = req("GET", "/v1.41/version")
print("version: %%d" %% status, flush=True)
if build_scratch_probe():
    # Cmd is the ADDRESS ALONE, with no "/egressprobe" in front of it. The
    # image already carries ENTRYPOINT ["/egressprobe"] (buildScratchProbeImageFor),
    # and podman APPENDS Cmd to the entrypoint rather than replacing it, so
    # passing the binary here too would hand the probe its own path as the
    # first address to dial. Measured, first run of this test: "RESULT
    # /egressprobe REFUSED dial tcp: address /egressprobe: missing port in
    # address".
    run_and_collect(%q, [%q], "host")
print("SCRIPT-COMPLETE", flush=True)
`, tag, addr)

	// SCRIPT-COMPLETE, not PROBE-COMPLETE: egressprobe prints PROBE-COMPLETE of
	// its own, inside the container logs, and the two markers are checked
	// separately below — one says the payload ran to the end, the other says a
	// container really executed. Sharing a marker would let either stand in for
	// the other, which is how a test stops being able to fail.
	run := func(withNet bool) sandboxRun {
		proj, _ := target(t)
		if err := os.WriteFile(filepath.Join(proj, "egress.py"), []byte(script), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proj, "egressprobe"), mustRead(t, probeBin), 0o755); err != nil {
			t.Fatal(err)
		}
		// @podman-build, where this test used @podman-socket before it built
		// an image of its own: @podman-socket's filter refuses /build, and it
		// refuses it by closing the connection, so the payload dies on a
		// BrokenPipeError with no status code — measured, first run of this
		// rewrite. The profile is not what the test is about (egress follows
		// @net under either one), but a container has to exist to have egress,
		// and building one is how this suite makes a container without a
		// registry.
		args := []string{"-p", "@podman-build"}
		if withNet {
			args = append(args, "-p", "@net")
		}
		return runEnv(t, env, args, proj, `python3 egress.py`).mustRun(t)
	}

	// checkRan is the three things that must hold in BOTH directions before
	// either verdict means anything: the payload finished, the engine was
	// alive, and a container really ran. Without them, "the probe did not
	// reach the internet" is equally true of a sandbox where no container
	// started at all.
	checkRan := func(label string, r sandboxRun) {
		t.Helper()
		if !strings.Contains(r.out, "SCRIPT-COMPLETE") {
			t.Fatalf("%s: the probe payload did not run to the end:\n%s", label, r.out)
		}
		if !strings.Contains(r.out, "version: 200") {
			t.Fatalf("control: %s: the engine did not even answer /version, so the egress "+
				"verdict below proves nothing about egress specifically:\n%s", label, r.out)
		}
		if !strings.Contains(r.out, "BUILD "+tag+": 200") {
			t.Fatalf("control: %s: the FROM scratch probe image did not build, so no container "+
				"ran and the egress verdict below is vacuous:\n%s", label, r.out)
		}
		if !strings.Contains(r.out, "PROBE-COMPLETE") {
			t.Fatalf("control: %s: the container never printed its own PROBE-COMPLETE, so it "+
				"did not run to the end and its verdict is not a network answer:\n%s", label, r.out)
		}
	}

	offline := run(false)
	checkRan("offline", offline)
	if strings.Contains(offline.out, "RESULT "+addr+" REACHED") {
		t.Errorf("a container REACHED %s without @net — the engine has egress an offline "+
			"sandbox must not have:\n%s", addr, offline.out)
	}
	if !strings.Contains(offline.out, "RESULT "+addr+" REFUSED") {
		t.Errorf("expected the offline container to be refused at %s, got:\n%s", addr, offline.out)
	}

	withNet := run(true)
	checkRan("@net", withNet)
	if !strings.Contains(withNet.out, "RESULT "+addr+" REACHED") {
		t.Errorf("the SAME container, with @net selected, must reach %s — the host reached it "+
			"from outside the sandbox moments ago, so this is snug's answer and not the "+
			"network's. Egress follows the profile in both directions or this tier does not "+
			"do what it claims:\n%s", addr, withNet.out)
	}
}

// TestAnEngineWithNetPullsFromARegistry is the leg
// TestContainerEgressFollowsNetProfile gave up when it stopped needing a
// registry (issue #235): an engine inside the sandbox, with @net, completing a
// real TLS pull from a public registry. That is a snug property and not
// podman's — the engine runs in snug's mount view, so it succeeds only if a CA
// bundle and a resolver are actually reachable from in there.
//
// # This test is ALLOWED to skip, and that is the fix rather than a weakness
//
// The registry is someone else's service and it refuses anonymous pulls
// whenever it likes. What issue #235 is actually about is not the refusal, it
// is that the refusal used to arrive as a thirty-second budget with nothing on
// screen naming a registry — so four separate diagnoses blamed cgroups, then
// the proxy, then preflight P5. Here the pull carries its own timeout, its
// body tail is printed, and a refusal SKIPS with the registry named and the
// registry's own words quoted. A skip nobody can misread beats a failure
// everybody does.
//
// A skip is right rather than convenient: a refused anonymous pull is a fact
// about Docker Hub's rate limiter, not about this branch, and there is no
// change to snug that would make it green.
func TestAnEngineWithNetPullsFromARegistry(t *testing.T) {
	budget(t, 180*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	requireInternet(t)

	// pullTimeout bounds the ONE request that talks to a registry. podman
	// retries a refused pull three times internally and only then answers, so
	// without a client-side bound this is exactly the silent budget-eater #235
	// was filed about. It is generous because a cold pull over a slow link is
	// legitimate, and still far inside the budget above.
	script := pyPreamble + fmt.Sprintf(`
status, _ = req("GET", "/v1.41/version")
print("version: %%d" %% status, flush=True)

try:
    status, body = req("POST", "/v1.41/images/create?fromImage=%[1]s&tag=%[2]s", timeout=%[3]d)
    print("pull-http: %%d" %% status, flush=True)
    print("pull-body-tail: %%s" %% body[-400:].decode(errors="replace").replace("\n", " "), flush=True)
except Exception as e:
    print("pull-http: -1", flush=True)
    print("pull-body-tail: the request to the registry did not answer within %[3]ds: %%r" %% (e,), flush=True)

status, _ = req("GET", "/v1.41/images/%[1]s:%[2]s/json")
print("inspect: %%d" %% status, flush=True)
print("PULLED" if status == 200 else "NOT-PULLED", flush=True)
print("SCRIPT-COMPLETE", flush=True)
`, dockerHubImage, dockerHubTag, 40)

	proj, _ := target(t)
	if err := os.WriteFile(filepath.Join(proj, "pull.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	r := runEnv(t, env, []string{"-p", "@podman-socket", "-p", "@net"}, proj, `python3 pull.py`).mustRun(t)

	if !strings.Contains(r.out, "SCRIPT-COMPLETE") {
		t.Fatalf("the pull payload did not run to the end:\n%s", r.out)
	}
	if !strings.Contains(r.out, "version: 200") {
		t.Fatalf("control: the engine did not even answer /version, so the pull result below "+
			"says nothing about registries:\n%s", r.out)
	}
	if strings.Contains(r.out, "PULLED") && !strings.Contains(r.out, "NOT-PULLED") {
		return
	}
	if reason := registryRefusal(r.out); reason != "" {
		t.Skipf("SKIP: %s refused the pull of %s:%s, so this host cannot measure the "+
			"engine's registry path today — this is the registry's answer, not snug's: %s",
			dockerHubRegistry, dockerHubImage, dockerHubTag, reason)
	}
	t.Errorf("an engine with @net could not pull %s:%s from %s, and %s did not refuse it in "+
		"words registryRefusalMarkers recognises — so this is snug's failure until the "+
		"pull-body-tail line below says otherwise:\n%s",
		dockerHubImage, dockerHubTag, dockerHubRegistry, dockerHubRegistry, r.out)
}

// The suite's ONE registry dependency, named once. Anything in this suite that
// contacts a registry must go through these three constants, and
// TestTheSuiteHasExactlyOneRegistryDependency enforces that by parsing every
// test file — because the dependency issue #235 is about was invisible: it sat
// in a python heredoc inside a helper, and "every container test needs a
// Docker Hub pull" was believed, filed, and wrong.
//
// Fully qualified on purpose. A SHORT name goes through registries.conf's
// short-name-alias cache, and __inengine reports euid 0, so containers/image
// picks the SYSTEM cache path (/var/cache/containers) that the real host uid
// cannot write to — measured, and recorded at requireRealEngine above.
const (
	dockerHubRegistry = "docker.io"
	dockerHubImage    = "docker.io/library/alpine"
	dockerHubTag      = "3.20"
)

// registryRefusalMarkers are the registry's OWN words for "not today", as
// distinct from any failure inside the sandbox. Matched against the body the
// engine streamed back, lowercased.
//
// Deliberately narrow: every marker here turns a failure into a skip, so a
// marker that is too broad silently deletes this test. Absent, and each for a
// reason worth stating, because each is a failure shape a reader will be
// tempted to add here the next time it appears:
//
//   - "connection refused", "no route to host", "i/o timeout", "did not answer
//     within" (our own bound) — this is what a BROKEN @net looks like, which is
//     the thing under test.
//   - "no such host", "temporary failure in name resolution" — DNS inside the
//     sandbox is snug's own property (the generated /etc/resolv.conf), and
//     requireInternet has already proved the HOST resolves, so a resolver
//     failure in here is snug's answer and must stay a failure.
//
// A skip is not the only way this stays legible when the registry is at fault:
// both paths out of this test name the registry and quote the body tail, which
// is the whole of what issue #235 asked for.
var registryRefusalMarkers = []string{
	"toomanyrequests",
	"rate limit",
	"429",
	"unauthorized",
}

// registryRefusal reports the registry's own explanation if the output carries
// one, and "" if it does not. The returned string is the pull-body-tail line
// itself, so a skip quotes the registry verbatim rather than paraphrasing it.
func registryRefusal(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "pull-body-tail: ") {
			continue
		}
		low := strings.ToLower(line)
		for _, m := range registryRefusalMarkers {
			if strings.Contains(low, m) {
				return line
			}
		}
	}
	return ""
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
		// os.MkdirTemp, NOT t.TempDir() (issue #401 sandbox-tester coverage,
		// MEASURED). The comment this replaced called the previous choice "a
		// deliberate simplicity trade... this is never on a hot path" and
		// reasoned about "paying it once per calling test" — but sync.Once
		// runs its function exactly ONCE FOR THE WHOLE BINARY, so a
		// t.TempDir() taken inside it belongs to whichever test happens to
		// call this FIRST, and is removed on THAT test's own cleanup. This
		// function had exactly one caller for its whole history, so the
		// defect never fired; adding
		// TestADefaultModeContainerCannotReachHostLoopback as a second
		// caller made it fire immediately: "fork/exec .../netprobe: no such
		// file or directory" in whichever test ran second. os.MkdirTemp with
		// no t.Cleanup, mirroring TestMain's own snugBin, is what makes a
		// second caller in the same binary safe.
		dir, err := os.MkdirTemp("", "snug-netprobe")
		if err != nil {
			netprobeBinErr = fmt.Errorf("creating a build dir for testdata/netprobe: %w", err)
			return
		}
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

// egressprobeBinPath is testdata/egressprobe, built the same lazy way as
// netprobeBin below and for the same reason — it is the entrypoint of a
// `FROM scratch` image, so it must be a static host-architecture binary, and
// most hosts skip every test in this file before ever needing it.
var (
	egressprobeBinOnce sync.Once
	egressprobeBinPath string
	egressprobeBinErr  error
)

func egressprobeBin(t *testing.T) string {
	t.Helper()
	egressprobeBinOnce.Do(func() {
		dir := t.TempDir()
		bin := filepath.Join(dir, "egressprobe")
		cmd := exec.Command("go", "build", "-o", bin, "./testdata/egressprobe")
		cmd.Dir = "."
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			egressprobeBinErr = fmt.Errorf("building test/integration/testdata/egressprobe: %w: %s", err, out.String())
			return
		}
		egressprobeBinPath = bin
	})
	if egressprobeBinErr != nil {
		t.Fatal(egressprobeBinErr)
	}
	return egressprobeBinPath
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
// verbatim — "host" is what every caller in this file has always passed
// explicitly, rather than relying on podman's own default.
//
// That comment used to say "host" is the ONLY mode this tier supports. Since
// issue #401's containers.conf pin (netns = "host" in
// internal/engine/engine.go's writeContainersConf) that is no longer true in
// the way it reads: an UNSET NetworkMode now lands in the same place "host"
// does — the engine's own netns, which is this sandbox's own since Tier B —
// so a caller could equally well omit HostConfig.NetworkMode entirely.
// Nothing here does, on purpose: this function's job is to be the STABLE
// helper every pre-#401 test already depends on, and
// TestAContainerThatNamesNoNetworkModeJoinsTheSandboxsNetns below is what
// actually exercises the omitted-key path, deliberately kept out of this
// shared helper so a caller that wants "host" spelled out still gets it.
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

	// POSITIVE CONTROL, on the exact binary the container will run: from a
	// process that CAN reach this listener, netprobe prints the REACHED
	// spelling the negatives below grep for, naming this address and carrying
	// the banner. Without it "no REACHED line" has two explanations — the
	// sandbox held, or netprobe never produces that line here at all — and
	// issue #243 was three security negatives living on the second one.
	hostOut, err := exec.Command(probeBin, strconv.Itoa(port)).CombinedOutput()
	if err != nil {
		t.Fatalf("control: netprobe failed on the host: %v\n%s", err, hostOut)
	}
	if !hasResultVerdict(parseProbeResults(string(hostOut)), "v4-loop", fmt.Sprintf("127.0.0.1:%d", port), "REACHED") {
		t.Fatalf("control: netprobe run ON THE HOST did not report REACHED for the host's own "+
			"listener — the negatives below cannot distinguish a closed sandbox from a broken "+
			"probe:\n%s", hostOut)
	}
	if !strings.Contains(string(hostOut), hostBanner) {
		t.Fatalf("control: netprobe run ON THE HOST did not read the banner this test's "+
			"escape assertion greps for:\n%s", hostOut)
	}

	probeOnce := func(withNet bool, tag string) string {
		proj, _ := target(t)
		if err := os.WriteFile(filepath.Join(proj, "netprobe"), mustRead(t, probeBin), 0o755); err != nil {
			t.Fatal(err)
		}
		// Cmd carries the PORT ALONE. podman APPENDS Cmd to the image's own
		// ENTRYPOINT rather than replacing it, so a Cmd of ["/netprobe",
		// "<port>"] ran the probe as `/netprobe /netprobe <port>` and it read
		// "/netprobe" as its port — issue #243, three security negatives that
		// could not fail for a milestone.
		script := buildScratchProbeImage(tag) + runContainerAndCollectFn + fmt.Sprintf(`
if build_scratch_probe():
    run_and_collect(%q, ["%d"], "host")
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
		// CONTROL: the RESULT lines are about the address this test opened.
		// The three controls above all held while issue #243 was live — the
		// payload ran, the image built, RESULT lines appeared — because none
		// of them asks what the probe aimed at. This one does, and it is the
		// only thing standing between "the container could not reach the
		// host's loopback" and "the container never tried".
		results := parseProbeResults(r.out)
		want := fmt.Sprintf("127.0.0.1:%d", port)
		if !hasResult(results, "v4-loop", want) {
			t.Fatalf("the container's probe never dialled %s (withNet=%v) — every negative "+
				"below would pass on a sandbox that leaks (issue #243). RESULT lines: %v\n%s",
				want, withNet, results, r.out)
		}
		// A dial that never left the probe process (unparseable address, port
		// or host name lookup) is not an answer about the network at all.
		for _, res := range results {
			if res.verdict == "ERROR" {
				t.Fatalf("the container's probe reported ERROR rather than a network verdict "+
					"(withNet=%v): %v — the probe is broken, and its negatives mean nothing\n%s",
					withNet, res, r.out)
			}
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
		for _, res := range parseProbeResults(out) {
			if res.verdict != "REACHED" {
				continue
			}
			switch res.label {
			case "v4-loop", "v6-loop":
				t.Errorf("a container (NetworkMode=host, @net=%v) REACHED the host's loopback "+
					"listener at %s:\n%s", tc.withNet, res.addr, out)
			case "gw":
				t.Errorf("a container (NetworkMode=host, @net=%v) REACHED the gateway address %s "+
					"— the one --map-host-loopback actually controls:\n%s", tc.withNet, res.addr, out)
			}
		}
	}
}

// TestADefaultModeContainerCannotReachHostLoopback is issue #401's
// adjacent-closed assertion: TestAContainerThatNamesNoNetworkModeJoinsThe
// SandboxsNetns proves WHERE a default-mode (no HostConfig.NetworkMode at
// all) container's netns is; this proves what that placement actually buys —
// the identical closure TestHostLoopbackClosedFromContainer above already
// measures for an EXPLICIT NetworkMode="host" container, now for the shape
// an ordinary docker client sends when it names no --network flag at all.
// Nothing before this test exercised that shape against a real listener —
// every existing caller of the closed-loopback check passes "host" or
// "none" explicitly.
//
// Same disciplines as TestHostLoopbackClosedFromContainer, on purpose: the
// host-side positive control (the listener really is reachable from the
// host before anything else runs), the ON-THE-HOST positive control for the
// probe binary itself (issue #243 — a probe that cannot report REACHED for
// a listener it truly reached proves nothing about a probe that reports
// nothing for one it could not reach), and the address-named RESULT check
// (a verdict about the wrong address is no result at all).
func TestADefaultModeContainerCannotReachHostLoopback(t *testing.T) {
	budget(t, 60*time.Second)
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

	// POSITIVE CONTROL, on the exact binary the container will run: from a
	// process that CAN reach this listener, netprobe prints the REACHED
	// spelling the negative below greps for, naming this address and
	// carrying the banner (issue #243's discipline).
	hostOut, err := exec.Command(probeBin, strconv.Itoa(port)).CombinedOutput()
	if err != nil {
		t.Fatalf("control: netprobe failed on the host: %v\n%s", err, hostOut)
	}
	if !hasResultVerdict(parseProbeResults(string(hostOut)), "v4-loop", fmt.Sprintf("127.0.0.1:%d", port), "REACHED") {
		t.Fatalf("control: netprobe run ON THE HOST did not report REACHED for the host's own "+
			"listener — the negative below cannot distinguish a closed sandbox from a broken "+
			"probe:\n%s", hostOut)
	}
	if !strings.Contains(string(hostOut), hostBanner) {
		t.Fatalf("control: netprobe run ON THE HOST did not read the banner this test's escape "+
			"assertion greps for:\n%s", hostOut)
	}

	tag := "snugtest-loopback401-default:1"
	proj, _ := target(t)
	if err := os.WriteFile(filepath.Join(proj, "netprobe"), mustRead(t, probeBin), 0o755); err != nil {
		t.Fatal(err)
	}
	// Cmd carries the PORT ALONE (issue #243: podman APPENDS Cmd to the
	// image's own ENTRYPOINT rather than replacing it, so a Cmd naming the
	// binary again pushed the port to argv[2] and the probe read its own
	// path as the port).
	script := buildScratchProbeImage(tag) + runContainerAndCollectDefaultFn + fmt.Sprintf(`
if build_scratch_probe():
    run_and_collect_default(%q, ["%d"])
print("PROBE-COMPLETE", flush=True)
`, tag, port)
	if err := os.WriteFile(filepath.Join(proj, "loopback401default.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 loopback401default.py`).mustRun(t)
	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the container-loopback probe did not run to the end:\n%s", r.out)
	}
	if !strings.Contains(r.out, fmt.Sprintf("BUILD %s: 200", tag)) {
		t.Fatalf("the from-scratch image did not build — this test proves nothing about a "+
			"container it never ran:\n%s", r.out)
	}
	if !strings.Contains(r.out, "LOGS-BEGIN") || !strings.Contains(r.out, "RESULT") {
		t.Fatalf("the container never produced its own RESULT lines — it did not actually "+
			"run:\n%s", r.out)
	}

	// CONTROL: the RESULT lines are about the address this test opened, not
	// about a dial that never left the probe process (issue #243).
	results := parseProbeResults(r.out)
	want := fmt.Sprintf("127.0.0.1:%d", port)
	if !hasResult(results, "v4-loop", want) {
		t.Fatalf("the container's probe never dialled %s — every negative below would pass on a "+
			"sandbox that leaks. RESULT lines: %v\n%s", want, results, r.out)
	}
	for _, res := range results {
		if res.verdict == "ERROR" {
			t.Fatalf("the container's probe reported ERROR rather than a network verdict — the "+
				"probe is broken, and its negatives mean nothing\n%s", r.out)
		}
	}

	if strings.Contains(r.out, hostBanner) {
		t.Errorf("a DEFAULT-mode container (no HostConfig.NetworkMode at all) READ the host's "+
			"loopback banner:\n%s", r.out)
	}
	for _, res := range results {
		if res.verdict != "REACHED" {
			continue
		}
		switch res.label {
		case "v4-loop", "v6-loop":
			t.Errorf("a DEFAULT-mode container REACHED the host's loopback listener at %s:\n%s",
				res.addr, r.out)
		case "gw":
			t.Errorf("a DEFAULT-mode container REACHED the gateway address %s — the one "+
				"--map-host-loopback actually controls:\n%s", res.addr, r.out)
		}
	}
}

// probeResult is one "RESULT <label> <addr> <verdict> [detail]" line from
// netprobe. The address is part of the line (issue #243) so that a test
// asserting a negative can first prove the probe aimed where it was told to:
// a verdict about the wrong address is not a weaker result, it is no result.
type probeResult struct {
	label   string
	addr    string
	verdict string
}

func (p probeResult) String() string { return p.label + " " + p.addr + " " + p.verdict }

func parseProbeResults(out string) []probeResult {
	var got []probeResult
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "RESULT" {
			continue
		}
		got = append(got, probeResult{label: f[1], addr: f[2], verdict: f[3]})
	}
	return got
}

func hasResult(results []probeResult, label, addr string) bool {
	for _, r := range results {
		if r.label == label && r.addr == addr {
			return true
		}
	}
	return false
}

func hasResultVerdict(results []probeResult, label, addr, verdict string) bool {
	for _, r := range results {
		if r.label == label && r.addr == addr && r.verdict == verdict {
			return true
		}
	}
	return false
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ── issue #401: the container netns pin, checked as an effect rather than a
//    grep of containers.conf's own bytes ───────────────────────────────────

// runContainerAndCollectDefaultFn is runContainerAndCollectFn's twin with NO
// HostConfig.NetworkMode key at all — the shape a client that never mentions
// --network actually sends, and which nothing else in this file exercises:
// every existing caller of runContainerAndCollectFn passes "host" explicitly
// (that function's own doc comment names why). Before issue #401 that
// omission had no settled answer; the containers.conf pin is what gives it
// one, and this is the helper that asks the question the pin is supposed to
// answer.
const runContainerAndCollectDefaultFn = `
def run_and_collect_default(tag, cmd):
    body = json.dumps({"Image": "localhost/" + tag, "Cmd": cmd, "Tty": True,
                        "HostConfig": {}}).encode()
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

// netnsprobeBinPath is built once, lazily, TRULY process-global rather than
// scoped to whichever test happens to trigger the sync.Once first — unlike
// netprobeBin/holderBin above, which hand back a path under THAT CALLER's
// own t.TempDir(). This probe has two callers
// (TestAContainerThatNamesNoNetworkModeJoinsTheSandboxsNetns and
// TestABuildsRunStepRunsInTheSandboxsNetns), and t.TempDir() is removed on
// ITS OWN test's cleanup — MEASURED: whichever of the two ran first left the
// second reading a path already unlinked ("no such file or directory"), a
// failure with nothing to do with either test's own subject. os.MkdirTemp
// with no t.Cleanup, mirroring TestMain's own snugBin, is what makes a
// second caller in the same binary safe.
var (
	netnsprobeBinOnce sync.Once
	netnsprobeBinPath string
	netnsprobeBinErr  error
)

func netnsprobeBin(t *testing.T) string {
	t.Helper()
	netnsprobeBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "snug-netnsprobe")
		if err != nil {
			netnsprobeBinErr = fmt.Errorf("creating a build dir for testdata/netnsprobe: %w", err)
			return
		}
		bin := filepath.Join(dir, "netnsprobe")
		cmd := exec.Command("go", "build", "-o", bin, "./testdata/netnsprobe")
		cmd.Dir = "."
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			netnsprobeBinErr = fmt.Errorf("building test/integration/testdata/netnsprobe: %w: %s", err, out.String())
			return
		}
		netnsprobeBinPath = bin
	})
	if netnsprobeBinErr != nil {
		t.Fatal(netnsprobeBinErr)
	}
	return netnsprobeBinPath
}

// netnsMarkers pulls every "NETNS net:[...]" line testdata/netnsprobe printed
// — one per container/RUN-step it ran as — in the order they appear in out.
// Regexp rather than a line scan: a build's RUN step output arrives wrapped
// in the streamed JSON build log (each line a `{"stream": "..."}` object,
// not the raw text run_and_collect's Tty=true container logs give), and a
// container log line carries a trailing \r (Tty=true) that a line-anchored
// match would have to know to strip. The marker text itself is plain ASCII
// with no JSON metacharacter, so it survives either wrapping unescaped.
var netnsMarkerRe = regexp.MustCompile(`NETNS (net:\[[0-9]+\])`)

func netnsMarkers(out string) []string {
	matches := netnsMarkerRe.FindAllStringSubmatch(out, -1)
	vals := make([]string, 0, len(matches))
	for _, m := range matches {
		vals = append(vals, m[1])
	}
	return vals
}

// outerNetnsMarkerRe is the sandbox PAYLOAD's own reading of the same path,
// printed by the python driver itself rather than by the compiled probe —
// deliberately a different word ("OUTERNS", not "...NETNS...") so a
// substring match cannot mistake this line for one of netnsMarkers' own.
var outerNetnsMarkerRe = regexp.MustCompile(`OUTERNS (net:\[[0-9]+\])`)

func outerNetnsMarker(out string) (string, bool) {
	m := outerNetnsMarkerRe.FindStringSubmatch(out)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// TestAContainerThatNamesNoNetworkModeJoinsTheSandboxsNetns is issue #401's
// central claim, checked as an effect: a container CREATED WITH NO
// HostConfig.NetworkMode AT ALL must land in the same network namespace as
// the sandbox payload that asked for it, because the containers.conf pin
// (netns = "host" in internal/engine/engine.go's writeContainersConf) makes
// an unset network mode resolve to the ENGINE's own netns, which since Tier
// B is this sandbox's.
//
// Before this test nothing in the suite exercised the omitted-key path at
// all — every existing container test passes NetworkMode="host" explicitly
// (runContainerAndCollectFn's own doc comment), which is why the pin's own
// property had no coverage. The explicit "host" path is this test's
// POSITIVE CONTROL rather than an assumption: it must land in the identical
// namespace the omitted-key path does, or the comparison this test relies on
// is not meaningful even for the well-established case. And the
// DISCRIMINATING CONTROL is that the sandbox payload's own namespace must
// differ from this TEST PROCESS's (the host's) — without it, "the
// container's netns equals the payload's" would also be (trivially) true of
// a sandbox that got no network isolation of its own at all.
func TestAContainerThatNamesNoNetworkModeJoinsTheSandboxsNetns(t *testing.T) {
	budget(t, 120*time.Second)
	requireSandbox(t)
	requireEngine(t)
	requirePython(t)
	requireRealEngine(t, baseEnv())

	proj, _ := target(t)
	if err := os.WriteFile(filepath.Join(proj, "netprobe"), mustRead(t, netnsprobeBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}

	tag := "snugtest-netns401:1"
	script := buildScratchProbeImage(tag) + runContainerAndCollectDefaultFn + runContainerAndCollectFn +
		fmt.Sprintf(`
print("OUTERNS " + os.readlink("/proc/self/ns/net"), flush=True)
if build_scratch_probe():
    run_and_collect_default(%[1]q, [])
    run_and_collect(%[1]q, [], "host")
print("PROBE-COMPLETE", flush=True)
`, tag)
	if err := os.WriteFile(filepath.Join(proj, "netns401.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	r := run(t, []string{"-p", "@podman-build"}, proj, `python3 netns401.py`).mustRun(t)
	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the probe did not run to the end:\n%s", r.out)
	}
	if !strings.Contains(r.out, fmt.Sprintf("BUILD %s: 200", tag)) {
		t.Fatalf("the from-scratch image did not build — this test proves nothing about a "+
			"container it never ran:\n%s", r.out)
	}

	payloadNS, ok := outerNetnsMarker(r.out)
	if !ok {
		t.Fatalf("the sandbox payload never reported its own netns:\n%s", r.out)
	}

	hostSelf, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("reading this TEST PROCESS's own (host) netns: %v", err)
	}
	if payloadNS == hostSelf {
		t.Fatalf("PRECONDITION: the sandbox payload's own netns (%s) equals this HOST test "+
			"process's — this run has no network isolation for a container's netns to be "+
			"compared against, so nothing below can distinguish containment from its absence",
			payloadNS)
	}

	got := netnsMarkers(r.out)
	if len(got) != 2 {
		t.Fatalf("expected exactly 2 NETNS lines (no-NetworkMode container, then the explicit "+
			"\"host\" one), got %d: %v\n%s", len(got), got, r.out)
	}
	noModeNS, hostModeNS := got[0], got[1]

	if hostModeNS != payloadNS {
		t.Fatalf("CONTROL FAILED: a container created with explicit NetworkMode=\"host\" (netns "+
			"%s) is not in the sandbox payload's own netns (%s) — every other test in this file "+
			"relies on that equality holding, so this run's engine is not in the state the rest "+
			"of the suite assumes", hostModeNS, payloadNS)
	}

	if noModeNS != payloadNS {
		t.Errorf("a container created with NO NetworkMode at all is in netns %s, not the "+
			"sandbox payload's own %s — issue #401's containers.conf pin (netns = \"host\" in "+
			"writeContainersConf) is supposed to make an UNSET network mode land here, exactly "+
			"as an explicit \"host\" one does", noModeNS, payloadNS)
	}
}

// TestABuildsRunStepRunsInTheSandboxsNetns is
// TestPodmanBuildIsFilteredEndToEnd's regression guard turned into a
// property: that test already fails without issue #401's containers.conf
// pin and passes with it (a RUN step that needs to bring its own `lo` up
// dies at `ioctl SIOCSIFFLAGS: Operation not permitted` otherwise), which
// proves ONLY that the step ran to completion. This test pins WHERE it ran —
// the RUN step's own netns must equal the sandbox payload's — which is the
// property the symptom is standing in for, not the symptom itself.
//
// The build request itself asks for nothing (networkmode "0", nsoptions
// naming only "user" — the same query buildScratchProbeImageFor already
// sends for every ENTRYPOINT-only build in this file), so this is the
// DEFAULT path, exactly as TestAContainerThatNamesNoNetworkModeJoinsTheSandboxsNetns
// is for a container.
func TestABuildsRunStepRunsInTheSandboxsNetns(t *testing.T) {
	budget(t, 120*time.Second)
	requireSandbox(t)
	requireEngine(t)
	requirePython(t)
	requireRealEngine(t, baseEnv())

	proj, _ := target(t)
	if err := os.WriteFile(filepath.Join(proj, "netnsprobe"), mustRead(t, netnsprobeBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}

	script := pyPreamble + `
import tarfile, io, urllib.parse

print("OUTERNS " + os.readlink("/proc/self/ns/net"), flush=True)

buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as tf:
    data = b"FROM scratch\nCOPY netnsprobe /netnsprobe\nRUN [\"/netnsprobe\"]\n"
    ti = tarfile.TarInfo("Dockerfile")
    ti.size = len(data)
    tf.addfile(ti, io.BytesIO(data))
    with open("netnsprobe", "rb") as f:
        binary = f.read()
    tb = tarfile.TarInfo("netnsprobe")
    tb.size = len(binary)
    tb.mode = 0o755
    tf.addfile(tb, io.BytesIO(binary))
ctx = buf.getvalue()

q = {"dockerfile": '["Dockerfile"]', "t": "snugtest-netns401b:1", "output": "snugtest-netns401b:1",
     "networkmode": "0", "nsoptions": '[{"Name":"user","Host":true,"Path":""}]',
     "isolation": "0", "rm": "1", "layers": "1", "pullpolicy": "missing",
     "seccomp": "/usr/share/containers/seccomp.json", "shmsize": "67108864", "nocache": "1"}
status, body = req("POST", "/v5.0.0/libpod/build?" + urllib.parse.urlencode(q), ctx,
                    {"Content-Type": "application/x-tar"})
print("BUILD: %d" % status, flush=True)
print("BODY-BEGIN", flush=True)
print(body.decode(errors="replace"), flush=True)
print("BODY-END", flush=True)
print("PROBE-COMPLETE", flush=True)
`
	if err := os.WriteFile(filepath.Join(proj, "netns401build.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	r := run(t, []string{"-p", "@podman-build"}, proj, `python3 netns401build.py`).mustRun(t)
	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the probe did not run to the end:\n%s", r.out)
	}
	if !strings.Contains(r.out, "BUILD: 200") {
		t.Fatalf("the build did not succeed — this test proves nothing about a RUN step that "+
			"never ran:\n%s", r.out)
	}

	payloadNS, ok := outerNetnsMarker(r.out)
	if !ok {
		t.Fatalf("the sandbox payload never reported its own netns:\n%s", r.out)
	}

	hostSelf, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("reading this TEST PROCESS's own (host) netns: %v", err)
	}
	if payloadNS == hostSelf {
		t.Fatalf("PRECONDITION: the sandbox payload's own netns (%s) equals this HOST test "+
			"process's — this run has no network isolation for the RUN step's netns to be "+
			"compared against", payloadNS)
	}

	got := netnsMarkers(r.out)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 NETNS line from the RUN step, got %d: %v\n%s", len(got), got, r.out)
	}
	runStepNS := got[0]

	if runStepNS != payloadNS {
		t.Errorf("the build's RUN step ran in netns %s, not the sandbox payload's own %s — "+
			"issue #401's containers.conf pin (netns = \"host\" in writeContainersConf) is "+
			"supposed to put the build step in the engine's own netns, which since Tier B is "+
			"this sandbox's", runStepNS, payloadNS)
	}
}

// sandboxOwnListenerBanner is what the listener TestAContainerReachesAListenerThePayloadHoldsInN's
// own sandbox PAYLOAD opens inside N answers with. Deliberately not hostBanner
// (sandbox_test.go), which answers on the HOST's own real loopback: a REACHED
// line naming this text can only mean the dialler reached the listener this
// test's own payload opened inside N, not some other listener entirely.
const sandboxOwnListenerBanner = "SNUG-SANDBOX-OWN-LISTENER"

// allSections is section's own line-scanning discipline (a Tty=true
// container log line carries a trailing \r before the \n, so an exact-line
// match against a bare "…-END" never fires without trimming it first)
// generalised to return every occurrence in call order rather than only the
// first. section (below) is reused everywhere else in this file, where a
// single sandbox run only ever produces one instance of a given marker pair;
// this test drives TWO containers through the same run_and_collect* helpers
// in one sandbox invocation, so their "LOGS-BEGIN"/"LOGS-END" pairs repeat
// and the first-only helper would silently hand back the first container's
// section for both.
func allSections(out, label string) []string {
	lines := strings.Split(out, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	var got []string
	for i := 0; i < len(lines); i++ {
		if lines[i] != label+"-BEGIN" {
			continue
		}
		end := -1
		for j := i + 1; j < len(lines); j++ {
			if lines[j] == label+"-END" {
				end = j
				break
			}
		}
		if end < 0 {
			break
		}
		got = append(got, strings.Join(lines[i+1:end], "\n"))
		i = end
	}
	return got
}

// TestAContainerReachesAListenerThePayloadHoldsInN is the functional
// counterpart the netns-pin family above lacked: both
// TestAContainerThatNamesNoNetworkModeJoinsTheSandboxsNetns and
// TestABuildsRunStepRunsInTheSandboxsNetns prove netns INODE equality between
// a container (or a build's RUN step) and the sandbox payload, which is not
// the same claim as "the namespace is usable" — `lo` inside a fresh netns
// must be brought UP, and doing that needs CAP_NET_ADMIN, which the engine
// deliberately does not hold (policy.EngineCapBounding, the 2026-08-18
// decision INDEX §"Networking" records). A container landing in the right
// netns with `lo` still down would pass every inode-equality assertion above
// while being unable to reach anything at all — exactly the gap this test
// closes: the sandbox payload opens a TCP listener on its own 127.0.0.1
// inside N, and a container started through the proxy must connect to it and
// read back a marker it could only have gotten from that listener.
//
// Both network-mode shapes runContainerAndCollectFn's own doc comment
// distinguishes are exercised, in one sandbox run against the one listener:
// an explicit NetworkMode="host" (Tier B's established path) and no
// HostConfig.NetworkMode at all (issue #401's own pin).
func TestAContainerReachesAListenerThePayloadHoldsInN(t *testing.T) {
	budget(t, 120*time.Second)
	requireSandbox(t)
	requireEngine(t)
	requirePython(t)
	requireRealEngine(t, baseEnv())

	proj, _ := target(t)
	if err := os.WriteFile(filepath.Join(proj, "netprobe"), mustRead(t, netprobeBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}

	tag := "snugtest-reachpayload401:1"
	script := buildScratchProbeImage(tag) + runContainerAndCollectFn + runContainerAndCollectDefaultFn +
		fmt.Sprintf(`
import threading, subprocess

print("OUTERNS " + os.readlink("/proc/self/ns/net"), flush=True)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(16)
port = srv.getsockname()[1]
print("LISTENER-PORT " + str(port), flush=True)

def serve():
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            conn.sendall((%[2]q + "\n").encode())
        finally:
            conn.close()

threading.Thread(target=serve, daemon=True).start()

# POSITIVE CONTROL: the payload itself, sharing N with the listener it just
# opened, can reach it -- run BEFORE either container, so a failure below
# cannot be confused with a listener that never came up (CLAUDE.md's "a test
# that cannot fail" rule).
self_out = subprocess.run(["./netprobe", str(port)], capture_output=True, text=True).stdout
print("SELF-BEGIN", flush=True)
print(self_out, flush=True)
print("SELF-END", flush=True)

if build_scratch_probe():
    run_and_collect(%[1]q, [str(port)], "host")
    run_and_collect_default(%[1]q, [str(port)])
print("PROBE-COMPLETE", flush=True)
`, tag, sandboxOwnListenerBanner)
	if err := os.WriteFile(filepath.Join(proj, "reachpayload401.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	r := run(t, []string{"-p", "@podman-build"}, proj, `python3 reachpayload401.py`).mustRun(t)
	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the probe did not run to the end:\n%s", r.out)
	}
	if !strings.Contains(r.out, fmt.Sprintf("BUILD %s: 200", tag)) {
		t.Fatalf("the from-scratch image did not build — this test proves nothing about a "+
			"container it never ran:\n%s", r.out)
	}

	payloadNS, ok := outerNetnsMarker(r.out)
	if !ok {
		t.Fatalf("the sandbox payload never reported its own netns:\n%s", r.out)
	}
	hostSelf, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("reading this TEST PROCESS's own (host) netns: %v", err)
	}
	if payloadNS == hostSelf {
		t.Fatalf("PRECONDITION: the sandbox payload's own netns (%s) equals this HOST test "+
			"process's — this run has no network isolation for a container's reach into it to "+
			"mean anything", payloadNS)
	}

	portLine := regexp.MustCompile(`LISTENER-PORT (\d+)`).FindStringSubmatch(r.out)
	if portLine == nil {
		t.Fatalf("the payload never reported the port its own listener bound to:\n%s", r.out)
	}
	want := fmt.Sprintf("127.0.0.1:%s", portLine[1])

	selfSections := allSections(r.out, "SELF")
	if len(selfSections) != 1 {
		t.Fatalf("expected exactly 1 SELF section (the payload's own positive control), got "+
			"%d:\n%s", len(selfSections), r.out)
	}
	if !hasResultVerdict(parseProbeResults(selfSections[0]), "v4-loop", want, "REACHED") ||
		!strings.Contains(selfSections[0], sandboxOwnListenerBanner) {
		t.Fatalf("POSITIVE CONTROL FAILED: the sandbox payload itself, sharing N with the "+
			"listener it just opened, could not reach %s and read its banner — nothing below "+
			"can distinguish a container that cannot reach it from a listener that never came "+
			"up:\n%s", want, selfSections[0])
	}

	logSections := allSections(r.out, "LOGS")
	if len(logSections) != 2 {
		t.Fatalf("expected exactly 2 container LOGS sections (explicit NetworkMode=\"host\", "+
			"then no HostConfig.NetworkMode at all), got %d:\n%s", len(logSections), r.out)
	}
	for i, mode := range []string{`NetworkMode="host"`, "no HostConfig.NetworkMode at all"} {
		section := logSections[i]
		results := parseProbeResults(section)
		// CONTROL: the container's probe actually dialled the address this
		// test opened, not something else entirely (issue #243's own
		// discipline — a verdict about the wrong address is no result).
		if !hasResult(results, "v4-loop", want) {
			t.Fatalf("a container created with %s never dialled %s at all — every assertion "+
				"below would pass on a container that never tried. RESULT lines: %v\n%s",
				mode, want, results, section)
		}
		if !hasResultVerdict(results, "v4-loop", want, "REACHED") ||
			!strings.Contains(section, sandboxOwnListenerBanner) {
			t.Errorf("a container created with %s could not reach the sandbox payload's own "+
				"listener at %s and read its banner — issue #401's containers.conf pin places "+
				"it in N, but that only proves inode equality: `lo` inside N must still be "+
				"brought up by something else, since the engine holds no CAP_NET_ADMIN to do "+
				"it itself:\n%s", mode, want, section)
		}
	}
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
	// The GUEST socket path, not the host one, and the difference is Tier C:
	// the engine is exec'd with an argv written in terms of its own derived
	// view (issue #125), so the host path this used to search for appears
	// nowhere in its cmdline. The pid part still comes from the host side —
	// engine.New names the socket after snug's own pid — so this stays a
	// search for THIS run's engine rather than for any engine.
	sock := filepath.Join(policy.EngineSockGuest, filepath.Base(engineSocketPath(uid, snugPID)))
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

	// The GUEST socket path, for findEnginePID's reason: the engine's argv is
	// written in terms of its derived view since Tier C (issue #125).
	sock := filepath.Join(policy.EngineSockGuest,
		filepath.Base(engineSocketPath(os.Getuid(), bg.pid())))

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
	writeBuildProbe(t, proj)
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
		// engine reported ready — this IS the commit point for the run-count
		// floor (issue #393 §4): a real engine served this control.
		markEngineRan(t, enginePathFromEnv(env))
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
    # Cmd is the token ALONE: podman appends Cmd to the image's ENTRYPOINT
    # rather than replacing it (issue #243), so naming the binary here made
    # the holder print "HOLDING /netprobe" and pushed the token to argv[2].
    # The host-side scan below matches on cmdline, so it survived that either
    # way -- which is the reason it went unnoticed, not a reason to keep it.
    body = json.dumps({"Image": "localhost/" + tag, "Cmd": [token],
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

	// The GUEST socket path: since Tier C the engine's argv is written in
	// terms of its own derived view, so the host path appears nowhere in its
	// cmdline (issue #125). Same shape as findEnginePID's own search.
	sock := filepath.Join(policy.EngineSockGuest,
		filepath.Base(engineSocketPath(os.Getuid(), bg.pid())))
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

	// Seed policy.json first. podman needs it to decide whether an image may
	// be used at all — without it requireRealEngine reports "a build
	// succeeded but its RUN step never actually executed a container", which
	// looks like a broken host rather than a missing file. Measured, not
	// guessed: the skip appeared the moment $HOME moved and went away when
	// the seed was added. Generating it (rather than copying a bundle's own
	// home/) is also what keeps this independent of undeclared host state —
	// see seedEngineHome's own doc comment.
	seedEngineHome(t, home)

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
	wrapper, toolchainRoot := engineWithHome(t, home)
	base, _ := attachEnv(t)
	// SNUG_PODMAN_ROOT is not optional: the wrapper is the engine binary for
	// this run and it lives outside every grant, so without the graft G4
	// refuses the run outright. See engineWithHome's own doc comment.
	env := append(base, "SNUG_PODMAN="+wrapper, "SNUG_PODMAN_ROOT="+toolchainRoot)
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

	podman := hostEngine(t)
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
//	pid=1899298 ppid=1899295 pid:[4026535001] /netprobe c0probe-...
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
    run_and_collect(%q, [], "host")

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
//     dereferenced into the engine's own mount namespace instead of the
//     container's own.
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
    run_and_collect(%q, [], "host")
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
// POSITIVE CONTROL, against the SAME real engine: a read-only bind of /usr,
// which the default profile set already grants and whose every path component
// is anchored (issue #284), is accepted — so the /proc refusal below is a
// decision about /proc specifically, not evidence that every bind request
// fails, or that the engine never came up at all.
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
    # has, is accepted by the same filter against the same engine. It is /usr
    # read-only rather than the writable target, since issue #284: every name
    # on /usr's path is anchored (the root tmpfs above it is not writable and
    # /usr is itself a read-only mount root), while the target's own path runs
    # through the plain, payload-renameable directory names the anchored source
    # rule now refuses -- see TestASwappedBindSourceCannotReachTheEngineGrafts.
    body2 = json.dumps({"Image": "localhost/%s",
                         "HostConfig": {"NetworkMode": "host",
                                        "Mounts": [{"Type": "bind", "Source": "/usr",
                                                     "Target": "/hostusr", "ReadOnly": True}]}}).encode()
    status2, resp2 = req("POST", "/v1.41/containers/create", body2, {"Content-Type": "application/json"})
    print("USRBIND-CREATE: %%d %%s" %% (status2, resp2.decode(errors="replace")[:400]), flush=True)
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
	if !strings.Contains(r.out, "USRBIND-CREATE: 201") {
		t.Fatalf("control: an ordinary read-only bind of /usr, every name on whose path is "+
			"anchored, was NOT accepted (want 201) — this test's /proc refusal below proves "+
			"nothing about a working bind filter:\n%s", r.out)
	}

	// The refusal itself.
	if !strings.Contains(r.out, "PROCBIND-CREATE: 403") {
		t.Errorf("`-v /proc:/hostproc` was not refused with 403:\n%s", r.out)
	}
	if !strings.Contains(r.out, "cannot see /proc") {
		t.Errorf("the refusal does not say the sandbox cannot see /proc, the actual mechanism:\n%s", r.out)
	}
}

// TestContainerRunGivesThePayloadAnEmptyUnwritableRun is the cost of modelling
// the engine's own /run tmpfs (issue #125's design pass §9.2), asserted from
// the payload's side rather than from the screen's.
//
// The engine mounts a fresh tmpfs on /run in ITS OWN namespace, because podman
// reads itself as root-like with the full delegated subuid range and does not
// self-mount one. A mount needs a mountpoint, and since issue #206 moved snug's
// own paths to /snug a sandbox creates no /run at all — so BwrapFlags now
// pre-creates the directory on a container run (EngineMountpoints). That is a
// real, if small, change to what the payload sees, and this is what it may see:
// an empty directory it cannot write.
//
// THE NEGATIVE CONTROL IS THE SECOND HALF and is what makes the first mean
// anything: a DEFAULT run has no /run at all. Without it, "the payload sees an
// empty /run" would pass on a snug that created /run for every sandbox.
func TestContainerRunGivesThePayloadAnEmptyUnwritableRun(t *testing.T) {
	budget(t, 60*time.Second)
	env, _ := containerEngineEnv(t)
	requireSandbox(t)
	proj, _ := target(t)

	script := `printf '%s\n' ` + payloadMarker + `
[ -d /run ] && echo "run-is-a-directory=yes" || echo "run-is-a-directory=no"
echo "run-entries=$(ls -A /run 2>/dev/null | wc -l)"
if touch /run/snug-probe 2>/dev/null; then echo "run-write=OK"; else echo "run-write=REFUSED"; fi
`
	out, code := cli(t, env, "-p", "@podman-socket", proj, "--", "/bin/sh", "-c", script)
	if code != 0 {
		t.Fatalf("a @podman-socket run exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "run-is-a-directory=yes") {
		t.Fatalf("the payload of a container run found no /run directory, so the engine's own "+
			"tmpfs would have nowhere to land once its view is derived from the sandbox's "+
			"(EngineMountpoints):\n%s", out)
	}
	// COMMIT POINT for the run-count floor (issue #393 §4): a @podman-socket
	// run that got past the fatal check above really stood the engine's own
	// mountpoint up.
	markEngineRan(t, enginePathFromEnv(env))
	if !strings.Contains(out, "run-entries=0") {
		t.Errorf("/run is not EMPTY in the payload's view — it is a mountpoint snug creates for "+
			"the ENGINE, and anything in it is something the payload was handed without a grant "+
			"saying so:\n%s", out)
	}
	if !strings.Contains(out, "run-write=REFUSED") {
		t.Errorf("/run is WRITABLE in the payload's view. It sits on the root tmpfs, which "+
			"--remount-ro / covers; a writable directory here is a shadow slot of exactly the "+
			"shape issue #22 measured:\n%s", out)
	}

	// NEGATIVE CONTROL: no container profile, no /run. Same payload, same
	// harness, one profile fewer.
	control := `printf '%s\n' ` + payloadMarker + `
[ -e /run ] && echo "control-run=present" || echo "control-run=absent"
`
	cout, ccode := cli(t, baseEnv(), proj, "--", "/bin/sh", "-c", control)
	if ccode != 0 {
		t.Fatalf("the default-selection control run exited %d:\n%s", ccode, cout)
	}
	if !strings.Contains(cout, "control-run=absent") {
		t.Errorf("control: a DEFAULT sandbox has a /run, so the assertions above say nothing "+
			"about the container selection — /run existed only because snug's own paths lived "+
			"under it, and issue #206 moved them:\n%s", cout)
	}
}

// TestTheEnginesViewIsDerivedAndCarriesNoHostTree is what Tier C's C2-view is
// FOR, asserted where it is true rather than through a container: the engine's
// own mount namespace, read from the host through /proc/<engine>/mountinfo.
//
// The engine's view is built from the resolved Policy, so the host tree is not
// there for a container to name. The proxy's bind filter refuses an ungranted
// path by name as well — enforcement by predicate — and every other test in
// this file exercises that half. This one exercises the structural half: the
// absence of anything to name.
//
// THREE ARMS, because the negative alone would pass on a namespace this test
// failed to find:
//
//	CONTROL A — the mount table was really read and is really the engine's:
//	            it has the graft destinations in it. A table with none of them
//	            is some other process's.
//	CONTROL B — a path the SANDBOX grants (/usr) is present, so "the host tree
//	            is absent" is not being satisfied by an empty namespace.
//	NEGATIVE  — no mount point under the host user's own home, and no
//	            /oldroot: the two shapes the measurement on #125 found when the
//	            engine joined too early.
func TestTheEnginesViewIsDerivedAndCarriesNoHostTree(t *testing.T) {
	budget(t, 60*time.Second)
	env, _ := containerEngineEnv(t)
	requireSandbox(t)
	proj, _ := target(t)

	// The payload prints the SANDBOX's own mount table and then waits, so the
	// comparison below is against what the payload really sees rather than
	// against a list this test keeps.
	var out bytes.Buffer
	cmd := exec.Command(snugBin, "-p", "@podman-socket", proj, "--",
		"/bin/sh", "-c", "cat /proc/self/mountinfo; echo "+payloadMarker+"; sleep 30")
	cmd.Env = env
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	enginePID, ok := findDescendant(cmd.Process.Pid, isEngineProcess, 20*time.Second)
	if !ok {
		t.Fatalf("PRECONDITION: no engine process appeared under a @podman-socket run, so there "+
			"is no mount namespace to read and this test proves nothing:\n%s", out.String())
	}
	// COMMIT POINT for the run-count floor (issue #393 §4): the fatal check
	// above already proved a real engine process exists.
	markEngineRan(t, enginePathFromEnv(env))
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(out.String(), payloadMarker) && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	sandbox := mountPointsOf(t, out.String())
	if len(sandbox) < 5 {
		t.Fatalf("PRECONDITION: the payload printed %d mount(s); the comparison below would be "+
			"vacuous:\n%s", len(sandbox), out.String())
	}

	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", enginePID))
	if err != nil {
		t.Fatalf("reading the engine's own mount table (pid %d): %v", enginePID, err)
	}
	points := mountPointsOf(t, string(raw))

	// CONTROL A: this really is the engine's namespace — the grafts landed.
	for _, want := range []string{policy.EngineStoreGuest, policy.EngineRunrootGuest,
		policy.EngineSockGuest, policy.EngineConfGuest} {
		if !points[want] {
			t.Fatalf("the engine's mount table has no %s — either this is not the engine's "+
				"namespace or the grafts did not land, and the negative below would then be "+
				"true of the wrong process:\n%s", want, raw)
		}
	}

	// CONTROL B: the engine's view really is DERIVED — it carries the
	// sandbox's own mounts, not merely its own additions.
	inherited := 0
	for p := range sandbox {
		if points[p] {
			inherited++
		}
	}
	if inherited < len(sandbox)/2 {
		t.Errorf("only %d of the sandbox's %d mounts appear in the engine's view; the engine's "+
			"namespace is supposed to BE the sandbox's plus this run's grafts:\n%s",
			inherited, len(sandbox), raw)
	}

	// THE NEGATIVE: every mount in the engine's view is either one the SANDBOX
	// itself has, or one snug added for the engine — and nothing else. This is
	// the whole of C2-view stated as a set relation, which is stronger than
	// naming shapes to forbid: a host mount nobody predicted fails it too.
	engineOwn := map[string]bool{
		"/proc": true, "/sys/fs/cgroup": true, "/run": true, "/var/tmp": true,
		policy.EngineStoreGuest: true, policy.EngineRunrootGuest: true,
		policy.EngineSockGuest: true, policy.EngineConfGuest: true,
		policy.EngineToolchainGuest: true,
	}
	for p := range points {
		if sandbox[p] || engineOwn[p] {
			continue
		}
		// A submount carried in by a graft (AT_RECURSIVE) is the graft's, not
		// a stray: it is inside a destination snug named.
		under := false
		for own := range engineOwn {
			if strings.HasPrefix(p, own+"/") {
				under = true
				break
			}
		}
		if under {
			continue
		}
		t.Errorf("the engine's view has a mount at %s that the SANDBOX does not have and snug "+
			"did not add for the engine. Before C2-view the engine held a private copy of the "+
			"whole host tree; a mount here that is neither the sandbox's nor a graft is that "+
			"tree coming back:\n%s", p, raw)
	}
}

// mountPointsOf is the set of mount points in a mountinfo dump — field 5,
// which is the one field of that format this comparison needs.
func mountPointsOf(t *testing.T, dump string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, ln := range strings.Split(dump, "\n") {
		f := strings.Fields(ln)
		if len(f) > 4 && strings.HasPrefix(f[4], "/") {
			out[f[4]] = true
		}
	}
	return out
}

// isEngineProcess identifies the engine by its ARGV: the stage execs the
// resolved podman with `system service` on it, which no other process in this
// tree does. By argv rather than by comm for the same reason isStageProcess
// gives — comm is truncated to 15 bytes and is the kernel's, not ours.
func isEngineProcess(pid int) bool {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	if len(args) < 3 {
		return false
	}
	sawSystem, sawService := false, false
	for _, a := range args {
		switch a {
		case "system":
			sawSystem = true
		case "service":
			sawService = true
		// __inengine carries the engine's whole argv on its OWN argv (it is
		// what execs it), so it matches `system service` too — for the window
		// between the stage forking it and the exec, during which it has not
		// finished building the derived view. A test that took that pid read
		// the engine's mount namespace BEFORE the grafts were attached and
		// reported them missing (measured: this test's own control fired).
		case "__inengine":
			return false
		}
	}
	return sawSystem && sawService
}

// ── issue #284: the create/start TOCTOU on a bind SOURCE ────────────────────

// TestASwappedBindSourceCannotReachTheEngineGrafts is issue #284's two
// measured reproductions, kept in one test because the second is the first
// amplified and a fix that closes only the first leaves the worse half open.
//
// The primitive. The proxy resolves a bind source once, at container CREATE,
// and forwards the resolved NAME. crun re-resolves that same string a second
// time, at container START, from a separate process in the ENGINE's
// namespace — a distinct client request with an attacker-controlled gap in
// between. filepath.Clean pins a string, not an inode, so:
//
//	mkdir realdir
//	POST /containers/create -v $PWD/realdir:/x:rw     -> 201 (pre-fix)
//	rmdir realdir; ln -s /snug/engine/store realdir
//	POST /containers/<id>/start                        -> the container got
//	                                                      /snug/engine/store
//	                                                      READ-WRITE
//
// — this sandbox's host-backed, cross-run container store, which the payload's
// own /snug/engine/store cannot even see (it is not in the sandbox's mount
// namespace at all).
//
// The amplification, and why the destination is not the interesting half: the
// SAME swap aimed at /snug/engine/sock hands the container the RAW engine
// API, the one this proxy exists to stand in front of. Measured on the
// unfixed tree: a create carrying {Privileged: true, CapAdd: ["SYS_ADMIN"],
// Binds: ["/snug/engine/store:/store:rw"]} — every one of which this proxy
// refuses by name — returned 201 through that socket. So a store-only pin
// would have left the bypass that reopens everything else.
//
// What the fix asserts here is destination-agnostic by construction
// (policy.CheckEngineBindSource): the refusal is about the SOURCE having a
// name this sandbox can still re-point, whatever it is eventually aimed at.
// Both reproductions therefore die at CREATE, before any symlink is planted,
// and the test also plants them anyway and re-attempts — a fix that only
// refused the pre-swap spelling would pass the first assertion and fail the
// second.
//
// POSITIVE CONTROL, against the same real engine and the same filter: a
// read-only bind of /usr — anchored, because the root tmpfs above it is not
// writable and /usr is itself a mount root — is accepted with 201. Without it
// every 403 below is equally explained by an engine that never came up.
func TestASwappedBindSourceCannotReachTheEngineGrafts(t *testing.T) {
	budget(t, 120*time.Second)
	env, _ := containerEngineEnv(t)
	requireRealEngine(t, env)
	proj, _ := target(t)

	// The image needs a file to COPY, not a working binary: this test never
	// STARTS a container — every create it makes must be refused, and the one
	// that is not is deleted immediately. So it writes its own placeholder
	// rather than calling one of this file's probe builders, which cache the
	// built path in a sync.Once against the FIRST calling test's t.TempDir()
	// and hand a deleted path to every later caller in a full-suite run
	// (measured: "open .../TestContainerGetsGeneratedResolvConf.../resolvprobe:
	// no such file or directory", passing in isolation and failing under
	// `make integration`).
	if err := os.WriteFile(filepath.Join(proj, "swapprobe"), []byte("#!/bin/false\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	tag := "snugtest-swapsrc:1"
	script := buildScratchProbeImageFor(tag, "swapprobe") + fmt.Sprintf(`
def create(label, src, dst="/x", opts="rw"):
    body = json.dumps({"Image": "localhost/%[1]s",
                       "HostConfig": {"Binds": ["%%s:%%s:%%s" %% (src, dst, opts)]}}).encode()
    status, resp = req("POST", "/v1.41/containers/create", body, {"Content-Type": "application/json"})
    text = resp.decode(errors="replace")
    print("%%s: %%d %%s" %% (label, status, text[:600].replace("\n", " | ")), flush=True)
    if status == 201:
        req("DELETE", "/v1.41/containers/%%s?force=1" %% json.loads(resp)["Id"])
    return status

if build_scratch_probe():
    # CONTROL: an anchored source is still mountable against this engine.
    create("CONTROL-ANCHORED", "/usr", "/u", "ro")

    # R1, the #284 primitive itself, as the issue reproduces it.
    os.mkdir("realdir")
    create("R1-CREATE", os.path.join(os.getcwd(), "realdir"))

    # ... and the swap the gap exists for, performed anyway: a fix that only
    # refused the pre-swap spelling would still forward this one.
    os.rmdir("realdir")
    os.symlink("%[2]s", "realdir")
    create("R1-AFTER-SWAP", os.path.join(os.getcwd(), "realdir"))
    create("R1-DIRECT", "%[2]s")

    # R2, the amplification: the same primitive aimed at the socket graft,
    # which is what turns a store write into the raw unfiltered API.
    os.symlink("%[3]s", "socklink")
    create("R2-CREATE", os.path.join(os.getcwd(), "socklink"), "/sock")
    create("R2-DIRECT", "%[3]s", "/sock")
print("PROBE-COMPLETE", flush=True)
`, tag, policy.EngineStoreGuest, policy.EngineSockGuest)
	if err := os.WriteFile(filepath.Join(proj, "swapsrc.py"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	r := runEnv(t, env, []string{"-p", "@podman-build"}, proj, `python3 swapsrc.py`).mustRun(t)
	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the probe did not run to the end:\n%s", r.out)
	}
	if !strings.Contains(r.out, fmt.Sprintf("BUILD %s: 200", tag)) {
		t.Fatalf("the from-scratch image did not even build — this test proves nothing:\n%s", r.out)
	}
	if !strings.Contains(r.out, "CONTROL-ANCHORED: 201") {
		t.Fatalf("control: an anchored read-only bind of /usr was NOT accepted (want 201) — "+
			"every refusal below is then equally explained by a dead engine:\n%s", r.out)
	}

	for _, label := range []string{"R1-CREATE", "R1-AFTER-SWAP", "R1-DIRECT", "R2-CREATE", "R2-DIRECT"} {
		if !strings.Contains(r.out, label+": 403") {
			t.Errorf("%s was not refused with 403 — issue #284's reproduction is open:\n%s",
				label, r.out)
		}
	}

	// The refusal for the pre-swap spelling must be THIS check and not one of
	// the older ones that happen to sit on the same path: only the anchored
	// source rule refuses a source that resolves, exists, and is visible to
	// the sandbox read-write, and only it says why.
	if !strings.Contains(r.out, "before the container starts") {
		t.Errorf("R1-CREATE was refused by some other check: the anchored source rule's own "+
			"wording is absent, so a later change could delete it and this test would still "+
			"pass:\n%s", r.out)
	}
	// The graft half of the source rule (CheckEngineBindSource's own refusal
	// for a component under /snug/engine/*) is deliberately NOT asserted from
	// the message here, and the measurement is the reason: against a real
	// engine an EARLIER check answers first on every route to a graft — a
	// direct spelling hits hostPathVisible ("this sandbox cannot see
	// /snug/engine/store as writable"), and a planted symlink hits the
	// dangling-symlink refusal of #251/#255, because a graft guest path
	// resolves to nothing in the sandbox's own namespace. So the graft clause
	// is a third layer under those two, and asserting its wording here would
	// be asserting which of three refusals happens to fire first. Its own
	// coverage is the unit table in internal/policy/enginebind_test.go
	// ("an ancestor is covered by a graft's Guest -> refused"). What matters
	// to #284 and IS asserted above: every one of these five routes to
	// /snug/engine/{store,sock} is refused, with no container id returned.
	if strings.Contains(r.out, `"Id"`) && !strings.Contains(r.out, "CONTROL-ANCHORED: 201") {
		t.Errorf("a create returned a container id where none should have:\n%s", r.out)
	}
}

// ── the create body's TOP level, end to end (issues #375, #397) ──────────────

// TestCreateTopLevelIsFilteredEndToEnd is the integration half of the
// inversion internal/dockerproxy/toplevelallowlist_test.go covers with a fake
// engine.
//
// What it adds over the unit tests, and the only reason it is worth a real
// engine: the unit tests prove snug REFUSES the right things, against an engine
// that accepts anything. This proves the other half — that what snug still
// FORWARDS is accepted by a real podman. An inversion that refuses everything
// is trivially "secure" and breaks the profile, and no fake engine can tell you
// which side of that line you landed on.
//
// It needs `create` to work and deliberately NOT `start`. That is not a
// convenience: on a host with no CAP_NET_ADMIN a container cannot start at all
// (measured — `netavark: Netlink error: Operation not permitted` for bridge, and
// `crun: ioctl SIOCSIFFLAGS` on the build path), which is why requireRealEngine
// SKIPS on this development host. The create path is unaffected and is the
// entire surface under test, so gating on requireRealEngine would skip this test
// on the machine it was written on and prove nothing anywhere else. The
// CONTROL below is the gate instead: an ordinary create must return 201, and if
// it does not the test skips naming what the engine said.
//
// CONSEQUENCE, STATED BECAUSE IT IS A REAL GAP AND NOT A FREE CHOICE: issue
// #393's SNUG_ENGINE_FLOOR counts test functions by a literal-string sweep over
// containerEngineEnv|podmanBundle|bundleRoot|requireRealEngine, and this test
// matches none of them — so it is NOT on the floor, and the floor stays 32. That
// means a run where this test skipped on its own control is not caught by the
// mechanism built to catch exactly that ("green by skipping", #393's own
// defect). The trade was taken deliberately: gating on requireRealEngine would
// make this test SKIP on the development host where it currently passes and
// really exercises the filter, which is worse than being uncounted. The skip
// paths below are t.Skipf with the engine's own words in them so the shortfall
// is at least visible in the log. A second floor category for "needs create, not
// run" belongs to #393/#395 and is filed rather than invented here.
func TestCreateTopLevelIsFilteredEndToEnd(t *testing.T) {
	budget(t, 240*time.Second)
	requireSandbox(t)
	requireEngine(t)
	requirePython(t)

	proj, _ := target(t)
	writeTopLevelProbe(t, proj)

	r := run(t, []string{"-p", "@podman-build"}, proj, `python3 probe.py`).mustRun(t)

	if !strings.Contains(r.out, "PROBE-COMPLETE") {
		t.Fatalf("the probe did not run to the end, so a missing marker below is absent "+
			"rather than negative:\n%s", r.out)
	}
	// The image has to exist before any create can be judged on its merits.
	if !strings.Contains(r.out, "build: 200") {
		t.Skipf("SKIP: this host's engine could not build the probe image, so nothing "+
			"below is a statement about the create filter:\n%s", r.out)
	}

	// ── THE CONTROL, FIRST AND FATAL ────────────────────────────────────
	//
	// A real create, with the top-level body a stock docker CLI sends, must be
	// ACCEPTED by a real podman. Every refusal after this is equally true of a
	// proxy that 403s every create, and the profile would be useless with this
	// test green.
	if !strings.Contains(r.out, "ordinary create: 201") {
		t.Skipf("SKIP: an ordinary create did not return 201 on this host, so the refusals "+
			"below prove nothing about filtering:\n%s", r.out)
	}
	// And what podman RECORDED must be what snug forwarded — the positive
	// control with teeth. Without reading the value back, "201" is satisfied by
	// an engine that accepted the body and dropped every field in it.
	if !strings.Contains(r.out, "recorded-cmd: ok") {
		t.Errorf("the create was accepted but podman did not record the Cmd snug forwarded, "+
			"so the allowlist is not actually passing values through:\n%s", r.out)
	}
	if !strings.Contains(r.out, "recorded-env: ok") {
		t.Errorf("a NAME=VALUE Env entry did not survive to the recorded container config, "+
			"so checkEnv is refusing more than the bare-name spelling:\n%s", r.out)
	}
	if !strings.Contains(r.out, "recorded-label: ok") {
		t.Errorf("snug's own run label is not on the created container, which is what "+
			"handleContainerDelete's ownership gate reads (#339):\n%s", r.out)
	}

	// ── the refusals ────────────────────────────────────────────────────
	for _, want := range []struct{ marker, why string }{
		{"unmodelled top-level: 403",
			"a non-empty top-level key nobody modelled must fail closed — the inversion itself"},
		{"healthcheck: 403",
			"a healthcheck asks the engine for a systemd unit and timer on the host user's " +
				"session manager (#397)"},
		{"healthcheck no interval: 403",
			"absent/0/negative Interval all record podman's 30s default, so the refusal is " +
				"on the object and not on Interval"},
		{"env bare name: 403",
			"a bare Env name copies the ENGINE's own variable of that name into the container"},
		{"env star: 403",
			"Env:[\"*\"] copies every engine variable, all of which name this run's grafts"},
		{"macaddress: 403",
			"a static MAC on the interface snug authors — refused at the top level"},
		{"endpoint macaddress: 403",
			"and refused inside NetworkingConfig, because one of the two spellings is no " +
				"refusal at all"},
		{"endpoint ipaddress: 403",
			"a static IP reaches the network namespace the containment rests on (#375)"},
		{"volumes: 403",
			"an anonymous volume is a host path by another name"},
	} {
		if !strings.Contains(r.out, want.marker) {
			t.Errorf("%s — expected %q in:\n%s", want.why, want.marker, r.out)
		}
	}

	// ── and the ergonomic floor, which is the other positive control ─────
	//
	// An EMPTY unmodelled key is dropped, not refused, and the create still
	// succeeds. Without this the refusals above are satisfied by an inversion
	// evaluated on raw presence, which would 403 every `docker run` on 18 keys.
	if !strings.Contains(r.out, "empty unmodelled: 201") {
		t.Errorf("an EMPTY unmodelled top-level key was not dropped-and-forwarded. That is "+
			"the half that makes the inversion shippable at all:\n%s", r.out)
	}
	// The stock client's own NetworkingConfig is structurally non-empty and
	// semantically zero. It must pass, or `docker run` is banned.
	if !strings.Contains(r.out, "stock networkingconfig: 201") {
		t.Errorf("the NetworkingConfig a real docker CLI sends was refused. That is a ban on "+
			"`docker run`, not a filter:\n%s", r.out)
	}
}

// writeTopLevelProbe puts the top-level create probe and the static binary its
// Dockerfile copies into a target directory.
//
// Both, always — the same trap writeBuildProbe's own comment records: the script
// tars "marker" from its working directory, so writing the script alone produces
// a probe that fails on a missing file and looks like a filter result.
func writeTopLevelProbe(t *testing.T, proj string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(proj, "probe.py"), []byte(topLevelProbe), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "marker"), mustRead(t, buildMarkerBin(t)), 0o755); err != nil {
		t.Fatal(err)
	}
}

// topLevelProbe drives POST /containers/create once per case and prints one
// marker per case, so a missing marker is distinguishable from a negative one
// (PROBE-COMPLETE is the end-of-script guard the caller checks first).
//
// It builds its own FROM-scratch image rather than pulling: no registry, no
// egress, and no dependency on Docker Hub's rate limiter (issue #235).
//
// It never STARTS a container. See the caller's doc comment for why that is a
// property of the test rather than a shortcut.
const topLevelProbe = pyPreamble + `
import io, tarfile

buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as tf:
    df = b'FROM scratch\nCOPY marker /marker\nENTRYPOINT ["/marker"]\n'
    ti = tarfile.TarInfo("Dockerfile"); ti.size = len(df); ti.mode = 0o644
    tf.addfile(ti, io.BytesIO(df))
    tf.add("marker", arcname="marker")
st, body = req("POST", "/v1.41/build?dockerfile=Dockerfile&t=snugtest-toplevel%3A1&rm=1&forcerm=1&q=0&nocache=0",
               body=buf.getvalue(), headers={"Content-Type": "application/x-tar"})
print("build: %d" % st, flush=True)
if st != 200:
    print("build-tail: %s" % body[-400:].decode(errors="replace").replace("\n", " | "), flush=True)

IMG = "snugtest-toplevel:1"
JSONH = {"Content-Type": "application/json"}

def create(label, body, want_id=False):
    st, resp = req("POST", "/v1.41/containers/create", body=json.dumps(body), headers=JSONH)
    print("%s: %d" % (label, st), flush=True)
    if st not in (200, 201):
        print("    %s" % resp[:220].decode(errors="replace").replace("\n", " "), flush=True)
        return None
    return json.loads(resp).get("Id") if want_id else None

# ── THE CONTROL: the top-level body a stock docker CLI sends, plus the two
#    fields the allowlist has to pass through by value.
cid = create("ordinary create", {
    "Image": IMG, "Cmd": ["/marker"], "Env": ["SNUG_PROBE=kept"],
    "Labels": {"mine": "kept"},
    "AttachStdout": True, "AttachStderr": True,
    "NetworkingConfig": {"EndpointsConfig": {}},
    "HostConfig": {"NetworkMode": "host"},
}, want_id=True)

# Read the values BACK, so "201" cannot pass on an engine that dropped them.
if cid:
    st, resp = req("GET", "/v1.41/containers/%s/json" % cid)
    if st == 200:
        cfg = json.loads(resp).get("Config") or {}
        print("recorded-cmd: %s" % ("ok" if (cfg.get("Cmd") or []) == ["/marker"] else
                                    "MISSING %r" % (cfg.get("Cmd"),)), flush=True)
        env = cfg.get("Env") or []
        print("recorded-env: %s" % ("ok" if "SNUG_PROBE=kept" in env else
                                    "MISSING %r" % (env,)), flush=True)
        labels = cfg.get("Labels") or {}
        ok = labels.get("mine") == "kept" and any(k == "snug.run" for k in labels)
        print("recorded-label: %s" % ("ok" if ok else "MISSING %r" % (labels,)), flush=True)
    else:
        print("recorded-cmd: inspect-%d" % st, flush=True)

# ── the ergonomic floor ──────────────────────────────────────────────
create("empty unmodelled", {"Image": IMG, "FieldPodmanAddsIn2027": None,
                            "HostConfig": {"NetworkMode": "host"}})
# The endpoint object a real docker CLI really sends: structurally non-empty,
# semantically all-zero. Refusing it would ban 'docker run'.
create("stock networkingconfig", {"Image": IMG, "HostConfig": {"NetworkMode": "host"},
    "NetworkingConfig": {"EndpointsConfig": {"default": {
        "IPAMConfig": None, "Links": None, "Aliases": None, "DriverOpts": None,
        "GwPriority": 0, "NetworkID": "", "EndpointID": "", "Gateway": "",
        "IPAddress": "", "MacAddress": "", "IPPrefixLen": 0, "IPv6Gateway": "",
        "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "DNSNames": None}}}})

# ── the refusals ─────────────────────────────────────────────────────
create("unmodelled top-level", {"Image": IMG, "FieldPodmanAddsIn2027": "anything"})
create("healthcheck", {"Image": IMG,
                       "Healthcheck": {"Test": ["CMD", "/marker"], "Interval": 30000000000}})
create("healthcheck no interval", {"Image": IMG, "Healthcheck": {"Test": ["CMD", "/marker"]}})
create("env bare name", {"Image": IMG, "Env": ["REGISTRY_AUTH_FILE"]})
create("env star", {"Image": IMG, "Env": ["*"]})
create("macaddress", {"Image": IMG, "MacAddress": "02:42:ac:11:00:02"})
create("endpoint macaddress", {"Image": IMG, "NetworkingConfig": {"EndpointsConfig":
        {"default": {"MacAddress": "02:42:ac:11:00:02"}}}})
create("endpoint ipaddress", {"Image": IMG, "NetworkingConfig": {"EndpointsConfig":
        {"default": {"IPAddress": "10.0.0.7"}}}})
create("volumes", {"Image": IMG, "Volumes": {"/data": {}}})

print("PROBE-COMPLETE", flush=True)
`
