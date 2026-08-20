package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/dockerproxy"
	"github.com/gomoni/snug/internal/engine"
	"github.com/gomoni/snug/internal/policy"
)

// TestContainerSocketNeverExposesEngineSocketDir is the red team's missing
// guard (CONTAINER-CLIENT.md §9): "there is currently no regression test
// asserting the upstream engine socket is unreachable — the property holds
// structurally and nothing guards it." The engine's own socket now lives
// under /tmp/snug-<uid>-<pid>/ (issue #63, Tier B — internal/engine.New);
// only the PROXY's socket — a completely different path, under
// $XDG_RUNTIME_DIR/snug/run-<pid>/ — may ever appear as a Mount.Host in the
// resolved policy. If that ever stopped being true, a container inside the
// sandbox could dial the real engine directly and bypass the filtering proxy
// entirely.
//
// This exercises the same wiring startContainers does — engine.New's path
// derivation, the proxy's socket bind, BindSocket — WITHOUT going through
// the host-capability preflight (P1-P6), which a CI runner may not satisfy:
// what this test guards is a property of the WIRING, not of whether this
// particular host can run a real podman.
//
// Positive control, per CLAUDE.md's working agreement ("a test that cannot
// fail is worse than no test"): the proxy socket bind IS asserted present, so
// this cannot pass on a sandbox that never wired up containers at all.
func TestContainerSocketNeverExposesEngineSocketDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	p := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@podman-socket"})

	eng, err := engine.New(p.Profiles, p.Target)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Stop()

	rt, err := openRuntimeDir()
	if err != nil {
		t.Fatal(err)
	}
	sock, err := rt.Socket("podman.sock")
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := dockerproxy.New(p, eng.Socket(), sock, eng.RunLabel(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	p.BindSocket(sock, containerSocketGuest, "(containers)")

	foundProxySocket := false
	for _, m := range p.Mounts {
		if m.Guest == containerSocketGuest {
			foundProxySocket = true
		}
		if m.Host != "" && strings.HasPrefix(m.Host, filepath.Dir(eng.Socket())) {
			t.Errorf("policy exposes the engine's OWN socket directory at %s -> %s; "+
				"a container could dial the engine directly and bypass the filtering proxy",
				m.Guest, m.Host)
		}
	}
	if !foundProxySocket {
		t.Fatalf("the proxy socket at %s was never bound — this test proves nothing "+
			"about the property it claims to guard", containerSocketGuest)
	}
}

// TestStartContainersRefusesNetHostPlusPodman is the settled edge from
// ENGINE-WIRING.md §4: @net-host keeps NetnsHost (deriveTopology's own `<`
// guard) while a container profile still raises Subuid to SubuidFull, and
// nothing downstream (stage.Start, __inengine) has a namespace for a
// host-netns engine to join. startContainers refuses the COMBINATION
// cleanly, before anything is created, rather than let it reach stage.Start
// as an unhandled case. This check runs BEFORE preflight, so it does not
// need a real podman/subuid-capable host to assert.
//
// Positive control: the same profile set WITHOUT @net-host (offline
// @podman-socket, still exercising the same preflight-adjacent code path via
// dryRun=true so no host capability is required) is not refused by this
// specific check — see TestStartContainersDryRunNeedsNoHostCapability.
func TestStartContainersRefusesNetHostPlusPodman(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	p := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@net-host", "@podman-socket"})
	_, err := startContainers(p, false, false)
	if err == nil {
		t.Fatal("startContainers accepted @net-host + @podman-socket; the container engine has " +
			"no sandbox network namespace to join under @net-host")
	}
	if !strings.Contains(err.Error(), "@net-host") {
		t.Errorf("error does not name @net-host, the profile to drop: %v", err)
	}
}

// TestStartContainersOffPodmanIsANoop is the positive control for the checks
// above: a policy with NO container profile selected must not be refused by
// anything in this file, whatever the host looks like.
func TestStartContainersOffPodmanIsANoop(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	p := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw"})
	ctr, err := startContainers(p, false, false)
	if err != nil {
		t.Fatalf("startContainers refused a policy with no container profile: %v", err)
	}
	if ctr.spec != nil || ctr.onEngineReady != nil || ctr.onPayloadExit != nil {
		t.Error("a policy with no container profile must not produce an EngineSpec or its hooks")
	}
	if len(ctr.excludeFromTeardown) != 0 {
		t.Errorf("a policy with no container profile armed no reaper, so nothing may be "+
			"exempted from the teardown sweep; got %v", ctr.excludeFromTeardown)
	}
	ctr.cleanup()
}

// TestStartContainersDryRunNeedsNoHostCapability is the other half of the
// @net-host refusal test above: --dry-run's own promise is "having started
// nothing" (CLAUDE.md), so it must not require a real podman, a real
// /etc/subuid range, or any of the other host capabilities preflight checks
// for — describing a policy is not the same act as running the engine it
// describes. Without this, `--dry-run -p @podman-socket` would fail on a CI
// runner with no podman installed, which is exactly the regression this
// guards.
func TestStartContainersDryRunNeedsNoHostCapability(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	p := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@podman-socket"})
	ctr, err := startContainers(p, false, true)
	if err != nil {
		t.Fatalf("startContainers(dryRun=true) refused a podman-selected policy: %v", err)
	}
	if ctr.spec != nil || ctr.onEngineReady != nil || ctr.onPayloadExit != nil {
		t.Error("startContainers(dryRun=true) must not build an EngineSpec or its hooks: " +
			"sandbox.Run is never called on the --dry-run path, so nothing would ever consume them")
	}
	if len(ctr.excludeFromTeardown) != 0 {
		t.Errorf("startContainers(dryRun=true) armed no reaper — --dry-run starts nothing — so "+
			"nothing may be exempted from the teardown sweep; got %v", ctr.excludeFromTeardown)
	}
	ctr.cleanup()

	foundProxySocket := false
	for _, m := range p.Mounts {
		if m.Guest == containerSocketGuest {
			foundProxySocket = true
		}
	}
	if !foundProxySocket {
		t.Error("startContainers(dryRun=true) did not bind the proxy socket into the policy, " +
			"so --dry-run's MOUNTS section would not show it")
	}
}
