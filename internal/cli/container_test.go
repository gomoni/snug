package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestContainerSocketNeverExposesEngineSocketDir is the red team's missing
// guard (CONTAINER-CLIENT.md §9): "there is currently no regression test
// asserting the upstream engine socket is unreachable — the property holds
// structurally and nothing guards it." The engine's own socket lives under
// $XDG_RUNTIME_DIR/snug/engines/<key>/podman-<pid>.sock (internal/engine);
// only the PROXY's socket — a completely different path, under
// $XDG_RUNTIME_DIR/snug/run-<pid>/ — may ever appear as a Mount.Host in the
// resolved policy. If that ever stopped being true, a container inside the
// sandbox could dial the real engine directly and bypass the filtering proxy
// entirely.
//
// Positive control, per CLAUDE.md's working agreement ("a test that cannot
// fail is worse than no test"): the proxy socket bind IS asserted present, so
// this cannot pass on a sandbox that never wired up containers at all.
//
// Calls startContainersHostNetwork, NOT startContainers, since issue #63
// Tier B: startContainers now refuses outright (see
// TestStartContainersRefusesUntilTheEngineIsWiredIntoTheStage below) because
// the engine is not yet forked through the stage. startContainersHostNetwork
// is the preserved pre-Tier-B implementation this property was written
// against, kept alive so the property is not lost when the guard lifts.
func TestContainerSocketNeverExposesEngineSocketDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	p := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@podman-socket"})

	// startContainersHostNetwork never actually starts podman: the engine is
	// brought up lazily on the proxy's first HTTP request (container.go), and
	// this test sends none. So this exercises the real wiring — engine.New's
	// path derivation, the proxy's socket bind, BindSocket — without needing
	// podman installed.
	cleanup, err := startContainersHostNetwork(p, false)
	if err != nil {
		t.Fatalf("startContainersHostNetwork: %v", err)
	}
	defer cleanup()

	engineDir := filepath.Join(dir, "snug", "engines")

	foundProxySocket := false
	for _, m := range p.Mounts {
		if m.Guest == containerSocketGuest {
			foundProxySocket = true
		}
		if m.Host != "" && strings.HasPrefix(m.Host, engineDir) {
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

// TestStartContainersRefusesUntilTheEngineIsWiredIntoTheStage is invariant 5
// applied to issue #63, Tier B's incomplete state: the resolved Policy now
// correctly demands the engine run inside the sandbox's own network
// namespace (deriveTopology), but nothing yet makes that true, so a REAL run
// (dryRun=false) must refuse rather than silently hand back an engine
// running on the host's network while --dry-run claims otherwise.
//
// Positive control: PodmanOff still returns a no-op cleanup with no error —
// this refusal is specific to a container profile being selected, not a
// blanket failure of startContainers itself.
func TestStartContainersRefusesUntilTheEngineIsWiredIntoTheStage(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	p := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@podman-socket"})
	if _, err := startContainers(p, false, false); err == nil {
		t.Fatal("startContainers succeeded for a podman-selected policy; it must refuse until " +
			"the engine actually runs inside the stage's netns (issue #63, Tier B)")
	}

	off := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw"})
	cleanup, err := startContainers(off, false, false)
	if err != nil {
		t.Fatalf("startContainers refused a policy with no container profile: %v", err)
	}
	cleanup()
}

// TestStartContainersDryRunIsExemptFromTheRefusal is the OTHER half: the
// refusal above must NOT reach --dry-run, whose entire promise is "having
// started nothing" (CLAUDE.md) — describing a policy is not the same act as
// running the engine it describes, and calling startContainers with
// dryRun=true starts nothing eagerly either way (the engine is lazy). Without
// this, --dry-run -p @podman-socket would abort before it ever reached
// describeTopology/describeContainers, which is exactly the regression this
// test exists to catch: it was found by actually running the binary, not by
// reading the diff.
func TestStartContainersDryRunIsExemptFromTheRefusal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	p := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@podman-socket"})
	cleanup, err := startContainers(p, false, true)
	if err != nil {
		t.Fatalf("startContainers(dryRun=true) refused a podman-selected policy: %v", err)
	}
	cleanup()

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
