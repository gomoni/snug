package main

import (
	"path/filepath"
	"strings"
	"testing"
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
func TestContainerSocketNeverExposesEngineSocketDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	p := resolveFor(t, []string{"@sys", "@home", "@cwd-rw", "@podman-socket"})

	// startContainers never actually starts podman: the engine is brought up
	// lazily on the proxy's first HTTP request (container.go), and this test
	// sends none. So this exercises the real wiring — engine.New's path
	// derivation, the proxy's socket bind, BindSocket — without needing podman
	// installed.
	cleanup, err := startContainers(p, false)
	if err != nil {
		t.Fatalf("startContainers: %v", err)
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
