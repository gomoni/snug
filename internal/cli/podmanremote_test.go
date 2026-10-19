package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestPreflightRefusesAPodmanRemoteEngine is issue #678: a `podman` that
// resolves to podman-remote is a client with no engine in it, and was
// accepted as the engine and exec'd with `system service`, failing in
// podman-remote's words. Both arms, because both returns go through the
// refusal: $SNUG_PODMAN naming it, and a client-only distrobox's
// `podman -> podman-remote` symlink found on $PATH. The control is the same
// symlink to a file named podman-real, which must be accepted — without it
// the test would pass on a preflight that refuses every symlink.
func TestPreflightRefusesAPodmanRemoteEngine(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) string {
		p := filepath.Join(dir, "real", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	remote := write("podman-remote")
	full := write("podman-real")

	onPath := func(t *testing.T, target string) {
		t.Helper()
		bin := t.TempDir()
		if err := os.Symlink(target, filepath.Join(bin, "podman")); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SNUG_PODMAN", "")
		t.Setenv("PATH", bin)
	}

	t.Run("$SNUG_PODMAN names podman-remote", func(t *testing.T) {
		t.Setenv("SNUG_PODMAN", remote)
		_, err := preflightPodmanBinary(policy.OSEnviron{}, &policy.Policy{})
		if err == nil || !strings.Contains(err.Error(), "podman-remote client build") {
			t.Fatalf("preflightPodmanBinary(SNUG_PODMAN=%s) = %v, want the podman-remote refusal", remote, err)
		}
	})

	t.Run("podman on $PATH is a symlink to podman-remote", func(t *testing.T) {
		onPath(t, remote)
		_, err := preflightPodmanBinary(policy.OSEnviron{}, &policy.Policy{})
		if err == nil || !strings.Contains(err.Error(), "podman-remote client build") {
			t.Fatalf("preflightPodmanBinary with podman -> %s on $PATH = %v, want the podman-remote refusal", remote, err)
		}
		if !strings.Contains(err.Error(), "Fix: install the distribution podman package") {
			t.Errorf("the refusal does not name the fix: %v", err)
		}
	})

	t.Run("control: a symlink to a full podman is accepted", func(t *testing.T) {
		onPath(t, full)
		got, err := preflightPodmanBinary(policy.OSEnviron{}, &policy.Policy{})
		if err != nil {
			t.Fatalf("preflightPodmanBinary refused podman -> %s: %v", full, err)
		}
		if got != full {
			t.Errorf("preflightPodmanBinary returned %q, want %q", got, full)
		}
	})
}
