package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestPreflightPodmanBinaryReturnsAResolvedPath is issue #405's resolution
// obligation (containerpreflight.go's own doc comment on
// preflightPodmanBinary): every return is put through
// policy.ResolveExistingHostPath immediately before it leaves the function,
// so policy.(*Policy).CheckEngineBinary and preflightToolchainRoot's
// containment check both judge the SAME string snug will actually exec,
// rather than a symlink spelling that could differ from it.
//
// This is THE mechanical guard that the resolution call cannot be silently
// removed — more load-bearing than the doc comments naming it, because a doc
// comment does not fail a build. It is deliberately red-on-mutation-proven:
// dropping the policy.ResolveExistingHostPath call from either return site in
// preflightPodmanBinary makes both of BOTH arms below fail, since each
// asserts the RESOLVED target, not the symlink it was named through.
func TestPreflightPodmanBinaryReturnsAResolvedPath(t *testing.T) {
	dir := t.TempDir()

	real := filepath.Join(dir, "real", "podman-real")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("$SNUG_PODMAN arm: a symlink resolves to its real target", func(t *testing.T) {
		link := filepath.Join(dir, "podman-via-env")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SNUG_PODMAN", link)
		got, err := preflightPodmanBinary(policy.OSEnviron{}, &policy.Policy{})
		if err != nil {
			t.Fatalf("preflightPodmanBinary refused a plain symlink to a real binary: %v", err)
		}
		if got != real {
			t.Errorf("preflightPodmanBinary returned %q, want the RESOLVED target %q — "+
				"policy.ResolveExistingHostPath is not being applied to the $SNUG_PODMAN "+
				"return, so CheckEngineBinary and preflightToolchainRoot would judge a "+
				"different string than the one that gets exec'd", got, real)
		}
	})

	t.Run("PATH arm: a symlink on $PATH resolves to its real target", func(t *testing.T) {
		t.Setenv("SNUG_PODMAN", "") // make sure the $SNUG_PODMAN arm above is not taken
		pathDir := filepath.Join(dir, "bin")
		if err := os.MkdirAll(pathDir, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(pathDir, "podman") // exec.LookPath needs the exact name
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", pathDir)
		got, err := preflightPodmanBinary(policy.OSEnviron{}, &policy.Policy{})
		if err != nil {
			t.Fatalf("preflightPodmanBinary refused a plain symlink found on $PATH: %v", err)
		}
		if got != real {
			t.Errorf("preflightPodmanBinary returned %q, want the RESOLVED target %q — "+
				"policy.ResolveExistingHostPath is not being applied to the PATH-lookup "+
				"return", got, real)
		}
	})

	// CONTROL: issue #396's shim refusal still fires on the NAME AS GIVEN,
	// before resolution ever runs — order is load-bearing (the doc comment on
	// preflightPodmanBinary says so explicitly), and this is what proves
	// resolution did not silently move ahead of the shim check.
	t.Run("control: the shim check still fires on the name as given", func(t *testing.T) {
		shimTarget := filepath.Join(dir, "distrobox-host-exec")
		if err := os.WriteFile(shimTarget, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "podman-shim-link")
		if err := os.Symlink(shimTarget, link); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SNUG_PODMAN", link)
		_, err := preflightPodmanBinary(policy.OSEnviron{}, &policy.Policy{})
		if err == nil {
			t.Fatal("a symlink resolving to a host-escape shim was accepted — issue #396 regressed")
		}
		if !strings.Contains(err.Error(), link) {
			t.Errorf("the shim refusal %q does not name %q, the path AS GIVEN — resolution must "+
				"run AFTER the shim check, not steer its message toward the resolved target", err, link)
		}
	})
}
