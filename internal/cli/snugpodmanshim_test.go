package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestSnugPodmanIsRunThroughTheShimCheck is issue #396: $SNUG_PODMAN named a
// binary and preflightPodmanBinary returned it after os.Stat and nothing else,
// so a host-escape shim reached the engine path through the variable while the
// same shim found on PATH was refused two lines below.
//
// The bypass had a rationale that expired: pointing at an explicit path used to
// mean "a static bundle snug ships", so re-resolving "podman" from PATH would
// have asked the wrong question. With the fallback retired (#384) the variable
// is a testing seam, and the configuration the whole subject existed because of
// — /usr/bin/podman being a symlink to distrobox-host-exec — was accepted
// without a word when named this way.
//
// POSITIVE CONTROL IS MANDATORY HERE, and not as a formality: this check has
// never existed, so "no shim was found" is the answer a missing check gives
// too. The control is the second subtest — a non-shim absolute path must still
// be ACCEPTED — plus the shim subtest asserting the refusal names the variable,
// so a refusal arriving for some unrelated reason cannot pass.
func TestSnugPodmanIsRunThroughTheShimCheck(t *testing.T) {
	dir := t.TempDir()

	// The thing a shim is: an executable whose resolved basename is in
	// hostEscapeShims. A symlink, because that is the real spelling —
	// /usr/bin/podman -> /usr/bin/distrobox-host-exec.
	realShim := filepath.Join(dir, "distrobox-host-exec")
	if err := os.WriteFile(realShim, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	shimmedPodman := filepath.Join(dir, "podman-shimmed")
	if err := os.Symlink(realShim, shimmedPodman); err != nil {
		t.Fatal(err)
	}

	// A real engine binary is anything whose resolved basename is not in that
	// set. Content is irrelevant — detectHostShim reads the name, not the ELF.
	realPodman := filepath.Join(dir, "podman-real")
	if err := os.WriteFile(realPodman, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("a shim named by $SNUG_PODMAN is refused", func(t *testing.T) {
		t.Setenv("SNUG_PODMAN", shimmedPodman)
		got, err := preflightPodmanBinary(policy.OSEnviron{}, &policy.Policy{})
		if err == nil {
			t.Fatalf("preflightPodmanBinary accepted a host-escape shim named by "+
				"$SNUG_PODMAN and returned %q — this is issue #396, and the control "+
				"subtest proves this test can distinguish accept from refuse", got)
		}
		// The refusal must be THIS refusal. Without these, a failure for any
		// unrelated reason — a stat error, a missing subuid range — would pass.
		for _, want := range []string{"$SNUG_PODMAN", "distrobox-host-exec"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal does not mention %q, so it may not be the shim check "+
					"that fired: %v", want, err)
			}
		}
	})

	t.Run("control: a real binary named by $SNUG_PODMAN is accepted", func(t *testing.T) {
		t.Setenv("SNUG_PODMAN", realPodman)
		got, err := preflightPodmanBinary(policy.OSEnviron{}, &policy.Policy{})
		if err != nil {
			t.Fatalf("preflightPodmanBinary refused a non-shim absolute path %q: %v — "+
				"the shim check must not refuse an ordinary engine binary, or the "+
				"refusal above proves nothing", realPodman, err)
		}
		if got != realPodman {
			t.Errorf("preflightPodmanBinary returned %q, want the named path %q — "+
				"$SNUG_PODMAN is trusted for WHICH binary, only checked for being a shim",
				got, realPodman)
		}
	})

	t.Run("control: a directory named by $SNUG_PODMAN is still refused", func(t *testing.T) {
		t.Setenv("SNUG_PODMAN", dir)
		if _, err := preflightPodmanBinary(policy.OSEnviron{}, &policy.Policy{}); err == nil {
			t.Fatal("a directory was accepted; the pre-existing os.Stat check regressed")
		}
	})
}
