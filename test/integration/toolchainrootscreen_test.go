//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDryRunRefusesAToolchainRootOverlappingAWritableGrant fails if a
// $SNUG_PODMAN_ROOT that a writable grant of this run lands inside is let
// through resolution again, in --dry-run as in a real run. Resolve refuses it
// (exit 77) before the CONTAINERS screen is ever built, so the screen's own
// "THIS RUN WILL REFUSE" judgement of a toolchain root is not reached from
// here: for an absolute root, Resolve's check canonicalises both sides and
// covers whatever the screen's tree check would, and a relative root is
// refused by path hygiene instead of the tree check. What this test does not
// reach is the screen arm itself; internal/cli's
// TestContainersScreenExistenceOnlyDowngradesAClearance and
// TestContainersScreenAgreesWithTheRunOnASymlinkedToolchainRoot pin that arm
// against a fake env.
func TestDryRunRefusesAToolchainRootOverlappingAWritableGrant(t *testing.T) {
	budget(t)
	proj, _ := target(t)

	// Nonexistent on purpose: the overlap is a question about path
	// membership, so a payload cannot quiet the refusal by not creating the
	// directory.
	root := filepath.Join(proj, "no-such-toolchain-root")
	env := baseEnv("SNUG_PODMAN_ROOT=" + root)

	// A podman profile is selected so the run is one that would use an engine
	// at all.
	out, code := cli(t, env, "--dry-run", "-p", "@podman-socket", proj)
	if code != 77 {
		t.Fatalf("snug --dry-run exited %d, want 77, for a $SNUG_PODMAN_ROOT inside the rw target:\n%s", code, out)
	}
	for _, want := range []string{"refusing to grant WRITE access to", proj, root, "$SNUG_PODMAN_ROOT", "engine toolchain root"} {
		if !strings.Contains(out, want) {
			t.Errorf("refusal does not contain %q:\n%s", want, out)
		}
	}

	// POSITIVE CONTROLS: the same invocation with a root that overlaps no
	// writable grant resolves and renders, so the 77 above is about the
	// fixture and not about every $SNUG_PODMAN_ROOT.
	clean := t.TempDir()
	cleanOut, cleanCode := cli(t, baseEnv("SNUG_PODMAN_ROOT="+clean), "--dry-run", "-p", "@podman-socket", proj)
	if cleanCode != 0 {
		t.Fatalf("control: snug --dry-run exited %d with a root outside every grant:\n%s", cleanCode, cleanOut)
	}
	if !strings.Contains(cleanOut, clean) {
		t.Errorf("control: the dry-run output never names the toolchain root %s, so it may not have rendered the CONTAINERS block at all:\n%s", clean, cleanOut)
	}

	// A root that only a read-only grant reaches is allowed: reading the
	// toolchain is not the hole. proj/sibling is inside @parent-ro and is
	// not under the rw target.
	ro := filepath.Join(filepath.Dir(proj), "sibling")
	if _, err := os.Stat(ro); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	roOut, roCode := cli(t, baseEnv("SNUG_PODMAN_ROOT="+ro), "--dry-run", "-p", "@podman-socket", proj)
	if roCode != 0 {
		t.Fatalf("control: snug --dry-run exited %d with a root only a read-only grant reaches:\n%s", roCode, roOut)
	}
}
