//go:build integration

package integration

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestDryRunExitsZeroWithARefusingToolchainRoot is the control on
// issue #422's screen: a $SNUG_PODMAN_ROOT this run's own grants make
// writable renders "THIS RUN WILL REFUSE" in the CONTAINERS block, and
// --dry-run still exits 0 — a screen judges what the run WOULD do; it never
// refuses the run itself, and does no preflight of its own.
// internal/cli's TestContainersScreenExistenceOnlyDowngradesAClearance and
// TestContainersScreenAgreesWithTheRunOnASymlinkedToolchainRoot
// (enginejudgeequivalence_test.go) pin this exact refusal text against a fake
// env and never run the real binary; nothing before this test asserted the
// exit code end to end.
func TestDryRunExitsZeroWithARefusingToolchainRoot(t *testing.T) {
	budget(t)
	proj, _ := target(t)

	// Nonexistent on purpose — the same fixture
	// TestContainersScreenExistenceOnlyDowngradesAClearance's "toolchain
	// root" subtest uses: the refusal is about PATH MEMBERSHIP inside a
	// writable grant (CheckEngineToolchainTree), never about an object
	// actually on disk, so a payload could not quiet the screen merely by
	// not creating the directory.
	root := filepath.Join(proj, "no-such-toolchain-root")
	env := baseEnv("SNUG_PODMAN_ROOT=" + root)

	// The CONTAINERS block — and with it the toolchain-root judgement — only
	// renders once a podman profile is selected (describeContainers returns
	// immediately while p.Podman == policy.PodmanOff); @podman-socket is the
	// same selection enginejudgeequivalence_test.go's own fixture uses for
	// this exact judgement.
	out, code := cli(t, env, "--dry-run", "-p", "@podman-socket", proj)
	if code != 0 {
		t.Fatalf("snug --dry-run exited %d with a refusing toolchain root — a screen must not "+
			"itself refuse the run, only say what a real one would do:\n%s", code, out)
	}
	if !strings.Contains(out, "THIS RUN WILL REFUSE") {
		t.Fatalf("--dry-run did not render THIS RUN WILL REFUSE for a $SNUG_PODMAN_ROOT this "+
			"run's own @target-rw grant makes writable:\n%s", out)
	}
	if !strings.Contains(out, root) {
		t.Errorf("the refusal does not name the toolchain root %s:\n%s", root, out)
	}

	// POSITIVE CONTROL: a CLEAN root — outside every grant this default
	// selection makes — clears instead, so the refusal above is about the
	// FIXTURE (a root inside @target-rw) and not about every
	// $SNUG_PODMAN_ROOT rendering as a refusal regardless of its value.
	clean := t.TempDir()
	cleanEnv := baseEnv("SNUG_PODMAN_ROOT=" + clean)
	cleanOut, cleanCode := cli(t, cleanEnv, "--dry-run", "-p", "@podman-socket", proj)
	if cleanCode != 0 {
		t.Fatalf("control: snug --dry-run exited %d with a clean toolchain root:\n%s", cleanCode, cleanOut)
	}
	if strings.Contains(cleanOut, "THIS RUN WILL REFUSE") {
		t.Errorf("control: a toolchain root outside every grant (%s) still rendered THIS RUN "+
			"WILL REFUSE, so the refusal above proves nothing about the fixture specifically:\n%s",
			clean, cleanOut)
	}
}
