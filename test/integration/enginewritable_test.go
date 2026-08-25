//go:build integration

package integration

// enginewritable_test.go is issue #405's end-to-end regression, both halves:
// a container engine binary, or its toolchain root's own TREE, inside a
// grant this sandbox's own profiles make WRITABLE. Both refusals fire in
// internal/cli's startContainers — pol.CheckEngineBinary right after
// preflight resolves pf.Podman, and policy.(*Policy).EngineToolchain's own
// B1 check when $SNUG_PODMAN_ROOT names a root — BEFORE engine.New, before
// the stage, before a single namespace exists for this run. Neither test
// here needs a container to actually build or run, unlike most of this
// file's neighbours.
//
// They are gated on requireRealEngine anyway, reusing containerEngineEnv's
// own env as the cache key every other test in this file already uses: it is
// the ONE shared "can this environment run one of these engine tests at all"
// answer, and a host where it currently fails (issue #401 at the time of
// writing: podman 6.0.2's build step needs the CAP_NET_ADMIN the engine pins
// out) skips here rather than failing for a reason this file's own gate
// exists to classify correctly.
//
// FIXTURE HAZARD, named explicitly because it manufactured a false clearing
// on this exact surface once already (the finding's own report): a layout
// that puts $HOME under the toolchain root's or the target's PARENT is
// refused by issue #220's own $HOME-ancestor guard before either check under
// test ever runs, and the resulting refusal looks identical in shape ("snug
// refused the run") to the one this file means to prove — a pass that is not
// the answer. scratchHomeEnv below roots $HOME and $XDG_CONFIG_HOME in their
// own t.TempDir(), sharing no ancestor with target(t)'s root or with the
// toolchain root either test constructs.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// scratchHomeEnv returns HOME/XDG_CONFIG_HOME overrides rooted in a fresh
// t.TempDir() with no ancestor relation to anything else a caller in this
// file builds — see the header comment's FIXTURE HAZARD paragraph. os/exec
// keeps the LAST duplicate key in an env slice (baseEnv's own doc comment),
// so appending these after attachEnv's own baseEnv-derived slice is enough
// to override it.
func scratchHomeEnv(t *testing.T) []string {
	t.Helper()
	home := t.TempDir()
	cfg := filepath.Join(home, ".config")
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	return []string{"HOME=" + home, "XDG_CONFIG_HOME=" + cfg}
}

// wrapperScript is a "#!/bin/sh exec <real podman> \"$@\"" pass-through —
// content is irrelevant to either check under test (both are purely lexical,
// asked before the binary is ever exec'd), but it is a real, executable file
// wrapping a real engine so a run that were NOT refused would behave like an
// ordinary one, rather than failing later for an unrelated reason that could
// be mistaken for this test's own assertion.
func wrapperScript(podman string) []byte {
	return []byte(fmt.Sprintf("#!/bin/sh\nexec %s \"$@\"\n", podman))
}

// TestEngineBinaryInsideAWritableGrantIsRefused is issue #405's first half,
// end to end: $SNUG_PODMAN names a file strictly inside @cwd-rw's rw grant of
// the target — the shape a real `$SNUG_PODMAN=./bin/podman` inside a
// sandboxed source tree produces — and policy.(*Policy).CheckEngineBinary
// must refuse it before the payload ever starts.
func TestEngineBinaryInsideAWritableGrantIsRefused(t *testing.T) {
	budget(t, 60*time.Second)

	gateEnv, _ := containerEngineEnv(t)
	requireRealEngine(t, gateEnv)
	podman := hostEngine(t)

	proj, _ := target(t) // <root>/proj/sub, rw via @cwd-rw

	wrapperDir := filepath.Join(proj, "bin")
	if err := os.MkdirAll(wrapperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(wrapperDir, "podman")
	if err := os.WriteFile(wrapper, wrapperScript(podman), 0o755); err != nil {
		t.Fatal(err)
	}

	base, _ := attachEnv(t)
	env := append(append([]string{}, base...), scratchHomeEnv(t)...)
	env = append(env, "SNUG_PODMAN="+wrapper)

	r := runEnv(t, env, []string{"-p", "@podman-socket"}, proj, `echo SHOULD-NOT-RUN`)
	if r.ran {
		t.Fatalf("the payload ran — CheckEngineBinary did not refuse an engine binary strictly "+
			"inside @cwd-rw's rw grant of the target (%s):\n%s", wrapper, r.out)
	}
	if r.code == 0 {
		t.Fatalf("snug exited 0 without running the payload — that is not a refusal:\n%s", r.out)
	}
	for _, want := range []string{wrapper, "cannot be this run's container engine", "WRITABLE"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("refusal does not contain %q:\n%s", want, r.out)
		}
	}

	// POSITIVE CONTROL: the identical wrapper, placed OUTSIDE every grant of
	// this sandbox and with no toolchain root naming it, is not refused for
	// THIS reason. It very likely IS refused for a different one (G4:
	// "nothing grafts it into the engine's view" — see engineWithHome's own
	// doc comment), which is expected and is exactly why this asserts the
	// ABSENCE of the specific text above rather than requiring acceptance:
	// the point is that "a custom $SNUG_PODMAN" alone does not trip
	// CheckEngineBinary — writability of a GRANT covering it does.
	outside := t.TempDir()
	wrapperOutside := filepath.Join(outside, "podman")
	if err := os.WriteFile(wrapperOutside, wrapperScript(podman), 0o755); err != nil {
		t.Fatal(err)
	}
	envOutside := append(append([]string{}, base...), scratchHomeEnv(t)...)
	envOutside = append(envOutside, "SNUG_PODMAN="+wrapperOutside)
	rOut := runEnv(t, envOutside, []string{"-p", "@podman-socket"}, proj, `echo SHOULD-NOT-RUN`)
	if strings.Contains(rOut.out, "cannot be this run's container engine") {
		t.Fatalf("control: a wrapper OUTSIDE every grant of this sandbox was ALSO refused by "+
			"CheckEngineBinary's own text — the refusal above is not distinguishing a WRITABLE "+
			"grant from merely naming a custom $SNUG_PODMAN:\n%s", rOut.out)
	}
}

// TestEngineToolchainRootContainsAWritableGrantIsRefused is issue #405's
// second half, end to end — the finding the ticket exists for. The toolchain
// root ($SNUG_PODMAN_ROOT) is the TARGET's own parent, which @parent-ro
// grants read-only; the target itself sits strictly inside it and @cwd-rw
// grants THAT rw. The root itself trips no check, but the writable grant
// inside its tree must.
func TestEngineToolchainRootContainsAWritableGrantIsRefused(t *testing.T) {
	budget(t, 60*time.Second)

	gateEnv, _ := containerEngineEnv(t)
	requireRealEngine(t, gateEnv)
	podman := hostEngine(t)

	proj, _ := target(t)                // <root>/proj/sub, rw via @cwd-rw
	toolchainRoot := filepath.Dir(proj) // <root>/proj, ro via @parent-ro, CONTAINS proj

	wrapper := filepath.Join(toolchainRoot, "podman-real")
	if err := os.WriteFile(wrapper, wrapperScript(podman), 0o755); err != nil {
		t.Fatal(err)
	}

	base, _ := attachEnv(t)
	env := append(append([]string{}, base...), scratchHomeEnv(t)...)
	env = append(env, "SNUG_PODMAN="+wrapper, "SNUG_PODMAN_ROOT="+toolchainRoot)

	r := runEnv(t, env, []string{"-p", "@podman-socket"}, proj, `echo SHOULD-NOT-RUN`)
	if r.ran {
		t.Fatalf("the payload ran — the toolchain root's TREE arm did not refuse a root whose own "+
			"descendant (%s) is a writable grant:\n%s", proj, r.out)
	}
	if r.code == 0 {
		t.Fatalf("snug exited 0 without running the payload — that is not a refusal:\n%s", r.out)
	}
	for _, want := range []string{toolchainRoot, proj, "engine toolchain root", "TREE"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("refusal does not contain %q:\n%s", want, r.out)
		}
	}

	// POSITIVE CONTROL: a toolchain root with nothing writable anywhere
	// inside it — an entirely fresh, unrelated directory — is not refused
	// for THIS reason.
	cleanRoot := t.TempDir()
	wrapper2 := filepath.Join(cleanRoot, "podman-real")
	if err := os.WriteFile(wrapper2, wrapperScript(podman), 0o755); err != nil {
		t.Fatal(err)
	}
	env2 := append(append([]string{}, base...), scratchHomeEnv(t)...)
	env2 = append(env2, "SNUG_PODMAN="+wrapper2, "SNUG_PODMAN_ROOT="+cleanRoot)
	r2 := runEnv(t, env2, []string{"-p", "@podman-socket"}, proj, `echo SHOULD-NOT-RUN`)
	if strings.Contains(r2.out, "engine toolchain root") && strings.Contains(r2.out, "TREE") {
		t.Fatalf("control: a clean toolchain root with nothing writable inside it was refused by "+
			"the tree check too:\n%s", r2.out)
	}
}

// TestEngineBinaryNamedThroughASymlinkInsideAWritableGrantIsRefused is issue
// #369's measured defect, end to end: $SNUG_PODMAN names a SYMLINK strictly
// inside @cwd-rw's rw grant of the target, resolving to a real engine binary
// OUTSIDE every grant. Before the fix, policy.CheckEngineBinary judged only
// the resolved bytes — clean, outside every grant — and ACCEPTED it; snug
// then exec'd the payload-chosen binary as the engine and the run failed
// much later with "the container engine did not create its socket ...
// within 30s" (exit 69), while a regular-file poison at the identical path
// was refused immediately (exit 77). policy.(*Policy).ResolveEngineBinary
// now judges the SYMLINK itself, before any of that.
func TestEngineBinaryNamedThroughASymlinkInsideAWritableGrantIsRefused(t *testing.T) {
	budget(t, 60*time.Second)

	gateEnv, _ := containerEngineEnv(t)
	requireRealEngine(t, gateEnv)
	podman := hostEngine(t)

	proj, _ := target(t) // <root>/proj/sub, rw via @cwd-rw

	// The real binary lives OUTSIDE every grant of this sandbox — an
	// ordinary host installation, exactly like /usr/bin/podman.
	outside := t.TempDir()
	real := filepath.Join(outside, "podman-real")
	if err := os.WriteFile(real, wrapperScript(podman), 0o755); err != nil {
		t.Fatal(err)
	}

	// The symlink is the payload's own: it sits inside @cwd-rw's rw grant, so
	// rewriting it is exactly what a payload running inside this sandbox
	// could do to itself. Its bytes resolve to something clean and outside
	// every grant — the shape that made the measured defect ACCEPT it.
	link := filepath.Join(proj, "podman")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	base, _ := attachEnv(t)
	env := append(append([]string{}, base...), scratchHomeEnv(t)...)
	env = append(env, "SNUG_PODMAN="+link)

	r := runEnv(t, env, []string{"-p", "@podman-socket"}, proj, `echo SHOULD-NOT-RUN`)

	// THE MARKER: the refusal must precede engine.New, so the payload — and
	// the engine it would have exec'd — never started at all.
	if r.ran {
		t.Fatalf("the payload ran — a symlink inside a writable grant, resolving to a binary "+
			"OUTSIDE every grant, was accepted as this run's container engine (%s -> %s):\n%s",
			link, real, r.out)
	}
	if r.code == 0 {
		t.Fatalf("snug exited 0 without running the payload — that is not a refusal:\n%s", r.out)
	}

	// THE DECISIVE ASSERTION, and it is the NEGATIVE one. This exact string is
	// what the measured defect produced (exit 69): the broken build ACCEPTED
	// the symlink, resolved it to the clean binary, exec'd that as the
	// engine, and the run failed here, much later, well after any refusal
	// would have. A test asserting only "exit != 0" would have passed on
	// that build.
	const socketTimeout = "the container engine did not create its socket"
	if strings.Contains(r.out, socketTimeout) {
		t.Fatalf("snug ran the ENGINE and then timed out waiting for its socket — this is the "+
			"measured defect's own symptom (issue #369), not a refusal of the symlink:\n%s", r.out)
	}

	for _, want := range []string{link, "cannot be this run's container engine", "CHOOSING"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("refusal does not contain %q:\n%s", want, r.out)
		}
	}

	// POSITIVE CONTROL: the identical real binary, named DIRECTLY — no
	// symlink, no writable grant involved — is not refused for THIS reason.
	// It may still be refused for an unrelated one (G4: nothing grafts it
	// into the engine's view, as TestEngineBinaryInsideAWritableGrantIsRefused's
	// own control notes), which is why this checks the ABSENCE of the
	// selection wording rather than requiring acceptance.
	envDirect := append(append([]string{}, base...), scratchHomeEnv(t)...)
	envDirect = append(envDirect, "SNUG_PODMAN="+real)
	rDirect := runEnv(t, envDirect, []string{"-p", "@podman-socket"}, proj, `echo SHOULD-NOT-RUN`)
	if strings.Contains(rDirect.out, "CHOOSING") {
		t.Fatalf("control: a binary named directly, with no symlink and no writable grant "+
			"involved, was ALSO refused by the selection wording — the refusal above is not "+
			"distinguishing the symlink from an ordinary custom $SNUG_PODMAN:\n%s", rDirect.out)
	}
}
