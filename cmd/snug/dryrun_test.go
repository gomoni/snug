package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"snug/internal/policy"
	"snug/internal/profile"
)

// loadTestRegistry loads the REAL builtin profile set, isolated from whatever
// this developer's own ~/.config/snug happens to contain. Without the
// isolation, this test would describe a different sandbox depending on who
// runs it — profile.Load reads $XDG_CONFIG_HOME/snug/profiles.d unconditionally
// (CLAUDE.md invariant 3's known gap).
func loadTestRegistry(t *testing.T) profile.Registry {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	reg, err := profile.Load()
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// testTree builds a throwaway home/project pair on the real filesystem.
// Resolve canonicalises paths against the real host via policy.OSEnviron, so
// the fixture has to actually exist — a fake Environ would make this a
// resolver test, not a --dry-run test.
//
// Deliberately NOT t.TempDir(): that resolves under os.TempDir(), which is
// "/tmp" on every host this suite runs on, and snug authors its OWN "/tmp"
// mount into every policy (resolve.go). A fixture home living under
// "/tmp/..." would then be "covered" by that unrelated tmpfs grant purely by
// path prefix, making the annotation genuinely (and correctly!) say "tmpfs" —
// a fixture bug that would look exactly like the defect this test exists to
// catch. Rooting the fixture beside the test source sidesteps the collision.
func testTree(t *testing.T) (home, target string) {
	t.Helper()
	root, err := os.MkdirTemp(".", "dryrun-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	home = filepath.Join(abs, "home", "u")
	target = filepath.Join(home, "proj", "sub")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	return home, target
}

func resolveFor(t *testing.T, sel []string) *policy.Policy {
	t.Helper()
	reg := loadTestRegistry(t)
	home, target := testTree(t)
	ctx := policy.Context{
		Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"},
	}
	p, err := policy.Resolve(reg, sel, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}
	return p
}

// TestDryRunAnnotationsAreTruthful pins the fix for the bug TODO.md's MVY0
// findings recorded: dryrun.go used to hard-code "(writable)" for TARGET and
// "(tmpfs, ephemeral)" for HOME, which is true only for the default selection
// and false the moment a human selected fewer profiles —
// `snug --dry-run --no-defaults -p @sys -p @parent-ro <dir>` printed both
// claims while neither held. --dry-run is CLAUDE.md's stated mechanism for a
// human to trust snug at all, so a false claim there outweighs one almost
// anywhere else in the program.
func TestDryRunAnnotationsAreTruthful(t *testing.T) {
	// POSITIVE CONTROL: with the shipped defaults, both claims genuinely hold —
	// without this, the negative assertions below could be passing because
	// resolveFor or the annotation helpers are broken, not because the claims
	// are honest.
	def := resolveFor(t, []string{"@sys", "@home", "@cwd-rw", "@parent-ro"})
	if got := targetAnnotation(def); !strings.Contains(got, "writable") {
		t.Errorf("control: with @cwd-rw selected the target really is writable, got %q", got)
	}
	if got := homeAnnotation(def); !strings.Contains(got, "tmpfs") {
		t.Errorf("control: with @home selected, $HOME really is a tmpfs, got %q", got)
	}

	// Without @cwd-rw or @home: @parent-ro covers the target read-only (via its
	// parent), and $HOME is not mounted at all. Neither claim holds any more.
	sparse := resolveFor(t, []string{"@sys", "@parent-ro"})
	if got := targetAnnotation(sparse); strings.Contains(got, "writable") {
		t.Errorf("--no-defaults -p @sys -p @parent-ro must not claim the target is writable, got %q", got)
	}
	if got := homeAnnotation(sparse); strings.Contains(got, "tmpfs") {
		t.Errorf("--no-defaults -p @sys -p @parent-ro must not claim $HOME is a tmpfs, got %q", got)
	}
}

// REGRESSION (redteam, MVY0): the annotation must not UNDERSTATE write access.
//
// TestDryRunAnnotationsAreTruthful above covers the safe direction — do not
// claim writable when it is not. This covers the dangerous one, which the fix
// for that bug introduced: reporting only the deepest mount COVERING the path
// made grants strictly BELOW it invisible, and those are exactly the ones that
// raise the write surface.
//
// The trigger is not exotic. It is the arrangement CLAUDE.md invariant 2
// recommends by name — "grant the tree read-only and the parts you want to
// write separately" — and it printed a bare "(read-only)" while a write inside
// {target}/src persisted to the host filesystem.
//
// Over-warning is a nuisance; under-warning is invariant 5.
func TestDryRunAnnotationDoesNotUnderstateWriteAccess(t *testing.T) {
	reg := loadTestRegistry(t)
	home, target := testTree(t)
	reg["layered"] = &policy.Profile{
		Name:    "layered",
		Include: []string{"@sys"},
		RO:      []string{"{target}"},
		RW:      []string{"{target}/src"},
	}
	if err := os.MkdirAll(filepath.Join(target, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	p, err := policy.Resolve(reg, []string{"layered"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	got := targetAnnotation(p)
	if !strings.Contains(got, "read-only") {
		t.Fatalf("control: the target itself is granted read-only here, so the "+
			"annotation should say so; got %q", got)
	}
	if !strings.Contains(got, filepath.Join(target, "src")) {
		t.Errorf("the annotation hides a writable grant that PERSISTS TO THE HOST "+
			"inside the target:\n  got:  %s\n  want: it to name %s",
			got, filepath.Join(target, "src"))
	}

	// And the noise control: an ephemeral tmpfs below an ephemeral tmpfs is not
	// a surprise and must NOT be listed, or the line becomes one people skip.
	def := resolveFor(t, []string{"@sys", "@home", "@cwd-rw", "@parent-ro"})
	if got := homeAnnotation(def); strings.Contains(got, ".cache") {
		t.Errorf("HOME lists tmpfs children as if they were surprises: %q", got)
	}
}
