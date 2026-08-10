package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// loadTestRegistry loads the REAL builtin profile set, isolated from whatever
// this developer's own ~/.config/snug happens to contain. Without the
// isolation, this test would describe a different sandbox depending on who
// runs it — profile.Load reads $XDG_CONFIG_HOME/snug/profiles.d unconditionally
// (CLAUDE.md invariant 3's known gap).
func loadTestRegistry(t *testing.T) profile.Registry {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	reg, _, err := profile.Load()
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

// captureFile runs fn with an *os.File --dry-run's describe* helpers can
// write to (they take *os.File, matching os.Stdout, not io.Writer) and
// returns what it wrote.
func captureFile(t *testing.T, fn func(*os.File)) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "dryrun-capture-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fn(f)
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestDescribeCommandsNamesTheStagedStub is the --dry-run review artifact for
// the podman dispatcher stub: it must be legible as "a new executable is
// running before the tool you typed", not just a line in FILESYSTEM that
// happens to read "exec" instead of "data" (CLAUDE.md's staged-executable
// abuse sentence, CONTAINER-CLIENT.md §8).
func TestDescribeCommandsNamesTheStagedStub(t *testing.T) {
	reg := loadTestRegistry(t)
	home, target := testTree(t)
	ctx := policy.Context{
		Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"},
		HostShims: []policy.HostShim{
			{Name: "podman", Path: "/usr/bin/podman", Resolved: "/usr/bin/distrobox-host-exec"},
		},
	}
	p, err := policy.Resolve(reg, []string{"@sys", "@home", "@cwd-rw", "@podman-socket"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	got := captureFile(t, func(f *os.File) { describeCommands(f, p) })
	if !strings.Contains(got, "COMMANDS") {
		t.Fatalf("no COMMANDS block: %q", got)
	}
	if !strings.Contains(got, policy.PodmanStubDir+"/podman") {
		t.Errorf("COMMANDS block does not name the staged path: %q", got)
	}
	if !strings.Contains(got, "read-only") {
		t.Errorf("COMMANDS block does not say the stub is read-only: %q", got)
	}
	if !strings.Contains(got, "/usr/bin/podman") || !strings.Contains(got, "UNTOUCHED") {
		t.Errorf("COMMANDS block does not say /usr/bin/podman is untouched: %q", got)
	}

	// CONTROL: without a detected shim, no podman profile grants a stub, and
	// the block must not print at all — a block that always prints proves
	// nothing about the staging condition.
	plain := resolveFor(t, []string{"@sys", "@home", "@cwd-rw"})
	if got := captureFile(t, func(f *os.File) { describeCommands(f, plain) }); got != "" {
		t.Errorf("COMMANDS block printed with no stub staged: %q", got)
	}
}

// TestGrantMarkStillUsesTheWiderPredicate guards against "unifying" grantMark
// with sanitise's narrower keepHostElement predicate. The two ask different
// questions on purpose (dryrun.go's grantMark doc comment): grantMark asks
// "does the sandbox have A NODE at this path", sanitise asks "does it have
// the HOST'S CONTENT here". @claude merges {home}/.local/bin onto PATH, and
// {home} is only a tmpfs — sanitise's predicate would say no — but the
// directory really is mounted and really does hold `claude` (the nested
// bind), so the mark must stay blank. If grantMark switched to the narrower
// rule, this line would grow "← not granted (1 grant inside)" — a false
// statement on the exact screen CLAUDE.md calls *the* mechanism by which a
// human trusts snug.
func TestGrantMarkStillUsesTheWiderPredicate(t *testing.T) {
	reg := loadTestRegistry(t)
	home, target := testTree(t)
	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	p, err := policy.Resolve(reg, []string{"@sys", "@home", "@cwd-rw", "@claude"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	localBin := filepath.Join(home, ".local", "bin")
	if got := grantMark(p, localBin); got != "" {
		t.Errorf("grantMark(%s) = %q, want no mark — grantMark must keep asking 'is there a "+
			"node here' (policy.GrantsGuestPath), not sanitise's narrower 'is the host's "+
			"content here' (policy.keepHostElement); unifying them would print a false "+
			"'not granted' next to a directory that genuinely holds `claude`", localBin, got)
	}
}

// TestDropLinesNameTheirReason is the --dry-run review artifact for
// EnvDropReason: "nothing grants that path" and "only an empty writable
// tmpfs is mounted there" are materially different facts and must render as
// two distinct, correctly-ordered lines rather than one ungrouped "N host
// entries dropped" line that conflates them.
//
// Hand-built rather than resolved: this file's other helpers use
// policy.OSEnviron, whose REAL PATH would make the exact set of dropped
// elements depend on the machine running the test.
func TestDropLinesNameTheirReason(t *testing.T) {
	p := &policy.Policy{
		Env: map[string]policy.EnvVar{
			"PATH": {
				Name: "PATH",
				List: true,
				Sep:  ":",
				Dropped: []policy.EnvDrop{
					{Value: "/srv/nothing", Var: "PATH", From: []string{"x"}, Reason: policy.DropNoGrant},
					{Value: "/tmp/x/bin", Var: "PATH", From: []string{"x"}, Reason: policy.DropTmpfsOnly},
				},
			},
		},
	}

	got := captureFile(t, func(f *os.File) { describeEnvironment(f, p) })

	noGrantLine := "nothing grants that path: /srv/nothing"
	tmpfsLine := "only an empty writable tmpfs is mounted there: /tmp/x/bin"
	iNoGrant := strings.Index(got, noGrantLine)
	iTmpfs := strings.Index(got, tmpfsLine)
	if iNoGrant < 0 {
		t.Errorf("no line names the DropNoGrant element:\n%s", got)
	}
	if iTmpfs < 0 {
		t.Errorf("no line names the DropTmpfsOnly element:\n%s", got)
	}
	if iNoGrant >= 0 && iTmpfs >= 0 && iNoGrant > iTmpfs {
		t.Errorf("drop lines are not in the fixed {DropNoGrant, DropTmpfsOnly} order:\n%s", got)
	}
	if n := strings.Count(got, "dropped —"); n != 2 {
		t.Errorf("expected exactly two drop lines (one per reason, never conflated), got %d:\n%s", n, got)
	}
}

// TestFilesystemBlockRendersTheStubAsExec pins the dry-run-only kind
// rendering: a KindData mount with an executable permission bit reads "exec"
// in the FILESYSTEM block, not "data" — the one visual cue that this line is
// code rather than config, without a human having to notice a permission
// column.
func TestFilesystemBlockRendersTheStubAsExec(t *testing.T) {
	reg := loadTestRegistry(t)
	home, target := testTree(t)
	ctx := policy.Context{
		Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"},
		HostShims: []policy.HostShim{
			{Name: "podman", Path: "/usr/bin/podman", Resolved: "/usr/bin/distrobox-host-exec"},
		},
	}
	p, err := policy.Resolve(reg, []string{"@sys", "@home", "@cwd-rw", "@podman-socket"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	args := p.BwrapArgs(0, 0)

	// dryRun writes to os.Stdout directly rather than taking a writer, so
	// this redirects the real thing for the duration of the call.
	orig := os.Stdout
	f, err := os.CreateTemp(t.TempDir(), "dryrun-stdout-")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = f
	dryRun(p, args, config{}, nil)
	os.Stdout = orig
	f.Close()
	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)

	if !strings.Contains(got, "exec   "+policy.PodmanStubDir+"/podman") {
		t.Errorf("FILESYSTEM block does not render the stub as kind 'exec':\n%s", got)
	}
	if strings.Contains(got, "data   "+policy.PodmanStubDir+"/podman") {
		t.Errorf("FILESYSTEM block still renders the stub as kind 'data'")
	}
}
