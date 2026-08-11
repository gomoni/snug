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
	if !strings.Contains(got, policy.StagedBinDir+"/podman") {
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
// "does the sandbox have A NODE at this path", sanitise asks "does it have the
// HOST'S CONTENT here".
//
// The fixture is a directory covered only by @home's tmpfs that nonetheless
// holds a real nested bind — {home}/.local/share, where @claude binds its
// support directory. sanitise's predicate says no (a tmpfs grants an EMPTY
// directory, so a host PATH element there was never truthful); grantMark must
// still say yes, because the sandbox really does have a node there. Switching to
// the narrower rule would print "← not granted (1 grant inside)" next to a
// directory that demonstrably holds something — a false statement on the exact
// screen CLAUDE.md calls *the* mechanism by which a human trusts snug.
func TestGrantMarkStillUsesTheWiderPredicate(t *testing.T) {
	reg := loadTestRegistry(t)
	home, target := testTree(t)
	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	p, err := policy.Resolve(reg, []string{"@sys", "@home", "@cwd-rw", "@claude"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	localShare := filepath.Join(home, ".local", "share")
	// CONTROL: the fixture only means something if a nested grant is actually
	// there and the covering mount really is a tmpfs. Otherwise this passes on a
	// path that is plainly granted and proves nothing about the predicate.
	if !p.GrantsGuestPath(localShare) {
		t.Fatalf("%s is not granted at all, so it cannot show which predicate is in use", localShare)
	}
	if !p.IsShadowSlot(localShare) {
		t.Fatalf("%s is not writable, so it is not the tmpfs-covered case this test needs", localShare)
	}

	if got := grantMark(p, "SOME_PATH_VAR", localShare); got != "" {
		t.Errorf("grantMark(%s) = %q, want no mark — grantMark must keep asking 'is there a "+
			"node here' (policy.GrantsGuestPath), not sanitise's narrower 'is the host's "+
			"content here' (policy.keepHostElement); unifying them would print a false "+
			"'not granted' next to a directory that genuinely holds a bind", localShare, got)
	}
}

// The two marks answer two different questions and must never be confused for
// each other: "not granted" means NOTHING IS THERE, "writable from inside" means
// something is there AND the payload can add to it. They are also mutually
// exclusive by construction — IsShadowSlot needs a covering mount, and
// GrantsGuestPath returning false means there is none — and this pins that.
//
// The writable mark is PATH-only, and that scope is the substance rather than a
// detail. PATH entries are searched for COMMANDS, so a writable one is a shadow
// slot; a writable CARGO_HOME or XDG_CACHE_HOME is what those variables are FOR,
// and marking them would train the reader to skip the mark on the one line where
// it matters.
func TestWritableMarkIsPathOnlyAndDistinctFromNotGranted(t *testing.T) {
	reg := loadTestRegistry(t)
	home, target := testTree(t)
	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	p, err := policy.Resolve(reg, []string{"@sys", "@home", "@cwd-rw"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// $HOME is @home's writable tmpfs: the arrangement @claude shipped.
	if got := grantMark(p, "PATH", home); !strings.Contains(got, "writable from inside") {
		t.Errorf("grantMark(PATH, %s) = %q, want the writable mark. %s is a writable tmpfs, "+
			"so a PATH entry naming it is a shadow slot the payload can fill — and the screen "+
			"saying nothing is how @claude's {home}/.local/bin survived a milestone in plain "+
			"sight", home, got, home)
	}
	if got := grantMark(p, "CARGO_HOME", home); got != "" {
		t.Errorf("grantMark(CARGO_HOME, %s) = %q, want no mark — the mark is about directories "+
			"searched for COMMANDS. A writable CARGO_HOME is correct, and marking it teaches "+
			"the reader to ignore the mark where it matters", home, got)
	}

	// Not granted at all: nothing is there, so it is not a slot to fill.
	if got := grantMark(p, "PATH", "/nowhere/at/all"); !strings.Contains(got, "not granted") {
		t.Errorf("grantMark(PATH, /nowhere/at/all) = %q, want the not-granted mark", got)
	}
	if strings.Contains(grantMark(p, "PATH", "/nowhere/at/all"), "writable") {
		t.Error("an ungranted path was marked writable; the two marks must stay exclusive")
	}

	// snug's own staging directory must never be marked writable — the rule
	// would otherwise be flagging its own repair.
	if strings.Contains(grantMark(p, "PATH", policy.StagedBinDir), "writable") {
		t.Errorf("%s was marked writable from inside", policy.StagedBinDir)
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

// TestDryRunDropLineDoesNotRenderControlCharsVerbatim is the REGRESSION
// (redteam, confirmed 2026-08-10) for the FORGED-ROW finding: a dropped or kept
// environment value was rendered VERBATIM, so an element containing a newline
// split the line it was printed on, and the injected second line read as a
// legitimate ENVIRONMENT row — a fake variable name, a fake value, a fake
// provenance column — on the exact screen CLAUDE.md calls the mechanism by
// which a human trusts snug:
//
//	(1 host entry dropped — only an empty writable tmpfs is mounted there: /tmp/x/bin
//	  FORGED_VAR       fake-value                    forged-provenance)
//
// The fix is visibleValue (dryrun.go): any control character (a bare newline
// above all) forces the whole value through %q-style quoting, so it can only
// ever be text WITHIN one line, never a line of its own. Applied at BOTH call
// sites — the drop-reason line and a kept EnvEntry's value in envLines — and
// this test pins both, because a fix at only one site would look identical on
// the drop line alone.
func TestDryRunDropLineDoesNotRenderControlCharsVerbatim(t *testing.T) {
	// Same text either way; only whether the separator is a real newline or a
	// plain space differs. The SAFE variant is the positive control that gives
	// the expected line count when nothing is being forged.
	forgedDrop := "/tmp/x/bin\n  FORGED_VAR       fake-value                    forged-provenance"
	safeDrop := "/tmp/x/bin   FORGED_VAR       fake-value                    forged-provenance"
	forgedKept := "/opt/tool\n  FORGED_KEPT      fake-value2                   forged-provenance2"
	safeKept := "/opt/tool   FORGED_KEPT      fake-value2                   forged-provenance2"

	build := func(drop, kept string) *policy.Policy {
		return &policy.Policy{
			Env: map[string]policy.EnvVar{
				"PATH": {
					Name: "PATH", List: true, Sep: ":",
					Dropped: []policy.EnvDrop{
						{Value: drop, Var: "PATH", From: []string{"x"}, Reason: policy.DropTmpfsOnly},
					},
				},
				// A KEPT entry, not another dropped one: visibleValue is applied at a
				// second call site (envLines) and nothing else would notice if that
				// call were removed — a test that only exercised the drop line would
				// pass on a half-applied fix.
				"SAFEVAR": {
					Name: "SAFEVAR",
					Entries: []policy.EnvEntry{
						{Value: kept, Verb: policy.VerbSet, From: []string{"x"}},
					},
				},
			},
		}
	}

	forged := captureFile(t, func(f *os.File) { describeEnvironment(f, build(forgedDrop, forgedKept)) })
	safe := captureFile(t, func(f *os.File) { describeEnvironment(f, build(safeDrop, safeKept)) })

	// THE ASSERTION THAT ACTUALLY MATTERS: a value with a newline in it must
	// not add a line to the block. Comparing against the space-separated
	// control means this does not depend on hand-counting the layout.
	forgedLines, safeLines := strings.Count(forged, "\n"), strings.Count(safe, "\n")
	if forgedLines != safeLines {
		t.Errorf("a newline in a value changed the ENVIRONMENT block's line count: "+
			"forged=%d safe=%d — an injected line reads as a legitimate row:\n%s",
			forgedLines, safeLines, forged)
	}

	// The escaped form is what actually appears — on the ONE line, not a raw
	// newline that the reader (or a script parsing --dry-run) would see as two.
	if !strings.Contains(forged, `\n`) {
		t.Errorf("the value's newline was not rendered as the escaped \\n at all:\n%s", forged)
	}
	if strings.Contains(forged, "\n  FORGED_VAR") {
		t.Errorf("a raw (unescaped) newline put FORGED_VAR at the start of its own line "+
			"in the ENVIRONMENT block:\n%s", forged)
	}
	if !strings.Contains(forged, "FORGED_KEPT") {
		t.Fatalf("control: the kept entry's forged text did not even appear in the output:\n%s", forged)
	}
	if strings.Contains(forged, "\n  FORGED_KEPT") {
		t.Errorf("a raw (unescaped) newline in a KEPT entry's value put FORGED_KEPT at the "+
			"start of its own line in the ENVIRONMENT block:\n%s", forged)
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

	if !strings.Contains(got, "exec   "+policy.StagedBinDir+"/podman") {
		t.Errorf("FILESYSTEM block does not render the stub as kind 'exec':\n%s", got)
	}
	if strings.Contains(got, "data   "+policy.StagedBinDir+"/podman") {
		t.Errorf("FILESYSTEM block still renders the stub as kind 'data'")
	}
}
