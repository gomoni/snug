package cli

import (
	"os"
	"path/filepath"
	"strconv"
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
// THE FIXTURE MUST NOT STAND ANYWHERE SNUG MOUNTS SOMETHING ITSELF, and both
// obvious spellings of "a temporary directory" get that wrong, in opposite
// directions:
//
//   - t.TempDir() resolves under os.TempDir() — "/tmp" on every host this suite
//     runs on — and snug authors its OWN "/tmp" tmpfs into every policy. The
//     fixture $HOME would then be covered by that unrelated grant purely by path
//     prefix, and pathAnnotation would correctly report "tmpfs" for a reason the
//     test is not about.
//   - os.MkdirTemp(".", …), which this used to be, moves the fixture out of /tmp
//     — unless the REPOSITORY is under /tmp, and then it is back. Measured on
//     four combinations: a worktree at /tmp/rt-env FAILS
//     TestDryRunAnnotationsAreTruthful on `main` and on this branch, and passes
//     from $HOME on both. That is the worse of the two failures: it fires
//     nowhere anybody looks (CI checks out under /home/runner/work) and reads,
//     when it does fire, as a regression in whatever branch is under test — a
//     red team lost twenty minutes to it before deciding the tree was innocent.
//
// So the root is one the test OWNS: $SNUG_TEST_FIXTURE_ROOT if the caller set
// one, else $HOME, else the package directory as a last resort. And the property
// the old comment stated in prose is now CHECKED rather than assumed, by the
// only predicate that can be right about it — the floor policy's own mounts. A
// selection of NO profiles still carries snug's own /tmp, /proc and /dev, so
// "does anything cover this path with nothing selected" is exactly the question,
// asked of the code that will answer it later.
func testTree(t *testing.T) (home, target string) {
	t.Helper()

	var roots []string
	if r := os.Getenv("SNUG_TEST_FIXTURE_ROOT"); r != "" {
		roots = append(roots, r)
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		roots = append(roots, h)
	}
	roots = append(roots, ".")

	var root string
	var errs []string
	for _, base := range roots {
		r, err := os.MkdirTemp(base, "snug-dryrun-fixture-")
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		root = r
		break
	}
	if root == "" {
		t.Fatalf("no writable root for the fixture tree (%s). Set SNUG_TEST_FIXTURE_ROOT to a "+
			"directory that is NOT under any path snug mounts itself — /tmp is not one",
			strings.Join(errs, "; "))
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
	assertFixtureIsOutsideSnugsOwnMounts(t, home)
	return home, target
}

// assertFixtureIsOutsideSnugsOwnMounts fails the fixture, loudly and with the
// fix in the message, rather than letting the test it feeds fail as though the
// code were wrong.
//
// It resolves the FLOOR — no profiles at all — because that is precisely the set
// of mounts snug authors regardless of what anyone selected, and asks
// mountedAt(), the same helper pathAnnotation uses. Reimplementing the check
// with a list of paths ("/tmp, /proc, /dev") would be a second copy of a fact
// resolve.go already holds, and the copy is what drifts.
func assertFixtureIsOutsideSnugsOwnMounts(t *testing.T, home string) {
	t.Helper()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	// The ERROR is expected and is deliberately ignored: Resolve REFUSES an empty
	// selection ("nothing can run in it") and returns the policy anyway, which is
	// the same contract --dry-run relies on to render a refused selection. The
	// mounts in it are exactly snug's own, which is what this check needs.
	floor, _ := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), nil,
		policy.Context{Target: home, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}},
		policy.OSEnviron{})
	if floor == nil {
		t.Fatal("Resolve returned no policy for the floor selection, so the fixture's location " +
			"was not checked at all — see its doc comment for why it returns one with the error")
	}
	if m, ok := mountedAt(floor, home); ok {
		t.Fatalf("the fixture home %s is under %s, which snug mounts ITSELF (%s) with no profile "+
			"selected. Every annotation this suite checks would then describe that mount rather "+
			"than the grant under test — a fixture bug wearing the exact costume of the defect "+
			"these tests exist to catch. Set SNUG_TEST_FIXTURE_ROOT to a directory outside it, "+
			"or move this checkout out of %s.",
			home, m.Guest, strings.Join(m.From, "+"), m.Guest)
	}
}

func resolveFor(t *testing.T, sel []policy.ProfileName) *policy.Policy {
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

// TestDryRunAnnotationsAreTruthful pins the fix for a bug found while
// retiring the @null profile: dryrun.go used to hard-code "(writable)" for TARGET and
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
	def := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@parent-ro"})
	if got := targetAnnotation(def); !strings.Contains(got, "writable") {
		t.Errorf("control: with @cwd-rw selected the target really is writable, got %q", got)
	}
	if got := homeAnnotation(def); !strings.Contains(got, "tmpfs") {
		t.Errorf("control: with @home selected, $HOME really is a tmpfs, got %q", got)
	}

	// Without @cwd-rw or @home: @parent-ro covers the target read-only (via its
	// parent), and $HOME is not mounted at all. Neither claim holds any more.
	sparse := resolveFor(t, []policy.ProfileName{"@sys", "@parent-ro"})
	if got := targetAnnotation(sparse); strings.Contains(got, "writable") {
		t.Errorf("--no-defaults -p @sys -p @parent-ro must not claim the target is writable, got %q", got)
	}
	if got := homeAnnotation(sparse); strings.Contains(got, "tmpfs") {
		t.Errorf("--no-defaults -p @sys -p @parent-ro must not claim $HOME is a tmpfs, got %q", got)
	}
}

// TestDryRunAnnotationsAreTruthfulFromACheckoutUnderTmp is the permanent
// regression for issue #53 (redteam, found while measuring #51, outside that
// diff): testTree used to build its fixture with os.MkdirTemp(".", …),
// relative to the process's WORKING DIRECTORY. A checkout living under /tmp
// therefore put the fabricated $HOME under snug's own /tmp tmpfs grant
// (every profile selection carries one — see base.toml's [profile.home]),
// and TestDryRunAnnotationsAreTruthful failed reporting a true fact about the
// wrong path: "$HOME really is a tmpfs" was correct about where the fixture
// accidentally stood, and said nothing about the policy under test. The
// failure text pointed at dryrun.go, and the actual bug was the fixture's
// address.
//
// Fixed (before this test existed) by testTree preferring
// $SNUG_TEST_FIXTURE_ROOT, then $HOME, over anything checkout-relative — see
// its doc comment — with assertFixtureIsOutsideSnugsOwnMounts as the positive
// control that would catch a regression of the fix itself. What nothing
// pinned by NAME until now is the specific scenario the issue reports: a
// checkout whose WORKING DIRECTORY is under /tmp must not affect the
// fixture's location at all. This test reproduces that condition directly —
// os.Chdir into a fresh directory under os.TempDir(), which is "/tmp" on
// every host this suite runs on — rather than by copying the checkout, and
// then runs the exact assertions TestDryRunAnnotationsAreTruthful makes.
func TestDryRunAnnotationsAreTruthfulFromACheckoutUnderTmp(t *testing.T) {
	checkout, err := os.MkdirTemp(os.TempDir(), "snug-issue53-checkout-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(checkout) })

	// POSITIVE CONTROL: the fixture only reproduces the reported failure if
	// the working directory genuinely lands under /tmp — without this, the
	// assertions below could be passing because os.TempDir() moved, not
	// because testTree stopped depending on the working directory.
	abs, err := filepath.Abs(checkout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(abs, "/tmp") {
		t.Fatalf("control: %s is not under /tmp on this host, so os.Chdir into it below does not "+
			"reproduce a checkout under /tmp — this test needs a different root here", abs)
	}
	t.Chdir(checkout)

	def := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@parent-ro"})
	if got := homeAnnotation(def); !strings.Contains(got, "tmpfs") {
		t.Errorf("control: with @home selected, $HOME really is a tmpfs, got %q", got)
	}

	sparse := resolveFor(t, []policy.ProfileName{"@sys", "@parent-ro"})
	if got := homeAnnotation(sparse); strings.Contains(got, "tmpfs") {
		t.Errorf("from a working directory under /tmp, --no-defaults -p @sys -p @parent-ro must not "+
			"claim $HOME is a tmpfs, got %q — this is issue #53: the fixture must not be built "+
			"relative to the checkout's working directory", got)
	}
}

// REGRESSION (redteam): the annotation must not UNDERSTATE write access.
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
		Include: []policy.ProfileName{"@sys"},
		RO:      []string{"{target}"},
		RW:      []string{"{target}/src"},
	}
	if err := os.MkdirAll(filepath.Join(target, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	p, err := policy.Resolve(reg, []policy.ProfileName{"layered"}, ctx, policy.OSEnviron{})
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
	def := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@parent-ro"})
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
	p, err := policy.Resolve(reg, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@podman-socket"}, ctx, policy.OSEnviron{})
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
	plain := resolveFor(t, []policy.ProfileName{"@sys", "@home", "@cwd-rw"})
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
	p, err := policy.Resolve(reg, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude"}, ctx, policy.OSEnviron{})
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
// something is there AND the payload can add to it.
//
// THEY ARE NOT MUTUALLY EXCLUSIVE, and an earlier version of this comment said
// they were "by construction" — true only while IsShadowSlot and
// GrantsGuestPath both stopped AT a symlink. Now that both follow one, a
// DANGLING link standing on writable ground is BOTH at once: GrantsGuestPath
// is false (the chain resolves to nothing) and IsShadowSlot is true (the
// payload can `rm` the link and `mkdir` its own directory at that name
// regardless of where it pointed). See
// TestGrantMarkPrecedesGrantedWhenBothConditionsHold below for that case and
// the precedence grantMark now applies to it.
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
	p, err := policy.Resolve(reg, []policy.ProfileName{"@sys", "@home", "@cwd-rw"}, ctx, policy.OSEnviron{})
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

	// Not granted at all, and no symlink on the way either: nothing is there,
	// so it is not a slot to fill. (This is the ORDINARY not-granted case, not
	// the one where the two marks can coincide — see
	// TestGrantMarkPrecedesGrantedWhenBothConditionsHold for that one.)
	if got := grantMark(p, "PATH", "/nowhere/at/all"); !strings.Contains(got, "not granted") {
		t.Errorf("grantMark(PATH, /nowhere/at/all) = %q, want the not-granted mark", got)
	}
	if strings.Contains(grantMark(p, "PATH", "/nowhere/at/all"), "writable") {
		t.Error("an ungranted path with no symlink on the way was marked writable")
	}

	// snug's own staging directory must never be marked writable — the rule
	// would otherwise be flagging its own repair.
	//
	// The fixture has to STAGE something first. This assertion used to run against
	// the selection above, which stages nothing, so grantMark returned "not
	// granted" and the check could never fail — it measured ABSENT and read as
	// UNWRITABLE. Two different facts, and the one being claimed is the second.
	stageMount(p, policy.KindBind, policy.AccessRO)
	if got := grantMark(p, "PATH", policy.StagedBinDir); strings.Contains(got, "writable") {
		t.Errorf("grantMark(PATH, %s) = %q with a read-only bind staged there. The directory "+
			"is the root tmpfs, which --remount-ro / covers, so nothing on this line may say "+
			"writable", policy.StagedBinDir, got)
	}
	// It renders as "not granted (1 grant inside)": no Mount covers the directory
	// itself, because it is snug's `--dir`. That wording is the documented
	// compromise above, and it is asserted here so this test fails if the mark
	// ever silently starts claiming something stronger.
	if got := grantMark(p, "PATH", policy.StagedBinDir); !strings.Contains(got, "1 grant inside") {
		t.Errorf("grantMark(PATH, %s) = %q, want the count of what is staged inside — "+
			"without it the fixture is not staging anything and both assertions here are "+
			"about an empty policy", policy.StagedBinDir, got)
	}

	// …and the same assertion has to be able to FAIL, or the line above is a
	// sentence about a predicate that cannot say yes at this path. This is the
	// shape Validate now refuses (snugsOwn), reconstructed here after resolution
	// precisely because it can no longer come out of one.
	stageMount(p, policy.KindTmpfs, policy.AccessRW)
	if got := grantMark(p, "PATH", policy.StagedBinDir); !strings.Contains(got, "writable from inside") {
		t.Errorf("grantMark(PATH, %s) = %q with a tmpfs mounted there, want the writable mark. "+
			"If this does not fire, the assertion above is vacuous and the shadow-slot rule is "+
			"unguarded at the one path snug puts on PATH itself", policy.StagedBinDir, got)
	}
}

// TestGrantMarkPrecedesGrantedWhenBothConditionsHold pins the precedence
// grantMark's doc comment describes: the shadow test is hoisted ABOVE the
// granted test, not merely added beside it, because the two questions used to
// be assumed mutually exclusive and are not any more.
//
// THE CASE THIS CLOSES. GrantsGuestPath and IsShadowSlot both used to stop AT
// a symlink, so "not granted" (the chain resolves to nothing) and "writable"
// (a covering mount is a tmpfs or an rw bind) could never both be true of the
// same path — one predicate needs a covering mount to say yes and the other
// needs one to say no. Now that both FOLLOW a symlink through
// resolveThroughLinks, a DANGLING link standing on writable ground breaks
// that: the chain still resolves to nothing (GrantsGuestPath = false,
// nothing is mounted at the far end) and the link is still on writable
// ground (IsShadowSlot = true — the payload does not need the link to point
// anywhere in order to `rm` it and `mkdir` its own directory at that name).
// grantMark used to test "granted" first and nest the shadow test inside
// that branch, so this combination rendered as a bare "not granted" with the
// writable warning gone — the more dangerous of the two true facts silently
// dropped from the one screen CLAUDE.md calls the mechanism by which a human
// decides whether to trust snug.
//
// NOT REACHABLE THROUGH A PROFILE, which is why this is built at the policy
// level rather than resolved. checkCoupled (envcoupling.go) refuses a PATH
// value whose resolution the profile does not grant, so a profile pairing a
// dangling symlink with a `merge PATH = [...]` naming it is refused before
// Resolve ever runs (internal/policy's
// TestACyclicSymlinkNamedOnPathIsRefusedByCouplingBeforeItCanResolve pins the
// same refusal for a cyclic variant). So this is a LATENT inconsistency the
// precedence fix closes, not a live screen bug reachable by a human's own
// profile — hand-building the policy is the only way to construct it at all.
func TestGrantMarkPrecedesGrantedWhenBothConditionsHold(t *testing.T) {
	p := &policy.Policy{Mounts: map[string]policy.Mount{
		"/data":     {Guest: "/data", Kind: policy.KindTmpfs},
		"/data/bin": {Guest: "/data/bin", Kind: policy.KindSymlink, Host: "/nowhere/at/all"},
	}}

	// CONTROLS: the fixture only means something if BOTH conditions genuinely
	// hold. Without these, the assertion below could pass on a fixture that is
	// merely granted, or merely a shadow slot, and prove nothing about
	// precedence.
	if p.GrantsGuestPath("/data/bin") {
		t.Fatal("control: /data/bin resolves after all (the dangling target turned out to be " +
			"granted); the fixture does not exercise the not-granted side of this case")
	}
	if !p.IsShadowSlot("/data/bin") {
		t.Fatal("control: /data/bin is not a shadow slot; the fixture does not stand the link " +
			"on writable ground")
	}

	got := grantMark(p, "PATH", "/data/bin")
	if !strings.Contains(got, "writable from inside") {
		t.Errorf("grantMark(PATH, /data/bin) = %q, want the writable mark. GrantsGuestPath is "+
			"false AND IsShadowSlot is true here, and the writable mark must win: 'you can be "+
			"given a command you did not install' outranks 'this names nothing'", got)
	}
	if strings.Contains(got, "not granted") {
		t.Errorf("grantMark(PATH, /data/bin) = %q, still carries the not-granted wording — the "+
			"shadow test must be hoisted ABOVE the granted test in grantMark, not merely "+
			"evaluated alongside it", got)
	}
}

// stageMount replaces whatever is at policy.StagedBinDir with one mount, so a
// test can put the directory into a state Validate refuses and still ask what
// the RENDERER would say about it. Both callers want the same two states, and
// spelling them out twice invites them to drift apart.
func stageMount(p *policy.Policy, kind policy.Kind, access policy.Access) {
	guest := policy.StagedBinDir
	if kind == policy.KindBind {
		// A staged executable is a file INSIDE the directory, which is the only
		// legitimate shape; the directory itself stays the root tmpfs.
		delete(p.Mounts, guest)
		guest += "/tool"
	}
	p.Mounts[guest] = policy.Mount{
		Guest:  guest,
		Kind:   kind,
		Access: access,
		Host:   "/etc/hostname",
		From:   []string{"fixture"},
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
	p, err := policy.Resolve(reg, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@podman-socket"}, ctx, policy.OSEnviron{})
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

// TestDescribeSSHNamesTheReplacedPathAndItsCost is the review artifact for
// issue #40's --dry-run disclosure: the SSH
// block must name the exact guest path that was replaced, the mechanism (one
// uid mapped -> root-owned file reads as 65534 -> OpenSSH refuses it), and the
// cost — RequiredRSASize dropping from the host crypto policy's value to
// OpenSSH's compiled-in 1024, which is the one entry in the loss that has
// security content (issue #40).
//
// It builds its own host fixture rather than relying on this developer's real
// /usr/etc/ssh or /etc/ssh — a golden-shaped test that only passes on
// openSUSE would tell the next reader nothing about the mechanism, only about
// this box. The fixture profile binds a throwaway directory at guest
// /etc/ssh, a path @sys (loadTestRegistry's REAL registry) does not grant at
// all, so there is no nesting conflict with any of @sys's fourteen /etc
// entries.
func TestDescribeSSHNamesTheReplacedPathAndItsCost(t *testing.T) {
	reg := loadTestRegistry(t)
	home, target := testTree(t)

	sshHost := t.TempDir()
	if err := os.WriteFile(filepath.Join(sshHost, "ssh_config"), []byte("# host's, unreadable inside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reg["sshhost"] = &policy.Profile{Name: "sshhost", RO: []string{sshHost + ":/etc/ssh"}}

	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	p, err := policy.Resolve(reg, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "sshhost"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	got := captureFile(t, func(f *os.File) { describeSSH(f, p) })
	if !strings.Contains(got, "SSH") {
		t.Fatalf("no SSH block: %q", got)
	}
	if !strings.Contains(got, "/etc/ssh/ssh_config") {
		t.Errorf("SSH block does not name the replaced path: %q", got)
	}
	if !strings.Contains(got, "65534") {
		t.Errorf("SSH block does not explain the mechanism (one mapped uid -> 65534): %q", got)
	}
	if !strings.Contains(got, "RequiredRSASize") {
		t.Errorf("SSH block does not name the one lossy entry with security content: %q", got)
	}

	// CONTROL: a selection covering NEITHER SystemSSHConfigPaths entry must
	// print nothing — a block that always prints proves nothing about the
	// coverage condition. "runtime-only" supplies the OS-runtime grant Validate
	// requires, deliberately bound at /bin from a fresh empty directory rather
	// than from /usr, so it cannot coincidentally cover an ssh_config path the
	// way selecting @sys would.
	reg["runtime-only"] = &policy.Profile{Name: "runtime-only", RO: []string{home + ":/bin"}}
	plain, err := policy.Resolve(reg, []policy.ProfileName{"@cwd-rw", "runtime-only"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := captureFile(t, func(f *os.File) { describeSSH(f, plain) }); got != "" {
		t.Errorf("SSH block printed with nothing covering either system ssh_config path: %q", got)
	}
}

// TestDescribeSSHNamesADiscoveredPath is the arm that makes the block honest
// after issue #42: the set of paths a run may replace is no longer
// policy.SystemSSHConfigPaths, it is that list PLUS whatever this host's ssh
// named. A screen that re-walks the fixed list would print nothing here, and
// the human would get a system ssh_config replaced with no line saying so —
// which is the same silence the issue is about, moved from ssh's error to
// snug's screen.
//
// Measured as non-vacuous: making describeSSH walk the fixed list again fails
// this test and passes the one above, which is exactly why both exist.
func TestDescribeSSHNamesADiscoveredPath(t *testing.T) {
	reg := loadTestRegistry(t)
	home, target := testTree(t)

	// The FreeBSD/Homebrew spelling: in no list snug ships. @sys is NOT
	// selected, so this bind is the only thing covering the path and there is
	// no nesting conflict with @sys's /usr.
	const guest = "/usr/local/etc/ssh/ssh_config"
	sshHost := t.TempDir()
	if err := os.WriteFile(filepath.Join(sshHost, "ssh_config"), []byte("# host's, unreadable inside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reg["sshhost"] = &policy.Profile{Name: "sshhost", RO: []string{sshHost + ":/usr/local/etc/ssh"}}
	reg["runtime-only"] = &policy.Profile{Name: "runtime-only", RO: []string{home + ":/bin"}}

	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"},
		HostSSHConfigs: []string{guest}}
	p, err := policy.Resolve(reg, []policy.ProfileName{"@home", "@cwd-rw", "sshhost", "runtime-only"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := captureFile(t, func(f *os.File) { describeSSH(f, p) }); !strings.Contains(got, guest) {
		t.Fatalf("SSH block does not name the discovered path %s:\n%s", guest, got)
	}
}

// TestDryRunAttachBlockNamesThePathPatternAndSaysItGatesNothing is §13.7 test
// 28: the ATTACH block's honesty requirements are load-bearing (describeAttach's
// own doc comment), so this pins them directly rather than trusting review.
func TestDryRunAttachBlockNamesThePathPatternAndSaysItGatesNothing(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/fake-runtime-dir-for-this-test")

	got := captureFile(t, describeAttach)

	if !strings.Contains(got, "run-<pid>") {
		t.Errorf("ATTACH block does not name the run-<pid> PATTERN:\n%s", got)
	}
	// The pattern, never a fabricated pid: --dry-run's own pid is not the
	// pid a real run would use, and printing one would be exactly the "small
	// lie" CLAUDE.md says makes the artifact untrustworthy.
	myPid := strconv.Itoa(os.Getpid())
	if strings.Contains(got, "run-"+myPid+string(filepath.Separator)) ||
		strings.Contains(got, "run-"+myPid+"/") {
		t.Errorf("ATTACH block printed THIS process's own pid instead of the pattern:\n%s", got)
	}
	if !strings.Contains(got, "/fake-runtime-dir-for-this-test") {
		t.Errorf("ATTACH block did not render the actual runtime base directory:\n%s", got)
	}
	if !strings.Contains(got, "0600") || !strings.Contains(got, "0700") {
		t.Errorf("ATTACH block does not state the file/directory modes:\n%s", got)
	}
	if !strings.Contains(got, "no command, no argv") {
		t.Errorf("ATTACH block does not say state.json carries no command/argv:\n%s", got)
	}
	if !strings.Contains(got, "NOT a permission") {
		t.Errorf("ATTACH block does not say attach gates nothing:\n%s", got)
	}
	if !strings.Contains(got, "seccomp") || !strings.Contains(got, "capability") {
		t.Errorf("ATTACH block does not name what attach DOES add (filter, capability set):\n%s", got)
	}
}
