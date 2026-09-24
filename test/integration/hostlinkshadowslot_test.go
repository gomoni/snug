//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Issue #604, end to end. walkLinks used to stop at the first read-only
// KindBind and hand it straight to the caller: the HOST tree a `ro` grant
// names can itself contain a symlink nobody's profile wrote, and the kernel
// still follows it — in the guest namespace, onto whatever is really there —
// exactly as it follows one of snug's own KindSymlink grants. Found by
// `redteam` on #603's working tree: `ro = ["$F/hd"]` with a host symlink
// `$F/hd/sub -> /tmp/sx` merged onto PATH carried no `← writable from
// inside` mark on --dry-run, and a payload's own
// `mkdir -p /tmp/sx && printf … >/tmp/sx/git` then ran ahead of the real git.
//
// /tmp is snug's own UNCONDITIONAL writable tmpfs (resolve.go's `(snug)`
// grant, present with no profile selected at all), which is what makes it the
// issue's own reproduction shape rather than a fixture needing its own tmpfs
// grant.

// hostLinkPathProfile writes a profile TOML granting `ro = [hd]` — hd's own
// host tree, containing the planted symlink — and merging both hd+"/sub" and
// a plain control element onto PATH.
func hostLinkPathProfile(t *testing.T, hd string) []string {
	t.Helper()
	return envProfileLayer(t, "hostlinkpath.toml",
		"[profile.hostlinkpath]\n"+
			"description = \"a ro bind whose host tree contains a symlink nothing in the profile wrote\"\n"+
			// §2.5's coupling rule: a profile may only merge onto PATH a path it
			// itself grants, so /usr/bin — the control element — has to be
			// granted here rather than relied on from @sys via -p's implicit
			// defaults.
			"ro = [\""+hd+"\", \"/usr/bin\"]\n"+
			"\n[profile.hostlinkpath.environ.merge]\n"+
			"PATH = [\""+hd+"/sub\", \"/usr/bin\"]\n",
		// envProfileLayer's hostPath param becomes the OUTER process's own PATH
		// (the one snug's own exec.LookPath("bwrap") searches) — this fixture
		// is not exercising `sanitise`, so it passes the real inherited PATH
		// through rather than an empty one that would leave snug unable to
		// find bwrap at all.
		os.Getenv("PATH"))
}

// rowContaining returns the ENVIRONMENT-block row naming want — the data line
// plus every continuation line indented under it (a mark sits at column 21,
// which is at least 19) — mirroring internal/cli's rowFor, reimplemented here
// because this package cannot reach an unexported helper in another one. It
// searches by VALUE rather than by variable name: a `merge` band renders the
// variable's own name only on its FIRST entry, so a second PATH element's row
// carries no "PATH" of its own to anchor on.
func rowContaining(t *testing.T, rendered, want string) string {
	t.Helper()
	lines := strings.Split(rendered, "\n")
	for i, line := range lines {
		if !strings.Contains(line, want) || strings.HasPrefix(line, strings.Repeat(" ", 19)) {
			continue
		}
		row := []string{line}
		for _, next := range lines[i+1:] {
			if !strings.HasPrefix(next, strings.Repeat(" ", 19)) {
				break
			}
			row = append(row, next)
		}
		return strings.Join(row, "\n")
	}
	t.Fatalf("no ENVIRONMENT row contains %q:\n%s", want, rendered)
	return ""
}

// TestHostSymlinkInReadOnlyBindIsMarkedOnPATH is the --dry-run half: the
// screen a human reads before any sandbox runs must carry the mark for the
// host symlink's row, and must NOT carry it for the /usr/bin control — a
// plain grant with no symlink on the way, on the same run, at the same read
// access.
func TestHostSymlinkInReadOnlyBindIsMarkedOnPATH(t *testing.T) {
	budget(t)
	proj, _ := target(t)

	hd := filepath.Join(t.TempDir(), "hd")
	if err := os.MkdirAll(hd, 0o755); err != nil {
		t.Fatal(err)
	}
	// The HOST symlink nobody in the profile wrote, onto snug's own
	// unconditional writable /tmp.
	if err := os.Symlink("/tmp/sx", filepath.Join(hd, "sub")); err != nil {
		t.Fatal(err)
	}

	env := hostLinkPathProfile(t, hd)
	out, code := cli(t, env, "--dry-run", "-p", "hostlinkpath", proj)
	if code != 0 {
		t.Fatalf("snug --dry-run exited %d:\n%s", code, out)
	}

	slotRow := rowContaining(t, out, hd+"/sub")
	if !strings.Contains(slotRow, "writable from inside") {
		t.Errorf("the row for %s/sub carries no `← writable from inside` mark, though the "+
			"host itself has a symlink there landing on snug's own writable /tmp:\n%s", hd, slotRow)
	}

	// CONTROL: the identical read access, the identical profile, no symlink on
	// the way. Without this, the assertion above could pass on a build that
	// marks every PATH row regardless of whether anything is actually
	// writable.
	ctrlRow := rowContaining(t, out, "/usr/bin")
	if strings.Contains(ctrlRow, "writable from inside") {
		t.Errorf("control: /usr/bin — granted read-only, no symlink on the way — carries the "+
			"writable mark:\n%s", ctrlRow)
	}
}

// TestHostSymlinkMarkIsTruthful is the live half: the mark
// TestHostSymlinkInReadOnlyBindIsMarkedOnPATH asserts on --dry-run must be
// TRUE of what a real sandbox does, not merely present on the screen. It
// reproduces the issue's own exploit — a payload plants `git` at the host
// symlink's target, and the SANDBOX's own `command -v git` resolves to the
// host-symlinked slot and runs it — and is deliberately not a test that the
// exploit is CLOSED: #604 is the trust screen omitting a mark for host state
// it never inspected, not a new containment boundary. A ro bind of a host
// tree already hands over whatever host symlinks that tree contains; this
// test is what makes sure the mark ADMITS that rather than hiding it.
func TestHostSymlinkMarkIsTruthful(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	hd := filepath.Join(t.TempDir(), "hd")
	if err := os.MkdirAll(hd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/sx", filepath.Join(hd, "sub")); err != nil {
		t.Fatal(err)
	}

	env := hostLinkPathProfile(t, hd)
	r := runEnv(t, env, []string{"-p", "hostlinkpath"}, proj,
		`mkdir -p /tmp/sx
printf '#!/bin/sh\necho SHADOW-GIT-RAN\n' >/tmp/sx/git
chmod +x /tmp/sx/git
command -v git
git --version`).mustRun(t)

	// POSITIVE CONTROL folded into the assertion itself: `command -v git` must
	// name the host-symlinked slot, not merely succeed. Without this, "git ran"
	// could equally mean the REAL /usr/bin/git ran, which would prove nothing
	// about the shadow.
	if !strings.Contains(r.out, hd+"/sub/git") {
		t.Fatalf("`command -v git` did not resolve to the host-symlinked slot (%s/sub/git), so "+
			"the run below cannot be attributed to it:\n%s", hd, r.out)
	}
	if !strings.Contains(r.out, "SHADOW-GIT-RAN") {
		t.Errorf("the payload's own git — reached through the host symlink %s/sub -> /tmp/sx — "+
			"did not run, so the --dry-run mark this test backs is not truthful:\n%s", hd, r.out)
	}
}

// TestHostLinkDotDotMarkIsTruthful is issue #604's follow-up conformance
// round, findings 1/2's shape, end to end: a PATH element climbs ".." out of
// a HOST symlink — typed directly into the merged PATH element, not hidden
// inside any link's own text — and the kernel resolves the symlink FIRST,
// landing on snug's own writable /tmp, before ever applying the "..". A
// lexical Clean of the whole element would instead cancel "abs/.." to
// nothing and land on the real, read-only hd/bin next to it — this test
// plants nothing there, so a payload reaching THAT directory instead would
// fail closed rather than run, which is what makes this a live
// discriminator and not merely a live reproduction.
func TestHostLinkDotDotMarkIsTruthful(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	hd := filepath.Join(t.TempDir(), "hd")
	if err := os.MkdirAll(hd, 0o755); err != nil {
		t.Fatal(err)
	}
	// The HOST symlink nobody in the profile wrote, onto an UNANCHORED name
	// under snug's own unconditional writable /tmp — so the trailing ".."
	// in the PATH element below has somewhere real to climb out of.
	if err := os.Symlink("/tmp/sx", filepath.Join(hd, "abs")); err != nil {
		t.Fatal(err)
	}

	env := envProfileLayer(t, "hostlinkdotdot.toml",
		"[profile.hostlinkdotdot]\n"+
			"description = \"a PATH element climbing dotdot out of a host symlink\"\n"+
			"ro = [\""+hd+"\", \"/usr/bin\"]\n"+
			"\n[profile.hostlinkdotdot.environ.merge]\n"+
			"PATH = [\""+hd+"/abs/../bin\", \"/usr/bin\"]\n",
		os.Getenv("PATH"))

	r := runEnv(t, env, []string{"-p", "hostlinkdotdot"}, proj,
		`mkdir -p /tmp/sx /tmp/bin
printf '#!/bin/sh\necho SHADOW-GIT-RAN\n' >/tmp/bin/git
chmod +x /tmp/bin/git
command -v git
git --version`).mustRun(t)

	// POSITIVE CONTROL folded into the assertion itself: `command -v git`
	// must name the PATH element the dotdot walk actually resolves through.
	if !strings.Contains(r.out, hd+"/abs/../bin/git") {
		t.Fatalf("`command -v git` did not resolve through %s/abs/../bin, so the run below "+
			"cannot be attributed to it:\n%s", hd, r.out)
	}
	if !strings.Contains(r.out, "SHADOW-GIT-RAN") {
		t.Errorf("the payload's own git — reached by climbing \"..\" out of the host symlink "+
			"%s/abs, landing on snug's own writable /tmp — did not run:\n%s", hd, r.out)
	}
}

// TestAliasedReadOnlyBindMarkIsTruthful is issue #604's follow-up
// conformance round, finding 4's shape, end to end: a read-only bind's own
// Access says ro, no symlink anywhere on the way, but its HOST tree sits
// inside the writable {target}'s — @target-rw's own grant. A payload that
// writes through the TARGET (a plain rw bind, nothing exotic) sees the write
// appear at the READ-ONLY PATH element too, because both are the same host
// directory bind-mounted twice, and can execute what it planted there.
func TestAliasedReadOnlyBindMarkIsTruthful(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	// Must exist before snug resolves the ro grant below (Resolve's own
	// EvalSymlinks check on every `ro` entry), empty otherwise.
	realbin := filepath.Join(proj, "realbin")
	if err := os.MkdirAll(realbin, 0o755); err != nil {
		t.Fatal(err)
	}

	env := envProfileLayer(t, "aliasedbin.toml",
		"[profile.aliasedbin]\n"+
			"description = \"a ro bind whose host tree sits inside the writable target\"\n"+
			// host:guest — a RELOCATED grant, host tree deliberately inside the
			// target @target-rw grants rw.
			"ro = [\""+realbin+":/srv/aliasedbin\", \"/usr/bin\"]\n"+
			"\n[profile.aliasedbin.environ.merge]\n"+
			"PATH = [\"/srv/aliasedbin\", \"/usr/bin\"]\n",
		os.Getenv("PATH"))

	r := runEnv(t, env, []string{"-p", "aliasedbin"}, proj,
		`mkdir -p "$SNUG_TARGET/realbin"
printf '#!/bin/sh\necho SHADOW-GIT-RAN\n' >"$SNUG_TARGET/realbin/git"
chmod +x "$SNUG_TARGET/realbin/git"
command -v git
git --version`).mustRun(t)

	// POSITIVE CONTROL folded into the assertion itself: `command -v git`
	// must name the ALIASED read-only bind, not the writable target itself —
	// this is a claim about the RO element, not about the target being
	// writable (which is unremarkable and not what finding 4 is about).
	if !strings.Contains(r.out, "/srv/aliasedbin/git") {
		t.Fatalf("`command -v git` did not resolve to the aliased read-only bind "+
			"(/srv/aliasedbin/git), so the run below cannot be attributed to it:\n%s", r.out)
	}
	if !strings.Contains(r.out, "SHADOW-GIT-RAN") {
		t.Errorf("the payload's own git — written through the WRITABLE target grant, read back "+
			"through the READ-ONLY /srv/aliasedbin bind of the SAME host directory — did not "+
			"run:\n%s", r.out)
	}
}
