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
