//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheTargetsParentCannotBeRenamedAway is issue #553's fix, in its
// positive form. The test this replaces,
// TestTheTargetPathIsRePointableFromInside, pinned the HOLE and said in its
// own header that the day an ancestor is anchored is the day it needs
// rewriting, not deleting silently — this is that rewrite.
//
// rename(2) refuses only when the dentry BEING RENAMED is itself a mount
// point; renaming a directory that merely CONTAINS one used to be allowed,
// and the mount travelled with it, freeing the original name for a payload to
// recreate. InstallAnchors (anchor.go) now mounts an empty tmpfs at every
// such ancestor, so the rename is refused at the kernel — EBUSY — before the
// payload ever gets to recreate the name.
func TestTheTargetsParentCannotBeRenamedAway(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	marker := filepath.Join(proj, "marker")
	if err := os.WriteFile(marker, []byte("REAL-HOST-CONTENT\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := run(t, nil, proj, `
		echo "before: $(cat "$SNUG_TARGET/marker")"
		cd "$(dirname "$SNUG_TARGET")/.." || exit 1
		mv "$(basename "$(dirname "$SNUG_TARGET")")" hidden 2>&1
		echo "after: $(cat "$SNUG_TARGET/marker" 2>&1)"`).mustRun(t)

	// CONTROL first, in the same run: the payload reads the host's file at
	// $SNUG_TARGET before it touches anything. Without it, "the rename was
	// refused" would also be satisfied by a target that was never mounted.
	if !strings.Contains(r.out, "before: REAL-HOST-CONTENT") {
		t.Fatalf("the payload could not read the host's file at $SNUG_TARGET, so nothing "+
			"below says anything about a re-point:\n%s", r.out)
	}
	if !strings.Contains(r.out, "Device or resource busy") {
		t.Errorf("renaming the target's parent was not refused with EBUSY. Without the anchor "+
			"at the parent it is a plain name in a writable tmpfs, and issue #553's primary "+
			"reproduction — mv 'proj' to 'hidden' — succeeds:\n%s", r.out)
	}
	// The rename having failed, the target must still resolve to the real
	// host content — never to a directory the payload rebuilt at the same
	// name after a rename that should not have been possible in the first
	// place.
	if !strings.Contains(r.out, "after: REAL-HOST-CONTENT") {
		t.Errorf("$SNUG_TARGET no longer reads the host's file after the rename was refused:\n%s", r.out)
	}

	got, err := os.ReadFile(marker)
	if err != nil || !strings.Contains(string(got), "REAL-HOST-CONTENT") {
		t.Fatalf("the host's marker changed (%v, %q) after a rename that was supposed to be "+
			"refused", err, got)
	}
}

// TestParentRoGrandparentCannotBeRenamedAway is #553's second reproduction:
// with `-p @parent-ro` selected, the profile's own bind anchors the target's
// PARENT (it is a real grant now, not snug's tmpfs), but the class reaches one
// level further up — the GRANDparent, still a plain name in @home's tmpfs,
// nothing anchored before this fix. Renaming it dragged the @parent-ro bind
// away with it exactly as the primary reproduction dragged the target's own
// mount away.
func TestParentRoGrandparentCannotBeRenamedAway(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	marker := filepath.Join(proj, "marker")
	if err := os.WriteFile(marker, []byte("REAL-HOST-CONTENT\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := run(t, []string{"-p", "@parent-ro"}, proj, `
		echo "before: $(cat "$SNUG_TARGET/marker")"
		grandparent="$(dirname "$(dirname "$SNUG_TARGET")")"
		cd "$(dirname "$grandparent")" || exit 1
		mv "$(basename "$grandparent")" grandparent-hidden 2>&1
		echo "after: $(cat "$SNUG_TARGET/marker" 2>&1)"`).mustRun(t)

	if !strings.Contains(r.out, "before: REAL-HOST-CONTENT") {
		t.Fatalf("the payload could not read the host's file at $SNUG_TARGET, so nothing "+
			"below says anything about a re-point:\n%s", r.out)
	}
	if !strings.Contains(r.out, "Device or resource busy") {
		t.Errorf("renaming the GRANDparent under -p @parent-ro was not refused with EBUSY. "+
			"issue #553's second reproduction — mv 'src' to 'src2' one level above the "+
			"@parent-ro bind — succeeded before this fix:\n%s", r.out)
	}
	if !strings.Contains(r.out, "after: REAL-HOST-CONTENT") {
		t.Errorf("$SNUG_TARGET no longer reads the host's file after the rename was refused:\n%s", r.out)
	}

	got, err := os.ReadFile(marker)
	if err != nil || !strings.Contains(string(got), "REAL-HOST-CONTENT") {
		t.Fatalf("the host's marker changed (%v, %q) after a rename that was supposed to be "+
			"refused", err, got)
	}
}

// TestAnchorHidesNothingAndEvaporatesAtTeardown is the two negatives an
// anchor's own doc comment promises: it grants nothing beyond what the
// tmpfs it stands on already granted (a sibling of the target stays
// invisible through it), and anything the payload writes directly into it —
// as opposed to renaming it — is real, but ends at the sandbox: the anchor is
// snug's own empty tmpfs for this run, with no host directory behind it.
func TestAnchorHidesNothingAndEvaporatesAtTeardown(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)
	anchoredParent := filepath.Dir(proj) // target()'s "proj" — the target's parent

	r := run(t, nil, proj, `
		ls "$(dirname "$SNUG_TARGET")" 2>&1
		echo PLANTED > "$(dirname "$SNUG_TARGET")/planted-in-anchor"
		ls "$(dirname "$SNUG_TARGET")" 2>&1`).mustRun(t)

	if !strings.Contains(r.out, "sub") {
		t.Fatalf("control: the target itself is not listed inside its own anchored parent, so "+
			"the sibling assertion below would prove nothing:\n%s", r.out)
	}
	if strings.Contains(r.out, "sibling") {
		t.Errorf("the target's sibling (target()'s own fixture directory) is visible through "+
			"the anchor at the target's parent — an anchor must grant nothing beyond what the "+
			"tmpfs it stands on already granted:\n%s", r.out)
	}
	if !strings.Contains(r.out, "planted-in-anchor") {
		t.Errorf("a file written directly into the anchor (not a rename, an ordinary write) did "+
			"not appear inside the sandbox — anchors are meant to be a WRITABLE empty tmpfs, "+
			"the same as the ground they stand on:\n%s", r.out)
	}

	if _, err := os.Stat(filepath.Join(anchoredParent, "planted-in-anchor")); err == nil {
		t.Errorf("a file written directly into the anchor reached the HOST at %s — the anchor "+
			"is supposed to be snug's own tmpfs for this run, with no host directory behind it",
			anchoredParent)
	}
}

// TestTheReadWriteBoundAncestorResidualStillReachesTheHost pins the residual
// anchor.go states rather than papers over, for real: InstallAnchors never
// anchors an ancestor covered by a read-write BIND (only a tmpfs cover
// qualifies — an empty tmpfs stacked on a real host directory would hide
// every entry in it that no profile separately granted, invariant 1's own
// subtraction). So a target one level inside an rw-granted directory is
// exactly as re-pointable as before #553, and — unlike the tmpfs case —
// the rename lands on the real host tree, because a read-write grant of a
// directory IS a grant of the right to rename inside it.
//
// No shipped builtin reaches this shape (@tmp-shared's rw of {host_tmpdir}
// looks like it should and does not: a target under /tmp nests @cwd-rw's
// bind inside @tmp-shared's and rejectMasking refuses the whole selection),
// so this test authors its own rw-granting profile, the shape a user's own
// profiles.d entry would take.
//
// This is the KNOWN residual `snug attach`'s planned st_dev/st_ino check
// (issue #553's "Detect" half) is meant to cover separately, in the style of
// the test it replaces: it fails the day that check lands and pins this
// shape, and when it does, the fix is right and this test is what needs
// rewriting.
func TestTheReadWriteBoundAncestorResidualStillReachesTheHost(t *testing.T) {
	budget(t)
	requireSandbox(t)

	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	subDir := filepath.Join(dataDir, "proj", "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(subDir, "marker")
	if err := os.WriteFile(marker, []byte("REAL-HOST-CONTENT\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	env := writeProfile(t, "[profile.data]\n"+
		"description = \"rw of a directory containing the target, for the residual pin\"\n"+
		"rw = [\""+dataDir+"\"]\n")

	r := runEnv(t, env, []string{"-p", "data"}, subDir, `
		echo "before: $(cat "$SNUG_TARGET/marker")"
		cd "$(dirname "$SNUG_TARGET")/.." || exit 1
		mv "$(basename "$(dirname "$SNUG_TARGET")")" hidden 2>&1
		mkdir -p "$SNUG_TARGET"
		echo DECOY > "$SNUG_TARGET/marker"
		echo "after: $(cat "$SNUG_TARGET/marker")"`).mustRun(t)

	if !strings.Contains(r.out, "before: REAL-HOST-CONTENT") {
		t.Fatalf("the payload could not read the host's file at $SNUG_TARGET, so nothing below "+
			"says anything about a re-point:\n%s", r.out)
	}
	if strings.Contains(r.out, "Device or resource busy") {
		t.Fatalf("the rename was REFUSED under an rw-granted ancestor — the residual is closed. "+
			"That is the outcome we want: delete this test and assert the refusal instead, and "+
			"say in the same change what closed it:\n%s", r.out)
	}
	if !strings.Contains(r.out, "after: DECOY") {
		t.Fatalf("the payload's rename+recreate did not take effect inside the sandbox:\n%s", r.out)
	}

	// THE HOST REALLY CHANGED, which is what makes this the residual rather
	// than #553's closed hole: an rw grant of a host tree is a grant of the
	// right to rename inside it, so unlike the anchored case the rename
	// reaches the real directory.
	if _, err := os.Stat(filepath.Join(dataDir, "hidden")); err != nil {
		t.Errorf("the host's %s/hidden does not exist — the rename did not reach the host, so "+
			"this is not the residual anchor.go describes: %v", dataDir, err)
	}
	hostMarker, err := os.ReadFile(filepath.Join(dataDir, "proj", "sub", "marker"))
	if err != nil || !strings.Contains(string(hostMarker), "DECOY") {
		t.Errorf("the host's %s/proj/sub/marker does not read DECOY (%v, %q) — the payload's "+
			"recreated directory did not reach the host", dataDir, err, hostMarker)
	}
	// And the REAL content is still there too, just under the renamed name —
	// the host tree was RENAMED, not overwritten, which is what makes the
	// hole a re-point rather than plain data loss.
	origMarker, err := os.ReadFile(filepath.Join(dataDir, "hidden", "sub", "marker"))
	if err != nil || !strings.Contains(string(origMarker), "REAL-HOST-CONTENT") {
		t.Errorf("the original content did not survive under the renamed directory "+
			"(%s/hidden/sub/marker, %v, %q) — expected a rename, not a loss",
			dataDir, err, origMarker)
	}
}

// TestSSHConfigDirectoryCannotBeRenamedAway is the identity-file half of
// #553: {home}/.ssh is covered by @home's tmpfs and holds only the two
// generated files (config, known_hosts) — never itself a mount — so before
// this fix `mv ~/.ssh ~/.sshOLD; mkdir ~/.ssh` stranded snug's real,
// generated, read-only config behind the renamed directory and let the
// payload author its own in its place, with a ProxyCommand of its choosing.
func TestSSHConfigDirectoryCannotBeRenamedAway(t *testing.T) {
	requireSandbox(t)
	pub, sock := sshAgentAndKey(t)
	proj, _ := target(t)
	env := writeProfile(t, "[profile.pinned]\n"+
		"description = \"one throwaway key, for the anchored ~/.ssh regression\"\n"+
		"[profile.pinned.identity]\n"+
		"ssh_mode = \"agent-proxy\"\n"+
		"ssh_key = \""+pub+"\"\n", "SSH_AUTH_SOCK="+sock)

	r := runEnv(t, env, []string{"-p", "pinned"}, proj, `
		mv ~/.ssh ~/.sshOLD 2>&1
		ssh -G github.com >/dev/null 2>&1 && echo SSH-OK || echo SSH-REFUSED
		ssh -G github.com | grep -i identityfile`).mustRun(t)

	if !strings.Contains(r.out, "Device or resource busy") {
		t.Errorf("renaming ~/.ssh away was not refused with EBUSY — the generated config is no "+
			"longer safe from being stranded behind a payload-authored replacement:\n%s", r.out)
	}
	if !strings.Contains(r.out, "SSH-OK") {
		t.Errorf("ssh could not even run after the refused rename:\n%s", r.out)
	}
	if !strings.Contains(r.out, "id_snug") {
		t.Errorf("ssh -G does not name the pinned identity file snug generated — the config "+
			"in effect is not the one this test pinned:\n%s", r.out)
	}
}
