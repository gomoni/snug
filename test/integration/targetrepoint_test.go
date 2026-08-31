//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheTargetPathIsRePointableFromInside pins issue #553's residual, the way
// TestProjectSettingsEROFSIsInPlaceOnlyAndRenameBypassesIt pins #286's.
//
// rename(2) refuses only when the dentry BEING RENAMED is a mount point.
// Renaming a directory that merely CONTAINS one is allowed and the mount travels
// with it, freeing the original name — so a payload re-points $SNUG_TARGET at a
// directory of its own making. bwrap builds the target's mount-point skeleton
// inside whatever filesystem covers the parent path, and for a t.TempDir()
// target that is snug's own /tmp tmpfs, which the payload can write.
//
// THE ASSERTION IS THE HOLE, NOT THE FIX. It fails the day an ancestor is
// anchored (#553's second fix: an authored empty tmpfs at every payload-writable
// proper ancestor makes each rename EBUSY), and when it does, the fix is right
// and this test is what needs rewriting — not the other way round.
//
// Found by the redteam agent in issue #550's round. The class predates #550:
// with @parent-ro selected the same thing works one level up, on the
// GRANDparent, which nothing ever anchored.
func TestTheTargetPathIsRePointableFromInside(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	marker := filepath.Join(proj, "marker")
	if err := os.WriteFile(marker, []byte("REAL-HOST-CONTENT\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// CONTROL first, in the same run: the payload reads the host's file at
	// $SNUG_TARGET before it touches anything. Without it, "the sandbox read a
	// decoy" would also be satisfied by a target that was never mounted.
	r := run(t, nil, proj, `
		echo "before: $(cat "$SNUG_TARGET/marker")"
		cd "$(dirname "$SNUG_TARGET")/.." || exit 1
		mv "$(basename "$(dirname "$SNUG_TARGET")")" hidden || echo "RENAME-REFUSED"
		mkdir -p "$SNUG_TARGET"
		echo DECOY > "$SNUG_TARGET/marker"
		echo "after: $(cat "$SNUG_TARGET/marker")"
		echo AGENT-WORK > "$SNUG_TARGET/work.txt"`).mustRun(t)

	if !strings.Contains(r.out, "before: REAL-HOST-CONTENT") {
		t.Fatalf("the payload could not read the host's file at $SNUG_TARGET, so nothing "+
			"below is about a re-point:\n%s", r.out)
	}

	if strings.Contains(r.out, "RENAME-REFUSED") {
		t.Fatalf("the rename was REFUSED, which means an ancestor of the target is now a "+
			"mount root — issue #553's second fix. That is the outcome we want: delete "+
			"this test and assert the refusal instead:\n%s", r.out)
	}
	if !strings.Contains(r.out, "after: DECOY") {
		t.Errorf("the payload renamed the target's parent and recreated the path, and "+
			"$SNUG_TARGET no longer reads as the payload's own directory. If it now reads "+
			"the host's file the hole is closed and #553 wants updating:\n%s", r.out)
	}

	// THE HOST IS UNTOUCHED, which is the half that keeps this a deception bug
	// and not a containment escape: nothing the payload wrote after the re-point
	// reaches the project, including the work it believes it saved.
	got, err := os.ReadFile(marker)
	if err != nil || !strings.Contains(string(got), "REAL-HOST-CONTENT") {
		t.Fatalf("the host's marker changed (%v, %q) — the re-point reached the project, "+
			"which is a containment failure and not the residual #553 describes", err, got)
	}
	if _, err := os.Stat(filepath.Join(proj, "work.txt")); err == nil {
		t.Errorf("work.txt written at $SNUG_TARGET after the re-point reached the host; " +
			"#553 says it evaporates with the tmpfs")
	}
}
