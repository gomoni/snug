package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEngineGCHoldsTheTargetLockWhenItsFileWasSwept pins the property `snug
// engine gc` actually needs, which is not the one a read-only probe answers.
//
// The defect this is the regression test for: sweepOneStaleLock made "this
// target has no lock file" the ordinary steady state, and targetLive read
// ENOENT as "not live" and handed back a no-op unlock. Phase 1 — OpenStore,
// ScanStore, RenameAside — then ran holding nothing, so a run starting one
// instruction later took the target lock while gc renamed its store aside.
// That is the silent overlayfs corruption enginegc.go's own header exists to
// prevent, reached with no attacker present.
//
// The assertion is the one that would have failed: while gc believes it is
// inside its protected phase, lockTarget on that target must be REFUSED.
//
// This is the ONLY thing that refuses a run on a locked target. Runs hold the
// target lock SHARED and never exclude each other; gc's reclaim arm asks for
// LOCK_EX precisely so that it does, and CONTROL 0 below is what tells the two
// modes apart — remove the exclusive request and a peer run still starts, so
// only the gc case can catch it.
func TestEngineGCHoldsTheTargetLockWhenItsFileWasSwept(t *testing.T) {
	snugDir := useTargetLockBase(t)
	if err := os.MkdirAll(snugDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}

	// The steady state after a sweep: this target has run before — that is
	// why it has a store for gc to consider — and its lock file is gone.
	if _, serr := os.Stat(filepath.Join(snugDir, targetLockName(real))); !os.IsNotExist(serr) {
		t.Fatalf("fixture: the lock file must be absent to reproduce this, got %v", serr)
	}

	// CONTROL 0: two runs on this target coexist. Without it, the refusal
	// below is equally true of a lock that refuses everything.
	first, err := lockTarget(target)
	if err != nil {
		t.Fatalf("a first run could not take the target lock: %v", err)
	}
	second, err := lockTarget(target)
	if err != nil {
		first()
		t.Fatalf("a second run on the same target was refused: %v", err)
	}
	second()
	first()

	live, unlock, err := targetLive(real, liveHoldForReclaim)
	if err != nil {
		t.Fatal(err)
	}
	if live {
		t.Fatal("targetLive reported a target live when no run exists at all")
	}

	if _, lerr := lockTarget(target); lerr == nil {
		unlock()
		t.Fatal("a run took the target lock while `snug engine gc` believed it was holding " +
			"the target not-live: phase 1 renames the store aside under exactly this window")
	} else {
		var busy *targetBusyError
		if !errors.As(lerr, &busy) {
			unlock()
			t.Fatalf("the run was refused, but not by the exclusive holder: %v", lerr)
		}
		if !strings.Contains(lerr.Error(), "engine gc") {
			unlock()
			t.Errorf("the refusal does not name what is actually in the way. A peer run cannot "+
				"cause this, so a message about `a run is live` sends the reader looking for a "+
				"sandbox that is not the problem: %v", lerr)
		}
	}
	unlock()

	// CONTROL 1: the refusal above is gc holding the lock, not a target that
	// cannot be locked at all.
	release, err := lockTarget(target)
	if err != nil {
		t.Fatalf("after gc released, a run could not take the target lock: %v", err)
	}
	release()
}

// CONTROL 2, and it is what makes the mode a design rather than a flag:
// liveProbeOnly answers the question and holds nothing, which is why nothing
// may reclaim under it. --dry-run is its only caller for exactly that reason.
func TestTheProbeOnlyLivenessModeHoldsNothing(t *testing.T) {
	snugDir := useTargetLockBase(t)
	if err := os.MkdirAll(snugDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}

	live, unlock, err := targetLive(real, liveProbeOnly)
	if err != nil {
		t.Fatal(err)
	}
	if live {
		t.Fatal("targetLive reported a target live when no run exists at all")
	}
	defer unlock()

	// Checked BEFORE the run below, which creates the file itself: what is
	// being asserted is that the PROBE created nothing.
	if _, serr := os.Stat(filepath.Join(snugDir, targetLockName(real))); !os.IsNotExist(serr) {
		t.Errorf("liveProbeOnly left a lock file behind (%v); --dry-run promises it creates no file", serr)
	}

	release, lerr := lockTarget(target)
	if lerr != nil {
		t.Fatalf("liveProbeOnly refused a run: it is a query and must hold nothing (%v)", lerr)
	}
	release()
}
