package cli

// enginegc_test.go is issue #308's `snug engine gc` driven end to end
// through engineGCCmd, with the two host-derived roots isolated exactly the
// way this package's own testing note in enginegc.go demands:
// $XDG_DATA_HOME for the store side, and useTargetLockBase(t) — NEVER
// $XDG_RUNTIME_DIR — for the lock side (issue #122: targetLockBase reads the
// uid alone, so an env var does not redirect it).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/engine"
	"golang.org/x/sys/unix"
)

// buildEngineStoreFixture builds engines/<key>/{storage,store.json} under
// dataHome, in the exact shape gc.go's ListEngineEntries/OpenStore and
// breadcrumb.go's ReadBreadcrumb expect: every snug-owned directory in the
// chain at exactly 0700. attributed controls whether a trustworthy
// store.json is written at all — an unattributed store (the common case
// right after this feature ships) has none.
func buildEngineStoreFixture(t *testing.T, dataHome, target string, lastUsed time.Time, attributed bool) (key, storageDir string) {
	t.Helper()
	key = engine.KeyForTarget(target)
	keyDir := filepath.Join(dataHome, "snug", "engines", key)
	storageDir = filepath.Join(keyDir, "storage")
	for _, d := range []string{filepath.Join(dataHome, "snug"), filepath.Join(dataHome, "snug", "engines"), keyDir, storageDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if attributed {
		bc := engine.Breadcrumb{
			Schema:   engine.BreadcrumbSchema,
			Target:   target,
			Created:  lastUsed.Format(time.RFC3339),
			LastUsed: lastUsed.Format(time.RFC3339),
		}
		b, err := json.MarshalIndent(bc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keyDir, "store.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(storageDir, "layer.dat"), []byte("some image bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	return key, storageDir
}

// storeExists reports whether engines/<key> is still present under dataHome.
func storeExists(dataHome, key string) bool {
	_, err := os.Lstat(filepath.Join(dataHome, "snug", "engines", key))
	return err == nil
}

// leftoverEntries lists any ".gc-" leftover directory names under
// dataHome/snug/engines.
func leftoverEntries(t *testing.T, dataHome string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dataHome, "snug", "engines"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), ".gc-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// countLockFiles counts entries in the lock directory useTargetLockBase(t)
// points at, treating an absent directory as zero — the shape it starts in
// before any run has ever locked anything.
func countLockFiles(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	return len(entries)
}

// holdTargetLockReleasable is orphansweep_test.go's holdTargetLock with an
// explicit release the caller controls mid-test (that file's own version
// only ever releases via t.Cleanup, at the very end) — needed here because
// several tests below release the lock partway through to prove the
// SUBSEQUENT reclaim, in the same test, is a positive control rather than a
// separate run.
func holdTargetLockReleasable(t *testing.T, snugDir, target string) (release func()) {
	t.Helper()
	if err := os.MkdirAll(snugDir, 0o700); err != nil {
		t.Fatal(err)
	}
	name := targetLockName(target)
	f, err := os.OpenFile(filepath.Join(snugDir, name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	return func() {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}
}

// TestEngineGCBareInvocationRemovesNothing is the maintainer's ruling in
// enginegc.go's own package comment: "no selector, no removal". A bare
// invocation must report both an attributed and an unattributed store and
// remove NEITHER.
//
// POSITIVE CONTROLS: --unattributed removes the unattributed one and
// --older-than 0s removes the attributed one — so the bare case's
// non-removal is a fact about the DEFAULT, not about a fixture that cannot
// be removed at all.
func TestEngineGCBareInvocationRemovesNothing(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	useTargetLockBase(t)

	attrKey, _ := buildEngineStoreFixture(t, dataHome, "/proj/bare-attributed", time.Now().Add(-1000*time.Hour), true)
	unattrKey, _ := buildEngineStoreFixture(t, dataHome, "/proj/bare-unattributed", time.Time{}, false)

	out := captureStdout(t, func() {
		if code := engineGCCmd(nil); code != 0 {
			t.Errorf("bare `snug engine gc` exited %d, want 0", code)
		}
	})
	if !strings.Contains(out, "Nothing selected, nothing removed") {
		t.Errorf("bare invocation's output does not say nothing was removed: %q", out)
	}
	if !storeExists(dataHome, attrKey) {
		t.Error("bare invocation removed the ATTRIBUTED store")
	}
	if !storeExists(dataHome, unattrKey) {
		t.Error("bare invocation removed the UNATTRIBUTED store")
	}

	// CONTROL: --unattributed removes the unattributed store, leaves the
	// attributed one.
	captureStdout(t, func() { engineGCCmd([]string{"--unattributed"}) })
	if storeExists(dataHome, unattrKey) {
		t.Error("control failed: --unattributed did not remove the unattributed store")
	}
	if !storeExists(dataHome, attrKey) {
		t.Error("control failed: --unattributed also removed the attributed store")
	}

	// CONTROL: --older-than 0s removes the attributed store.
	captureStdout(t, func() { engineGCCmd([]string{"--older-than", "0s"}) })
	if storeExists(dataHome, attrKey) {
		t.Error("control failed: --older-than 0s did not remove the attributed store")
	}
}

// TestEngineGCNeverCreatesALockFile is the regression test for the real
// incident: an earlier O_CREATE probe in the liveness check left permanent
// 0-byte lock files in the real /run/user/<uid>/snug, including under
// --dry-run, which promises it creates no file. This asserts the delta is
// ZERO across bare, --older-than --dry-run, and --unattributed --dry-run.
func TestEngineGCNeverCreatesALockFile(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	snugDir := useTargetLockBase(t)
	// The lock directory itself already exists — some OTHER run has locked
	// some OTHER target on this host at some point — but neither fixture
	// target below has ever been locked. This is the shape that actually
	// exercises targetLive/anyRunLive's Open call: with no "snug" directory
	// at all, both arms short-circuit before reaching it (their own doc
	// comment: absence of the directory means nothing has EVER locked
	// anything, so there is nothing left to probe).
	if err := os.MkdirAll(snugDir, 0o700); err != nil {
		t.Fatal(err)
	}

	buildEngineStoreFixture(t, dataHome, "/proj/lockfile-attributed", time.Now().Add(-1000*time.Hour), true)
	buildEngineStoreFixture(t, dataHome, "/proj/lockfile-unattributed", time.Time{}, false)

	before := countLockFiles(snugDir)

	captureStdout(t, func() { engineGCCmd(nil) })
	if got := countLockFiles(snugDir); got != before {
		t.Errorf("bare `gc`: lock directory went from %d to %d entries — it must create none", before, got)
	}

	captureStdout(t, func() { engineGCCmd([]string{"--older-than", "1s", "--dry-run"}) })
	if got := countLockFiles(snugDir); got != before {
		t.Errorf("--older-than --dry-run: lock directory went from %d to %d entries", before, got)
	}

	captureStdout(t, func() { engineGCCmd([]string{"--unattributed", "--dry-run"}) })
	if got := countLockFiles(snugDir); got != before {
		t.Errorf("--unattributed --dry-run: lock directory went from %d to %d entries", before, got)
	}
}

// TestEngineGCDryRunCreatesNothingAndRemovesNothing is --dry-run's promise,
// exercised against every selector: no store removed, no ".gc-*" leftover
// created, and (restated from the lock-file regression above, for this
// specific command shape) no lock file created either.
func TestEngineGCDryRunCreatesNothingAndRemovesNothing(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	snugDir := useTargetLockBase(t)

	attrKey, _ := buildEngineStoreFixture(t, dataHome, "/proj/dryrun-attributed", time.Now(), true)
	unattrKey, _ := buildEngineStoreFixture(t, dataHome, "/proj/dryrun-unattributed", time.Time{}, false)
	beforeLocks := countLockFiles(snugDir)

	for _, args := range [][]string{
		{"--older-than", "0s", "--dry-run"},
		{"--unattributed", "--dry-run"},
		{attrKey, "--dry-run"},
	} {
		out := captureStdout(t, func() { engineGCCmd(args) })
		if !storeExists(dataHome, attrKey) {
			t.Fatalf("args %v: --dry-run removed the attributed store", args)
		}
		if !storeExists(dataHome, unattrKey) {
			t.Fatalf("args %v: --dry-run removed the unattributed store", args)
		}
		if got := leftoverEntries(t, dataHome); len(got) != 0 {
			t.Fatalf("args %v: --dry-run created a .gc-* leftover: %v", args, got)
		}
		if got := countLockFiles(snugDir); got != beforeLocks {
			t.Fatalf("args %v: --dry-run changed the lock directory's entry count from %d to %d",
				args, beforeLocks, got)
		}
		_ = out
	}

	// CONTROL: the SAME selector, without --dry-run, actually removes —
	// proving --dry-run's non-removal above is real, not a fixture that
	// cannot be removed at all.
	captureStdout(t, func() { engineGCCmd([]string{"--older-than", "0s"}) })
	if storeExists(dataHome, attrKey) {
		t.Fatal("control failed: the same selector without --dry-run did not remove the store")
	}
}

// TestEngineGCSkipsALiveStore is the measured consequence of getting
// liveness wrong stated as a test: removing a live store's layer directory
// produces silent overlayfs corruption with no error on either side. This
// holds the SAME per-target flock a live run holds and asserts the store
// with that target is skipped, not removed, regardless of --older-than.
//
// CONTROL: releasing the lock and re-running removes it — proving the skip
// above is really about liveness, not about a store that cannot be removed.
func TestEngineGCSkipsALiveStore(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	snugDir := useTargetLockBase(t)

	target := "/proj/live-store"
	key, _ := buildEngineStoreFixture(t, dataHome, target, time.Now().Add(-1000*time.Hour), true)

	release := holdTargetLockReleasable(t, snugDir, target)

	out := captureStdout(t, func() { engineGCCmd([]string{"--older-than", "0s"}) })
	if !strings.Contains(out, "skip") || !strings.Contains(out, "live") {
		t.Errorf("output does not say the live store was skipped: %q", out)
	}
	if !storeExists(dataHome, key) {
		t.Fatal("a LIVE store was removed — this is the corruption-causing bug")
	}

	release()
	captureStdout(t, func() { engineGCCmd([]string{"--older-than", "0s"}) })
	if storeExists(dataHome, key) {
		t.Fatal("control failed: after releasing the lock, the store was still not removed")
	}
}

// TestEngineGCUnattributedRefusesWhileAnyRunIsLive is Arm B's coarse rule:
// with no target string to derive an exact lock name from, an unattributed
// store is refused whenever ANY snug run is live on the host, not just a
// run of "this" target.
func TestEngineGCUnattributedRefusesWhileAnyRunIsLive(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	snugDir := useTargetLockBase(t)

	key, _ := buildEngineStoreFixture(t, dataHome, "/proj/unattributed-arm-b", time.Time{}, false)

	// A lock for a COMPLETELY UNRELATED target — Arm B must still refuse.
	release := holdTargetLockReleasable(t, snugDir, "/proj/some-other-live-target")

	out := captureStdout(t, func() { engineGCCmd([]string{"--unattributed"}) })
	if !strings.Contains(out, "skip") {
		t.Errorf("output does not say the unattributed store was skipped: %q", out)
	}
	if !storeExists(dataHome, key) {
		t.Fatal("an unattributed store was removed while an UNRELATED run was live")
	}

	// CONTROL: no lock held anywhere -> it removes.
	release()
	captureStdout(t, func() { engineGCCmd([]string{"--unattributed"}) })
	if storeExists(dataHome, key) {
		t.Fatal("control failed: with no run live anywhere, --unattributed did not remove it")
	}
}

// TestEngineGCReportsSizeAsALowerBound: a store with a mode-0000, non-empty
// directory hiding content from the scan must report ">=" and must show the
// "unreadable subtree" qualifier — never an unqualified number that chmod
// would be needed to produce.
//
// CONTROL: an otherwise-identical store with NO unreadable directory still
// shows ">=" (the walk always states a lower bound) but must NOT carry the
// "unreadable subtree" qualifier — proving that phrase is conditional on the
// walk actually being blocked, not boilerplate that always appears.
func TestEngineGCReportsSizeAsALowerBound(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	useTargetLockBase(t)

	hiddenKey, hiddenStorage := buildEngineStoreFixture(t, dataHome, "/proj/hidden-size", time.Now(), true)
	locked := filepath.Join(hiddenStorage, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "f.txt"), []byte("hidden"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o700) })

	out := captureStdout(t, func() { engineGCCmd([]string{hiddenKey, "--dry-run"}) })
	if !strings.Contains(out, ">=") {
		t.Errorf("output does not state a lower bound (\">=\"): %q", out)
	}
	if !strings.Contains(out, "unreadable subtree") {
		t.Errorf("output does not flag the unreadable subtree: %q", out)
	}
	if !storeExists(dataHome, hiddenKey) {
		t.Fatal("--dry-run removed the store")
	}

	// CONTROL fixture: no mode-0 directory.
	cleanKey, _ := buildEngineStoreFixture(t, dataHome, "/proj/clean-size", time.Now(), true)
	cleanOut := captureStdout(t, func() { engineGCCmd([]string{cleanKey, "--dry-run"}) })
	if !strings.Contains(cleanOut, ">=") {
		t.Errorf("control: output does not state a lower bound: %q", cleanOut)
	}
	if strings.Contains(cleanOut, "unreadable subtree") {
		t.Errorf("control: a store with NOTHING hidden still claimed an unreadable subtree: %q", cleanOut)
	}
}

// TestEngineGCTwoPhaseLeavesNoPartialStore asserts both halves of the
// two-phase design: a successful removal leaves no ".gc-*" behind, and a
// PRE-EXISTING ".gc-*" leftover (a previous GC's phase 2 that stopped
// partway) is retried and removed on the very next invocation, selector or
// not.
func TestEngineGCTwoPhaseLeavesNoPartialStore(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	useTargetLockBase(t)

	// Half 1: a normal successful removal leaves no leftover.
	key, _ := buildEngineStoreFixture(t, dataHome, "/proj/two-phase-clean", time.Now(), true)
	captureStdout(t, func() { engineGCCmd([]string{"--older-than", "0s"}) })
	if storeExists(dataHome, key) {
		t.Fatal("the store was not removed at all")
	}
	if got := leftoverEntries(t, dataHome); len(got) != 0 {
		t.Fatalf("a successful removal left a .gc-* leftover behind: %v", got)
	}

	// Half 2: a pre-existing ".gc-*" leftover, planted by hand exactly as
	// RenameAside would have left it, is retried and removed by a BARE
	// invocation (no selector at all) — it needs no liveness question.
	leftoverKey, _ := buildEngineStoreFixture(t, dataHome, "/proj/two-phase-leftover-target", time.Now(), true)
	// buildEngineStoreFixture already created engines/<leftoverKey>/...; move
	// it aside under the ".gc-" name a real RenameAside produces.
	enginesDir := filepath.Join(dataHome, "snug", "engines")
	leftoverName := ".gc-" + leftoverKey + "-1-1"
	if err := os.Rename(filepath.Join(enginesDir, leftoverKey), filepath.Join(enginesDir, leftoverName)); err != nil {
		t.Fatal(err)
	}
	// CONTROL: it is there before GC runs.
	if _, err := os.Lstat(filepath.Join(enginesDir, leftoverName)); err != nil {
		t.Fatalf("control failed: the leftover fixture is not where the test put it: %v", err)
	}

	out := captureStdout(t, func() { engineGCCmd(nil) }) // bare: no selector
	if !strings.Contains(out, "leftover") {
		t.Errorf("bare gc did not report the leftover: %q", out)
	}
	if !strings.Contains(out, "reclaimed") {
		t.Errorf("bare gc did not report reclaiming the leftover: %q", out)
	}
	if _, err := os.Lstat(filepath.Join(enginesDir, leftoverName)); !os.IsNotExist(err) {
		t.Errorf("the pre-existing .gc-* leftover was not removed (err=%v)", err)
	}
}
