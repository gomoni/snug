package engine

// scanstore_test.go is F7's own half of the red-team round on this diff:
// StoreScan.WriteBlockedDirs exists to disclose the overlayfs diff/ shape
// (0555 — enterable, but blocking removal of what's inside) that
// UnreadableDirs alone missed. Before the fix, --dry-run never incremented
// any counter for a 0555 directory, so a reclaim's own chmod was invisible
// to the report that is supposed to be honest about what removal will do.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestScanStoreCountsA0555DirectoryAsWriteBlocked is the counter half of F7:
// a 0555 directory (readable and enterable, but not writable — the overlayfs
// diff/ shape gc.go's package comment measures) must be counted in
// WriteBlockedDirs and NOT in UnreadableDirs, which counts the stricter,
// unenterable mode-0000 shape.
//
// POSITIVE CONTROL: an otherwise-identical clean fixture (no 0555 anywhere)
// must report zero for both counters — without it, "the walk sees the 0555
// shape" would be indistinguishable from a scan that always reports nonzero.
func TestScanStoreCountsA0555DirectoryAsWriteBlocked(t *testing.T) {
	base := t.TempDir()
	blocked := filepath.Join(base, "blocked")
	diff := filepath.Join(blocked, "storage", "overlay", "hex1", "diff")
	if err := os.MkdirAll(diff, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(diff, "marker"), []byte("layer content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(diff, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(diff, 0o700) })

	root, err := os.OpenRoot(blocked)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	scan, err := ScanStore(root, blocked)
	if err != nil {
		t.Fatalf("ScanStore: %v", err)
	}
	if scan.WriteBlockedDirs != 1 {
		t.Errorf("WriteBlockedDirs = %d, want 1 (the one 0555 diff/ directory)", scan.WriteBlockedDirs)
	}
	if scan.UnreadableDirs != 0 {
		t.Errorf("UnreadableDirs = %d, want 0 — a 0555 directory is ENTERABLE, it is not the "+
			"mode-0000 shape UnreadableDirs counts", scan.UnreadableDirs)
	}
	// The walk can still read INTO a 0555 directory (it only lacks write),
	// so the content inside is not hidden from the size total the way a
	// mode-0000 directory's content is.
	if scan.SizeBytes != int64(len("layer content")) {
		t.Errorf("SizeBytes = %d, want %d — a 0555 directory is readable, so its content must "+
			"still be counted", scan.SizeBytes, len("layer content"))
	}

	// CONTROL fixture: identical shape, no 0555 anywhere.
	clean := filepath.Join(base, "clean")
	cleanDiff := filepath.Join(clean, "storage", "overlay", "hex1", "diff")
	if err := os.MkdirAll(cleanDiff, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cleanDiff, "marker"), []byte("layer content"), 0o644); err != nil {
		t.Fatal(err)
	}
	cleanRoot, err := os.OpenRoot(clean)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanRoot.Close()
	cleanScan, err := ScanStore(cleanRoot, clean)
	if err != nil {
		t.Fatalf("ScanStore (control): %v", err)
	}
	if cleanScan.WriteBlockedDirs != 0 {
		t.Errorf("control: WriteBlockedDirs = %d, want 0 — nothing in this tree is 0555",
			cleanScan.WriteBlockedDirs)
	}
}
