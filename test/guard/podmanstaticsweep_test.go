package guard

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ── issue #393 §7: nothing in-tree may name the retired static-podman bundle ─
//
// #398 retired the pinned static-podman fallback and deleted its own design
// document. What stops the constant (or a path, or a fresh design doc)
// coming back is this sweep: no file tracked by git, anywhere under the
// module root, may contain the retired bundle's own name — assembled below
// as two words joined by a hyphen, podman then static, and never spelled
// that way anywhere else in this file (see retiredBundleNeedle's own doc
// comment for why).
//
// "Tracked by git" rather than "every file under the root", deliberately:
// CLAUDE.md's own working agreement puts scratch notes under
// .claude/scratchpad/, which is in .gitignore for exactly this reason (a
// routine `git add -A` must not be the thing that un-retires this), and a
// developer's own retired bundle sitting on disk under their own home
// directory is host state this repository does not own. `git ls-files` is
// the tree this sweep is actually answerable for.

// retiredBundleNeedle assembles the forbidden substring at RUNTIME rather
// than spelling it anywhere in this file's own source. Spelling it here
// would make this sweep's own file the one tracked file that legitimately
// contains it, which is exactly the kind of one-off exception CLAUDE.md's
// invariant 2 calls a design smell — and it would need excluding by name,
// the catalogue shape that invariant rejects. Building it from parts, and
// never naming the whole word anywhere else below, means the check needs no
// exception at all.
func retiredBundleNeedle() string {
	return "podman" + "-" + "static"
}

// TestNoTrackedFileNamesTheRetiredPodmanStaticBundle is issue #393 §7.
func TestNoTrackedFileNamesTheRetiredPodmanStaticBundle(t *testing.T) {
	needle := retiredBundleNeedle()

	// POSITIVE CONTROL, and the reason it exists: a sweep that cannot fail is
	// worse than no sweep (CLAUDE.md, and issue #393's own tasking twice
	// names this as a requirement). Plant the needle in a throwaway file
	// OUTSIDE the module root (t.TempDir(), never under the checkout — see
	// TestNoTestWritesATemporaryDirectoryUnderTheModuleRoot in this same
	// package) and prove the matcher used below actually catches it before
	// trusting a clean run of the real sweep.
	planted := filepath.Join(t.TempDir(), "planted.txt")
	if err := os.WriteFile(planted, []byte("bundle at .local/opt/"+needle+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(planted)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), needle) {
		t.Fatalf("control: the planted fixture does not contain the needle %q — the matcher below "+
			"would report a clean tree even with the retired bundle's name reintroduced", needle)
	}

	root := moduleRoot(t)
	out, err := exec.Command("git", "-C", root, "ls-files").Output()
	if err != nil {
		t.Fatalf("git -C %s ls-files: %v", root, err)
	}
	var files []string
	for _, rel := range strings.Split(string(out), "\n") {
		if rel != "" {
			files = append(files, rel)
		}
	}
	if len(files) == 0 {
		t.Fatal("`git ls-files` returned nothing, so this sweep did not check a single tracked file")
	}

	checked := 0
	var bad []string
	for _, rel := range files {
		body, rerr := os.ReadFile(filepath.Join(root, rel))
		if rerr != nil {
			if errors.Is(rerr, fs.ErrNotExist) {
				// Vanished between `git ls-files` and the read (a rename mid-test-run
				// elsewhere in this module) — not this sweep's job; see
				// TestEverySourceSweepToleratesAVanishedEntry for why every such walk
				// in this module carries this exact tolerance.
				continue
			}
			t.Fatalf("reading %s: %v", rel, rerr)
		}
		checked++
		if strings.Contains(string(body), needle) {
			bad = append(bad, rel)
		}
	}
	if checked == 0 {
		t.Fatal("every tracked file vanished before it could be read, so this sweep measures nothing")
	}

	for _, rel := range bad {
		t.Errorf("%s names the retired podman/static bundle (issue #398). Its design document is "+
			"deleted and the harness no longer resolves an engine through it (issue #393) — a "+
			"constant, a path or a doc pointing at it again is how the retired fallback comes back.",
			rel)
	}
}
