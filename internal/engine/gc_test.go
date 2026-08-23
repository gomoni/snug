package engine

// gc_test.go is issue #308's Purge primitive: the recursive delete that
// tolerates a mode-0000, non-empty directory an overlayfs work/work leaves
// behind, and the containment properties that go with descending into a
// tree neither this package nor the payload fully controls. See gc.go's own
// package comment for the measurements ("permission denied" from
// os.RemoveAll, EACCES from openat even through an already-opened
// descriptor) these tests exist to hold in place.

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/vdir"
)

func openRootT(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

// plantModeZeroTree builds base/name as a small tree with exactly ONE
// mode-0000 directory (leaf, non-empty) somewhere inside it — the shape
// gc.go's package comment measures against a real overlayfs work directory.
// Returns the full path to base/name.
func plantModeZeroTree(t *testing.T, base, name string) string {
	t.Helper()
	root := filepath.Join(base, name)
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "keep.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "leaf.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(root, "sub", "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "hidden.txt"), []byte("secret bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestPurgeRemovesAModeZeroNonEmptyDirectory is the core of issue #308's
// Purge: a mode-0000, non-empty directory (the exact overlayfs work/work
// shape gc.go's package comment measures) is removed along with everything
// around it.
//
// POSITIVE CONTROL, mandatory: os.RemoveAll on an IDENTICAL sibling fixture
// must fail first, with "permission denied" — without this, the test would
// pass equally on a tree that never had a mode-0 directory in it at all.
func TestPurgeRemovesAModeZeroNonEmptyDirectory(t *testing.T) {
	base := t.TempDir()

	// The control fixture, built the same way, removed with the stdlib.
	controlRoot := plantModeZeroTree(t, base, "control")
	rmErr := os.RemoveAll(controlRoot)
	if rmErr == nil {
		t.Fatal("control failed: os.RemoveAll succeeded on a tree containing a mode-0000, " +
			"non-empty directory — this fixture proves nothing about what Purge does " +
			"differently, because RemoveAll already handled it")
	}
	if !strings.Contains(rmErr.Error(), "permission denied") {
		t.Fatalf("control: os.RemoveAll failed for an unexpected reason (want \"permission "+
			"denied\"): %v", rmErr)
	}
	// The control's mode-0 leaf must still exist — the failure really left
	// content behind rather than partially succeeding.
	if _, err := os.Stat(filepath.Join(controlRoot, "sub", "locked")); err != nil {
		t.Fatalf("control: RemoveAll's failure did not leave the mode-0 directory in place: %v", err)
	}
	// Restore so t.TempDir()'s own cleanup can remove it.
	os.Chmod(filepath.Join(controlRoot, "sub", "locked"), 0o700)

	// Now Purge, on a fresh, identically-built tree.
	purgeRoot := plantModeZeroTree(t, base, "purge-me")
	if err := Purge(openRootT(t, base), base, "purge-me"); err != nil {
		t.Fatalf("Purge failed on a mode-0000, non-empty directory: %v", err)
	}
	if _, err := os.Lstat(purgeRoot); !os.IsNotExist(err) {
		t.Errorf("Purge did not remove %s (err=%v) — Purge must succeed where RemoveAll, "+
			"proven above, cannot", purgeRoot, err)
	}
}

// TestPurgeChmodsOnlyWhatBlockedIt is the rmdir-first ordering's whole
// point: Purge must reach for chmod ONLY on the one directory whose own
// mode actually blocks removal, never as a blanket `chmod -R` over
// everything it descends into. Measured via strace counting real chmod-
// family syscalls made by an out-of-process Purge call — a Purge that
// chmodded every directory on its way down would show up here as a much
// higher count, not merely as "worked anyway".
func TestPurgeChmodsOnlyWhatBlockedIt(t *testing.T) {
	if dir := os.Getenv("SNUG_GC_CHMOD_HELPER_DIR"); dir != "" {
		// Re-exec'd under strace: perform exactly one Purge call and exit.
		// Deliberately not using the *testing.T from this invocation for
		// anything but Fatal — this process's own exit code is what the
		// parent checks.
		root, err := os.OpenRoot(filepath.Dir(dir))
		if err != nil {
			t.Fatalf("helper: opening %s: %v", filepath.Dir(dir), err)
		}
		defer root.Close()
		if err := Purge(root, filepath.Dir(dir), filepath.Base(dir)); err != nil {
			t.Fatalf("helper: Purge failed: %v", err)
		}
		return
	}

	if _, err := exec.LookPath("strace"); err != nil {
		t.Skipf("strace not on PATH: cannot count chmod syscalls without it: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	base := t.TempDir()
	root := plantModeZeroTree(t, base, "store")
	// Pad the tree so "one chmod out of ~10 entries" is a real ratio, not
	// one chmod out of two.
	for i := 0; i < 8; i++ {
		if err := os.WriteFile(filepath.Join(root, "pad"+strconv.Itoa(i)+".txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	traceFile := filepath.Join(t.TempDir(), "trace.log")
	cmd := exec.Command("strace", "-f", "-e", "trace=chmod,fchmodat,fchmodat2", "-o", traceFile,
		exe, "-test.run", "^TestPurgeChmodsOnlyWhatBlockedIt$", "-test.v")
	cmd.Env = append(os.Environ(), "SNUG_GC_CHMOD_HELPER_DIR="+root)
	if out, rerr := cmd.CombinedOutput(); rerr != nil {
		t.Fatalf("re-exec under strace failed: %v\n%s", rerr, out)
	}

	trace, err := os.ReadFile(traceFile)
	if err != nil {
		t.Fatalf("reading strace output: %v", err)
	}
	n := 0
	for _, line := range strings.Split(string(trace), "\n") {
		if strings.Contains(line, "chmod(") || strings.Contains(line, "fchmodat(") || strings.Contains(line, "fchmodat2(") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("Purge made %d chmod-family syscall(s) on a tree with exactly one mode-0000 "+
			"directory out of about a dozen entries, want exactly 1 — a higher count means "+
			"Purge is chmodding directories that were never blocking removal (a `chmod -R` "+
			"shape); trace:\n%s", n, trace)
	}

	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Errorf("tree was not fully removed (err=%v)", err)
	}
}

// TestPurgeDoesNotFollowASymlinkOutOfTheTree is the containment property: a
// symlink planted inside a store, pointing OUTSIDE the tree Purge is asked
// to remove, must not cause Purge to touch whatever it points at. The link
// itself is removed (it is part of the store); the victim directory it
// pointed to is untouched — same mode, same contents.
func TestPurgeDoesNotFollowASymlinkOutOfTheTree(t *testing.T) {
	base := t.TempDir()

	victim := filepath.Join(base, "victim")
	if err := os.Mkdir(victim, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victim, "do-not-touch.txt"), []byte("host content"), 0o640); err != nil {
		t.Fatal(err)
	}

	store := filepath.Join(base, "store")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "keep.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An ABSOLUTE symlink out of the tree — the shape a hostile or merely
	// buggy container image layer could plant.
	if err := os.Symlink(victim, filepath.Join(store, "escape")); err != nil {
		t.Fatal(err)
	}

	if err := Purge(openRootT(t, base), base, "store"); err != nil {
		t.Fatalf("Purge failed on a tree containing a symlink out of it: %v", err)
	}

	if _, err := os.Lstat(store); !os.IsNotExist(err) {
		t.Errorf("store was not fully removed (err=%v)", err)
	}

	// The victim must be COMPLETELY unaffected: still present, same mode,
	// same content.
	fi, err := os.Stat(victim)
	if err != nil {
		t.Fatalf("the symlink's target directory was itself removed or is now unreachable: %v", err)
	}
	if fi.Mode().Perm() != 0o750 {
		t.Errorf("victim directory's mode changed to %#o, want unchanged 0750", fi.Mode().Perm())
	}
	content, err := os.ReadFile(filepath.Join(victim, "do-not-touch.txt"))
	if err != nil {
		t.Fatalf("victim's file was removed or is unreadable: %v", err)
	}
	if string(content) != "host content" {
		t.Errorf("victim's file content changed: %q", content)
	}
}

// TestPurgeRefusesAForeignOwnedDirectory is EPERM-vs-EACCES kept apart,
// measured against a REAL cross-uid directory (see makeForeignOwnedDirEngine
// below for how it is built without root): Purge must refuse the whole
// subtree at the foreign-owned entry, via a *vdir.ForeignOwnerError, and
// must NOT retry it as if EACCES (a mode it owns) had been returned — a
// retry-as-EACCES bug would either chmod something it does not own (EPERM
// from that chmod) or, worse, silently succeed against a directory the
// pre-flight ownership sweep exists specifically to protect.
func TestPurgeRefusesAForeignOwnedDirectory(t *testing.T) {
	base := t.TempDir()
	store := filepath.Join(base, "store")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "keep.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(store, "foreign-layer")
	if err := os.Mkdir(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "layer.tar"), []byte("image bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	foreignUID, restore := makeForeignOwnedDirEngine(t, foreign)

	err := Purge(openRootT(t, base), base, "store")
	var fo *vdir.ForeignOwnerError
	if err == nil {
		t.Fatal("Purge removed a store containing a foreign-owned directory")
	}
	if !errors.As(err, &fo) {
		t.Fatalf("Purge failed for the wrong reason (want *vdir.ForeignOwnerError, i.e. EPERM "+
			"territory, not retried as EACCES): %v", err)
	}
	if fo.UID != foreignUID {
		t.Errorf("ForeignOwnerError named uid %d, want the real foreign owner %d", fo.UID, foreignUID)
	}

	// The refusal must leave everything ABOVE the foreign entry exactly
	// where it was: nothing partially removed.
	if _, err := os.Stat(filepath.Join(store, "keep.txt")); err != nil {
		t.Errorf("a sibling file was removed even though Purge refused the whole store: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("the foreign-owned directory itself was removed despite the refusal: %v", err)
	}

	// CONTROL: restore this process's own ownership of the directory that
	// blocked removal, and the identical Purge call now succeeds — proving
	// the refusal above is really about ownership, not about something else
	// broken in the fixture.
	restore()
	if err := Purge(openRootT(t, base), base, "store"); err != nil {
		t.Fatalf("control: Purge refused an otherwise-owned store: %v", err)
	}
}

// ── makeForeignOwnedDirEngine: a REAL cross-uid directory, no root needed ──
//
// Duplicated, deliberately small, from internal/vdir's identical helper
// (makeForeignOwnedDir) rather than shared through a new package: this is
// test-only tooling, not a security check subject to CLAUDE.md's "one rule,
// one author" for policy code, and a third package existing solely to hold
// ~90 lines two test suites call would be its own thing to keep in sync.
//
// It uses an unprivileged user namespace with a delegated subuid range —
// the same mechanism rootless podman itself relies on for a container
// image's own uid-1..N content, and the one gc.go's own doc comment names
// (internal/stage/subuid.go: ns uid 0 -> this process's own uid, ns uid 1
// -> host uid+1). Skips, naming the reason, when the host cannot supply it.

func makeForeignOwnedDirEngine(t *testing.T, dir string) (foreignUID int, restore func()) {
	t.Helper()
	for _, bin := range []string{"unshare", "newuidmap", "newgidmap"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("makeForeignOwnedDirEngine needs %s on PATH: %v", bin, err)
		}
	}
	subStart, ok := readSubuidStartEngine(t)
	if !ok {
		t.Skip("makeForeignOwnedDirEngine needs a /etc/subuid delegation for this user; none found")
	}

	runInUsernsEngine(t, subStart, "chown -R 1:1 "+shqEngine(dir))

	// restore reverses the ownership: the same userns mapping that made it
	// foreign can put it back, because ns uid 0 is still this process's own
	// real uid in that mapping. Idempotent — calling it twice (once
	// explicitly for a test's positive control, once via the t.Cleanup
	// safety net below) just chowns an already-owned tree again.
	//
	// Restoring matters beyond tidiness: an empty foreign-owned directory
	// can still be rmdir'd by this process (that needs only write+exec on
	// the PARENT), but a NON-empty one needs to be opened first to remove
	// its children, and this process cannot open a directory it does not
	// own — exactly the property this fixture exists to exercise, and
	// exactly what would otherwise make t.TempDir()'s own cleanup fail.
	restore = func() { runInUsernsEngine(t, subStart, "chown -R 0:0 "+shqEngine(dir)) }
	t.Cleanup(func() {
		// Best-effort safety net only: if the test's OWN positive control
		// already restored ownership and went on to remove dir entirely
		// (Purge succeeding once it is no longer foreign-owned), there is
		// nothing left to chown back, and that is success, not a fixture
		// leak — do not Fatal a cleanup over a directory the test itself
		// already disposed of correctly.
		if _, err := os.Lstat(dir); os.IsNotExist(err) {
			return
		}
		restore()
	})

	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("stat after chown: %v", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("could not read the directory's owner on this platform")
	}
	if int(st.Uid) == os.Getuid() {
		t.Fatalf("makeForeignOwnedDirEngine: chown did not change ownership — %s is still "+
			"owned by this process's own uid %d", dir, os.Getuid())
	}
	return int(st.Uid), restore
}

// runInUsernsEngine runs script inside an unprivileged user namespace mapped
// ns uid/gid 0 -> this process's own real uid/gid and ns uid/gid 1 ->
// subStart (a genuinely different host uid/gid delegated to this user via
// /etc/subuid, per newuidmap(1)). It is the whole mechanism
// makeForeignOwnedDirEngine and its cleanup both drive, factored out so
// "make foreign" and "make ours again" are the same three lines run with a
// different one-line script.
func runInUsernsEngine(t *testing.T, subStart int, script string) {
	t.Helper()
	tmp := t.TempDir()
	readyFile := filepath.Join(tmp, "ready")
	mappedFile := filepath.Join(tmp, "mapped")
	realUID, realGID := os.Getuid(), os.Getgid()

	full := "set -e\n" +
		"echo $$ > " + shqEngine(readyFile) + "\n" +
		"while [ ! -f " + shqEngine(mappedFile) + " ]; do sleep 0.02; done\n" +
		script + "\n"

	cmd := exec.Command("unshare", "--user", "bash", "-c", full)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the userns helper: %v", err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if b, err := os.ReadFile(readyFile); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatalf("timed out waiting for the userns helper to report its pid; stderr: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	pidBytes, _ := os.ReadFile(readyFile)
	pid := strings.TrimSpace(string(pidBytes))

	if out, err := exec.Command("newuidmap", pid, "0", strconv.Itoa(realUID), "1", "1", strconv.Itoa(subStart), "1").CombinedOutput(); err != nil {
		cmd.Process.Kill()
		<-waitDone
		t.Skipf("newuidmap failed, no usable subuid delegation on this host: %v: %s", err, out)
	}
	if out, err := exec.Command("newgidmap", pid, "0", strconv.Itoa(realGID), "1", "1", strconv.Itoa(subStart), "1").CombinedOutput(); err != nil {
		cmd.Process.Kill()
		<-waitDone
		t.Skipf("newgidmap failed, no usable subgid delegation on this host: %v: %s", err, out)
	}
	if err := os.WriteFile(mappedFile, []byte("go"), 0o600); err != nil {
		t.Fatalf("signalling the userns helper to proceed: %v", err)
	}
	if err := <-waitDone; err != nil {
		t.Fatalf("userns helper failed: %v; stderr: %s", err, stderr.String())
	}
}

func readSubuidStartEngine(t *testing.T) (int, bool) {
	t.Helper()
	data, err := os.ReadFile("/etc/subuid")
	if err != nil {
		return 0, false
	}
	u, err := user.Current()
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) != 3 {
			continue
		}
		if parts[0] == u.Username || parts[0] == u.Uid {
			start, err := strconv.Atoi(parts[1])
			if err != nil {
				continue
			}
			return start, true
		}
	}
	return 0, false
}

func shqEngine(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
