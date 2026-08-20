package cli

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRuntimeDirRefusesAPreplantedSymlinkOnTheSharedDirectory is the guard
// issue #61 part (c) asked for, tried rather than merely asserted: something
// that got to $XDG_RUNTIME_DIR first plants a symlink at the "snug" name,
// pointing at a directory it controls, and runtimeDir must refuse to follow
// it rather than silently creating this run's sockets inside the attacker's
// directory.
//
// CONTROL: the same setup with no symlink planted must succeed, so a failure
// above is known to be the guard firing and not some unrelated brokenness in
// the environment this test built.
func TestRuntimeDirRefusesAPreplantedSymlinkOnTheSharedDirectory(t *testing.T) {
	base := t.TempDir()
	trap := filepath.Join(base, "attacker-owned")
	if err := os.MkdirAll(trap, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(trap, filepath.Join(base, "snug")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", base)

	if _, err := openRuntimeDir(); err == nil {
		t.Fatal("openRuntimeDir followed a pre-planted symlink instead of refusing it")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("openRuntimeDir refused for the wrong reason: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(trap, fmt.Sprintf("run-%d", os.Getpid()))); err == nil {
		t.Fatal("a run directory was created INSIDE the attacker's directory through the symlink")
	}

	// CONTROL: an unplanted base must succeed.
	clean := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", clean)
	rt, err := openRuntimeDir()
	if err != nil {
		t.Fatalf("control: openRuntimeDir failed on a clean base: %v", err)
	}
	dir := rt.Path()
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("control: openRuntimeDir did not create a usable directory: %s (%v)", dir, err)
	}
}

// TestRuntimeDirRefusesAPreplantedSymlinkOnTheRunSubdirectory is the same
// attack one level deeper: the shared "snug" directory is legitimate, but the
// entry this specific run would use — run-<pid> — is itself a symlink,
// planted by anything else running as this uid before this process got
// there. The run-<pid> name is a human-readable label, not a computed
// identity (see runtimeDir's doc comment on why it no longer needs to be
// anything more), so this test can just build it directly rather than
// calling back into production code to derive it.
func TestRuntimeDirRefusesAPreplantedSymlinkOnTheRunSubdirectory(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", base)

	snugDir := filepath.Join(base, "snug")
	if err := os.MkdirAll(snugDir, 0o700); err != nil {
		t.Fatal(err)
	}

	runName := fmt.Sprintf("run-%d", os.Getpid())

	trap := filepath.Join(base, "attacker-owned-run")
	if err := os.MkdirAll(trap, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(trap, filepath.Join(snugDir, runName)); err != nil {
		t.Fatal(err)
	}

	if _, err := openRuntimeDir(); err == nil {
		t.Fatal("openRuntimeDir followed a pre-planted symlink at the run-* name instead of refusing it")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("openRuntimeDir refused for the wrong reason: %v", err)
	}

	// CONTROL: remove the trap and the exact same base must now succeed.
	if err := os.Remove(filepath.Join(snugDir, runName)); err != nil {
		t.Fatal(err)
	}
	rt, err := openRuntimeDir()
	if err != nil {
		t.Fatalf("control: openRuntimeDir failed once the symlink was gone: %v", err)
	}
	dir := rt.Path()
	if filepath.Base(dir) != runName {
		t.Errorf("openRuntimeDir returned %s, want a directory named %s", dir, runName)
	}
}

// TestRuntimeDirRefusesAWronglyPermissionedSharedDirectory: a "snug"
// directory that already exists but is not private — created, for instance,
// by a version of snug that predates this guard, or by hand — must be
// refused rather than silently trusted or silently chmod'd back to 0700.
// Invariant 5: repairing it quietly would hide exactly the kind of mistake
// this check exists to catch.
func TestRuntimeDirRefusesAWronglyPermissionedSharedDirectory(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", base)

	if err := os.MkdirAll(filepath.Join(base, "snug"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := openRuntimeDir()
	if err == nil {
		t.Fatal("openRuntimeDir accepted a group/other-readable shared directory")
	}
	if !strings.Contains(err.Error(), "mode") {
		t.Errorf("openRuntimeDir refused for the wrong reason: %v", err)
	}
}

// TestRuntimeDirIsIdempotentWithinARun pins the property both call sites
// depend on (identity.go's ssh-agent proxy and container.go's engine proxy
// both call runtimeDir independently): two calls from the same process must
// land on the exact same directory, not two. It is also what proves the
// second call does NOT attempt to re-flock the lock file: flock is scoped to
// the open file description, not the process, so an unguarded second
// open+flock from this same process would contend with its own first one and
// this test would fail with an error instead of a mismatched path.
func TestRuntimeDirIsIdempotentWithinARun(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	first, err := openRuntimeDir()
	if err != nil {
		t.Fatal(err)
	}
	second, err := openRuntimeDir()
	if err != nil {
		t.Fatal(err)
	}
	if first.Path() != second.Path() {
		t.Errorf("openRuntimeDir returned two different directories in one run: %s then %s",
			first.Path(), second.Path())
	}
	// The memo hands back the SAME value, not an equal one: the flock and the
	// verified parent descriptor belong to that value, and a second
	// independent value holding a second descriptor for the same directory is
	// exactly what the memo exists to prevent (issue #103).
	if first != second {
		t.Errorf("openRuntimeDir returned two distinct values for one directory")
	}
}

// TestRuntimeDirHoldsItsLockForTheLifeOfTheProcess is the fd-lifetime
// property #85's fix depends on: runtimeDir must keep the descriptor for its
// own run's lock file open (and locked) for as long as this process runs,
// because closing it early is indistinguishable, to a later sweep, from this
// run having crashed. A second, independent attempt to lock the same file
// must fail while this process is still alive.
func TestRuntimeDirHoldsItsLockForTheLifeOfTheProcess(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	rt, err := openRuntimeDir()
	if err != nil {
		t.Fatal(err)
	}

	lockPath := filepath.Join(rt.Path(), "lock")
	f, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("opening the lock file openRuntimeDir must have created: %v", err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		t.Fatal("a second, independent flock on runtimeDir's own lock file succeeded — " +
			"openRuntimeDir released or never took its own lock")
	}
}

// TestSweepStaleRunDirsDistinguishesDeadFromMidCreationFromLive is #85's
// regression test at the unit level, rebuilt around the lock mechanism: a
// directory whose lock nobody holds must go, a directory with NO lock file
// at all must be left alone (it may be mid-creation), and a directory whose
// lock is held by a genuinely live process must survive.
//
// There used to be a fourth case here — a directory naming a pid that has
// been recycled by an unrelated process — because the previous
// implementation told a live run apart from a dead one by parsing
// /proc/<pid>/stat and comparing start times. flock replaces that reasoning
// rather than adding to it: the lock says nothing about WHICH process holds
// it, only whether one still does, so pid reuse is no longer a case this
// function has to reason about at all.
//
// The live case is the positive control: without it, "the stale ones are
// gone" would pass just as well on a sweep that deletes everything. It is
// built the same way #85's original test built a real live process, except
// the flock is taken in this test process and handed to the child through
// cmd.ExtraFiles — an flock belongs to the open file description, not the
// process that created it, so the child holding the inherited descriptor
// open is what keeps the lock alive, exactly as a real snug process holding
// its own lock open would.
func TestSweepStaleRunDirsDistinguishesDeadFromMidCreationFromLive(t *testing.T) {
	snugDir := t.TempDir()

	// DEAD: a lock file nobody holds — the shape a SIGKILLed run leaves
	// behind. The process that took this lock is gone, and the kernel
	// released the flock along with everything else it held.
	dead := "run-dead"
	if err := os.MkdirAll(filepath.Join(snugDir, dead), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snugDir, dead, "lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// MID-CREATION: a directory with no lock file at all. Must be left
	// alone: it may be a run that has not reached the point of taking its
	// lock yet, and being conservative here costs one stale directory
	// rather than a live run's sockets.
	midCreation := "run-mid-creation"
	if err := os.MkdirAll(filepath.Join(snugDir, midCreation), 0o700); err != nil {
		t.Fatal(err)
	}

	// LIVE: a lock file held by a real, still-running process — the
	// positive control.
	live := "run-live"
	if err := os.MkdirAll(filepath.Join(snugDir, live), 0o700); err != nil {
		t.Fatal(err)
	}
	lockFile, err := os.OpenFile(filepath.Join(snugDir, live, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("locking the control lock file: %v", err)
	}
	// Never killed by name: this exact pid only, in a cleanup this test
	// arms below.
	cmd := exec.Command("sleep", "30")
	cmd.ExtraFiles = []*os.File{lockFile}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the positive control process: %v", err)
	}
	lockFile.Close() // the child's inherited copy is what must keep it locked now

	killed := false
	killAndWait := func() {
		if killed {
			return
		}
		killed = true
		cmd.Process.Kill()
		cmd.Wait()
	}
	t.Cleanup(killAndWait)

	root, err := os.OpenRoot(snugDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	sweepStaleRunDirs(root, snugDir)

	if _, err := os.Stat(filepath.Join(snugDir, dead)); !os.IsNotExist(err) {
		t.Errorf("a directory whose lock nobody held (dead) survived the sweep: %v", err)
	}
	if _, err := os.Stat(filepath.Join(snugDir, midCreation)); err != nil {
		t.Errorf("a directory with NO lock file (mid-creation) was swept; it should have been left alone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(snugDir, live)); err != nil {
		t.Errorf("the LIVE process's directory was removed (it must survive): %v", err)
	}

	// Kill the control process and sweep again: the live directory must now
	// go too, which is what proves its earlier survival was really about the
	// lock and not some unrelated reason sweepStaleRunDirs happened to skip
	// it.
	killAndWait()
	sweepStaleRunDirs(root, snugDir)
	if _, err := os.Stat(filepath.Join(snugDir, live)); !os.IsNotExist(err) {
		t.Errorf("the now-dead control process's directory survived a second sweep: %v", err)
	}
}

// TestRuntimeDirSweepsOnStartup pins #85's fix at the level runtimeDir
// itself is called: a stale directory left by an earlier, now-dead
// invocation — a lock file nobody holds, alongside a dead socket — is gone
// after the very next call, with no separate janitor command to remember to
// run.
func TestRuntimeDirSweepsOnStartup(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", base)

	snugDir := filepath.Join(base, "snug")
	stale := "run-1999999998"
	staleDir := filepath.Join(snugDir, stale)
	if err := os.MkdirAll(staleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The lock file left behind by a run that never got the chance to
	// release it cleanly — nobody holds it, which is exactly what tells the
	// sweep it is safe to remove.
	if err := os.WriteFile(filepath.Join(staleDir, "lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A dead ssh-agent.sock in it, the shape #85 measured: an inode with no
	// listener behind it, not merely an empty directory.
	if err := os.WriteFile(filepath.Join(staleDir, "ssh-agent.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := openRuntimeDir(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(staleDir); !os.IsNotExist(err) {
		t.Errorf("a stale run-* directory from an earlier, dead invocation survived a later runtimeDir() call: %v", err)
	}
}

// TestStillLinkedDetectsAConcurrentSweepUnlinkingOurLockFile is
// lockRunDir's guard against the race a maintainer review of this file
// found: a DIFFERENT snug process's sweepStaleRunDirs can land between this
// process's OpenFile and Flock of its own run's lock file, see it present
// but not yet held — indistinguishable, from the sweep's side, from "the
// owner died holding it" — and RemoveAll the whole run directory. flock on
// an already-unlinked descriptor still succeeds, so the lock alone cannot
// tell the two apart; stillLinked (Nlink on the open descriptor) is what
// can, and this test proves it does rather than hitting the race, which is
// not deterministic: create the file, open it, remove the directory holding
// it, and check the helper reports it gone.
//
// CONTROL: the same descriptor while the directory is still in place must
// report present — without this half, a stillLinked that always returned
// false (or always true) would also make the assertion below pass.
func TestStillLinkedDetectsAConcurrentSweepUnlinkingOurLockFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// CONTROL: still in place.
	if linked, err := stillLinked(f); err != nil {
		t.Fatalf("stillLinked (control): %v", err)
	} else if !linked {
		t.Fatal("control: stillLinked reported an in-place file as gone")
	}

	// The shape a concurrent sweep's RemoveAll produces: the whole directory
	// this descriptor's file lived in is removed while the descriptor stays
	// open.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}

	if linked, err := stillLinked(f); err != nil {
		t.Fatalf("stillLinked (after removal): %v", err)
	} else if linked {
		t.Fatal("stillLinked reported a removed file as still present")
	}
}

// TestRuntimeDirSocketRefusesAnythingThatIsNotASingleName pins the guard the
// TYPE carries and a string could not (issue #103): the old call sites said
// filepath.Join(dir, "podman.sock"), which is an operation anyone can perform
// on any string, with any second argument. "What may be created in here" is
// now a method on the value that owns the directory, and it answers for what
// it is given.
func TestRuntimeDirSocketRefusesAnythingThatIsNotASingleName(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	rt, err := openRuntimeDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", ".", "..", "../escape.sock", "sub/dir.sock", "/abs.sock"} {
		if got, err := rt.Socket(name); err == nil {
			t.Errorf("Socket(%q) returned %q instead of refusing", name, got)
		}
	}
	// POSITIVE CONTROL: the ordinary case still works, and lands INSIDE this
	// run's own directory rather than anywhere else.
	got, err := rt.Socket("podman.sock")
	if err != nil {
		t.Fatalf("Socket refused an ordinary socket name: %v", err)
	}
	if want := filepath.Join(rt.Path(), "podman.sock"); got != want {
		t.Errorf("Socket = %q, want %q", got, want)
	}
}

// TestRuntimeDirRemoveTakesTheDirectoryAway is the other end of the value's
// life. main.go used to call os.RemoveAll on the returned string, which walks
// the whole path by name again at the end of the run; Remove goes through the
// parent descriptor this value has held open since the checks passed.
func TestRuntimeDirRemoveTakesTheDirectoryAway(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	rt, err := openRuntimeDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rt.Path()); err != nil {
		t.Fatalf("PRECONDITION: the run directory was not created: %v", err)
	}
	if err := rt.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(rt.Path()); !os.IsNotExist(err) {
		t.Errorf("the run directory survived Remove (err=%v)", err)
	}
}

// TestRuntimeDirRemoveGoesThroughTheDescriptorNotThePath is the test that can
// tell the two implementations apart, which the one above cannot: both
// os.RemoveAll(d.path) and snugRoot.RemoveAll(runName) leave the directory
// gone on an undisturbed filesystem.
//
// Renaming the PARENT after the value was opened separates them. A descriptor
// names an inode, so removal through it still finds this run's directory; a
// path string names a route that no longer exists, and os.RemoveAll would
// report success having removed NOTHING (RemoveAll treats a missing path as
// success), leaving the run's directory behind with its sockets in it. That
// is the re-derivation issue #103 is about, in the one place it survived
// after the checks passed.
func TestRuntimeDirRemoveGoesThroughTheDescriptorNotThePath(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", base)

	rt, err := openRuntimeDir()
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "snug-moved")
	if err := os.Rename(filepath.Join(base, "snug"), moved); err != nil {
		t.Fatal(err)
	}
	if err := rt.Remove(); err != nil {
		t.Fatalf("Remove after the parent was renamed: %v — removal is re-walking the path "+
			"instead of using the descriptor the checks left open", err)
	}
	if _, err := os.Stat(filepath.Join(moved, filepath.Base(rt.Path()))); !os.IsNotExist(err) {
		t.Errorf("the run directory survived Remove at its new location (err=%v); a path-based "+
			"removal would report success having removed nothing", err)
	}
}

// TestASocketBindsThroughAVerifiedDescriptor is the measurement issue #103
// asks for by name, and it is here rather than in a comment because a
// measurement quoted in prose is a claim nothing checks.
//
// The hypothesis: bind(2) has no *at variant, so the last step of both socket
// call sites is net.Listen("unix", <path string>) — but a path of the form
// /proc/self/fd/<fd>/<name> resolves through an ALREADY-OPEN descriptor
// rather than re-walking the name, which is the one thing the runtimeDir type
// cannot otherwise carry to the bind. It holds: the listener binds, the socket
// appears at the real path, and a peer dialling the real path connects.
//
// What it also shows is why it is not adopted yet: the listener reports the
// /proc path as its own address, a string meaningless outside this process.
// Both proxies take a path and Listen themselves today, so adopting this
// means changing their signatures to take a net.Listener — the next site.
func TestASocketBindsThroughAVerifiedDescriptor(t *testing.T) {
	dir := t.TempDir()
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	viaFD := fmt.Sprintf("/proc/self/fd/%d/x.sock", root.Fd())
	ln, err := net.Listen("unix", viaFD)
	if err != nil {
		t.Fatalf("net.Listen through /proc/self/fd: %v — the hypothesis in runtimeDir's doc "+
			"comment does not hold on this kernel and that comment must be corrected", err)
	}
	defer ln.Close()

	real := filepath.Join(dir, "x.sock")
	fi, err := os.Stat(real)
	if err != nil {
		t.Fatalf("the socket did not appear at the real path %s: %v", real, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("%s is not a socket: %v", real, fi.Mode())
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err == nil {
			c.Write([]byte("ok"))
			c.Close()
		}
	}()
	c, err := net.Dial("unix", real)
	if err != nil {
		t.Fatalf("dialling the real path: %v", err)
	}
	defer c.Close()
	b := make([]byte, 2)
	if _, err := c.Read(b); err != nil || string(b) != "ok" {
		t.Errorf("read %q, %v; want \"ok\"", b, err)
	}
	<-done

	// The caveat, asserted rather than described: the listener's address is
	// the /proc path, not the real one.
	if addr := ln.Addr().String(); addr != viaFD {
		t.Logf("listener address is %q, not the /proc path — the caveat in runtimeDir's "+
			"doc comment may no longer apply", addr)
	}
}
