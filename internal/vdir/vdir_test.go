package vdir

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
)

// These are the checks every caller inherits, tested where they live — one
// implementation, one suite. Before #233 they were tested only through
// internal/cli's runtime directory, so the two other copies of them (the
// engine's, prepareHostTmpDir's) had no coverage at all, which is how they
// came to be missing one guard each.

func mustRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

// TestSecureSubdirRefusesAnInRootSymlink is the case os.Root does NOT cover,
// and the reason this package has an Lstat at all.
//
// os.Root's documented contract is that its methods FOLLOW symlinks as long as
// the target stays inside the root. So an ABSOLUTE symlink is refused by
// os.Root itself and tests nothing of ours — measured: with this refusal
// deleted, an absolute-symlink test still passed. A RELATIVE, in-root symlink
// is the one os.Root will happily follow, and at a name snug creates for
// itself that is one degree more permissive than any caller wants.
func TestSecureSubdirRefusesAnInRootSymlink(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "elsewhere"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(base, "mine")); err != nil {
		t.Fatal(err)
	}

	_, _, err := SecureSubdir(mustRoot(t, base), base, "mine")
	if err == nil {
		t.Fatal("SecureSubdir followed a relative in-root symlink instead of refusing it")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	// CONTROL: the same name, no symlink, must succeed.
	if err := os.Remove(filepath.Join(base, "mine")); err != nil {
		t.Fatal(err)
	}
	child, created, err := SecureSubdir(mustRoot(t, base), base, "mine")
	if err != nil {
		t.Fatalf("control: SecureSubdir refused a clean name: %v", err)
	}
	child.Close()
	if !created {
		t.Error("control: created flag is false for a directory that did not exist")
	}
}

func TestSecureSubdirRefusesAWrongMode(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "loose"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, err := SecureSubdir(mustRoot(t, base), base, "loose")
	if err == nil {
		t.Fatal("SecureSubdir accepted a group/other-readable directory")
	}
	if !strings.Contains(err.Error(), "mode") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
	// Refused, never repaired (invariant 5): a chmod here would hide whatever
	// the wrong mode already exposed.
	fi, statErr := os.Stat(filepath.Join(base, "loose"))
	if statErr != nil {
		t.Fatal(statErr)
	}
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("the directory's mode was CHANGED to %#o; snug refuses, it does not repair",
			fi.Mode().Perm())
	}
}

// TestSecureSubdirReportsReuse is the flag two callers read in opposite
// directions: internal/cli's runtime directory reuses the shared "snug"
// directory between runs by design, while the engine's run directory must
// never find one (MustCreateSubdir).
func TestSecureSubdirReportsReuse(t *testing.T) {
	base := t.TempDir()

	child, created, err := SecureSubdir(mustRoot(t, base), base, "d")
	if err != nil {
		t.Fatal(err)
	}
	child.Close()
	if !created {
		t.Fatal("first call did not report creating the directory")
	}

	child, created, err = SecureSubdir(mustRoot(t, base), base, "d")
	if err != nil {
		t.Fatalf("second call refused a directory it created itself: %v", err)
	}
	child.Close()
	if created {
		t.Error("second call reported creating a directory that already existed")
	}
}

func TestMustCreateSubdirRefusesReuse(t *testing.T) {
	base := t.TempDir()

	child, err := MustCreateSubdir(mustRoot(t, base), base, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	child.Close()

	if _, err := MustCreateSubdir(mustRoot(t, base), base, "run-1"); err == nil {
		t.Fatal("MustCreateSubdir reused an existing directory; the name is unique per run, " +
			"so an entry already at it is a leftover or something planted first")
	}
}

// TestOpenExistingSubdirCreatesNothing is the property `snug attach`'s
// discovery depends on: looking for a run must never bring a directory into
// existence.
func TestOpenExistingSubdirCreatesNothing(t *testing.T) {
	base := t.TempDir()

	if _, err := OpenExistingSubdir(mustRoot(t, base), base, "absent"); err == nil {
		t.Fatal("OpenExistingSubdir succeeded on a directory that does not exist")
	}
	if _, err := os.Lstat(filepath.Join(base, "absent")); !os.IsNotExist(err) {
		t.Errorf("OpenExistingSubdir created %s just by looking for it (err=%v)",
			filepath.Join(base, "absent"), err)
	}
}

// TestOpenForRemovalRefusesASymlink is OpenForRemoval's first of its two
// reasons to exist, kept apart from SecureSubdir: SecureSubdir Mkdirs an
// absent name, which would make `snug engine gc`'s Purge CREATE the very
// store it was asked to delete the instant it hit an already-removed
// component. OpenForRemoval must refuse a symlink exactly as hard as every
// other predicate here, AND must never bring a name it did not find into
// existence.
func TestOpenForRemovalRefusesASymlink(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "elsewhere"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(base, "mine")); err != nil {
		t.Fatal(err)
	}

	_, _, err := OpenForRemoval(mustRoot(t, base), base, "mine")
	if err == nil {
		t.Fatal("OpenForRemoval followed a relative in-root symlink instead of refusing it")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	// CONTROL: the same name, no symlink, must succeed — so the refusal above
	// is really about the symlink, not about OpenForRemoval refusing
	// everything.
	if err := os.Remove(filepath.Join(base, "mine")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "mine"), 0o700); err != nil {
		t.Fatal(err)
	}
	child, _, err := OpenForRemoval(mustRoot(t, base), base, "mine")
	if err != nil {
		t.Fatalf("control: OpenForRemoval refused a clean directory: %v", err)
	}
	child.Close()

	// The other half of "must not be SecureSubdir": a name that is not there
	// at all is refused, not created. A GC walk that Mkdir'd an absent name
	// on its way to removing it would leave a fresh empty directory exactly
	// where the store it meant to delete used to be.
	if _, _, err := OpenForRemoval(mustRoot(t, base), base, "absent"); err == nil {
		t.Fatal("OpenForRemoval succeeded on a name that does not exist")
	}
	if _, err := os.Lstat(filepath.Join(base, "absent")); !os.IsNotExist(err) {
		t.Errorf("OpenForRemoval CREATED %s while failing to open it — a GC walk must never "+
			"bring into existence the very thing it was asked to remove (err=%v)",
			filepath.Join(base, "absent"), err)
	}
}

// TestOpenForRemovalReportsModeWithoutRequiring0700 is OpenForRemoval's
// second reason to exist, kept apart from OpenExistingSubdir:
// OpenExistingSubdir (via VerifyOwnedAndPrivate) requires a directory's mode
// to be EXACTLY 0700, which would make a store at any other mode
// unreclaimable forever — precisely the overlayfs work/work shape
// (internal/engine's Purge) that `snug engine gc` exists to clean up.
// OpenForRemoval must open a directory at an odd mode it still owns and
// report that mode back rather than refusing it.
func TestOpenForRemovalReportsModeWithoutRequiring0700(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "odd"), 0o755); err != nil {
		t.Fatal(err)
	}

	child, mode, err := OpenForRemoval(mustRoot(t, base), base, "odd")
	if err != nil {
		t.Fatalf("OpenForRemoval refused an owned directory at mode 0755: %v", err)
	}
	child.Close()
	if mode != 0o755 {
		t.Errorf("OpenForRemoval reported mode %#o, want 0755 — it must report the mode it "+
			"found, not silently normalise it", mode)
	}

	// CONTROL: the SAME directory, at the SAME mode, is refused by
	// OpenExistingSubdir — proving OpenForRemoval's acceptance above is a
	// real relaxation and not evidence that 0755 was fine all along.
	if _, err := OpenExistingSubdir(mustRoot(t, base), base, "odd"); err == nil {
		t.Fatal("control: OpenExistingSubdir accepted a 0755 directory — if this predicate " +
			"stopped requiring exactly 0700, OpenForRemoval's own relaxation would no longer " +
			"be tested by this file")
	}
}

// TestOpenForRemovalRefusesAForeignOwnedDirectory is Purge's pre-flight
// refusal, measured rather than reasoned: a REAL directory owned by a
// different host uid, produced the same way a container image's own
// foreign-uid layer content lands on disk under this process's delegated
// subuid range (internal/stage/subuid.go: ns uid 0 -> this process's own
// uid, ns uid 1 -> host uid+1, taken from /etc/subuid). Building it for real
// — via an unprivileged user namespace and newuidmap/newgidmap, the same
// mechanism rootless podman itself uses — is what lets this test assert
// OpenForRemoval's ownership branch on genuine cross-uid content rather than
// a fabricated stat result.
//
// Skips (with a stated reason) when the host cannot supply the mechanism:
// unshare/newuidmap/newgidmap missing, or no /etc/subuid delegation for this
// user. That is a property of the HOST, not of vdir, and is not silently
// downgraded to a fabricated stat — see this file's other tests for the
// predicate's ordinary behaviour, which is fully covered without this one.
func TestOpenForRemovalRefusesAForeignOwnedDirectory(t *testing.T) {
	base := t.TempDir()
	victim := filepath.Join(base, "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}

	foreignUID := makeForeignOwnedDir(t, victim)

	_, _, err := OpenForRemoval(mustRoot(t, base), base, "victim")
	var foreign *ForeignOwnerError
	if err == nil {
		t.Fatal("OpenForRemoval opened a directory owned by a different uid")
	}
	if !errors.As(err, &foreign) {
		t.Fatalf("refused for the wrong reason (want *ForeignOwnerError): %v", err)
	}
	if foreign.UID != foreignUID {
		t.Errorf("ForeignOwnerError named uid %d, want the real foreign owner %d",
			foreign.UID, foreignUID)
	}

	// CONTROL: an OWNED sibling directory, built the same way modulo the
	// chown, is accepted — so the refusal above is really about ownership,
	// not about every directory under this userns dance failing somehow.
	owned := filepath.Join(base, "owned")
	if err := os.Mkdir(owned, 0o700); err != nil {
		t.Fatal(err)
	}
	child, _, err := OpenForRemoval(mustRoot(t, base), base, "owned")
	if err != nil {
		t.Fatalf("control: OpenForRemoval refused a directory this process owns: %v", err)
	}
	child.Close()
}

// makeForeignOwnedDir re-chowns the already-created directory dir to a REAL,
// different host uid, using an unprivileged user namespace with a delegated
// subuid range — the same mechanism rootless podman itself relies on to give
// a container image's own uid-1..N content a real (if unusual) host owner.
// It returns the foreign uid the directory now carries.
//
// It t.Skips, naming the reason, when the host cannot supply the mechanism
// (unshare/newuidmap/newgidmap absent, or no /etc/subuid delegation for this
// user) — never falls back to fabricating a stat result, so a green run of
// this test is always evidence about a REAL cross-uid directory.
func makeForeignOwnedDir(t *testing.T, dir string) (foreignUID int) {
	t.Helper()
	for _, bin := range []string{"unshare", "newuidmap", "newgidmap"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("makeForeignOwnedDir needs %s on PATH: %v", bin, err)
		}
	}
	subStart, ok := readSubuidStart(t)
	if !ok {
		t.Skip("makeForeignOwnedDir needs a /etc/subuid delegation for this user; none found")
	}

	tmp := t.TempDir()
	readyFile := filepath.Join(tmp, "ready")
	mappedFile := filepath.Join(tmp, "mapped")
	realUID, realGID := os.Getuid(), os.Getgid()

	script := "set -e\n" +
		"echo $$ > " + shq(readyFile) + "\n" +
		"while [ ! -f " + shq(mappedFile) + " ]; do sleep 0.02; done\n" +
		"chown 1:1 " + shq(dir) + "\n"

	cmd := exec.Command("unshare", "--user", "bash", "-c", script)
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
	pid := strings.TrimSpace(mustReadFile(t, readyFile))

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
		// SKIP, not Fatal: the chown IS the mechanism, so its failure means
		// this host cannot supply the fixture — same class as a missing
		// newuidmap, and it must be reported the same way. CI proved the
		// distinction matters: four preconditions were guarded with t.Skip
		// (the three binaries, the /etc/subuid delegation, newuidmap and
		// newgidmap succeeding), all four passed on a GitHub runner, and the
		// FIFTH step — the chown itself — was fatal, so the suite went red on
		// a host that simply cannot do this. A guard list is a catalogue of
		// known-bad conditions and the thing that fails is the one not on the
		// list; making the OUTCOME the guard removes the list.
		//
		// The real stderr goes in the skip reason: "cannot chown" without the
		// kernel's own words is the unfalsifiable skip this project treats as
		// worse than no test.
		//
		// What stays FATAL is the chown claiming success and changing nothing
		// (checked by the caller): that is a mechanism that LIED, producing a
		// fabricated fixture, which is worse than an absent one.
		t.Skipf("this host cannot build a real cross-uid fixture — the userns chown failed: "+
			"%v; stderr: %s", err, stderr.String())
	}

	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("stat after chown: %v", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("could not read the directory's owner on this platform")
	}
	if int(st.Uid) == realUID {
		t.Fatalf("makeForeignOwnedDir: chown did not change ownership — %s is still owned by "+
			"this process's own uid %d", dir, realUID)
	}
	return int(st.Uid)
}

// readSubuidStart reads /etc/subuid for the current user's delegated range,
// returning its start uid.
func readSubuidStart(t *testing.T) (int, bool) {
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

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// shq single-quotes a path for embedding in the tiny bash script above. Test
// fixtures only, never a value an attacker controls.
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// TestOpenForRemovalRefusesARootOwnedDirectory is the ownership branch with a
// REAL cross-uid stat and NO privileges: /usr is owned by uid 0 on every Linux
// host, and this process is not uid 0.
//
// It exists because its userns sibling below CANNOT run everywhere, and the
// ownership branch had no unprivileged coverage at all until this test — which
// is exactly how CI went red on a branch whose `make gate` was green locally.
// The two tests are deliberately not one:
//
//   - THIS one always runs, in CI included, and proves the predicate refuses a
//     directory this process does not own and names the owning uid.
//   - the userns one proves the same branch fires on genuinely DELEGATED
//     subuid-range content, the way a container image's foreign layer actually
//     lands. That is host-specific by nature, so it may skip.
//
// One test that skips-or-explodes was the wrong shape. A skip must never be
// the only coverage of a branch.
func TestOpenForRemovalRefusesARootOwnedDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as uid 0, so /usr is not foreign to this process and the " +
			"ownership branch cannot be reached this way")
	}
	root := mustRoot(t, "/")
	defer root.Close()

	child, mode, err := OpenForRemoval(root, "/", "usr")
	if child != nil {
		child.Close()
	}
	if err == nil {
		t.Fatalf("OpenForRemoval accepted /usr, which uid %d does not own (mode %#o)",
			os.Getuid(), mode.Perm())
	}
	var fo *ForeignOwnerError
	if !errors.As(err, &fo) {
		t.Fatalf("OpenForRemoval refused /usr for the wrong reason — want *ForeignOwnerError "+
			"so the caller can tell EPERM territory (a foreign owner) from EACCES territory "+
			"(a mode we own and may chmod): %v", err)
	}
	if fo.UID != 0 {
		t.Errorf("ForeignOwnerError named uid %d, want 0 — /usr is root-owned", fo.UID)
	}
	// The refusal must be a decision, not a side effect: /usr is still there.
	if _, serr := os.Stat("/usr"); serr != nil {
		t.Fatalf("/usr is no longer statable after a refusal that must not have touched it: %v", serr)
	}
}
