package cli

// enginegcforging_test.go is F4, the red-team round's finding on this diff:
// a leading newline in an attacker-controlled path component forges a whole
// "reclaimed >= 4.0 GB" line and an ESC erases the true one. The commit
// routed scan.ForeignPath, EngineEntry.Name and every rendered Purge error
// through visibleValue; this file drives each of those three sites through
// the real command and asserts the forged bytes never reach stdout raw.

import (
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

// TestEngineGCEscapesAForgingRuneInALeftoverName is the FIRST of F4's three
// sites and needs no privilege at all: EngineEntry.Name for a ".gc-" leftover
// is read straight off the directory listing (leftoverKey only validates the
// KEY portion before the first '-', never the pid/timestamp suffix a crash-
// interrupted phase 2 leaves after it), so a directory entry carrying a
// newline or ESC there reaches describeLeftover's first Printf unless it goes
// through visibleValue.
func TestEngineGCEscapesAForgingRuneInALeftoverName(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	useTargetLockBase(t)

	key, _ := buildEngineStoreFixture(t, dataHome, "/proj/forging-leftover", time.Now(), true)
	enginesDir := filepath.Join(dataHome, "snug", "engines")
	const forged = "FORGED-LEFTOVER-LINE"
	maliciousName := ".gc-" + key + "-\n          reclaimed  " + forged + "\x1b[2K"
	if err := os.Rename(filepath.Join(enginesDir, key), filepath.Join(enginesDir, maliciousName)); err != nil {
		t.Fatal(err)
	}

	// POSITIVE CONTROL, checked below: --dry-run so describeLeftover never
	// calls Purge, isolating this assertion to the Name-rendering site alone.
	out := captureStdout(t, func() { engineGCCmd([]string{"--dry-run"}) })
	if !strings.Contains(out, forged) {
		t.Fatalf("the fixture's forged text never reached stdout at all, so this test measures "+
			"nothing:\n%s", out)
	}
	if i := strings.IndexFunc(out, func(r rune) bool { return r != '\n' && isForgingRune(r) }); i >= 0 {
		t.Errorf("`engine gc --dry-run` printed a raw control character (%q) from a leftover's "+
			"own directory name — the exact shape a leading newline forges a whole extra line "+
			"and an ESC erases the one above it:\n%s", []rune(out[i:])[0], strings.ReplaceAll(out, "\x1b", "<ESC>"))
	}
	if !strings.Contains(out, `\n`) {
		t.Errorf("the escaped form of the newline never reached stdout — either the fixture's "+
			"name stopped reaching describeLeftover or visibleValue stopped being applied:\n%s", out)
	}
}

// TestEngineGCEscapesAForgingRuneInARenderedPurgeError and
// TestEngineGCEscapesAForgingRuneInAForeignPath are the other two sites,
// F4's second and third. Both need a REAL cross-uid entry (a foreign owner is
// what makes Purge fail at all, and what makes ScanStore set ForeignPath),
// built the same way internal/engine's own gc_test.go does — duplicated
// here, deliberately small, per that file's own note on why: test-only
// tooling, not the security check CLAUDE.md's "one rule, one author" binds.

func TestEngineGCEscapesAForgingRuneInARenderedPurgeError(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	useTargetLockBase(t)

	key, _ := buildEngineStoreFixture(t, dataHome, "/proj/forging-purge-error", time.Now(), true)
	enginesDir := filepath.Join(dataHome, "snug", "engines")

	const forged = "FORGED-PURGE-ERROR-LINE"
	maliciousName := ".gc-" + key + "-\n          reclaimed  " + forged + "\x1b[2K"
	storeDir := filepath.Join(enginesDir, key)
	maliciousDir := filepath.Join(enginesDir, maliciousName)
	if err := os.Rename(storeDir, maliciousDir); err != nil {
		t.Fatal(err)
	}

	// A foreign-owned entry directly under the leftover's own top level: its
	// non-empty-directory removal fails ENOTEMPTY, so vdir.OpenForRemoval
	// Lstats the leftover NAME ITSELF (maliciousName, via the "store"
	// argument to the top-level Purge call) and reports its ownership —
	// which is still this process's own, so instead chown the "storage"
	// subdirectory that Purge would need to descend into, to force the
	// refusal at the point where `full` already carries maliciousName as a
	// path component.
	storageDir := filepath.Join(maliciousDir, "storage")
	_, restore := makeForeignOwnedDirCLI(t, storageDir)
	t.Cleanup(restore)

	out := captureStdout(t, func() { engineGCCmd(nil) }) // bare: leftovers are retried unconditionally
	if !strings.Contains(out, forged) {
		t.Fatalf("the fixture's forged text never reached stdout at all, so this test measures "+
			"nothing:\n%s", out)
	}
	if !strings.Contains(out, "still stuck") {
		t.Fatalf("the leftover was not reported stuck at all, so the rendered-Purge-error site "+
			"was never reached:\n%s", out)
	}
	if i := strings.IndexFunc(out, func(r rune) bool { return r != '\n' && isForgingRune(r) }); i >= 0 {
		t.Errorf("`engine gc` printed a raw control character (%q) from a rendered Purge error "+
			"whose text embeds an attacker-controlled path component:\n%s",
			[]rune(out[i:])[0], strings.ReplaceAll(out, "\x1b", "<ESC>"))
	}
	if !strings.Contains(out, `\n`) {
		t.Errorf("the escaped form of the newline never reached stdout:\n%s", out)
	}
}

func TestEngineGCEscapesAForgingRuneInAForeignPath(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	useTargetLockBase(t)

	key, storageDir := buildEngineStoreFixture(t, dataHome, "/proj/forging-foreign-path", time.Now(), true)

	const forged = "FORGED-FOREIGN-PATH-LINE"
	maliciousChild := "\n          reclaimed  " + forged + "\x1b[2K"
	foreignPath := filepath.Join(storageDir, maliciousChild)
	if err := os.Mkdir(foreignPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreignPath, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, restore := makeForeignOwnedDirCLI(t, foreignPath)
	t.Cleanup(restore)

	out := captureStdout(t, func() { engineGCCmd([]string{key}) }) // named explicitly: selects it regardless of attribution
	if !strings.Contains(out, forged) {
		t.Fatalf("the fixture's forged text never reached stdout at all, so this test measures "+
			"nothing:\n%s", out)
	}
	if !strings.Contains(out, "refuse") {
		t.Fatalf("the store was not reported refused at all, so the ForeignPath-rendering site "+
			"was never reached:\n%s", out)
	}
	if i := strings.IndexFunc(out, func(r rune) bool { return r != '\n' && isForgingRune(r) }); i >= 0 {
		t.Errorf("`engine gc` printed a raw control character (%q) from scan.ForeignPath, an "+
			"attacker-controlled path component under storage/:\n%s",
			[]rune(out[i:])[0], strings.ReplaceAll(out, "\x1b", "<ESC>"))
	}
	if !strings.Contains(out, `\n`) {
		t.Errorf("the escaped form of the newline never reached stdout:\n%s", out)
	}
}

// ── makeForeignOwnedDirCLI: a REAL cross-uid directory, no root needed ──
//
// Duplicated, deliberately small, from internal/engine's identical helper
// (makeForeignOwnedDirEngine, itself already a duplicate of internal/vdir's)
// rather than shared through a new package — see that file's own comment for
// why a third copy of ~90 lines of test-only tooling is the accepted shape
// here rather than a fourth package.

func makeForeignOwnedDirCLI(t *testing.T, dir string) (foreignUID int, restore func()) {
	t.Helper()
	for _, bin := range []string{"unshare", "newuidmap", "newgidmap"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("makeForeignOwnedDirCLI needs %s on PATH: %v", bin, err)
		}
	}
	subStart, ok := readSubuidStartCLI(t)
	if !ok {
		t.Skip("makeForeignOwnedDirCLI needs a /etc/subuid delegation for this user; none found")
	}

	runInUsernsCLI(t, subStart, "chown -R 1:1 "+shqCLI(dir))

	restore = func() { runInUsernsCLI(t, subStart, "chown -R 0:0 "+shqCLI(dir)) }
	t.Cleanup(func() {
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
		t.Fatalf("makeForeignOwnedDirCLI: chown did not change ownership — %s is still owned by "+
			"this process's own uid %d", dir, os.Getuid())
	}
	return int(st.Uid), restore
}

func readSubuidStartCLI(t *testing.T) (int, bool) {
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

func shqCLI(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func runInUsernsCLI(t *testing.T, subStart int, script string) {
	t.Helper()
	tmp := t.TempDir()
	readyFile := filepath.Join(tmp, "ready")
	mappedFile := filepath.Join(tmp, "mapped")
	realUID, realGID := os.Getuid(), os.Getgid()

	full := "set -e\n" +
		"echo $$ > " + shqCLI(readyFile) + "\n" +
		"while [ ! -f " + shqCLI(mappedFile) + " ]; do sleep 0.02; done\n" +
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
		t.Skipf("this host cannot build a real cross-uid fixture — the userns chown failed: "+
			"%v; stderr: %s", err, stderr.String())
	}
}
