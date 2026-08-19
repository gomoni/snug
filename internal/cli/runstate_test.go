package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/sandbox"
)

// openTestRoot and writeTestFile are the minimal *os.Root plumbing
// readRunStateFrom needs, kept local to this file rather than reused from
// runtimedir_test.go: those tests exercise runtimeDir's OWN
// ownership/symlink refusals, and duplicating a two-line helper here is
// cheaper than coupling this file's tests to that one's fixtures.
func openTestRoot(t *testing.T, dir string) (*os.Root, error) {
	t.Helper()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return os.OpenRoot(dir)
}

func writeTestFile(root *os.Root, name string, data []byte) error {
	f, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// TestStateFileCarriesNoCommandNoArgvAndNoExecutablePath is a mechanical
// sweep over the marshalled JSON keys, not an allowlist of the ones a human
// remembers — the design's own §6.2 demands exactly this shape of test
// rather than one that lists "command" and "argv" by name and stops.
func TestStateFileCarriesNoCommandNoArgvAndNoExecutablePath(t *testing.T) {
	st := runState{
		Schema: runStateSchema,
		Target: "/home/u/proj",
		Chdir:  "/home/u/proj",
		Sandbox: runStateSandbox{
			InitPID: 123, InitStarttime: 456,
			Namespaces: map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6},
		},
		Seccomp: runStateSeccomp{State: "active", Digest: "sha256:aa"},
		Env:     [][2]string{{"HOME", "/home/u"}, {"SHELL", "/bin/bash"}},
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"command", "argv", "argv0", "exe", "executable", "cmd"}
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch vv := v.(type) {
		case map[string]any:
			for k, val := range vv {
				for _, f := range forbidden {
					if k == f {
						t.Errorf("state.json carries forbidden key %q at %s", k, path)
					}
				}
				walk(val, path+"."+k)
			}
		case []any:
			for i, val := range vv {
				walk(val, path)
				_ = i
			}
		}
	}
	walk(generic, "$")

	// The one bounded exception (§8.4): SHELL is allowed to appear as an
	// ordinary env pair, because it is data the run's OWN policy authored,
	// not a channel this file invents.
	found := false
	for _, kv := range st.Env {
		if kv[0] == "SHELL" {
			found = true
		}
	}
	if !found {
		t.Fatal("test setup is wrong: expected SHELL in Env")
	}
}

func TestReadRunStateFromRefusesUnknownSchema(t *testing.T) {
	dir := t.TempDir()
	root, err := openTestRoot(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	write := func(name string, v any) {
		data, _ := json.Marshal(v)
		if err := writeTestFile(root, name, data); err != nil {
			t.Fatal(err)
		}
	}
	write("state.json", map[string]any{"schema": 99})

	if _, err := readRunStateFrom(root); err == nil {
		t.Fatal("expected a schema mismatch to be refused")
	}
}

func TestReadRunStateFromRefusesMissingNamespace(t *testing.T) {
	dir := t.TempDir()
	root, err := openTestRoot(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	st := runState{
		Schema: runStateSchema,
		Sandbox: runStateSandbox{
			Namespaces: map[string]uint64{"mnt": 1, "pid": 2}, // missing net/ipc/uts/cgroup
		},
	}
	data, _ := json.Marshal(st)
	if err := writeTestFile(root, "state.json", data); err != nil {
		t.Fatal(err)
	}

	if _, err := readRunStateFrom(root); err == nil {
		t.Fatal("expected a missing namespace id to be refused")
	}
}

func TestReadRunStateFromAcceptsAWellFormedFile(t *testing.T) {
	dir := t.TempDir()
	root, err := openTestRoot(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	st := runState{
		Schema: runStateSchema,
		Target: "/x",
		Chdir:  "/x",
		Sandbox: runStateSandbox{
			InitPID: 1, InitStarttime: 2,
			Namespaces: map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6},
		},
		Seccomp: runStateSeccomp{State: "none"},
	}
	data, _ := json.Marshal(st)
	if err := writeTestFile(root, "state.json", data); err != nil {
		t.Fatal(err)
	}

	got, err := readRunStateFrom(root)
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if got.Target != "/x" || got.Sandbox.InitPID != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// TestFilterDigestConsistent is the shape assertion for the sha256:<hex>
// convention shared between sandbox.FilterDigest and this package's reader.
func TestFilterDigestConsistent(t *testing.T) {
	if !filterDigestConsistent("sha256:" + zeros(64)) {
		t.Fatal("expected a well-formed digest to pass")
	}
	for _, bad := range []string{"", "sha256:", "md5:" + zeros(32), "sha256:zz"} {
		if filterDigestConsistent(bad) {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}

// TestAttachRefusesAStateFileInADirectoryItDoesNotOwn is §13.1 test 2.
// openExistingSubroot is the exact check `snug attach`'s own discovery path
// (discoverLiveRuns -> readLiveRunState) uses to open a run directory it did
// not itself create THIS call — the uid half of "does not own" cannot be
// forced without root (there is no other uid this test can create a
// directory as), so this exercises the mode half, on the same
// verifyOwnedAndPrivate check TestRuntimeDirRefusesAWronglyPermissionedSharedDirectory
// already relies on for the shared "snug" directory one level up.
func TestAttachRefusesAStateFileInADirectoryItDoesNotOwn(t *testing.T) {
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	bad := "run-bad"
	if err := os.MkdirAll(filepath.Join(base, bad), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openExistingSubroot(root, base, bad); err == nil {
		t.Fatal("expected a refusal for a group/other-readable run directory")
	}

	// CONTROL: the identical shape, correctly permissioned, is accepted — so
	// the refusal above is attributable to the mode and not to some other
	// mistake in this test's setup.
	good := "run-good"
	if err := os.MkdirAll(filepath.Join(base, good), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := openExistingSubroot(root, base, good); err != nil {
		t.Fatalf("control: a correctly permissioned run directory should be accepted: %v", err)
	}
}

// TestAttachRefusesWhenTheRunLockIsNotHeld is §13.1 test 3: runDirIsLive is
// the liveness probe both discoverLiveRuns and attach's own selection path
// use to tell a live run's directory from a corpse the next run's sweep will
// remove (§6.3's own table: "the run's lock is not held" -> "this is a
// corpse"). LOCK_SH|LOCK_NB succeeding means nobody holds the exclusive lock;
// EWOULDBLOCK means a live owner does.
func TestAttachRefusesWhenTheRunLockIsNotHeld(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	// No lock file at all: not live.
	if runDirIsLive(root) {
		t.Fatal("a directory with no lock file at all read as live")
	}

	lockPath := filepath.Join(dir, "lock")
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A lock file that exists but that nothing holds: a corpse, per §6.3.
	if runDirIsLive(root) {
		t.Fatal("an unheld lock file read as live")
	}

	// CONTROL: with the lock genuinely HELD (a separate open file description
	// on the same file — flock is scoped to the OFD, not the process, exactly
	// as runLock's own doc comment relies on), the same probe must report
	// live. Without this control, "not live" above is equally true of a probe
	// that can never observe liveness at all.
	holder, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if !runDirIsLive(root) {
		t.Fatal("control: a genuinely held lock did not read as live")
	}
}

// TestStateFileIsWrittenSixOhOhInASevenHundredDirectory is §13.1 test 6:
// pins §6.3's mode table end to end, through the real runtimeDir()/
// writeRunState() path rather than by asserting a literal 0o600/0o700
// somewhere in the source — a test that reads the mode off the filesystem
// is the one thing a refactor of HOW the file is opened cannot quietly break
// without also breaking real attach.
func TestStateFileIsWrittenSixOhOhInASevenHundredDirectory(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	runPath, err := runtimeDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runPath)

	if fi, err := os.Stat(runPath); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("run directory mode is %#o, want 0700", fi.Mode().Perm())
	}

	pol := &policy.Policy{
		Target: "/x",
		Chdir:  "/x",
		Env:    map[string]policy.EnvVar{},
	}
	pol.AuthorEnv("HOME", "/home/u")

	info := sandbox.RunInfo{
		InitPID: os.Getpid(), // a pid guaranteed to exist for procStartTime
		Namespaces: map[string]uint64{
			"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6,
		},
	}
	if err := writeRunState(runPath, pol, info); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(filepath.Join(runPath, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("state.json mode is %#o, want 0600", fi.Mode().Perm())
	}
}

func zeros(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '0'
	}
	return string(b)
}

// TestSnugAuthoredEnvPairsExcludesAProfilePassedVariable is the test that
// keeps a token off disk: a profile-authored (non-VerbSnug) variable must
// never appear in state.json's env list, only names snug itself authored.
func TestSnugAuthoredEnvPairsExcludesAProfilePassedVariable(t *testing.T) {
	pol := &policy.Policy{
		Env: map[string]policy.EnvVar{},
	}
	pol.AuthorEnv("HOME", "/home/u")
	// Simulate a profile-authored variable the way the resolver would,
	// without needing a full Resolve: addEnvEntry is unexported, but a
	// profile-shaped entry has Verb != VerbSnug, and EnvValue/EnvPairs only
	// care about Present() — reach it through the public surface instead:
	// there is no public writer for a non-snug verb, which is exactly
	// invariant 2's point (a profile cannot write these names at all in the
	// wild), so this test constructs the struct directly to prove the FILTER
	// itself is verb-aware rather than name-aware.
	pol.Env["SOME_TOKEN"] = policy.EnvVar{
		Name:    "SOME_TOKEN",
		Entries: []policy.EnvEntry{{Value: "secret", Verb: policy.VerbSet, From: []string{"@some-profile"}}},
	}

	pairs := snugAuthoredEnvPairs(pol)
	for _, kv := range pairs {
		if kv[0] == "SOME_TOKEN" {
			t.Fatal("a profile-authored variable leaked into the snug-authored env record")
		}
	}
	foundHome := false
	for _, kv := range pairs {
		if kv[0] == "HOME" {
			foundHome = true
		}
	}
	if !foundHome {
		t.Fatal("expected the snug-authored HOME entry to be present")
	}
}

// TestDiscoverLiveRunsTreatsAMissingRuntimeDirAsZeroRuns is the regression for
// issue #124.
//
// `snug attach <dir>` on a host where snug has never run surfaced a raw
// stdlib path error —
//
//	snug: runtime directory: checking /run/user/1000/snug: no such file or directory
//
// — where the intended answer is the clean "no live snug run found for <dir>".
// "Nothing has ever run here" is the zero case, not a failure.
//
// The mechanism is worth naming because it is invisible at the call site and
// it is a whole CLASS of mistake, not one typo. discoverLiveRuns asked
// `os.IsNotExist(err)`, and openExistingSubroot returns
// `fmt.Errorf("checking %s: %w", full, lerr)`. os.IsNotExist is the pre-errors
// API: it inspects the concrete error value and does NOT unwrap, so it answers
// false for a perfectly ordinary wrapped ENOENT. errors.Is does unwrap. Every
// `%w` between a syscall and a predicate is a place this can happen, and it
// gives no compile error and no test failure — only a wrong answer.
//
// The positive control is the second half and it is not optional: "returns no
// error" is also what a discoverLiveRuns that had stopped checking anything at
// all would do. So the same call, against a snug directory that EXISTS with
// the wrong mode, must still refuse.
func TestDiscoverLiveRunsTreatsAMissingRuntimeDirAsZeroRuns(t *testing.T) {
	t.Run("missing-snug-dir-is-zero-runs", func(t *testing.T) {
		base := t.TempDir()
		t.Setenv("XDG_RUNTIME_DIR", base)
		// Deliberately do NOT create base/snug: this is the never-run-here host.

		runs, err := discoverLiveRuns()
		if err != nil {
			t.Errorf("discoverLiveRuns on a host where snug has never run returned an error "+
				"instead of zero runs: %v\nThat error reaches the user as a raw path error where "+
				"`snug attach` should have said no live run was found (issue #124).", err)
		}
		if len(runs) != 0 {
			t.Errorf("discoverLiveRuns invented %d run(s) under a directory that does not exist: %v",
				len(runs), runs)
		}
	})

	t.Run("positive-control/wrong-mode-still-refused", func(t *testing.T) {
		base := t.TempDir()
		t.Setenv("XDG_RUNTIME_DIR", base)
		// It EXISTS, and it is world-readable — the thing snug refuses to put
		// sockets and run state into.
		if err := os.Mkdir(filepath.Join(base, "snug"), 0o755); err != nil {
			t.Fatal(err)
		}

		_, err := discoverLiveRuns()
		if err == nil {
			t.Fatal("PRECONDITION: discoverLiveRuns accepted a snug runtime directory with mode " +
				"0755. The ownership/mode guard is what makes the zero-run case above safe to " +
				"report as empty rather than as an error — if nothing is refused any more, that " +
				"subtest passes for the wrong reason.")
		}
		if !strings.Contains(err.Error(), "0700") {
			t.Errorf("the refusal does not name the mode it wants, so it does not name the fix: %v", err)
		}
	})
}
