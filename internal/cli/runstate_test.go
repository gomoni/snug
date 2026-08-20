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
// (openTargetStateDir, since issue #123) uses to open the shared runtime
// directory it did not itself create THIS call — the uid half of "does not own" cannot be
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

// TestAttachRefusesWhenTheTargetLockIsNotHeld is §13.1 test 3, restated for
// the layout issue #123 moved to.
//
// Liveness used to be a per-run flock in each run-* directory, probed by
// runDirIsLive. It is now the PER-TARGET lock — the same file, and the same
// fact, that `snug <dir>` consults when it refuses to start a second sandbox
// (#119). That is the substantive half of the change, not a mechanical one:
// there was previously a second liveness mechanism that could in principle
// disagree with the first, and now there is one.
//
// LOCK_SH|LOCK_NB succeeding means nobody holds the exclusive lock;
// EWOULDBLOCK means a live owner does.
func TestAttachRefusesWhenTheTargetLockIsNotHeld(t *testing.T) {
	snugDir := useTargetLockBase(t)
	if err := os.MkdirAll(snugDir, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(snugDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	const target = "/some/target"

	// No lock file at all: not live. (The probe creates it — the lock file's
	// existence has never been the signal, only whether it is held.)
	held, err := targetLockIsHeld(root, snugDir, target)
	if err != nil {
		t.Fatal(err)
	}
	if held {
		t.Fatal("a target with no lock file at all read as live")
	}

	// It exists now and nothing holds it: a corpse.
	held, err = targetLockIsHeld(root, snugDir, target)
	if err != nil {
		t.Fatal(err)
	}
	if held {
		t.Fatal("an unheld lock file read as live")
	}

	// CONTROL: with the lock genuinely HELD from a separate open file
	// description (flock is scoped to the OFD, not the process — the same
	// property lockTarget relies on), the probe must report live. Without
	// this, "not live" above is equally true of a probe that can never
	// observe liveness at all.
	holder, err := os.OpenFile(filepath.Join(snugDir, targetLockName(target)), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	held, err = targetLockIsHeld(root, snugDir, target)
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("control: a genuinely held lock did not read as live")
	}
}

// TestStateFileIsWrittenSixOhOhInASevenHundredDirectory is §13.1 test 6:
// pins §6.3's mode table end to end, through the real openRuntimeDir()/
// writeRunState() path rather than by asserting a literal 0o600/0o700
// somewhere in the source — a test that reads the mode off the filesystem
// is the one thing a refactor of HOW the file is opened cannot quietly break
// without also breaking real attach.
func TestStateFileIsWrittenSixOhOhInASevenHundredDirectory(t *testing.T) {
	snugDir := useTargetLockBase(t)
	// $XDG_RUNTIME_DIR still governs the RUN directory (sockets, the run
	// lock); it deliberately no longer governs where state.json lands.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	rt, err := openRuntimeDir()
	if err != nil {
		t.Fatal(err)
	}
	runPath := rt.Path()
	defer rt.Remove()

	if fi, err := os.Stat(runPath); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("run directory mode is %#o, want 0700", fi.Mode().Perm())
	}

	const target = "/x"
	pol := &policy.Policy{
		Target: target,
		Chdir:  target,
		Env:    map[string]policy.EnvVar{},
	}
	pol.AuthorEnv("HOME", "/home/u")

	info := sandbox.RunInfo{
		InitPID: os.Getpid(), // a pid guaranteed to exist for procStartTime
		Namespaces: map[string]uint64{
			"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6,
		},
	}
	if err := writeRunState(pol, info); err != nil {
		t.Fatal(err)
	}

	if fi, err := os.Stat(snugDir); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("the shared runtime directory mode is %#o, want 0700", fi.Mode().Perm())
	}

	statePath := filepath.Join(snugDir, targetStateName(target))
	fi, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("state.json was not written to the target-keyed path %s: %v", statePath, err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("state file mode is %#o, want 0600", fi.Mode().Perm())
	}

	// The temporary the atomic rename went through must not survive.
	entries, err := os.ReadDir(snugDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("writeTargetState left its temporary %q behind", e.Name())
		}
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

// TestReadTargetStateTreatsAMissingRuntimeDirAsZeroRuns is the regression for
// issue #124, restated for the layout issue #123 moved to. The property it
// pins is the one that mattered, not the function that used to hold it: on a
// host where snug has never run, `snug attach` must report "no live run", not
// a raw stdlib path error.
//
//	snug: runtime directory: checking /run/user/1000/snug: no such file or directory
//
// "Nothing has ever run here" is the ZERO CASE, not a failure.
//
// The mechanism is worth naming because it is invisible at the call site and
// it is a whole CLASS of mistake, not one typo. The old code asked
// `os.IsNotExist(err)` about an error openExistingSubroot had wrapped with
// %w. os.IsNotExist is the pre-errors API: it inspects the concrete error
// value and does NOT unwrap, so it answered false for a perfectly ordinary
// wrapped ENOENT. errors.Is does unwrap. Every %w between a syscall and a
// predicate is a place this can happen, and it gives no compile error and no
// test failure — only a wrong answer. That is what
// TestNoProductionCodeUsesANonUnwrappingErrorPredicate exists to prevent
// coming back.
//
// The positive control is the second half and it is not optional: "returns no
// error" is also what a reader that had stopped checking anything at all would
// do. So the same call, against a runtime directory that EXISTS with the wrong
// mode, must still refuse.
func TestReadTargetStateTreatsAMissingRuntimeDirAsZeroRuns(t *testing.T) {
	t.Run("missing-snug-dir-is-zero-runs", func(t *testing.T) {
		useTargetLockBase(t) // points at a fresh dir; the snug/ subdir is NOT created
		_, live, err := readTargetState("/some/target")
		if err != nil {
			t.Errorf("readTargetState on a host where snug has never run returned an error "+
				"instead of zero runs: %v\nThat error reaches the user as a raw path error where "+
				"`snug attach` should have said no live run was found (issue #124).", err)
		}
		if live {
			t.Error("readTargetState reported a live run under a directory that does not exist")
		}
	})

	t.Run("stale-state-beside-an-unheld-lock-is-zero-runs", func(t *testing.T) {
		snugDir := useTargetLockBase(t)
		if err := os.MkdirAll(snugDir, 0o700); err != nil {
			t.Fatal(err)
		}
		const target = "/some/target"
		// A previous run's file, left behind on purpose: writeTargetState
		// never unlinks, exactly as the lock never does. The LOCK is the
		// truth, so this must read as "nothing live", not as a live run.
		if err := os.WriteFile(filepath.Join(snugDir, targetStateName(target)),
			[]byte(`{"schema":1,"target":"/some/target"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		_, live, err := readTargetState(target)
		if err != nil {
			t.Errorf("a stale state file beside an unheld lock produced an error: %v", err)
		}
		if live {
			t.Error("a state file whose run is gone read as a live run — the lock is what says " +
				"a run is alive, and nothing holds this one")
		}
	})

	t.Run("positive-control/wrong-mode-still-refused", func(t *testing.T) {
		base := t.TempDir()
		prev := canonicalRuntimeDir
		canonicalRuntimeDir = func(int) string { return base }
		t.Cleanup(func() { canonicalRuntimeDir = prev })

		// It EXISTS, and it is world-readable — the thing snug refuses to put
		// run state into.
		if err := os.Mkdir(filepath.Join(base, "snug"), 0o755); err != nil {
			t.Fatal(err)
		}

		if _, _, err := readTargetState("/some/target"); err == nil {
			t.Fatal("PRECONDITION: readTargetState accepted a runtime directory with mode 0755. " +
				"The ownership/mode guard is what makes the zero-run cases above safe to report " +
				"as empty rather than as an error — if nothing is refused any more, those " +
				"subtests pass for the wrong reason.")
		} else if !strings.Contains(err.Error(), "0700") {
			t.Errorf("the refusal does not name the mode it wants, so it does not name the fix: %v", err)
		}
	})
}

// TestRunStateIsPublishedWhereAnAttachInAnyEnvironmentLooks is the regression
// for issue #123.
//
// The run and the `snug attach` that must find it are frequently launched
// under different environments — an interactive shell has $XDG_RUNTIME_DIR,
// cron/systemd/ssh-non-login does not — and the state file used to live under
// runtimeBase(), which reads $XDG_RUNTIME_DIR then $TMPDIR. So a run published
// its state where an attach would never look, and `snug attach` silently could
// not find its own live run. This is the same root cause as #122, which was
// fixed for the target LOCK only.
//
// Written under one environment, read under another, with the writer's
// variables not merely changed but REMOVED — the cron shape, which is the one
// that bit.
func TestRunStateIsPublishedWhereAnAttachInAnyEnvironmentLooks(t *testing.T) {
	snugDir := useTargetLockBase(t)
	const target = "/some/target"

	// WRITER: $XDG_RUNTIME_DIR and $TMPDIR both set, to directories that have
	// nothing to do with where the state must land.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())

	st := runState{
		Schema: runStateSchema,
		Target: target,
		Sandbox: runStateSandbox{
			InitPID: os.Getpid(), InitStarttime: 1,
			Namespaces: map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6},
		},
	}
	if err := writeTargetState(target, st); err != nil {
		t.Fatal(err)
	}

	// The run must look live to a reader, so hold the target lock the way a
	// live run does — from a separate open file description.
	holder, err := os.OpenFile(filepath.Join(snugDir, targetLockName(target)), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}

	// READER: the cron shape — neither variable set at all.
	t.Setenv("XDG_RUNTIME_DIR", "")
	os.Unsetenv("XDG_RUNTIME_DIR")
	t.Setenv("TMPDIR", "")
	os.Unsetenv("TMPDIR")

	got, live, err := readTargetState(target)
	if err != nil {
		t.Fatalf("reading a run's state with the writer's environment removed failed: %v", err)
	}
	if !live {
		t.Fatal("a run published under $XDG_RUNTIME_DIR was invisible to a reader without it — " +
			"that is issue #123: `snug attach` cannot find its own live run")
	}
	if got.Target != target {
		t.Errorf("read back target %q, want %q", got.Target, target)
	}

	// CONTROL: the lookup is not simply answering yes. A DIFFERENT target,
	// under the identical environment, must not be found.
	if _, live, err := readTargetState("/some/other/target"); err != nil || live {
		t.Errorf("a target with no run of its own read as live (live=%v, err=%v) — the lookup "+
			"is not discriminating, so the assertion above proves nothing", live, err)
	}
}
