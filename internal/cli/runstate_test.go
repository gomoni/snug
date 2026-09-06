package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/sandbox"
	"github.com/gomoni/snug/internal/vdir"
)

// TestStateFileCarriesNoCommandNoArgvNoEnvAndNoExecutablePath is a mechanical
// sweep over the marshalled JSON keys, not an allowlist of the ones a human
// remembers: a field added to runState reaches this test without anyone
// updating it.
//
// "env" and "profiles" are in the forbidden set now, and their absence is a
// stronger guarantee than the filter that used to police them. The record
// carried a snug-authored env list, and snugAuthoredEnvPairs existed to keep a
// profile-passed token out of it; the record has no env list at all now, so
// there is no filter left to get wrong. Nothing read those fields once `snug
// attach` was deleted — the two readers are the orphan sweep, which needs the
// identity chain, and `snug proxy`, which needs run_dir.
func TestStateFileCarriesNoCommandNoArgvNoEnvAndNoExecutablePath(t *testing.T) {
	st := runState{
		Schema: runStateSchema,
		Target: "/home/u/proj",
		Sandbox: runStateSandbox{
			InitPID: 123, InitStarttime: 456,
			Namespaces: map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6},
		},
		RunDir: "/run/user/1000/snug/run-123",
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"command", "argv", "argv0", "exe", "executable", "cmd", "env", "profiles"}
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

	// POSITIVE CONTROL: the sweep can see a key at all. Without it, "no
	// forbidden key was found" is equally true of a walk that visited nothing.
	if _, ok := generic["target"]; !ok {
		t.Fatal("the key sweep did not find \"target\", so it is not walking the document and " +
			"the assertions above prove nothing")
	}
}

func TestDecodeRunStateRefusesUnknownSchema(t *testing.T) {
	data, _ := json.Marshal(map[string]any{"schema": 99})
	if _, err := decodeRunState(bytes.NewReader(data)); err == nil {
		t.Fatal("expected a schema mismatch to be refused")
	}
}

// TestDecodeRunStateRefusesMissingNamespace guards the orphan sweep's own
// precondition: killOrphanInit compares all six inodes before it signals, so a
// record naming fewer must never decode into one the sweep would act on.
func TestDecodeRunStateRefusesMissingNamespace(t *testing.T) {
	st := runState{
		Schema: runStateSchema,
		Sandbox: runStateSandbox{
			Namespaces: map[string]uint64{"mnt": 1, "pid": 2}, // missing net/ipc/uts/cgroup
		},
	}
	data, _ := json.Marshal(st)
	if _, err := decodeRunState(bytes.NewReader(data)); err == nil {
		t.Fatal("expected a missing namespace id to be refused")
	}
}

func TestDecodeRunStateAcceptsAWellFormedFile(t *testing.T) {
	st := runState{
		Schema: runStateSchema,
		Target: "/x",
		Sandbox: runStateSandbox{
			InitPID: 1, InitStarttime: 2,
			Namespaces: map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6},
		},
	}
	data, _ := json.Marshal(st)

	got, err := decodeRunState(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected refusal: %v", err)
	}
	if got.Target != "/x" || got.Sandbox.InitPID != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// TestStateReaderRefusesADirectoryItDoesNotOwn covers the check
// openTargetStateDir's reading mode makes: vdir.OpenExistingSubdir is what
// opens a directory this process did not itself create on this call. The uid
// half of "does not own" cannot be forced without root (there is no other uid
// this test can create a directory as), so this exercises the mode half, on
// the same vdir.VerifyOwnedAndPrivate check
// TestRuntimeDirRefusesAWronglyPermissionedSharedDirectory already relies on
// for the shared "snug" directory one level up.
func TestStateReaderRefusesADirectoryItDoesNotOwn(t *testing.T) {
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
	if _, err := vdir.OpenExistingSubdir(root, base, bad); err == nil {
		t.Fatal("expected a refusal for a group/other-readable run directory")
	}

	// CONTROL: the identical shape, correctly permissioned, is accepted — so
	// the refusal above is attributable to the mode and not to some other
	// mistake in this test's setup.
	good := "run-good"
	if err := os.MkdirAll(filepath.Join(base, good), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := vdir.OpenExistingSubdir(root, base, good); err != nil {
		t.Fatalf("control: a correctly permissioned run directory should be accepted: %v", err)
	}
}

// TestTargetLockIsHeldSeesAShodRunAndACorpse pins the fact the orphan sweep
// acts on: "is any run live on this target".
//
// The SHARED control is the one that matters and it is why this test cannot be
// written with LOCK_EX alone. A run holds the target lock SHARED, so a probe
// that asked for LOCK_SH would succeed alongside it and answer "nobody holds
// it" — and that answer is what licenses sweepOneOrphan to SIGKILL the init the
// record names. targetLockIsHeld asks for LOCK_EX for exactly this reason, and
// the LOCK_SH holder below is what tells the two implementations apart: both
// pass against an idle target, and only the exclusive probe passes against a
// live run.
func TestTargetLockIsHeldSeesAShodRunAndACorpse(t *testing.T) {
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

	// CONTROL, in the mode a REAL run uses: LOCK_SH, from a separate open file
	// description (flock is scoped to the OFD, not the process — the same
	// property lockTarget relies on). Without this, "not live" above is
	// equally true of a probe that can never observe liveness at all.
	shared, err := os.OpenFile(filepath.Join(snugDir, targetLockName(target)), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	if err := unix.Flock(int(shared.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	held, err = targetLockIsHeld(root, snugDir, target)
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("a run holding the target lock SHARED — which is how every run holds it — did " +
			"not read as live. The sweep would then SIGKILL that run's init.")
	}

	// A SECOND shared holder, because that is the new shape: two runs on one
	// target. It must still read as live, and taking the second lock must not
	// fail either.
	second, err := os.OpenFile(filepath.Join(snugDir, targetLockName(target)), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := unix.Flock(int(second.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatalf("a second run could not take the shared target lock beside the first: %v", err)
	}
	held, err = targetLockIsHeld(root, snugDir, target)
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("two runs holding the target lock did not read as live")
	}

	// And once both let go it is a corpse again — otherwise "live" above would
	// be equally true of a probe stuck saying yes.
	unix.Flock(int(shared.Fd()), unix.LOCK_UN)
	unix.Flock(int(second.Fd()), unix.LOCK_UN)
	held, err = targetLockIsHeld(root, snugDir, target)
	if err != nil {
		t.Fatal(err)
	}
	if held {
		t.Fatal("a target whose every holder released read as live")
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
	if err := writeRunState(pol, info, ""); err != nil {
		t.Fatal(err)
	}

	if fi, err := os.Stat(snugDir); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("the shared runtime directory mode is %#o, want 0700", fi.Mode().Perm())
	}

	statePath := filepath.Join(snugDir, targetStateName(target, os.Getpid()))
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

// TestReadTargetStateTreatsAMissingRuntimeDirAsZeroRuns is the regression for
// issue #124, restated for the layout issue #123 moved to. The property it
// pins is the one that mattered, not the function that used to hold it: on a
// host where snug has never run, a reader must report "no live run", not a raw
// stdlib path error.
//
//	snug: runtime directory: checking /run/user/1000/snug: no such file or directory
//
// "Nothing has ever run here" is the ZERO CASE, not a failure.
//
// The mechanism is worth naming because it is invisible at the call site and
// it is a whole CLASS of mistake, not one typo. The old code asked
// `os.IsNotExist(err)` about an error vdir.OpenExistingSubdir had wrapped with
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
func TestLiveRunsForTreatsAMissingRuntimeDirAsZeroRuns(t *testing.T) {
	t.Run("missing-snug-dir-is-zero-runs", func(t *testing.T) {
		useTargetLockBase(t) // points at a fresh dir; the snug/ subdir is NOT created
		runs, err := liveRunsFor("/some/target")
		if err != nil {
			t.Errorf("liveRunsFor on a host where snug has never run returned an error "+
				"instead of zero runs: %v\nThat error reaches the user as a raw path error where "+
				"`snug proxy` should have said no live run was found (issue #124).", err)
		}
		if len(runs) != 0 {
			t.Errorf("liveRunsFor reported %d live runs under a directory that does not exist", len(runs))
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
		if err := os.WriteFile(filepath.Join(snugDir, targetStateName(target, os.Getpid())),
			[]byte(`{"schema":1,"target":"/some/target"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		runs, err := liveRunsFor(target)
		if err != nil {
			t.Errorf("a stale state file beside an unheld lock produced an error: %v", err)
		}
		if len(runs) != 0 {
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

		if _, err := liveRunsFor("/some/target"); err == nil {
			t.Fatal("PRECONDITION: liveRunsFor accepted a runtime directory with mode 0755. " +
				"The ownership/mode guard is what makes the zero-run cases above safe to report " +
				"as empty rather than as an error — if nothing is refused any more, those " +
				"subtests pass for the wrong reason.")
		} else if !strings.Contains(err.Error(), "0700") {
			t.Errorf("the refusal does not name the mode it wants, so it does not name the fix: %v", err)
		}
	})
}

// TestRunStateIsPublishedWhereAReaderInAnyEnvironmentLooks is the regression
// for issue #123.
//
// A run and the later process that must read its record are frequently launched
// under different environments — an interactive shell has $XDG_RUNTIME_DIR,
// cron/systemd/ssh-non-login does not — and the state file used to live under
// runtimeBase(), which reads $XDG_RUNTIME_DIR then $TMPDIR. So a run published
// its state where a reader would never look. This is the same root cause as
// #122, which was fixed for the target LOCK only. It still bites: the reader is
// the NEXT run's orphan sweep, which walks that directory looking for a
// leftover init to kill.
//
// Written under one environment, read under another, with the writer's
// variables not merely changed but REMOVED — the cron shape, which is the one
// that bit.
func TestRunStateIsPublishedWhereAReaderInAnyEnvironmentLooks(t *testing.T) {
	snugDir := useTargetLockBase(t)
	const target = "/some/target"

	// WRITER: $XDG_RUNTIME_DIR and $TMPDIR both set, to directories that have
	// nothing to do with where the state must land.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())

	owner, err := currentOwner()
	if err != nil {
		t.Fatal(err)
	}
	st := runState{
		Schema: runStateSchema,
		Target: target,
		Sandbox: runStateSandbox{
			InitPID: os.Getpid(), InitStarttime: 1,
			Namespaces: map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6},
		},
		// This test process, which is genuinely running: the record's name is
		// derived from the owner's pid, and the reader below filters out
		// records whose owner is provably gone.
		Owner: owner,
	}
	if err := writeTargetState(target, st); err != nil {
		t.Fatal(err)
	}

	// The run must look live to a reader, so hold the target lock the way a
	// live run does — SHARED, from a separate open file description.
	holder, herr := os.OpenFile(filepath.Join(snugDir, targetLockName(target)), os.O_CREATE|os.O_RDWR, 0o600)
	if herr != nil {
		t.Fatal(herr)
	}
	defer holder.Close()
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}

	// READER: the cron shape — neither variable set at all.
	t.Setenv("XDG_RUNTIME_DIR", "")
	os.Unsetenv("XDG_RUNTIME_DIR")
	t.Setenv("TMPDIR", "")
	os.Unsetenv("TMPDIR")

	runs, err := liveRunsFor(target)
	if err != nil {
		t.Fatalf("reading a run's state with the writer's environment removed failed: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("a run published under $XDG_RUNTIME_DIR was invisible to a reader without it "+
			"(%d records found) — that is issue #123: the next run's sweep cannot find this "+
			"run's record", len(runs))
	}
	if runs[0].Target != target {
		t.Errorf("read back target %q, want %q", runs[0].Target, target)
	}

	// CONTROL: the lookup is not simply answering yes. A DIFFERENT target,
	// under the identical environment, must not be found.
	if other, err := liveRunsFor("/some/other/target"); err != nil || len(other) != 0 {
		t.Errorf("a target with no run of its own read as live (%d records, err=%v) — the lookup "+
			"is not discriminating, so the assertion above proves nothing", len(other), err)
	}
}
