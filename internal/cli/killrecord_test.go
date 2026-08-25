package cli

// killrecord_test.go is issue #236's own regression suite: the ".starting"
// record (initstate.go) that closes the window between bwrap naming its init
// and state.json landing. TestGoldenInitState (initstate_test.go) already
// pins the wire shape; everything here is about what the record DOES —
// written, read, killed on, removed, and never confused with state.json.
//
// Reuses orphansweep_test.go's own fixtures (liveProcess, stateDirForTest,
// waitDead, settle, processAlive) rather than a second copy of them: the
// ".starting" record is judged by the SAME killOrphanInit as state.json, so
// its tests should look like that file's, not like a new family.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/sandbox"
)

// initStateFor is stateFor's sibling for a ".starting" record.
func initStateFor(target string, v testVictim) initState {
	return initState{
		Schema:        initStateSchema,
		Target:        target,
		InitPID:       v.pid,
		InitStarttime: v.starttime,
		Namespaces:    v.namespaces,
	}
}

// writeInitStateFile is writeState's sibling: it writes the record BYTES
// directly into dir, bypassing writeInitState's own /proc reads entirely —
// what these tests need is a record with CHOSEN identity fields (a genuine
// victim's, or a deliberately wrong one), not whatever the current process
// happens to be.
func writeInitStateFile(t *testing.T, dir, target string, st initState) {
	t.Helper()
	writeInitStateFileAtName(t, dir, initStateName(target), st)
}

// writeInitStateFileAtName is writeInitStateFile with the filename chosen by
// the caller rather than derived from st.Target — orphansweep_test.go's
// writeStateAtName, for the ".starting" shape.
func writeInitStateFileAtName(t *testing.T, dir, name string, st initState) {
	t.Helper()
	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(blob, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSweepKillsAnInitNamedOnlyByTheKillRecord is issue #236's central claim:
// a run that never reached state.json at all — killed during the mount
// settle, or during a container run's whole cold start — still left a
// ".starting" record, and the next sweep must kill the init it names and
// remove the record, with NO state.json anywhere in the directory.
func TestSweepKillsAnInitNamedOnlyByTheKillRecord(t *testing.T) {
	dir, root := stateDirForTest(t)
	victim := liveProcess(t)
	const target = "/tmp/starting-only-target"
	writeInitStateFile(t, dir, target, initStateFor(target, victim))

	sweepOrphanedSandboxesIn(root, dir)

	if !waitDead(victim.pid, 5*time.Second) {
		t.Errorf("the sweep left pid %d alive: its .starting record named an unheld target, "+
			"which is exactly the run that never reached state.json at all — issue #236's "+
			"whole point", victim.pid)
	}
	if _, err := os.Stat(filepath.Join(dir, initStateName(target))); !os.IsNotExist(err) {
		t.Errorf("the .starting record survived the sweep (err=%v)", err)
	}

	// CONTROL: no state.json was ever written for this target — a mutation
	// that made the sweep only ever look at ".json" files (deleting the
	// ".starting" dispatch branch) would leave this record untouched and
	// this assertion would catch it via the pid check above; this one
	// confirms the fixture itself never created a competing record that
	// could explain the kill some other way.
	if _, err := os.Stat(filepath.Join(dir, targetStateName(target))); !os.IsNotExist(err) {
		t.Fatalf("test fixture bug: a state.json exists for %s, so the pid's death is not "+
			"attributable to the .starting record alone", target)
	}
}

// TestTheKillRecordIsRemovedOnceStateJSONLands reproduces main.go's own
// sequence directly — writeInitState, then (once it succeeds) writeRunState,
// then removeInitState — the same three calls run() makes from OnInit and
// OnInfo. After it, exactly state.json should remain: the ".starting" record
// is spent the instant a run has a real state.json naming the same init.
func TestTheKillRecordIsRemovedOnceStateJSONLands(t *testing.T) {
	snugDir := useTargetLockBase(t)
	const target = "/some/init-lands-target"
	pid := os.Getpid() // a pid guaranteed to exist for procStartTime/procNamespaceInodes

	if err := writeInitState(target, pid); err != nil {
		t.Fatalf("writeInitState: %v", err)
	}
	if _, err := os.Stat(filepath.Join(snugDir, initStateName(target))); err != nil {
		t.Fatalf("PRECONDITION: writeInitState did not publish a .starting record: %v", err)
	}

	pol := &policy.Policy{Target: target, Chdir: target, Env: map[string]policy.EnvVar{}}
	info := sandbox.RunInfo{
		InitPID:    pid,
		Namespaces: map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6},
	}
	if err := writeRunState(pol, info); err != nil {
		t.Fatalf("writeRunState: %v", err)
	}
	if err := removeInitState(target); err != nil {
		t.Fatalf("removeInitState: %v", err)
	}

	if _, err := os.Stat(filepath.Join(snugDir, initStateName(target))); !os.IsNotExist(err) {
		t.Errorf("the .starting record survived after state.json was published and "+
			"removeInitState ran (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(snugDir, targetStateName(target))); err != nil {
		t.Errorf("state.json itself is missing after a successful writeRunState (err=%v)", err)
	}
}

// TestTheKillRecordSurvivesAFailedStateWrite is the OTHER half of main.go's
// OnInfo callback: "return"s on a failed writeRunState BEFORE calling
// removeInitState, on purpose — a SIGKILL right after a failed write must
// still leave the .starting record as the only thing naming the init.
func TestTheKillRecordSurvivesAFailedStateWrite(t *testing.T) {
	snugDir := useTargetLockBase(t)
	const target = "/some/failed-write-target"
	pid := os.Getpid()

	if err := writeInitState(target, pid); err != nil {
		t.Fatalf("writeInitState: %v", err)
	}

	// No Namespaces at all: writeRunState's own guard ("bwrap's --info-fd
	// answer did not carry a ... namespace id") refuses this, which is
	// exactly the failure main.go's OnInfo warns about and returns from
	// without calling removeInitState.
	pol := &policy.Policy{Target: target, Chdir: target, Env: map[string]policy.EnvVar{}}
	info := sandbox.RunInfo{InitPID: pid}
	if err := writeRunState(pol, info); err == nil {
		t.Fatal("PRECONDITION: writeRunState succeeded with no namespaces recorded, so this " +
			"test is not exercising the failure path it claims to")
	}
	// main.go's OnInit callback never calls removeInitState here — that is
	// the property under test, reproduced directly rather than through
	// run(), which this package cannot drive without a real sandbox.

	if _, err := os.Stat(filepath.Join(snugDir, initStateName(target))); err != nil {
		t.Errorf("the .starting record is gone even though writeRunState FAILED (err=%v) — a "+
			"SIGKILL right after this point would leave the init with no record naming it at "+
			"all, which is issue #236's own accumulation happening again", err)
	}
	if _, err := os.Stat(filepath.Join(snugDir, targetStateName(target))); !os.IsNotExist(err) {
		t.Errorf("state.json exists despite writeRunState having failed (err=%v)", err)
	}
}

// TestKillRecordAndStateFileAgreeOnTheInitIdentity is the cross-check the
// milestone names explicitly: the two records are built from DIFFERENT
// sources — writeInitState from a direct procNamespaceInodes(pid) read,
// writeRunState from whatever sandbox.RunInfo the caller hands it (bwrap's
// --info-fd answer, in production) — so agreement between them is a fact
// worth checking rather than assuming. Both are pointed at the SAME real
// pid's SAME real namespaces here, which is what production guarantees:
// namespaces do not change over a process's life, so any real run's two
// records name the identical four fields.
func TestKillRecordAndStateFileAgreeOnTheInitIdentity(t *testing.T) {
	snugDir := useTargetLockBase(t)
	const target = "/some/identity-target"
	pid := os.Getpid()

	if err := writeInitState(target, pid); err != nil {
		t.Fatalf("writeInitState: %v", err)
	}

	ns, err := procNamespaceInodes(pid)
	if err != nil {
		t.Fatalf("procNamespaceInodes: %v", err)
	}
	pol := &policy.Policy{Target: target, Chdir: target, Env: map[string]policy.EnvVar{}}
	info := sandbox.RunInfo{InitPID: pid, Namespaces: ns}
	if err := writeRunState(pol, info); err != nil {
		t.Fatalf("writeRunState: %v", err)
	}

	initBlob, err := os.ReadFile(filepath.Join(snugDir, initStateName(target)))
	if err != nil {
		t.Fatal(err)
	}
	var initSt initState
	if err := json.Unmarshal(initBlob, &initSt); err != nil {
		t.Fatal(err)
	}

	runBlob, err := os.ReadFile(filepath.Join(snugDir, targetStateName(target)))
	if err != nil {
		t.Fatal(err)
	}
	var runSt runState
	if err := json.Unmarshal(runBlob, &runSt); err != nil {
		t.Fatal(err)
	}

	if initSt.Target != runSt.Target {
		t.Errorf("target disagrees: .starting=%q state.json=%q", initSt.Target, runSt.Target)
	}
	if initSt.InitPID != runSt.Sandbox.InitPID {
		t.Errorf("init pid disagrees: .starting=%d state.json=%d", initSt.InitPID, runSt.Sandbox.InitPID)
	}
	if initSt.InitStarttime != runSt.Sandbox.InitStarttime {
		t.Errorf("start time disagrees: .starting=%d state.json=%d",
			initSt.InitStarttime, runSt.Sandbox.InitStarttime)
	}
	if len(initSt.Namespaces) != len(runStateNamespaceKinds) {
		t.Fatalf(".starting record carries %d namespace ids, want %d", len(initSt.Namespaces),
			len(runStateNamespaceKinds))
	}
	for _, k := range runStateNamespaceKinds {
		if initSt.Namespaces[k] != runSt.Sandbox.Namespaces[k] {
			t.Errorf("namespace %q disagrees: .starting=%d state.json=%d",
				k, initSt.Namespaces[k], runSt.Sandbox.Namespaces[k])
		}
	}
}

// TestSweepIgnoresTheKillRecordInTheStateJSONBranch is the naming half of
// sweepOrphanedSandboxesIn's dispatch: a ".starting" name must never satisfy
// the ".json" suffix check, structurally, so a kill record can never reach
// sweepOneOrphan (which calls decodeRunState, not decodeInitState) by
// accident.
func TestSweepIgnoresTheKillRecordInTheStateJSONBranch(t *testing.T) {
	name := initStateName("/tmp/some-init-target")
	if strings.HasSuffix(name, ".json") {
		t.Fatalf("initStateName produced %q, which sweepOrphanedSandboxesIn's \".json\" dispatch "+
			"would route to sweepOneOrphan instead of sweepOneStartingOrphan", name)
	}
	if !strings.HasSuffix(name, ".starting") {
		t.Fatalf("initStateName produced %q, want a \".starting\" suffix", name)
	}
}

// TestKillRecordIsNotReadableAsRunState is decodeRunState's own refusal of a
// ".starting" record's bytes: the shapes are different JSON documents (a
// flat five keys here, "sandbox.namespaces" nested there), so even a record
// handed to the WRONG decoder by a future bug is refused rather than
// silently misread as a live run with no recorded namespaces.
func TestKillRecordIsNotReadableAsRunState(t *testing.T) {
	st := initState{
		Schema:        initStateSchema,
		Target:        "/tmp/wrong-decoder-target",
		InitPID:       123,
		InitStarttime: 456,
		Namespaces:    map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6},
	}
	blob, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRunState(bytes.NewReader(blob)); err == nil {
		t.Fatal("decodeRunState accepted a .starting record's bytes as a valid state.json")
	}
}

// TestKillRecordCarriesNoSeccompOrEnvironment is the structural twin of
// TestGoldenInitState (initstate_test.go): that one pins the five keys
// byte-for-byte in a golden file, which a patch adding a sixth key AND
// updating the golden together would still pass. This one reflects over the
// Go type directly, so the same patch fails here regardless of whether the
// golden file was updated to match.
func TestKillRecordCarriesNoSeccompOrEnvironment(t *testing.T) {
	want := map[string]bool{
		"Schema": true, "Target": true, "InitPID": true, "InitStarttime": true, "Namespaces": true,
	}
	typ := reflect.TypeOf(initState{})
	if typ.NumField() != len(want) {
		t.Fatalf("initState has %d fields, want exactly %d — a field added here (a command, an "+
			"argv, a seccomp digest, anything else runstate.go's own abuse-sentence forbids in "+
			"this file) must fail this test even if testdata/initstate.golden.json was updated "+
			"to match it", typ.NumField(), len(want))
	}
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !want[name] {
			t.Errorf("initState carries an unexpected field %q (json tag %q)",
				name, typ.Field(i).Tag.Get("json"))
		}
	}
}

// TestSweepRefusesAKillRecordWhoseNameDoesNotHashItsTarget is
// TestSweepIgnoresAStateFileWhoseNameDoesNotMatchItsTarget's twin for the
// ".starting" record: a hand-placed file under the wrong name must not let
// its content steer a kill, or dropping one file into a directory this user
// owns becomes a way to make the next `snug` run kill an arbitrary process.
func TestSweepRefusesAKillRecordWhoseNameDoesNotHashItsTarget(t *testing.T) {
	dir, root := stateDirForTest(t)
	victim := liveProcess(t)
	st := initStateFor("/tmp/some-init-target", victim)

	// Written under a DIFFERENT target's name.
	name := initStateName("/tmp/a-completely-different-init-target")
	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(blob, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	sweepOrphanedSandboxesIn(root, dir)

	settle()
	if !processAlive(victim.pid) {
		t.Errorf("the sweep killed pid %d named by a .starting record whose name is not the "+
			"hash of the target it carries", victim.pid)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Errorf("the sweep removed a .starting record it had decided not to act on (err=%v)", err)
	}
}

// TestSweepFindsAKillRecordNamedByThePreIssue349Prefix is F2's ".starting"
// half: a kill record a PRE-#349 binary wrote is named
// "target-<bare-64-hex>.starting", and before the fix
// sweepOneStartingOrphan's own name check rejected it exactly as
// sweepOneOrphan rejected the legacy ".json" shape — an orphan init caught
// mid-mount-settle or mid-engine-cold-start by a pre-upgrade binary's crash
// would then be invisible to every later sweep, forever.
func TestSweepFindsAKillRecordNamedByThePreIssue349Prefix(t *testing.T) {
	dir, root := stateDirForTest(t)
	victim := liveProcess(t)
	const target = "/tmp/legacy-prefix-init-target"
	name := legacyTargetKeyPrefix(target) + ".starting"
	if name == initStateName(target) {
		t.Fatalf("control failed: the legacy name and the current name are identical (%q)", name)
	}
	writeInitStateFileAtName(t, dir, name, initStateFor(target, victim))

	sweepOrphanedSandboxesIn(root, dir)

	if !waitDead(victim.pid, 5*time.Second) {
		t.Errorf("the sweep left pid %d alive: its .starting record used the PRE-#349 name "+
			"%q, which initStateNameMatches must still recognise as %s's own record",
			victim.pid, name, target)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Errorf("the legacy-named .starting record survived the sweep (err=%v)", err)
	}
}

// TestSweepRefusesAKillRecordWhoseNamespacesDoNotMatch is
// TestSweepDoesNotKillAPidInForeignNamespaces's twin for the ".starting"
// record (#285): the starttime check alone only rules out pid reuse, not
// that the pid is a sandbox init at all, and a hostile or forged record must
// not turn the sweep into an arbitrary-pid kill.
func TestSweepRefusesAKillRecordWhoseNamespacesDoNotMatch(t *testing.T) {
	dir, root := stateDirForTest(t)

	// FOREIGN: correct pid, correct starttime, correct name — wrong
	// namespace inodes. A real sleep runs in the host namespaces, which
	// these small fabricated ones cannot match.
	foreign := liveProcess(t)
	const foreignTarget = "/tmp/foreign-ns-init-target"
	fSt := initStateFor(foreignTarget, foreign)
	fSt.Namespaces = map[string]uint64{"mnt": 1, "pid": 2, "net": 3, "ipc": 4, "uts": 5, "cgroup": 6}
	writeInitStateFile(t, dir, foreignTarget, fSt)

	// OWN (the control): identical in every other respect, with its real
	// namespaces, so the sweep SHOULD kill it. If this one survives too, the
	// foreign assertion below proves nothing.
	own := liveProcess(t)
	const ownTarget = "/tmp/own-ns-init-target"
	writeInitStateFile(t, dir, ownTarget, initStateFor(ownTarget, own))

	sweepOrphanedSandboxesIn(root, dir)

	if !waitDead(own.pid, 5*time.Second) {
		t.Fatalf("control: the sweep did not kill pid %d whose recorded namespaces MATCH its "+
			"real ones — the sweep is not killing anything, so the foreign-namespace assertion "+
			"below would prove nothing", own.pid)
	}
	settle()
	if !processAlive(foreign.pid) {
		t.Errorf("the sweep killed pid %d although its .starting record's namespace inodes do "+
			"not match the ones it actually runs in (#285)", foreign.pid)
	}
}

// TestNoKillRecordIsPublishedWithAZeroNamespaceID mirrors runstate.go's own
// zero refusal (writeRunState's "could not determine the ... namespace id
// (got 0)"): 0 is never a real namespace inode on any Linux kernel, so a
// record built from one is worse than no record — it would fail the sweep's
// identity check it exists to satisfy, silently, on the one run that needed
// it. writeInitState's namespaces come from a live procNamespaceInodes(pid)
// read, which can never actually produce a 0 for a real process, so the
// guard is exercised here directly against a fabricated map rather than
// through writeInitState/a real pid.
func TestNoKillRecordIsPublishedWithAZeroNamespaceID(t *testing.T) {
	nsIno := map[string]uint64{"mnt": 1, "pid": 2, "net": 0, "ipc": 4, "uts": 5, "cgroup": 6}
	if _, err := validatedInitNamespaces(nsIno); err == nil {
		t.Fatal("validatedInitNamespaces accepted a namespace id of 0")
	}

	// CONTROL: the identical map with every id nonzero must be accepted, so
	// the refusal above is attributable to the 0 alone and not to some other
	// mistake in the fixture.
	nsIno["net"] = 3
	if _, err := validatedInitNamespaces(nsIno); err != nil {
		t.Fatalf("control: validatedInitNamespaces refused an otherwise-valid map: %v", err)
	}
}

// TestNoKillRecordIsPublishedWithAMissingNamespaceKind is the "!ok" half of
// the same guard: a map missing a kind entirely (not merely zero) must be
// refused the same way.
func TestNoKillRecordIsPublishedWithAMissingNamespaceKind(t *testing.T) {
	nsIno := map[string]uint64{"mnt": 1, "pid": 2, "ipc": 4, "uts": 5, "cgroup": 6} // no "net"
	if _, err := validatedInitNamespaces(nsIno); err == nil {
		t.Fatal("validatedInitNamespaces accepted a map missing the \"net\" namespace id entirely")
	}
}
