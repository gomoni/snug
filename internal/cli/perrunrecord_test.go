package cli

// perrunrecord_test.go is the regression suite for the record name carrying
// its owning pid. Before it, `state.json` and the ".starting" record beside it
// were keyed by the TARGET alone, which was correct only while snug refused a
// second sandbox on one directory. Once several runs may be live on one target
// the second to publish overwrote the first's record, and the cost was not a
// stale file: the overwritten run's init was then named by nothing on the
// host, so no later sweep could ever kill it — invariant 4 ("nothing survives
// the user") failing on a sequence that needs no attacker at all.
//
// Every case here uses TWO runs on ONE target, because that is the only shape
// that can tell the two implementations apart: with one run, the target-keyed
// name and the pid-keyed name behave identically.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The publication half: two runs on one target leave two records, not one.
func TestTwoRunsOnOneTargetPublishSeparateRecords(t *testing.T) {
	snugDir := useTargetLockBase(t)
	const target = "/tmp/two-record-target"

	first := liveProcess(t)
	second := liveProcess(t)

	stA := stateFor(target, liveProcess(t))
	stA.Owner = liveOwner(first)
	if err := writeTargetState(target, stA); err != nil {
		t.Fatal(err)
	}
	stB := stateFor(target, liveProcess(t))
	stB.Owner = liveOwner(second)
	if err := writeTargetState(target, stB); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(snugDir)
	if err != nil {
		t.Fatal(err)
	}
	var records []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			records = append(records, e.Name())
		}
	}
	if len(records) != 2 {
		t.Fatalf("two runs on %s published %d records (%v), want 2: keyed by the target alone "+
			"the second run overwrites the first, and the first run's init is then named by "+
			"nothing for the sweep to find", target, len(records), records)
	}
	for _, name := range records {
		if !targetStateNameMatches(target, name) {
			t.Errorf("record %q is not recognised as %s's own, so no sweep will ever act on it",
				name, target)
		}
	}
}

// A record with no owner is refused rather than published: the name addresses
// the owning pid, so there is no name to publish it under, and a record the
// sweep's #489 gate can never confirm is one whose init can never be killed.
func TestWriteTargetStateRefusesARecordThatNamesNoOwner(t *testing.T) {
	useTargetLockBase(t)
	const target = "/tmp/ownerless-write-target"
	st := stateFor(target, liveProcess(t))
	st.Owner = stateOwner{}
	err := writeTargetState(target, st)
	if err == nil {
		t.Fatal("writeTargetState published a record naming no owning snug process")
	}
	if !strings.Contains(err.Error(), "owning snug process") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

// The invariant-4 half, and the defect the pid in the name exists to fix: run
// A is SIGKILLed while run B is live on the same target. Both runs' inits must
// still be named by a record of their own, and the sweep must kill BOTH — each
// on its own owner's liveness, which is what lets it act on one record while a
// peer on that target is live (orphansweep_test.go's held-lock case).
//
// Under the target-keyed name run B's record landed on run A's file, so this
// test finds run A's victim alive: nothing on the host names it.
func TestSweepKillsEveryOrphanedInitOnOneTarget(t *testing.T) {
	dir, root := stateDirForTest(t)
	const target = "/tmp/two-orphan-target"

	victimA := liveProcess(t)
	stA := stateFor(target, victimA)
	stA.Owner = spawnAndReap(t)
	writeState(t, dir, target, stA)

	victimB := liveProcess(t)
	stB := stateFor(target, victimB)
	stB.Owner = spawnAndReap(t)
	writeState(t, dir, target, stB)

	nameA := targetStateName(target, stA.Owner.PID)
	nameB := targetStateName(target, stB.Owner.PID)
	if nameA == nameB {
		t.Fatalf("control failed: both runs published at %q, so the fixture cannot tell one "+
			"record from two", nameA)
	}

	sweepOrphanedSandboxesIn(root, dir)

	for _, c := range []struct {
		what   string
		pid    int
		record string
	}{
		{"the run that was killed first", victimA.pid, nameA},
		{"the run that outlived it", victimB.pid, nameB},
	} {
		if !waitDead(c.pid, 5*time.Second) {
			t.Errorf("the sweep left %s's init (pid %d) alive: its record is %q, and a record "+
				"per run is the only thing that names an init a peer run's publication used to "+
				"overwrite", c.what, c.pid, c.record)
		}
		if _, err := os.Stat(filepath.Join(dir, c.record)); !os.IsNotExist(err) {
			t.Errorf("%s's record %q survived the sweep (err=%v)", c.what, c.record, err)
		}
	}
}

// The ".starting" record is the sharper case of the same defect: it exists
// precisely while a run is too young to have published anything else, so two
// runs starting on one target within the same second are exactly when one
// overwriting the other loses an init that NOTHING else names.
func TestSweepKillsEveryStartingOrphanOnOneTarget(t *testing.T) {
	dir, root := stateDirForTest(t)
	const target = "/tmp/two-starting-target"

	victimA := liveProcess(t)
	stA := initStateFor(target, victimA)
	stA.Owner = spawnAndReap(t)
	writeInitStateFileAtName(t, dir, initStateName(target, stA.Owner.PID), stA)

	victimB := liveProcess(t)
	stB := initStateFor(target, victimB)
	stB.Owner = spawnAndReap(t)
	writeInitStateFileAtName(t, dir, initStateName(target, stB.Owner.PID), stB)

	if stA.Owner.PID == stB.Owner.PID {
		t.Fatalf("control failed: both fixtures claim owner pid %d", stA.Owner.PID)
	}

	sweepOrphanedSandboxesIn(root, dir)

	if !waitDead(victimA.pid, 5*time.Second) {
		t.Errorf("the sweep left pid %d alive, the init of the first of two runs starting on "+
			"one target: its \".starting\" record is the only thing that names it", victimA.pid)
	}
	if !waitDead(victimB.pid, 5*time.Second) {
		t.Errorf("the sweep left pid %d alive, the init of the second run", victimB.pid)
	}
}

// `snug proxy` must not guess which sandbox a door is opened into. Naming the
// candidates and the flag that picks one is the whole refusal: a message that
// only says "several runs" leaves the human with no move.
func TestProxyRefusesToGuessBetweenTwoLiveRunsOnOneTarget(t *testing.T) {
	snugDir := useTargetLockBase(t)
	if err := os.MkdirAll(snugDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const target = "/tmp/two-live-proxy-target"

	ownerA := liveProcess(t)
	ownerB := liveProcess(t)
	stA := stateFor(target, liveProcess(t))
	stA.Owner = liveOwner(ownerA)
	stA.RunDir = "/run/a"
	stB := stateFor(target, liveProcess(t))
	stB.Owner = liveOwner(ownerB)
	stB.RunDir = "/run/b"
	for _, st := range []runState{stA, stB} {
		if err := writeTargetState(target, st); err != nil {
			t.Fatal(err)
		}
	}
	holdTargetLock(t, snugDir, target)

	_, err := selectLiveRun(target, 0)
	if err == nil {
		t.Fatal("selectLiveRun picked one of two live runs on its own — which sandbox a door " +
			"is opened into is a decision, and making it silently tells the human a hole was " +
			"opened somewhere it was not")
	}
	msg := err.Error()
	for _, want := range []string{"--pid", strconv.Itoa(ownerA.pid), strconv.Itoa(ownerB.pid)} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not contain %q, so it does not name every candidate and "+
				"the fix: %s", want, msg)
		}
	}

	got, err := selectLiveRun(target, ownerB.pid)
	if err != nil {
		t.Fatalf("--pid %d named a live run and was refused: %v", ownerB.pid, err)
	}
	if got.Owner.PID != ownerB.pid || got.RunDir != "/run/b" {
		t.Errorf("--pid %d selected the record owned by pid %d (run dir %q), want pid %d",
			ownerB.pid, got.Owner.PID, got.RunDir, ownerB.pid)
	}

	// A pid that names no live run refuses with the same list rather than
	// falling back to whatever else is there: a pid copied from a run that
	// has since exited must not silently open a door into a different one.
	if _, err := selectLiveRun(target, 1); err == nil {
		t.Error("--pid 1 names no live run on this target and was accepted anyway")
	} else if !strings.Contains(err.Error(), strconv.Itoa(ownerA.pid)) {
		t.Errorf("the refusal for an unknown pid does not list the runs that ARE live: %v", err)
	}
}

// One live run needs no flag: the ambiguity is what the refusal above is
// about, and a single run has none. Without this case the refusal could be
// satisfied by a `snug proxy` that never resolves anything.
func TestProxyNeedsNoPidWhenOneRunIsLive(t *testing.T) {
	snugDir := useTargetLockBase(t)
	if err := os.MkdirAll(snugDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const target = "/tmp/one-live-proxy-target"

	owner := liveProcess(t)
	st := stateFor(target, liveProcess(t))
	st.Owner = liveOwner(owner)
	st.RunDir = "/run/only"
	if err := writeTargetState(target, st); err != nil {
		t.Fatal(err)
	}
	holdTargetLock(t, snugDir, target)

	got, err := selectLiveRun(target, 0)
	if err != nil {
		t.Fatalf("selectLiveRun refused with exactly one live run on the target: %v", err)
	}
	if got.RunDir != "/run/only" {
		t.Errorf("selectLiveRun returned run dir %q, want %q", got.RunDir, "/run/only")
	}
}

// A dead peer's record must not be offered as a candidate. The target lock
// says only that SOMETHING is live here, and a run SIGKILLed beside a live one
// leaves a record on disk until some sweep reaches it — so per-record liveness
// is the owner check, the same gate the sweep's kill uses.
func TestProxyDoesNotOfferARunWhoseOwnerIsGone(t *testing.T) {
	snugDir := useTargetLockBase(t)
	if err := os.MkdirAll(snugDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const target = "/tmp/dead-peer-target"

	owner := liveProcess(t)
	live := stateFor(target, liveProcess(t))
	live.Owner = liveOwner(owner)
	live.RunDir = "/run/live"
	if err := writeTargetState(target, live); err != nil {
		t.Fatal(err)
	}
	dead := stateFor(target, liveProcess(t))
	dead.Owner = spawnAndReap(t)
	dead.RunDir = "/run/dead"
	if err := writeTargetState(target, dead); err != nil {
		t.Fatal(err)
	}
	holdTargetLock(t, snugDir, target)

	got, err := selectLiveRun(target, 0)
	if err != nil {
		t.Fatalf("with one live run and one corpse beside it, selectLiveRun refused: %v", err)
	}
	if got.RunDir != "/run/live" {
		t.Errorf("selectLiveRun chose the record with run dir %q, want %q — a record whose "+
			"owning snug is provably gone describes no sandbox to open a door into",
			got.RunDir, "/run/live")
	}
}

// The name matcher, which is what decides whether a record on disk is swept at
// all. A shape it does not claim is a record no sweep removes and an init no
// sweep kills, forever.
func TestTargetRecordNameMatchesEveryGenerationAndNothingElse(t *testing.T) {
	const target = "/tmp/name-generation-target"
	stem := targetKeyPrefix(target)
	legacy := legacyTargetKeyPrefix(target)

	accept := []struct {
		name string
		why  string
	}{
		{stem + ".4321.json", "the current name"},
		{stem + ".json", "the name written before the owning pid was in it"},
		{legacy + ".json", "the pre-#349 name, before the digest was labelled"},
		{legacy + ".4321.json", "a legacy stem this binary would never write, still claimed"},
	}
	for _, c := range accept {
		if !targetStateNameMatches(target, c.name) {
			t.Errorf("targetStateNameMatches rejected %q (%s): a record it does not claim is "+
				"an orphan init nothing will ever kill", c.name, c.why)
		}
	}

	reject := []struct {
		name string
		why  string
	}{
		{stem + ".x.json", "the pid component is not a number"},
		{stem + ".0.json", "pid 0 owns nothing"},
		{stem + ".-1.json", "a negative pid"},
		{stem + ".01.json", "a pid no strconv.Itoa would produce"},
		{stem + ".4321.4321.json", "two pid components"},
		{stem + ".4321.starting", "the \".starting\" record, which the sweep judges elsewhere"},
		{targetKeyPrefix("/tmp/another-target") + ".4321.json", "another target's record"},
	}
	for _, c := range reject {
		if targetStateNameMatches(target, c.name) {
			t.Errorf("targetStateNameMatches claimed %q as %s's record (%s)", c.name, target, c.why)
		}
	}

	if !initStateNameMatches(target, targetKeyPrefix(target)+".4321.starting") {
		t.Error("initStateNameMatches does not recognise the current \".starting\" name")
	}
	if initStateNameMatches(target, targetKeyPrefix(target)+".4321.json") {
		t.Error("initStateNameMatches claimed a state.json: the two sweep branches must stay " +
			"disjoint by filename")
	}
}

// The directory listing behind both readers: it must return this target's
// records and nothing else, whatever else is in a directory shared by every
// target this uid has ever sandboxed.
func TestTargetStateNamesInReturnsOnlyThisTargetsRecords(t *testing.T) {
	dir, root := stateDirForTest(t)
	const target = "/tmp/listing-target"

	want := map[string]bool{
		targetStateName(target, 111):      true,
		targetStateName(target, 222):      true,
		targetKeyPrefix(target) + ".json": true,
	}
	others := []string{
		targetStateName("/tmp/some-other-target", 333),
		targetLockName(target),
		initStateName(target, 111),
		targetStateName(target, 111) + ".tmp-111",
	}
	for name := range want {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range others {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := targetStateNamesIn(root, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("targetStateNamesIn returned %v, want the %d records of %s", got, len(want), target)
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("targetStateNamesIn returned %q, which is not one of %s's records", name, target)
		}
	}

}
