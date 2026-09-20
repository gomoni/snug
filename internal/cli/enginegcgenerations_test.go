package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEngineGCSeesEveryGenerationOfStoreName is issue #349's cost, driven
// through engineGCCmd against a store directory holding one of each older
// name shape.
//
// internal/targetkey.Hash labels the digest, so a store is `sha256_<64 hex>`
// and a later algorithm change is a new prefix rather than a silent
// reinterpretation of 64 hex characters. The label's own cost is that `engine
// gc` can stop SEEING what snug itself once wrote: a store from before the
// label carries no store.json at all, so nothing marks it as snug's own
// unless the GC still recognises the bare, unlabelled name.
//
// THE SPLIT IS THE POINT, NOT THE TOTALS. What has to hold on every machine
// is that both older generations are COUNTED, and that --older-than reaches
// the attributed one while leaving the unattributed one alone. The fixture
// makes exactly one of each, so the counts to assert are 1 and 1 by
// construction rather than a reading off whatever a real host happens to have
// accumulated.
//
// The two shapes are the two engine.ReclaimableStoreKey still recognises
// beyond KeyForTarget's own output:
//
//   - bare 64-hex WITH a store.json whose target hashes to the LABELLED form
//     of the same digest. That is snug's own rename landing on a directory it
//     has not renamed yet — ReadBreadcrumb's `"sha256_"+key == want` arm — so
//     it is ATTRIBUTED, not a mismatch.
//   - bare 16-hex with no store.json: this generation predates store.json
//     entirely, so it is UNATTRIBUTED and --older-than must never touch it —
//     it has no last_used to compare a duration against.
//
// engine.ReclaimableStoreKey's own table test covers which names are
// accepted. This one covers what the COMMAND does with directories carrying
// them, which is the half that regressed: the rename risked the labelled
// pattern REPLACING the bare 64-hex one instead of joining it, and the
// resulting --older-than would have been a silent no-op over every store
// written before the label.
func TestEngineGCSeesEveryGenerationOfStoreName(t *testing.T) {
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	useTargetLockBase(t)

	enginesDir := filepath.Join(dataHome, "snug", "engines")

	// last_used in 2020, so any --older-than duration selects it.
	const attributedTarget = "/proj/pre-label-attributed"
	labelled, _ := buildEngineStoreFixture(t, dataHome, attributedTarget,
		time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), true)
	bare64 := strings.TrimPrefix(labelled, "sha256_")
	if bare64 == labelled {
		t.Fatalf("KeyForTarget no longer labels the digest (%q has no sha256_ prefix), so "+
			"this test's pre-label fixture is not the shape it claims to be", labelled)
	}
	if err := os.Rename(filepath.Join(enginesDir, labelled), filepath.Join(enginesDir, bare64)); err != nil {
		t.Fatal(err)
	}

	// The pre-store.json generation: a 16-hex truncation, no breadcrumb.
	const bare16 = "0123456789abcdef"
	unlabelled, _ := buildEngineStoreFixture(t, dataHome, "/proj/pre-store-json", time.Time{}, false)
	if err := os.Rename(filepath.Join(enginesDir, unlabelled), filepath.Join(enginesDir, bare16)); err != nil {
		t.Fatal(err)
	}

	var code int
	report := captureStdout(t, func() { code = engineGCCmd([]string{"--dry-run"}) })
	if code != 0 {
		t.Fatalf("`engine gc --dry-run` exited %d over two legacy-named stores:\n%s", code, report)
	}
	if !strings.Contains(report, "2 store(s)") {
		t.Errorf("gc did not see both legacy generations under engines/:\n%s", report)
	}
	if !strings.Contains(report, "1 unattributed") {
		t.Errorf("the bare 16-hex, store.json-less generation was not counted unattributed:\n%s", report)
	}
	if !strings.Contains(report, "1 attributed") {
		t.Errorf("the bare 64-hex generation, attributed through ReadBreadcrumb's rename "+
			"fallback, was not counted attributed:\n%s", report)
	}

	older := captureStdout(t, func() { code = engineGCCmd([]string{"--dry-run", "--older-than", "1s"}) })
	if code != 0 {
		t.Fatalf("`engine gc --dry-run --older-than 1s` exited %d:\n%s", code, older)
	}
	want := "would reclaim  " + bare64 + "  (target: " + attributedTarget + ")"
	if !strings.Contains(older, want) {
		t.Errorf("--older-than did not select the pre-label attributed store; wanted a line "+
			"%q in:\n%s", want, older)
	}
	if strings.Contains(older, bare16) {
		t.Errorf("--older-than selected %s, which carries no last_used to compare a duration "+
			"against:\n%s", bare16, older)
	}
}
