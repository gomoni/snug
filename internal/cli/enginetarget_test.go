package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// TestTargetGraftIsRenderedInTheEngineViewBlock drives startContainers itself
// — the real Tier C call sequence installEngineViewGrafts,
// installEngineTargetGraft, engine.PlannedPaths and engine.GraftPathsInto
// make on a container run's --dry-run path — rather than calling any one of
// those in isolation. Neither engineview.enginemounts.txt nor
// engineview.planned.txt does this: both install their own slice of p.Grafts
// by hand and never exercise installEngineTargetGraft at all, so nothing
// pinned the target-graft ROW as it is actually produced by a run, only as
// EngineTargetGraft/EngineTargetForwarded answer in isolation
// (enginetarget_test.go, internal/policy).
//
// If a golden regeneration ever grows an `owned:` line under the target
// graft's row, HostPathVisible disagreed with G4 about the target and the
// change is wrong (describeGrafts prints `owned:` only when
// !HostPathVisible(gr.Host, ...), and the target graft's Host is p.Target,
// which G4's own first disjunct already required visible) — that is a
// finding to report, not a golden to accept.
func TestTargetGraftIsRenderedInTheEngineViewBlock(t *testing.T) {
	// Same normalisation TestGoldenEngineViewPlannedPaths uses: the store and
	// runroot rows embed this process's own uid/pid, and startContainers
	// installs those grafts too since it drives the whole real sequence.
	t.Setenv("XDG_DATA_HOME", plannedDataHome)
	t.Setenv("TMPDIR", plannedTmpDir)

	p := engineViewPolicy(t) // @sys @cwd-rw @podman-socket, target /home/u/proj/sub
	env := newEnvFakeEnv()

	ctr, err := startContainers(env, p, nil, false, true)
	if err != nil {
		t.Fatalf("startContainers: %v", err)
	}
	defer ctr.cleanup()

	wantGuest := policy.EngineBindsDir + "/sub"
	gr, ok := p.Grafts[wantGuest]
	if !ok {
		guests := make([]string, 0, len(p.Grafts))
		for g := range p.Grafts {
			guests = append(guests, g)
		}
		t.Fatalf("startContainers recorded no graft at %s; grafts recorded: %v", wantGuest, guests)
	}
	if gr.Host != p.Target {
		t.Errorf("target graft Host = %q, want the resolved target %q", gr.Host, p.Target)
	}
	if gr.Access != policy.AccessRW {
		t.Errorf("target graft Access = %v, want AccessRW — the fixture's target is @cwd-rw", gr.Access)
	}
	if gr.Why == "" {
		t.Error("target graft has no abuse sentence")
	}

	rep := Report{TmpfsSizeBytes: p.TmpfsSizeBytes, Grafts: sortedGrafts(p)}
	rep.GraftTmpfsSizeBytes = graftTmpfsSizeBytes(rep.Grafts, rep.TmpfsSizeBytes)
	raw := captureFile(t, func(f io.Writer) { describeGrafts(f, rep, p) })

	for _, sub := range plannedIdentitySubs() {
		if !strings.Contains(raw, sub.from) {
			t.Fatalf("the rendered block contains no %q; the store/runroot rows this fixture also "+
				"installs would make the golden below unstable across machines if this substitution "+
				"stopped firing:\n%s", sub.from, raw)
		}
	}
	got := replacePlannedIdentity(raw)

	row := graftRowBlock(t, got, wantGuest)
	if !strings.Contains(row, "graft-rw") {
		t.Errorf("the target graft's row is not graft-rw:\n%s", row)
	}
	if !strings.Contains(row, "from "+p.Target) {
		t.Errorf("the target graft's row does not name its source %s:\n%s", p.Target, row)
	}
	if !strings.Contains(row, "abuse:") {
		t.Errorf("the target graft's row has no abuse sentence:\n%s", row)
	}
	if strings.Contains(row, "owned:") {
		t.Fatalf("the target graft's row carries an `owned:` line — HostPathVisible disagreed with "+
			"G4 about the target, which is a finding about the implementation, not a golden to "+
			"accept:\n%s", row)
	}

	path := filepath.Join("testdata", "engineview.targetgraft.txt")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/cli -update)", err)
	}
	if got != string(want) {
		t.Errorf("the ENGINE VIEW block, rendered from a real startContainers run, changed:\n"+
			"--- got\n%s\n--- want\n%s", got, string(want))
	}
}

// graftRowBlock returns the screen text for one graft's row: from the line
// naming guest up to (but not including) the next row's kind-column line, or
// the end of the ENGINE VIEW block. A row's kind line starts with exactly two
// spaces followed by a non-space (the "graft-rw"/"graft-ro"/... column);
// every wrapped continuation line is indented to graftIndent (12 spaces), so
// it never matches that pattern.
func graftRowBlock(t *testing.T, screen, guest string) string {
	t.Helper()
	lines := strings.Split(screen, "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "   ") && strings.Contains(l, guest) {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no row for guest %s on screen:\n%s", guest, screen)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "  ") && !strings.HasPrefix(lines[i], "   ") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}
