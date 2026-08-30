package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// The review artifact for SUPERVISOR-DESIGN.md's topology work: the
// TOPOLOGY block of --dry-run, resolved against profile.Builtins() (the REAL
// profiles), in the shape of TestGoldenEnvironment above.
//
// Three cases, one per NetMode, because Topology.Netns is derived FROM NetMode
// and this is the block that renders it. Commit A's golden had every case
// reading "netns sandbox", because deriveTopology(NetEgress, _) mapped to
// NetnsSandbox — what snug did before the stage existed. Commit B changed ONE
// line in deriveTopology, and this file's "egress" case is the golden that
// diff shows: NetEgress now needs a stage, and topology.egress.txt says so.
func TestGoldenTopology(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sel  []policy.ProfileName
	}{
		{"isolated", []policy.ProfileName{"@sys", "@cwd-rw"}},
		{"egress", []policy.ProfileName{"@sys", "@cwd-rw", "@net"}},
		// Issue #63, Tier B: a container engine needs a stage even OFFLINE —
		// the engine line group and the CAP_SYS_PTRACE/CAP_NET_ADMIN-excluding
		// bounding set only render when p.Podman != PodmanOff, so these two
		// are the only cases in this file that walk that branch at all.
		{"podman-offline", []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}},
		{"podman-egress", []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket", "@net"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), tc.sel, envGoldenCtx(), newEnvFakeEnv())
			if err != nil {
				t.Fatalf("Resolve(%v): %v", tc.sel, err)
			}
			got := captureFile(t, func(f io.Writer) { describeTopology(f, p) })

			path := filepath.Join("testdata", "topology."+tc.name+".txt")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
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
				t.Errorf("the topology block changed — this is what a human reads to learn how many\n"+
					"long-lived processes snug started and what they hold.\n--- got\n%s\n--- want\n%s",
					got, want)
			}
		})
	}
}

// TestTheSubuidLineNamesTheRightAuthorPerArm is the named regression for a
// redteam finding on the change that added this annotation: the SubuidNone
// text said "mapped by the stage itself" UNCONDITIONALLY, so the stage-less
// isolated arm claimed a process that does not exist — on the same screen
// that says "control none — there is no stage to control" four lines below.
//
// It is a separate test from TestGoldenTopology on purpose. The golden was
// regenerated WITH the wrong sentence in it, so the suite stayed green while
// the screen misstated who writes the map. A golden pins that the text did not
// change; only an assertion about the CLAIM can pin that the text is true, and
// --dry-run is the artifact whose whole value is being true (CLAUDE.md).
//
// SubuidNone covers both arms, which is why one sentence could be wrong on
// one of them: staged, P1 writes its own single-uid map through
// SysProcAttr.UidMappings; stage-less, there is no P1 and the map belongs to
// the intermediate user namespace __inpidns creates.
func TestTheSubuidLineNamesTheRightAuthorPerArm(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		sel        []policy.ProfileName
		wantStage  bool
		mustNotSay string
	}{
		{"isolated", []policy.ProfileName{"@sys", "@cwd-rw"}, false, "the stage"},
		{"egress", []policy.ProfileName{"@sys", "@cwd-rw", "@net"}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), tc.sel, envGoldenCtx(), newEnvFakeEnv())
			if err != nil {
				t.Fatalf("Resolve(%v): %v", tc.sel, err)
			}
			// PRECONDITION: both cases must really be SubuidNone, or this
			// test is asserting about the branch it does not mean to reach.
			if p.Topology.Subuid != policy.SubuidNone {
				t.Fatalf("PRECONDITION: %s resolved to Subuid %s, not none — this test only "+
					"covers the branch where both arms share one sentence", tc.name, p.Topology.Subuid)
			}
			if p.Topology.NeedsStage() != tc.wantStage {
				t.Fatalf("PRECONDITION: %s NeedsStage()=%v, want %v", tc.name, p.Topology.NeedsStage(), tc.wantStage)
			}

			got := captureFile(t, func(f io.Writer) { describeTopology(f, p) })
			line := subuidLine(t, got)

			if tc.mustNotSay != "" && strings.Contains(line, tc.mustNotSay) {
				t.Errorf("the %s arm has NO stage, but its subuid line credits one:\n  %s\n"+
					"full block:\n%s", tc.name, line, got)
			}
			if tc.wantStage && !strings.Contains(line, "the stage") {
				t.Errorf("the %s arm HAS a stage and its subuid line does not name it:\n  %s",
					tc.name, line)
			}
			// True on both arms, and the half worth stating: this is the path
			// with no setuid binary on it at all.
			for _, want := range []string{"/etc/subuid", "newuidmap", "setuid"} {
				if !strings.Contains(line, want) {
					t.Errorf("the %s arm's subuid line does not mention %q, which is what a "+
						"reader checks the \"no root, no setuid\" claim against:\n  %s",
						tc.name, want, line)
				}
			}
		})
	}
}

// subuidLine returns the "subuid" row of a TOPOLOGY block, joined with its
// continuation lines, so an assertion about the SENTENCE is not defeated by
// where the wrapping happens to fall.
func subuidLine(t *testing.T, block string) string {
	t.Helper()
	var out []string
	collecting := false
	for _, l := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(trimmed, "subuid "):
			collecting = true
			out = append(out, trimmed)
		case collecting && strings.HasPrefix(l, "                  "):
			out = append(out, trimmed)
		case collecting:
			return strings.Join(out, " ")
		}
	}
	if len(out) == 0 {
		t.Fatalf("the TOPOLOGY block has no subuid row at all:\n%s", block)
	}
	return strings.Join(out, " ")
}
