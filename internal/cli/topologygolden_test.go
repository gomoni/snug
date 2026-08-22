package cli

import (
	"io"
	"os"
	"path/filepath"
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
		{"host", []policy.ProfileName{"@sys", "@cwd-rw", "@net-host"}},
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
