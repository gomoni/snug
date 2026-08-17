package cli

import (
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), tc.sel, envGoldenCtx(), newEnvFakeEnv())
			if err != nil {
				t.Fatalf("Resolve(%v): %v", tc.sel, err)
			}
			got := captureFile(t, func(f *os.File) { describeTopology(f, p) })

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
