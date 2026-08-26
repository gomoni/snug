package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestGoldenNetwork is the review artifact issue #288 was missing: before this
// file, no golden anywhere captured describeNetwork's own rendered text.
// testdata/show.net.txt golds a DIFFERENT function (config.go's
// networkConsequence, reached through `snug profile show`), and
// testdata/topology.*.txt golds describeTopology, not describeNetwork —
// dnsscreen_test.go and visible_test.go both call describeNetwork, but only
// ever assert a handful of substrings, never the whole block. So the two arms
// #288 actually rewrote (NetIsolated and NetEgress) had no golden diff to
// review the wording change against — and they are the whole set now that host
// mode is gone.
//
// Modelled on TestGoldenTopology (topologygolden_test.go): the REAL builtin
// profiles, one case per NetMode, `-update` to regenerate.
func TestGoldenNetwork(t *testing.T) {
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), tc.sel, envGoldenCtx(), newEnvFakeEnv())
			if err != nil {
				t.Fatalf("Resolve(%v): %v", tc.sel, err)
			}
			got := captureFile(t, func(f io.Writer) { describeNetwork(f, p) })

			path := filepath.Join("testdata", "network."+tc.name+".txt")
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
				t.Fatalf("%v (run: go test ./internal/cli -run TestGoldenNetwork -update, "+
					"then READ the diff: this block is what a human reads to decide whether "+
					"a sandbox can reach the network, X11, D-Bus or Wayland)", err)
			}
			if got != string(want) {
				t.Errorf("the NETWORK block changed — this is what a human reads to learn what\n"+
					"the sandbox can and cannot reach.\n--- got\n%s\n--- want\n%s", got, want)
			}
		})
	}
}
