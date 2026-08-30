package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestGoldenExplain pins the whole --explain screen, per selection.
//
// A golden on PROSE, which this repo is otherwise sceptical of — CLAUDE.md
// retired a generated user guide because "the prose churned faster than the
// code it described and nobody was going to keep it honest". The difference
// that earns this one: these sentences are not a description of the code, they
// are the code's OUTPUT, so a change to them cannot drift away from what snug
// does — it either shows up in this diff or it did not happen. That is the
// same argument the argv goldens make, and it is why the WHAT IS NOT IN HERE
// block needs it most: those five lines are claims about absences no other
// test can see, because an absence leaves no row anywhere else.
//
// Three selections, chosen for what each turns on rather than for coverage:
// the defaults are the screen most people will read, @net is the arm where the
// network section changes shape, and @podman-socket is the one with an engine
// and no network at all — the combination issue #542 records as the one people
// get wrong.
func TestGoldenExplain(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sel  []policy.ProfileName
	}{
		{"defaults", profile.BuiltinDefaults()},
		{"net", append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "@net")},
		{"podman-offline", append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "@podman-socket")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The same fake Environ the other goldens use, so nothing on this
			// screen can depend on the developer's own shell.
			env := newEnvFakeEnv()
			p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), tc.sel, envGoldenCtx(), env)
			if err != nil {
				t.Fatalf("Resolve(%v): %v", tc.sel, err)
			}
			// nil notes: a golden must not carry whatever this host happened to
			// say about its own /etc/resolv.conf or its own podman. The NOTES
			// block has its own tests in notes_test.go, where the collector is
			// built by hand and the content is the test's own.
			got := captureFile(t, func(f io.Writer) {
				if err := explain(env, f, p, p.BwrapArgs(0, 0), config{}, nil, nil); err != nil {
					t.Fatal(err)
				}
			})

			path := filepath.Join("testdata", "explain."+tc.name+".txt")
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
				t.Errorf("the --explain screen changed. It is what a human reads to learn what "+
					"they are handing over and what they are not, so read this diff as prose "+
					"rather than as a fixture update.\n--- got\n%s\n--- want\n%s", got, want)
			}
		})
	}
}
