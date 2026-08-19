package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// pastaGoldenCtx pins HostNameservers to ONE routable address so the golden
// is host-independent — this developer's real /etc/resolv.conf must never
// leak into a committed file (J.7).
func pastaGoldenCtx() policy.Context {
	ctx := envGoldenCtx()
	ctx.HostNameservers = []string{"192.168.1.1"}
	return ctx
}

// TestGoldenPastaArgv is the review artifact §H's own audit found MISSING:
// no committed golden captured the pasta argv at all (`git grep -n
// "dns-forward\|map-host-loopback" -- 'internal/cli/testdata/*'` returned
// nothing), so a change whose entire content IS a change to the pasta argv —
// exactly what issues #162 and #165 are — had no review artifact.
//
// @net is the CONTROL and must be byte-identical to what shipped before this
// milestone: no security-relevant flag may move for a fix scoped to
// @net-anon. @net-anon is the artifact a human actually reads: `-n 24` is
// gone, both prefixes are inline, one new `-a`/`-g` pair appears, and
// `--map-host-loopback none` still appears EXACTLY once.
func TestGoldenPastaArgv(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sel  []policy.ProfileName
	}{
		{"egress", []policy.ProfileName{"@sys", "@cwd-rw", "@net"}},
		{"egress-anon", []policy.ProfileName{"@sys", "@cwd-rw", "@net-anon"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), tc.sel, pastaGoldenCtx(), newEnvFakeEnv())
			if err != nil {
				t.Fatalf("Resolve(%v): %v", tc.sel, err)
			}
			// PastaTargetStage(0, 63), exactly as dryrun.go's own NetnsStage
			// arm calls it (dryrun.go:~1500) — the placeholder every real
			// --dry-run prints, not a fixture invented for this test.
			args := p.PastaArgs(policy.PastaTargetStage(0, 63))
			got := "pasta " + strings.Join(args, " ") + "\n"

			path := filepath.Join("testdata", "pasta."+tc.name+".txt")
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
				t.Errorf("the pasta argv changed — this is a change to the network security "+
					"boundary and is read as such.\n--- got\n%s--- want\n%s", got, want)
			}
		})
	}

	// CONTROL: @net's argv is BYTE-IDENTICAL before and after this milestone
	// (D.3's own claim) — asserted structurally rather than only by golden
	// diff, so a future reader does not have to open the golden to see the
	// property this test exists to pin.
	t.Run("net argv is unaffected by the v6 pair", func(t *testing.T) {
		p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
			[]policy.ProfileName{"@sys", "@cwd-rw", "@net"}, pastaGoldenCtx(), newEnvFakeEnv())
		if err != nil {
			t.Fatal(err)
		}
		args := strings.Join(p.PastaArgs(policy.PastaTargetStage(0, 63)), " ")
		for _, mustNotContain := range []string{"-a ", "-g ", "fd00:5e79"} {
			if strings.Contains(args, mustNotContain) {
				t.Errorf("@net's argv contains %q — @net copies the host's addresses and must "+
					"never carry a synthetic one: %s", mustNotContain, args)
			}
		}
	})
}
