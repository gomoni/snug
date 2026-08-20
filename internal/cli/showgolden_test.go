package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// ── the review artifact for `snug profile show` ─────────────────────────────
//
// This is the screen a human reads to decide WHETHER to select a profile, which
// puts it upstream of every --dry-run. It had no golden, and the gap was not
// theoretical: relocating @claude's binary to policy.StagedBinDir changed this
// line
//
//	ro    {home}/.local/bin/claude          ->  {home}/.local/bin/claude:/snug/bin/claude
//
// and produced no test diff at all. By CLAUDE.md's own standard — a security
// change that produces no golden diff is probably untested — that one qualified.
//
// What the pre-existing test covered, and why it was not enough:
// TestProfileShowRendersEveryEnvironVerb calls showEnviron DIRECTLY with a
// hand-built EnvGrants. It pins five label strings and never exercises the
// header, `includes`, `ro`/`rw`/`tmpfs`, `symlink`, `optional`, the footer, or
// the `show` closure that lays any of them out.
//
// It drives the REAL command (profileCmd), not a re-implementation of its
// rendering, so the exit code and the `profile.Load()` path are covered too —
// a golden built from an extracted helper would pass while the command itself
// printed something else.

// showGolden runs `snug profile show NAME` with the host's own profile
// directories pointed at an empty temp dir, and returns what it printed.
//
// XDG_CONFIG_HOME is redirected so this cannot depend on whose machine runs it.
// The names below are all @-marked builtins, which no host file can shadow
// (profile.checkName refuses a leading @ in every file it parses), so the
// registry could gain entries from /etc/snug without changing a byte of this
// output — but the redirect is still right, because a golden whose stability
// rests on an argument rather than on a fixture is one bad edit from drifting.
func showGolden(t *testing.T, name string) (string, int) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	orig := os.Stdout
	f, err := os.CreateTemp(t.TempDir(), "show-")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = f
	code := profileCmd([]string{"show", name})
	os.Stdout = orig
	f.Close()

	b, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(b), code
}

func TestGoldenProfileShow(t *testing.T) {
	// Three profiles, chosen for the DISTINCT SHAPES they render rather than for
	// coverage of the profile list. Adding a fourth is only worth it when it
	// renders a key none of these three does.
	cases := []struct {
		name string
		why  string
	}{
		// Filesystem grants and symlinks, and the longest `ro` list snug ships:
		// the fourteen curated /etc entries that exist so `deny by default` can
		// be enumerated instead of masked.
		{"@sys", "ro/rw/tmpfs and symlink, with no environ block at all"},
		// The only builtin whose `ro` carries a host:guest pair, plus `includes`,
		// `environ.inherit` and `optional`. This is the case that changed
		// silently and is the reason the file exists.
		{"@claude", "host:guest relocation, includes, environ.inherit, optional"},
		// `include` of another builtin. Used to also carry an interim @net
		// include (guarded by the now-deleted
		// TestPodmanSocketIncludesNetAsAnInterimHonestyFix); issue #63, Tier B
		// removed it, since the engine now runs in the sandbox's own netns and
		// no longer needs @net to be honest about egress. This golden is where
		// that removal shows up as a diff.
		{"@podman-socket", "include closure, now WITHOUT the removed interim @net include"},
		// ISSUE #195. Before this pair existed, every golden here was a
		// path-only profile, so the nine missing capability rows produced no
		// diff when they were absent and would have produced none when a tenth
		// went missing. @net carries `network` and `dns`; @net-anon carries the
		// two synthetic address pairs and nothing else of its own.
		{"@net", "network and dns — the grant that read as no grant at all"},
		{"@net-anon", "the v4 and v6 synthetic address pairs, on their own"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, code := showGolden(t, tc.name)
			if code != 0 {
				t.Fatalf("`profile show %s` exited %d; a golden of a failed command "+
					"pins the failure, not the screen", tc.name, code)
			}
			// A golden that captured nothing would compare two empty files and
			// pass forever. Assert the command actually rendered before trusting
			// the comparison.
			if got == "" {
				t.Fatalf("`profile show %s` printed nothing", tc.name)
			}

			path := filepath.Join("testdata", "show."+tc.name[1:]+".txt")
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
				t.Fatalf("%v — run `go test ./internal/cli/ -run TestGoldenProfileShow -update` "+
					"to create it, then READ the diff before committing", err)
			}
			if string(want) != got {
				t.Errorf("`snug profile show %s` changed. This is the screen someone reads to "+
					"decide whether to SELECT this profile, so a diff here is a change to what "+
					"a human will believe the profile grants — read it as such rather than "+
					"regenerating.\n--- got\n%s\n--- want\n%s", tc.name, got, want)
			}
		})
	}
}

// An unknown name must be a NAMED error and a non-zero exit, not an empty
// screen. `profile show` is where someone lands after a typo, and "printed
// nothing, exited 0" would read as "this profile grants nothing" — the worst
// possible answer, because it is the one that looks like information.
func TestProfileShowRefusesAnUnknownName(t *testing.T) {
	got, code := showGolden(t, "@nosuchprofile")
	if code == 0 {
		t.Errorf("`profile show @nosuchprofile` exited 0")
	}
	if got != "" {
		t.Errorf("an unknown profile printed to stdout: %q — the diagnostic belongs on "+
			"stderr so a script reading stdout cannot mistake it for a profile", got)
	}
}
