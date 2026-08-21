package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestGoldenContainers is the review artifact for describeContainers, which
// had none before issue #63, Tier B: a security statement with no golden is
// untested by "golden diffs are the review artifact" (CLAUDE.md). Mirrors
// TestGoldenTopology's shape.
//
// Two cases: @podman-socket offline (the closing claim of this ticket — a
// container really has no egress) and @podman-socket + @net (full egress,
// covered by the same pasta guarantees as the sandbox). PodmanOff renders
// nothing, so there is no third "no containers" case here — that emptiness
// is asserted directly in TestDescribeContainersIsSilentWhenPodmanIsOff.
func TestGoldenContainers(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		sel  []policy.ProfileName
	}{
		{"podman-offline", []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}},
		{"podman-egress", []policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket", "@net"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The PATH-case goldens must not depend on the developer's own shell:
			// describeEngineSource reads $SNUG_PODMAN/$SNUG_PODMAN_ROOT, and a dev
			// who exports one would otherwise regenerate a different golden. Clear
			// them so these two cases are the unpinned PATH branch by construction;
			// the pinned branch has its own test below (issue #278).
			t.Setenv("SNUG_PODMAN", "")
			t.Setenv("SNUG_PODMAN_ROOT", "")
			p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), tc.sel, envGoldenCtx(), newEnvFakeEnv())
			if err != nil {
				t.Fatalf("Resolve(%v): %v", tc.sel, err)
			}
			got := captureFile(t, func(f *os.File) { describeContainers(f, p) })

			path := filepath.Join("testdata", "containers."+tc.name+".txt")
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
				t.Errorf("the CONTAINERS block changed — this is what a human reads to learn whether\n"+
					"a container has egress and what it can mount.\n--- got\n%s\n--- want\n%s",
					got, want)
			}
		})
	}
}

// TestDescribeContainersIsSilentWhenPodmanIsOff is the negative control
// TestGoldenContainers above deliberately does not carry as a golden case: an
// empty file is easy to mistake for a missing fixture rather than an
// intentional silence.
func TestDescribeContainersIsSilentWhenPodmanIsOff(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		[]policy.ProfileName{"@sys", "@cwd-rw"}, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	got := captureFile(t, func(f *os.File) { describeContainers(f, p) })
	if got != "" {
		t.Errorf("describeContainers printed %q for a PodmanOff policy, want nothing", got)
	}
}

// TestGoldenContainersEnginePinned is the OTHER branch of describeEngineSource
// (issue #278): a run whose engine comes from $SNUG_PODMAN with a
// $SNUG_PODMAN_ROOT bundle root reads DIFFERENTLY from the PATH-case goldens
// above — a shim on PATH plus $SNUG_PODMAN exported is exactly the run whose
// engine binary a human could not tell from --dry-run before this. The env
// values are what the screen must name, so they are set here and asserted to
// appear.
func TestGoldenContainersEnginePinned(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SNUG_PODMAN", "/opt/snug-podman/bin/podman")
	t.Setenv("SNUG_PODMAN_ROOT", "/opt/snug-podman")

	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		[]policy.ProfileName{"@sys", "@cwd-rw", "@podman-socket"}, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	got := captureFile(t, func(f *os.File) { describeContainers(f, p) })

	path := filepath.Join("testdata", "containers.podman-pinned.txt")
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
		t.Errorf("the pinned-engine CONTAINERS block changed — this names which binary the run "+
			"starts and that PATH was bypassed.\n--- got\n%s\n--- want\n%s", got, want)
	}
}
