package policy

import (
	"strings"
	"testing"
)

// TestProfileCannotWritePWD fails if bwrapOwnedEnv ever stops naming PWD, or
// if checkEnvOwnership/checkEnvTypes stop consulting it: bwrap sets PWD to
// its working directory AFTER applying --setenv, with or without --chdir
// (measured bubblewrap 0.12.0: `--clearenv --setenv PWD /opt/x --chdir /tmp
// printenv PWD` printed /tmp, and so did the same line without --chdir). A
// profile's line on PWD therefore never reaches the payload — before this
// check existed it was silently rendered on --dry-run's ENVIRONMENT block and
// the payload got bwrap's own value instead, which is exactly the "no silent
// downgrade" invariant one screen over.
func TestProfileCannotWritePWD(t *testing.T) {
	cases := []struct {
		name string
		g    EnvGrants
	}{
		{"set", EnvGrants{Set: map[string]string{"PWD": "/somewhere"}}},
		{"inherit", EnvGrants{Inherit: []string{"PWD"}}},
		{"merge", EnvGrants{Merge: map[string][]string{"PWD": {"/somewhere"}}}},
		{"prepend", EnvGrants{Prepend: map[string][]string{"PWD": {"/somewhere"}}}},
		{"sanitise", EnvGrants{Sanitise: []string{"PWD"}}},
		{"types_path", EnvGrants{Types: map[string]EnvKind{"PWD": EnvKindPath}}},
		{"types_path_list", EnvGrants{Types: map[string]EnvKind{"PWD": EnvKindPathList}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEnvGrants(tc.g)
			if err == nil {
				t.Fatalf("a profile line on PWD (%s) resolved cleanly; bwrap sets PWD after "+
					"every --setenv, so the payload never sees it and --dry-run would show a "+
					"value it does not have", tc.name)
			}
			for _, want := range []string{"PWD", "bwrap"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
		})
	}
}

// TestPWDIsRefusedAtEveryVerbThroughResolve is TestProfileCannotWritePWD's
// end-to-end counterpart: ValidateEnvGrants alone proves the parse-time rule
// fires, but Resolve is what a real run calls, and resolve.go's own fold
// invokes ValidateEnvGrants per profile before collectEnv ever sees the
// grant. This fails if that wiring is ever removed even though the rule
// itself stays intact.
func TestPWDIsRefusedAtEveryVerbThroughResolve(t *testing.T) {
	reg := testRegistry()
	reg["pwder"] = &Profile{Name: "pwder", Environ: EnvGrants{
		Set: map[string]string{"PWD": "/somewhere"},
	}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "pwder"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("Resolve accepted a profile setting PWD")
	}
	for _, want := range []string{"pwder", "PWD", "bwrap"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}
