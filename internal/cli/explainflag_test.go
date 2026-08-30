package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestExplainFlagCombinations. A flag pair that parses but cannot MEAN
// anything is a usage error here rather than a silent resolution in one flag's
// favour, which is the rule --json already followed and the reason it is
// stated in checkFlagCombination's own doc comment: silently ignoring a format
// flag yields prose on a stream something is about to parse.
func TestExplainFlagCombinations(t *testing.T) {
	tests := []struct {
		name    string
		argv    []string
		wantErr string
	}{
		{
			name: "--explain alone",
			argv: []string{"--explain", "/tmp/x"},
		},
		{
			// The ORDER of the two --json arms matters and this is what pins
			// it: this pair satisfies both conditions, and under the general
			// "--json needs --dry-run" rule the caller would be told to add a
			// flag they did not forget.
			name:    "--explain --json names the real conflict",
			argv:    []string{"--explain", "--json", "/tmp/x"},
			wantErr: "--json cannot be combined with --explain",
		},
		{
			name:    "--explain --dry-run asks which screen",
			argv:    []string{"--explain", "--dry-run", "/tmp/x"},
			wantErr: "two renderings of the same resolved policy",
		},
		{
			name:    "--json still needs --dry-run without --explain in the picture",
			argv:    []string{"--json", "/tmp/x"},
			wantErr: "--json needs --dry-run",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseArgs(tt.argv)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("parseArgs(%v) = %v, want no error", tt.argv, err)
				}
				if !cfg.explain {
					t.Error("--explain did not set cfg.explain")
				}
				if !cfg.startsNothing() {
					t.Error("--explain does not report startsNothing, so every guard in run " +
						"that protects the host would let it through")
				}
				return
			}
			if err == nil {
				t.Fatalf("parseArgs(%v) accepted a pair that cannot mean anything", tt.argv)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("parseArgs(%v) = %q, want it to name %q — an error that names the "+
					"fix is worth the sentence", tt.argv, err, tt.wantErr)
			}
		})
	}
}

// TestDryRunStillStartsNothing is the other half of startsNothing: adding
// --explain must not have changed what --dry-run promises.
func TestDryRunStillStartsNothing(t *testing.T) {
	cfg, err := parseArgs([]string{"--dry-run", "/tmp/x"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.startsNothing() {
		t.Error("--dry-run no longer reports startsNothing")
	}
	real, err := parseArgs([]string{"/tmp/x"})
	if err != nil {
		t.Fatal(err)
	}
	// The negative, and it is the one that matters: an ordinary run must NOT
	// take the "touch nothing" path, or snug would render a screen and never
	// build a sandbox.
	if real.startsNothing() {
		t.Error("an ordinary run reports startsNothing, so it would take every host-touching " +
			"guard's false branch and start no sandbox at all")
	}
}

// TestExplainRendersARefusedPolicy covers the arm refusePolicy reaches when
// Validate refused a policy Resolve still handed back.
//
// It is a unit test rather than a CLI one because the live refusals that take
// that branch are few and awkward to provoke by hand — which is exactly why
// the arm needs pinning: an unexercised branch that prints a screen is one
// rewrite away from printing a screen that says a REFUSED sandbox is what you
// are about to get.
//
// The heading is the assertion. A human who asked what this sandbox would be,
// and whose policy will not run, must be told that in the first line and not
// left to infer it from an exit code they cannot see behind a pager.
func TestExplainRendersARefusedPolicy(t *testing.T) {
	env := newEnvFakeEnv()
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		profile.BuiltinDefaults(), envGoldenCtx(), env)
	if err != nil {
		t.Fatal(err)
	}
	refusedBy := errors.New("a profile grants something Validate will not allow")

	var buf bytes.Buffer
	if rerr := explain(env, &buf, p, p.BwrapArgs(0, 0), config{}, nil, refusedBy); rerr != nil {
		t.Fatal(rerr)
	}
	got := buf.String()
	if !strings.Contains(got, "REFUSED") {
		t.Errorf("--explain rendered a refused policy without saying so:\n%s", got)
	}
	if !strings.Contains(got, refusedBy.Error()) {
		t.Errorf("--explain did not name what refused the policy:\n%s", got)
	}
	// The screen is still rendered. Refusing to describe a refused policy is
	// the behaviour --dry-run deliberately does not have: seeing what was
	// refused is how a human finds the profile to change.
	if !strings.Contains(got, "WHAT IS NOT IN HERE") {
		t.Errorf("--explain stopped at the refusal instead of describing what was refused:\n%s", got)
	}
	// And it must NOT claim the sandbox exists. "Nothing was started" is the
	// unrefused heading; a refused policy gets the stronger sentence.
	if strings.Contains(got, "what this sandbox would be. Nothing was started.") {
		t.Error("a refused policy got the ordinary heading, which reads as though it would run")
	}
}
