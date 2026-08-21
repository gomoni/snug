package cli

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestDryRunDisclosesTheProcfsClosureExemption is the condition the maintainer
// attached to accepting issue #29's exemption: a run that keeps the host's
// procfs values must SAY SO on the screen a human reads to decide whether to
// trust it.
//
// The exemption is a named exception to invariant 1 — selecting a container
// profile makes that run less protected — and the case it must cover is the
// one nobody types: a profile that INCLUDES a container profile takes the
// closures away from every selection carrying it, with the word "podman"
// appearing nowhere on the command line. The guard keys on the resolved Podman
// mode, so the disclosure does too, and the include case is what this test
// selects with.
//
// It is asserted in BOTH directions. A line that is always printed would
// satisfy a one-sided test while telling every ordinary run that its closures
// are missing, which is the same lie pointing the other way.
func TestDryRunDisclosesTheProcfsClosureExemption(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	// A profile that names no container profile itself and INCLUDES one. This
	// is the shape the disclosure exists for: nothing a reader types says
	// "podman", and the closures are gone all the same.
	m := map[policy.ProfileName]*policy.Profile(reg)
	m["viaInclude"] = &policy.Profile{
		Name:        "viaInclude",
		Description: "a profile whose INCLUDE turns the engine on",
		Include:     []policy.ProfileName{"@podman-socket"},
	}

	for _, tc := range []struct {
		name     string
		sel      []policy.ProfileName
		disclose bool
	}{
		{"ordinary run", []policy.ProfileName{"@sys", "@home", "@cwd-rw"}, false},
		{"engine named", []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@podman-socket"}, true},
		{"engine via include", []policy.ProfileName{"@sys", "@home", "@cwd-rw", "viaInclude"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := policy.Resolve(m, tc.sel, envGoldenCtx(), newEnvFakeEnv())
			if err != nil {
				t.Fatal(err)
			}
			got := captureStdout(t, func() { dryRun(p, p.BwrapArgs(0, 0), config{}, nil) })

			// CONTROL: the /proc row itself is on the screen. The disclosure
			// hangs off that row precisely because the closures are absent on
			// an engine run, so a missing row would make both assertions below
			// vacuous.
			if !strings.Contains(got, "proc   /proc") {
				t.Fatalf("no /proc row on the screen, so this test is asserting about a row "+
					"that is not there:\n%s", got)
			}

			said := strings.Contains(got, "closures are NOT applied")
			switch {
			case tc.disclose && !said:
				t.Errorf("this run keeps the HOST's /proc/config.gz, keys and key-users and the "+
					"screen does not say so. That disclosure is the condition the exemption "+
					"was accepted under (issue #29):\n%s", got)
			case !tc.disclose && said:
				t.Errorf("an ordinary run's screen claims the closures were not applied, while "+
					"they were — a lie in the reassuring direction is still a lie:\n%s", got)
			}

			// And the rows themselves must agree with the sentence, or the
			// screen contradicts itself twenty lines apart — which is the
			// defect issue #252 was filed for, in a different block.
			hasRows := strings.Contains(got, "data   /proc/keys")
			if hasRows == tc.disclose {
				t.Errorf("the closure rows (%v) and the disclosure (%v) disagree on the same "+
					"screen:\n%s", hasRows, said, got)
			}
		})
	}
}
