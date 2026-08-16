//go:build integration

package integration

import (
	"sort"
	"strings"
	"testing"
)

// TestDryRunEnvironmentBlockAccountsForEveryNameInside is the F5 regression
// (redteam host round 2), and it is the one assertion in this area that the unit
// suite structurally cannot make.
//
// describeEnvironment's doc comment used to say: "bwrap --clearenv discards the
// host's, so this block is the WHOLE of it — there is nothing inherited that does
// not appear here". Measured across five selections, the block, the argv's
// --setenv pairs and `env` INSIDE agreed on every name and every value byte for
// byte, with exactly one exception every time: PWD, which is inside and was on
// neither screen. bwrap authors it after --chdir — isolated with a bare bwrap
// invocation whose payload was `env`, exec'd directly, with no shell anywhere:
//
//	bwrap --ro-bind /usr /usr … --clearenv --chdir /usr /usr/bin/env
//	  PWD=/usr
//
// Harmless in CONTENT — PWD is the target, which the screen already names twice —
// and exactly the shape invariant 5 is about: the artifact claiming a
// completeness it does not have.
//
// WHY THIS TEST AND NOT A UNIT TEST, which is the reusable half. Round 1 already
// compared "18 variables, byte for byte" between the ENVIRONMENT block and the
// argv block, and it PASSED while the claim was false — because both of those are
// generated from p.Env, by one author. An equivalence check between two things
// snug generates cannot see a third party adding to the result. Only a real
// sandbox can, so the assertion has to live here.
//
// PWD IS NAMED EXPLICITLY rather than tolerated as "one extra name". The day
// bwrap stops setting it, or sets something else beside it, this test fails and
// says which — a set difference of "anything at all" would silently accept a
// second unexplained variable, which is the whole defect one rerun later.
//
// THE PAYLOAD IS `env` EXEC'D DIRECTLY, and that is load-bearing: run()'s script
// goes through `bash -c`, and bash adds SHLVL and `_` of its own. Those would be
// real additions to the environment inside and NOT snug's or bwrap's doing, so a
// bash payload would measure the shell instead of the sandbox. It also means the
// usual payload marker is unavailable, so SNUG=1 — which only snug ever sets — is
// the positive control that the payload really ran.
func TestDryRunEnvironmentBlockAccountsForEveryNameInside(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"defaults", nil},
		{"minimal", []string{"--no-defaults", "-p", "@sys", "-p", "@home", "-p", "@cwd-rw"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			screen, code := cli(t, nil, append(append([]string{"--dry-run"}, tc.args...), proj)...)
			if code != 0 {
				t.Fatalf("snug --dry-run exited %d:\n%s", code, screen)
			}
			block := environmentBlockNames(t, screen)
			setenv := setenvNames(screen)

			out, code := cli(t, nil, append(append([]string{}, tc.args...), proj, "--", "/usr/bin/env")...)
			if code != 0 {
				t.Fatalf("running /usr/bin/env inside exited %d:\n%s", code, out)
			}
			inside := map[string]bool{}
			for _, line := range strings.Split(out, "\n") {
				if i := strings.IndexByte(line, '='); i > 0 {
					inside[line[:i]] = true
				}
			}
			// POSITIVE CONTROL: the payload ran and this is really the sandbox's
			// environment. SNUG is snug's own name and nothing else sets it.
			if !inside["SNUG"] {
				t.Fatalf("SNUG is not in the environment inside, so this is not a sandbox's "+
					"environment and the comparison below means nothing:\n%s", out)
			}

			// 1. The screen accounts for everything inside, and vice versa.
			if missing := diff(inside, block); len(missing) > 0 {
				t.Errorf("%v is set inside the sandbox and appears on NO line of --dry-run's "+
					"ENVIRONMENT block. That block is the artifact a human reads to decide "+
					"whether to trust this sandbox, and it is read as complete — PWD was such a "+
					"name for a milestone, authored by bwrap from --chdir. Render the new one "+
					"too, in whoever's provenance authors it.", missing)
			}
			if extra := diff(block, inside); len(extra) > 0 {
				t.Errorf("%v is on --dry-run's ENVIRONMENT block and is NOT set inside. The "+
					"screen promising a variable the payload does not get is the same defect "+
					"facing the other way.", extra)
			}

			// 2. PWD, by name: not something snug sets, and present inside.
			if setenv["PWD"] {
				t.Errorf("snug now passes --setenv PWD itself. That is a policy change: PWD is " +
					"bwrap's, from --chdir, and this test (plus the (bwrap) row on the screen) " +
					"is written on that division of authorship.")
			}
			if !inside["PWD"] {
				t.Errorf("PWD is not set inside. bwrap 0.11.2 sets it from --chdir — measured, " +
					"and corroborated in its binary with `strings -n 3` (the default -n 4 hides " +
					"a three-character string, which nearly retracted the finding). If a newer " +
					"bwrap stopped, the (bwrap) PWD row in describeEnvironment is now a lie and " +
					"must go.")
			}
			// 3. …and PWD is the ONLY name in that position, which is what makes
			//    the block complete rather than merely nearly complete.
			for name := range inside {
				if !setenv[name] && name != "PWD" {
					t.Errorf("%s is set inside and is not one of snug's --setenv names. Exactly "+
						"one name is supposed to be in that position (PWD, from bwrap's "+
						"--chdir); a second one is something nobody has accounted for.", name)
				}
			}
		})
	}
}

// environmentBlockNames parses the names out of --dry-run's ENVIRONMENT block:
// the lines indented exactly 2, which is the block's own geometry rule (a
// continuation band is at 19, a drop line at 19, a mark at 21 —
// cmd/snug's TestNoEnvironmentLineCanBeMistakenForAMark). Parsing by that rule
// rather than by "any line with an =" is what keeps this test measuring the
// screen a human reads.
func environmentBlockNames(t *testing.T, screen string) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	in := false
	for _, line := range strings.Split(screen, "\n") {
		if strings.HasPrefix(line, "ENVIRONMENT") {
			in = true
			continue
		}
		if !in {
			continue
		}
		if !strings.HasPrefix(line, "  ") {
			break // the block ended
		}
		if strings.HasPrefix(line, "   ") {
			continue // a band, a drop line or a mark
		}
		if f := strings.Fields(line); len(f) > 0 {
			names[f[0]] = true
		}
	}
	if len(names) < 5 {
		t.Fatalf("parsed %d names out of the ENVIRONMENT block; the block's layout changed and "+
			"this test is now measuring almost nothing:\n%s", len(names), screen)
	}
	return names
}

// setenvNames is the names snug actually passes to bwrap, read off the argv
// block. It is the second, independent reading of "what snug sets" — the point
// of F5 is that the block and the argv agree with each other and both missed a
// third party.
func setenvNames(screen string) map[string]bool {
	names := map[string]bool{}
	for _, line := range strings.Split(screen, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "--setenv" {
			names[f[1]] = true
		}
	}
	return names
}

// diff returns the names in a that are not in b, sorted so a failure message is
// stable.
func diff(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
