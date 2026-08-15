package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// The profile-model hardening, item 7: everything the staging layer adds — claudeFiles' staged
// credentials, stageGhConfig's generated hosts.yml, the ssh-agent and
// container proxy sockets — is added to the policy AFTER policy.Resolve
// returns, which means it is added AFTER Resolve's own Validate call already
// ran. Before main.go grew a second pol.Validate(env) call following the
// staging steps, none of that layer was ever validated at all.
//
// This exercises the real staging code (claudeFiles), not a simulation: a
// hostile profile — the kind that could live in $XDG_CONFIG_HOME/snug/profiles.d
// (CLAUDE.md invariant 3's known gap) — grants something strictly INSIDE the
// path @claude is about to stage as a generated file. Resolve alone cannot
// catch it, because nothing occupies that path yet at the time it runs.
func TestPostStagingValidateCatchesNestedGrant(t *testing.T) {
	reg := loadTestRegistry(t)
	home, target := testTree(t)

	if err := os.MkdirAll(filepath.Join(home, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The file @claude is about to stage. It must actually exist on the host,
	// or claudeFiles' stage() skips it silently and there is nothing for the
	// hostile grant to nest under.
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	reg["hostile"] = &policy.Profile{
		Name: "hostile",
		RO:   []string{filepath.Join(home, "empty") + ":" + filepath.Join(home, ".claude.json", "evil")},
	}

	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	pol, err := policy.Resolve(reg, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude", "hostile"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("control: Resolve alone must accept this selection — the KindData mount "+
			"@claude is about to stage at ~/.claude.json does not exist yet, so Resolve's own "+
			"Validate call cannot see the nesting: %v", err)
	}

	claudeFiles(pol, home)

	err = pol.Validate(policy.OSEnviron{})
	if err == nil {
		t.Fatal("a profile grant nested inside the staged ~/.claude.json went unnoticed after " +
			"claudeFiles ran; main.go's post-staging pol.Validate(env) call must catch this")
	}
	if !strings.Contains(err.Error(), "beneath a file is meaningless") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// POSITIVE CONTROL for the test above, and for the re-validate call in
// main.go generally: a normal @claude run — no hostile profile, real staged
// files — must pass the second Validate silently. The doc comment on that
// call in main.go promises exactly this ("a passing run is byte-identical to
// before"); without this control, TestPostStagingValidateCatchesNestedGrant
// could pass for the wrong reason — e.g. claudeFiles always producing an
// invalid policy regardless of the hostile profile.
func TestPostStagingValidateStaysSilentOnANormalRun(t *testing.T) {
	reg := loadTestRegistry(t)
	home, target := testTree(t)

	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := policy.Context{Target: target, Home: home, Shell: "/bin/sh", Command: []string{"/bin/sh"}}
	pol, err := policy.Resolve(reg, []policy.ProfileName{"@sys", "@home", "@cwd-rw", "@claude"}, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	claudeFiles(pol, home)

	if err := pol.Validate(policy.OSEnviron{}); err != nil {
		t.Fatalf("the post-staging Validate must be silent on a policy that was fine: %v", err)
	}
}
