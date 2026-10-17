package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// Red-team findings on the per-block identity join: the ssh and gh blocks may
// come from two profiles, so the agent's guidance must not claim one account,
// and every staged file must name the profiles it came from.

func TestClaudeGuidanceClaimsOneAccountOnlyWhenOneProfileOwnsSSHAndGh(t *testing.T) {
	pol := &policy.Policy{Identity: &policy.Identity{
		SSH: policy.IdentitySSH{Key: "/home/u/.ssh/a.pub", Agent: policy.SSHAgentProxy},
		Gh:  policy.IdentityGh{User: "someone"},
	}}
	pol.IdentityOwners = map[string][]policy.ProfileName{"ssh": {"acct-ssh"}, "gh": {"acct-gh"}}
	if got := string(claudeGuidance(pol)); strings.Contains(got, "scoped to the account") {
		t.Errorf("ssh and gh from two profiles, and the guidance still claims one account:\n%s", got)
	}
	pol.IdentityOwners = map[string][]policy.ProfileName{"ssh": {"acct"}, "gh": {"acct"}}
	if got := string(claudeGuidance(pol)); !strings.Contains(got, "scoped to the account `someone`") {
		t.Errorf("one profile owns ssh and gh, and the guidance does not say so:\n%s", got)
	}
}

func TestClaudeGuidanceCountsTheSigningKey(t *testing.T) {
	pol := &policy.Policy{Identity: &policy.Identity{
		SSH: policy.IdentitySSH{Key: "/home/u/.ssh/a.pub", Agent: policy.SSHAgentProxy},
		Git: policy.IdentityGit{SigningKey: "/home/u/.ssh/s.pub", Email: "u@example.com"},
	}}
	if got := string(claudeGuidance(pol)); !strings.Contains(got, "Exactly two ssh keys") {
		t.Errorf("auth and signing keys differ, and the guidance does not say two:\n%s", got)
	}
}

func TestGhHostsFileNamesTheGhOwner(t *testing.T) {
	pol := ghPolicy(t)
	pol.IdentityOwners = map[string][]policy.ProfileName{"gh": {"acct-gh"}, "ssh": {"acct-ssh"}}
	id := &policy.Identity{Gh: policy.IdentityGh{User: "some-one"}}
	if err := stageGhConfig(pol, id, false, func(string, string) policy.Secret { return policy.Secret("t0ken") }); err != nil {
		t.Fatal(err)
	}
	for _, m := range pol.Mounts {
		if strings.HasSuffix(m.Guest, "hosts.yml") {
			if !reflect.DeepEqual(m.From, []string{"identity:acct-gh"}) {
				t.Errorf("hosts.yml From = %v, want [identity:acct-gh]", m.From)
			}
			return
		}
	}
	t.Fatal("no hosts.yml staged")
}
