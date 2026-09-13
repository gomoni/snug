package cli

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── the gh half of #454's host split ─────────────────────────────────────────
//
// internal/policy/testdata/identity-generated.txt pins the SSH half byte for
// byte: the generated ~/.ssh/config Host line, the known_hosts body and git's
// insteadOf rewrite all follow identity.ssh.host. It cannot see the gh half at
// all, because that one is not a generated file Resolve produces — it is
// `gh auth token --hostname`, the hosts.yml top key and GH_HOST, produced here
// after resolution and behind an exec.
//
// So the half that MOVES A CREDENTIAL was the half no test could reach without a
// forge account, and a swap of the two host fields in stageGhConfig would have
// produced no golden diff anywhere. tokenMinter is the seam that fixes it; these
// are the assertions it exists for.

func ghPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	return &policy.Policy{
		Mounts: map[string]policy.Mount{},
		Env:    map[string]policy.EnvVar{},
		Home:   "/home/u",
	}
}

// TestStageGhConfigFollowsGhHostAndNotSSHHost sets the two hosts to DIFFERENT
// values, which is the only arrangement that can tell them apart, and pins all
// four places the gh host reaches: the hostname `gh auth token` is asked for,
// the hosts.yml top key, GH_HOST, and — the negative — that ssh.example appears
// in none of them.
func TestStageGhConfigFollowsGhHostAndNotSSHHost(t *testing.T) {
	pol := ghPolicy(t)
	id := &policy.Identity{
		SSH: policy.IdentitySSH{Host: "ssh.example", Key: "/home/u/.ssh/id.pub", Agent: policy.SSHAgentProxy},
		Gh:  policy.IdentityGh{Host: "gh.example", User: "some-one"},
	}

	var gotHost, gotUser string
	mint := func(host, user string) policy.Secret {
		gotHost, gotUser = host, user
		return policy.Secret("t0ken")
	}
	if err := stageGhConfig(pol, id, false, mint); err != nil {
		t.Fatalf("stageGhConfig: %v", err)
	}

	if gotHost != "gh.example" {
		t.Errorf("`gh auth token --hostname %s`, want gh.example — the token was minted for "+
			"the host you PUSH to rather than the host gh talks to", gotHost)
	}
	if gotUser != "some-one" {
		t.Errorf("`gh auth token --user %s`, want some-one", gotUser)
	}

	m, ok := pol.Mounts["/home/u/.config/gh/hosts.yml"]
	if !ok {
		t.Fatalf("no hosts.yml was staged; mounts = %v", pol.Mounts)
	}
	body := string(m.Content)
	if !strings.HasPrefix(body, "gh.example:\n") {
		t.Errorf("hosts.yml top key is not gh.example — gh reads the token under the host key, "+
			"so a wrong one stages a credential gh will never find:\n%s", body)
	}
	if strings.Contains(body, "ssh.example") {
		t.Errorf("identity.ssh.host reached hosts.yml:\n%s", body)
	}
	if got := pol.Env["GH_HOST"].Entries[0].Value; got != "gh.example" {
		t.Errorf("GH_HOST = %q, want gh.example", got)
	}
	if got := pol.Env["GH_CONFIG_DIR"].Entries[0].Value; got != "/home/u/.config/gh" {
		t.Errorf("GH_CONFIG_DIR = %q", got)
	}
}

// TestStageGhConfigDefaultsBothHostsIndependently is the control for the test
// above: with neither host named, the gh side must reach DefaultIdentityHost on
// its own accessor rather than by inheriting anything from the ssh block. No
// fallback runs between the two — a fallback is a precedence rule and snug has
// none — so "both say github.com" has to be two independent defaults.
func TestStageGhConfigDefaultsBothHostsIndependently(t *testing.T) {
	pol := ghPolicy(t)
	id := &policy.Identity{Gh: policy.IdentityGh{User: "some-one"}}

	var gotHost string
	mint := func(host, _ string) policy.Secret {
		gotHost = host
		return policy.Secret("t0ken")
	}
	if err := stageGhConfig(pol, id, false, mint); err != nil {
		t.Fatalf("stageGhConfig: %v", err)
	}
	if gotHost != policy.DefaultIdentityHost {
		t.Errorf("an unnamed gh host minted for %q, want %q", gotHost, policy.DefaultIdentityHost)
	}
	if got := pol.Env["GH_HOST"].Entries[0].Value; got != policy.DefaultIdentityHost {
		t.Errorf("GH_HOST = %q, want %q", got, policy.DefaultIdentityHost)
	}
}

// TestStageGhConfigMintsNothingWithoutAPinnedUser asserts the gate BEFORE the
// exec, not merely that no file is staged after it. The distinction is the whole
// point of the narrowing: `gh auth token` with no --user returns the token of
// whatever account the host is currently logged in to, so a gate placed after
// the call would have already asked for a credential the profile never named.
//
// Resolve refuses gh.host with no gh.user, so this shape cannot come from a
// profile that resolved; the gate is written this way round anyway, so deleting
// that refusal later reverts to "no token" rather than "unpinned token".
func TestStageGhConfigMintsNothingWithoutAPinnedUser(t *testing.T) {
	pol := ghPolicy(t)
	id := &policy.Identity{
		SSH: policy.IdentitySSH{Key: "/home/u/.ssh/id.pub", Agent: policy.SSHAgentProxy},
		Gh:  policy.IdentityGh{Host: "gh.example"},
	}

	called := false
	mint := func(string, string) policy.Secret {
		called = true
		return policy.Secret("t0ken")
	}
	if err := stageGhConfig(pol, id, false, mint); err != nil {
		t.Fatalf("stageGhConfig: %v", err)
	}
	if called {
		t.Error("stageGhConfig asked the host for a token for an account the profile did not name")
	}
	if len(pol.Mounts) != 0 || len(pol.Env) != 0 {
		t.Errorf("mounts = %v, env = %v; want neither", pol.Mounts, pol.Env)
	}
}

// TestStageGhConfigRefusesARealRunWithNoToken and its dry-run half pin invariant
// 5 at this seam: identity.gh.user is an explicit request for a capability, so a
// run that cannot have it must stop rather than proceed without it. The dry run
// is the exception and says why on stderr — it INSPECTS a policy, and refusing
// there makes the policy unreadable on a machine with no gh, which is one of the
// machines where reading it matters.
func TestStageGhConfigRefusesARealRunWithNoToken(t *testing.T) {
	none := func(string, string) policy.Secret { return nil }
	id := &policy.Identity{Gh: policy.IdentityGh{Host: "gh.example", User: "some-one"}}

	err := stageGhConfig(ghPolicy(t), id, false, none)
	if err == nil {
		t.Fatal("a real run continued with no credential for the pinned account")
	}
	for _, want := range []string{"some-one", "gh.example", "gh auth login"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}

	pol := ghPolicy(t)
	if err := stageGhConfig(pol, id, true, none); err != nil {
		t.Fatalf("--dry-run refused a policy because the host cannot mint a token: %v", err)
	}
	if len(pol.Mounts) != 0 {
		t.Errorf("a dry run with no token staged a hosts.yml anyway: %v", pol.Mounts)
	}
}
