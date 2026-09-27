package policy

import (
	"slices"
	"strings"
	"testing"
)

// ── conditionally owned names (issue #621) ──────────────────────────────────
//
// A name snug fills only when a profile key turns a feature on is a profile's
// to write in every OTHER selection, and a symmetric conflict in a selection
// that turns the feature on. The tests below pin the three properties the rule
// stands on: the refusal fires in the selection, never on the write; the claim
// is the profile's TEXT, never what the host happened to hold; and the verdict
// does not depend on the order a selection is given in.

// conditionalReg adds `mine`, which claims DOCKER_HOST and grants the socket it
// names, the #477 shape.
func conditionalReg() map[ProfileName]*Profile {
	reg := testRegistry()
	reg["mine"] = &Profile{Name: "mine", Environ: EnvGrants{
		Set: map[string]string{"DOCKER_HOST": "unix:///run/docker.sock"}}}
	return reg
}

// refusalConditionalEnvPodman: a profile's DOCKER_HOST in a selection whose
// podman makes snug point DOCKER_HOST at its proxy.
func refusalConditionalEnvPodman(t testing.TB) error {
	_, err := Resolve(conditionalReg(),
		[]ProfileName{"@sys", "@target-rw", "@podman-socket", "mine"}, testCtxWithPodmanShim(), newFakeEnv())
	return err
}

// refusalConditionalEnvInherit: `inherit` is a claim on the slot even on a host
// that does not have the variable — the fake host has no SSH_AUTH_SOCK.
func refusalConditionalEnvInherit(t testing.TB) error {
	reg := testRegistry()
	reg["pinned"] = &Profile{Name: "pinned", Identity: &Identity{
		SSH: IdentitySSH{Agent: SSHAgentProxy},
		Git: IdentityGit{Name: "A", Email: "a@example.com"}}}
	reg["agent"] = &Profile{Name: "agent", Environ: EnvGrants{Inherit: []string{"SSH_AUTH_SOCK"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "agent", "pinned"}, testCtx(), newFakeEnv())
	return err
}

func TestConditionalEnvRefusedWhenTheSelectionTurnsTheFeatureOn(t *testing.T) {
	err := refusalConditionalEnvPodman(t)
	if err == nil {
		t.Fatal("a profile's DOCKER_HOST resolved beside @podman-socket; snug then points " +
			"DOCKER_HOST at its proxy and the profile's line is discarded with no trace")
	}
	for _, want := range []string{"DOCKER_HOST", "mine (environ.set)", "@podman-socket sets podman"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
}

func TestConditionalEnvAdmittedWhenTheFeatureIsOff(t *testing.T) {
	p, err := Resolve(conditionalReg(), []ProfileName{"@sys", "@target-rw", "mine"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("a profile's DOCKER_HOST was refused in a selection with no podman: %v", err)
	}
	v := p.Env["DOCKER_HOST"]
	if len(v.Entries) != 1 || v.Entries[0].Verb != VerbSet || v.Value() != "unix:///run/docker.sock" {
		t.Errorf("DOCKER_HOST = %+v, want the profile's one `set` entry", v)
	}
	if slices.Contains(p.AuthoredEnvNames(), "DOCKER_HOST") {
		t.Error("snug authored DOCKER_HOST in a selection with no podman")
	}
}

func TestConditionalEnvRefusalIsCommutative(t *testing.T) {
	sels := [][]ProfileName{
		{"@sys", "@target-rw", "@podman-socket", "mine"},
		{"mine", "@podman-socket", "@target-rw", "@sys"},
	}
	var msgs []string
	for _, sel := range sels {
		_, err := Resolve(conditionalReg(), sel, testCtxWithPodmanShim(), newFakeEnv())
		if err == nil {
			t.Fatalf("Resolve(%v) was admitted", sel)
		}
		msgs = append(msgs, err.Error())
	}
	if msgs[0] != msgs[1] {
		t.Errorf("the refusal depends on selection order:\n%s\n---\n%s", msgs[0], msgs[1])
	}
}

// The claim is the TEXT: the same `inherit` is refused whether or not the host
// has the variable, so the verdict is the same on every host.
func TestConditionalEnvInheritRefusedWhetherOrNotTheHostHasIt(t *testing.T) {
	if err := refusalConditionalEnvInherit(t); err == nil {
		t.Error("inherit SSH_AUTH_SOCK beside an agent-proxy identity resolved on a host " +
			"WITHOUT SSH_AUTH_SOCK; the same profile would be refused on a host with one (§4.4)")
	}
	reg := testRegistry()
	reg["pinned"] = &Profile{Name: "pinned", Identity: &Identity{
		SSH: IdentitySSH{Agent: SSHAgentProxy},
		Git: IdentityGit{Name: "A", Email: "a@example.com"}}}
	reg["agent"] = &Profile{Name: "agent", Environ: EnvGrants{Inherit: []string{"SSH_AUTH_SOCK"}}}
	env := newFakeEnv()
	env.env["SSH_AUTH_SOCK"] = "/run/user/1000/agent.sock"
	if _, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "agent", "pinned"}, testCtx(), env); err == nil {
		t.Error("inherit SSH_AUTH_SOCK beside an agent-proxy identity resolved on a host WITH it")
	}
}

// Selection-keyed, not write-keyed: `git = "extract"` on a host with an empty
// git config writes no GIT_CONFIG_GLOBAL, and a profile's GIT_CONFIG_GLOBAL is
// refused all the same.
func TestConditionalEnvGitExtractRefusedEvenWhenSnugWritesNothing(t *testing.T) {
	reg := testRegistry()
	reg["gitex"] = &Profile{Name: "gitex", Git: "extract"}
	sel := []ProfileName{"@sys", "@target-rw", "gitex"}

	// CONTROL: this host really makes snug write nothing.
	p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Env["GIT_CONFIG_GLOBAL"]; ok {
		t.Fatal("control: snug wrote GIT_CONFIG_GLOBAL with an empty host git config; " +
			"this test no longer covers the write-less case")
	}

	reg["ptr"] = &Profile{Name: "ptr", Environ: EnvGrants{
		Set: map[string]string{"GIT_CONFIG_GLOBAL": "{target}/gitconfig"}}}
	_, err = Resolve(reg, append(sel, "ptr"), testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("GIT_CONFIG_GLOBAL beside git = \"extract\" resolved because this host's git " +
			"config is empty; on a host with one the same selection is refused")
	}
	if !strings.Contains(err.Error(), `gitex sets git = "extract"`) {
		t.Errorf("refusal does not name the key that made snug the author: %v", err)
	}
}

// LISTEN_FDS is authored INSIDE Resolve, before the profile bands are applied,
// so this is the case where a missing check would carry the profile's entry
// beside snug's and use snug's.
func TestConditionalEnvListenFDsRefused(t *testing.T) {
	reg := testRegistry()
	reg["door"] = &Profile{Name: "door", ListenNames: []string{"web"}}
	reg["fds"] = &Profile{Name: "fds", Environ: EnvGrants{Set: map[string]string{"LISTEN_FDS": "7"}}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "door", "fds"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("LISTEN_FDS beside listen_names resolved")
	}
	if !strings.Contains(err.Error(), "door sets listen_names") {
		t.Errorf("refusal does not name the door: %v", err)
	}
}

// Every name in the table is legal profile TEXT: the parse-time verdict does
// not depend on the selection, so none of them may be refused there.
func TestConditionalEnvNamesPassParseTime(t *testing.T) {
	for _, n := range ConditionalEnvNames() {
		if err := ValidateEnvGrants(EnvGrants{Inherit: []string{n}}); err != nil {
			t.Errorf("inherit %s refused at parse time: %v", n, err)
		}
		if slices.Contains(SnugOwnedEnv, n) {
			t.Errorf("%s is both unconditionally and conditionally owned", n)
		}
	}
	if len(ConditionalEnvNames()) != 9 {
		t.Errorf("ConditionalEnvNames() = %v, want the nine of issue #621", ConditionalEnvNames())
	}
}
