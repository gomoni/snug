package policy

import (
	"strings"
	"testing"
)

func resolveGlab(t *testing.T, ids map[ProfileName]Identity) (*Policy, error) {
	t.Helper()
	reg, sel := identityProfiles(ids)
	return Resolve(reg, sel, testCtx(), newFakeEnv())
}

func wantRefusal(t *testing.T, err error, why string, contains ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("resolved; %s", why)
	}
	for _, w := range contains {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("refusal does not contain %q: %v", w, err)
		}
	}
}

func TestGlabHostWithoutUserIsRefused(t *testing.T) {
	_, err := resolveGlab(t, map[ProfileName]Identity{"lab": {Glab: IdentityGlab{Host: "gitlab.example"}}})
	wantRefusal(t, err, "identity.glab.host with no user would stage whichever account glab holds for the host",
		"identity.glab", "missing user", `user = "you"`, "[profile.lab.identity.glab]")

	// CONTROL: both leaves is the pinned shape.
	if _, err := resolveGlab(t, map[ProfileName]Identity{"lab": {Glab: glabBlock}}); err != nil {
		t.Fatalf("a complete glab block was refused: %v", err)
	}
}

func TestGlabUserWithoutHostIsRefused(t *testing.T) {
	_, err := resolveGlab(t, map[ProfileName]Identity{"lab": {Glab: IdentityGlab{User: "you"}}})
	wantRefusal(t, err, "identity.glab has no default host, so a user alone would stage a token for a host nobody wrote",
		"identity.glab", "missing host", `host = "gitlab.example.com"`)
}

func TestGlabTokenSourceAloneIsRefused(t *testing.T) {
	for _, src := range []GlabTokenSource{GlabTokenFromNetrc, "glab"} {
		_, err := resolveGlab(t, map[ProfileName]Identity{"lab": {Glab: IdentityGlab{TokenSource: src}}})
		wantRefusal(t, err, "a block holding only token_source = "+string(src)+" names no account",
			"identity.glab", "host and user")
	}
}

func TestGlabUnknownTokenSourceRefusesAndQuotesBoth(t *testing.T) {
	_, err := resolveGlab(t, map[ProfileName]Identity{"lab": {Glab: IdentityGlab{
		Host: "gitlab.example", User: "you", TokenSource: "keyring"}}})
	wantRefusal(t, err, "an unrecognised token_source was read as the nearest thing it resembles",
		`"keyring"`, "glab", "netrc", "identity.glab.token_source")

	for in, want := range map[string]GlabTokenSource{"": GlabTokenFromGlab, "glab": GlabTokenFromGlab, "netrc": GlabTokenFromNetrc} {
		got, err := ParseGlabTokenSource(in)
		if err != nil || got != want {
			t.Errorf("ParseGlabTokenSource(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"NETRC", "Glab", " netrc", "env", "none"} {
		if _, err := ParseGlabTokenSource(bad); err == nil {
			t.Errorf("ParseGlabTokenSource(%q) accepted", bad)
		}
	}
}

// The default and the spelled-out default are one identity, as an omitted
// ssh.agent and `agent = "none"` are.
func TestGlabTokenSourceGlabAndOmittedJoinAsOneBlock(t *testing.T) {
	p, err := resolveGlab(t, map[ProfileName]Identity{
		"a": {Glab: IdentityGlab{Host: "gitlab.example", User: "you"}},
		"b": {Glab: IdentityGlab{Host: "gitlab.example", User: "you", TokenSource: "glab"}},
	})
	if err != nil {
		t.Fatalf("`token_source = \"glab\"` and an omitted one refused each other: %v", err)
	}
	if p.Identity.Glab.TokenSource != GlabTokenFromGlab {
		t.Errorf("TokenSource = %q, want the normalised default", p.Identity.Glab.TokenSource)
	}
}

func TestGlabUserWithWhitespaceIsRefused(t *testing.T) {
	for _, u := range []string{"u password X", "u  password", "you ", " you", "-you", ".you", "_you", "a#b", "a:b", `a"b`} {
		_, err := resolveGlab(t, map[ProfileName]Identity{"lab": {Glab: IdentityGlab{Host: "gitlab.example", User: u}}})
		wantRefusal(t, err, "user "+u+" is written unquoted into a netrc line, where a space authors a second credential",
			"identity.glab.user", "netrc")
	}
	for _, u := range []string{"you", "you.me-1_x", "A9"} {
		if _, err := resolveGlab(t, map[ProfileName]Identity{"lab": {Glab: IdentityGlab{Host: "gitlab.example", User: u}}}); err != nil {
			t.Errorf("user %q refused: %v", u, err)
		}
	}
}

func TestGlabHostUnhostlikeIsRefused(t *testing.T) {
	for _, h := range []string{"a b", `a"]`, "-evil", ".x", "a:8443", "a/b", "a#b"} {
		_, err := resolveGlab(t, map[ProfileName]Identity{"lab": {Glab: IdentityGlab{Host: h, User: "you"}}})
		wantRefusal(t, err, "host "+h+" is written unquoted into config.yml and ~/.netrc",
			"identity.glab.host", "config.yml", ".netrc")
	}
}

func TestGlabHostWithSSHPinnedAndNoSSHHostIsRefused(t *testing.T) {
	_, err := resolveGlab(t, map[ProfileName]Identity{
		"lab":   {Glab: glabBlock},
		"keyed": {SSH: sshBlock},
	})
	wantRefusal(t, err, "glab names a host and ssh does not, so ssh's three artifacts would name github.com",
		`"lab"`, `"keyed"`, "identity.glab.host", "identity.ssh.host")

	// One profile holding both is the same refusal, naming it once.
	_, err = resolveGlab(t, map[ProfileName]Identity{"both": {Glab: glabBlock, SSH: sshBlock}})
	wantRefusal(t, err, "same profile", `"both"`, "identity.ssh.host")

	// CONTROLS: ssh.host named (equal or different — nothing is inherited), and a
	// glab block beside an ssh-less selection.
	for _, h := range []string{"gitlab.example", "elsewhere.example"} {
		ssh := sshBlock
		ssh.Host = h
		if _, err := resolveGlab(t, map[ProfileName]Identity{"lab": {Glab: glabBlock, SSH: ssh}}); err != nil {
			t.Errorf("glab beside ssh.host = %q refused: %v", h, err)
		}
	}
	if _, err := resolveGlab(t, map[ProfileName]Identity{"lab": {Glab: glabBlock}}); err != nil {
		t.Errorf("glab with no ssh block refused: %v", err)
	}
}

func TestTwoProfilesPinningDifferentGlabBlocksAreRefused(t *testing.T) {
	for name, other := range map[string]IdentityGlab{
		"host":         {Host: "other.example", User: "base-user"},
		"user":         {Host: "gitlab.example", User: "someone-else"},
		"token_source": {Host: "gitlab.example", User: "base-user", TokenSource: GlabTokenFromNetrc},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := resolveGlab(t, map[ProfileName]Identity{
				"ident-a": {Glab: glabBlock},
				"ident-b": {Glab: other},
			})
			wantRefusal(t, err, "two glab pins resolved", `"ident-a"`, `"ident-b"`, "identity.glab")
		})
	}
}

func TestGlabSetGitlabTokenBesideThePinIsRefused(t *testing.T) {
	owned := []string{"GLAB_CONFIG_DIR", "GITLAB_HOST", "GITLAB_TOKEN", "GITLAB_ACCESS_TOKEN", "OAUTH_TOKEN", "GITLAB_URI", "GL_HOST"}
	for _, name := range owned {
		for _, verb := range []string{"set", "inherit"} {
			t.Run(name+"/"+verb, func(t *testing.T) {
				reg := testRegistry()
				reg["lab"] = &Profile{Name: "lab", Identity: &Identity{Glab: glabBlock}}
				env := EnvGrants{}
				if verb == "set" {
					env.Set = map[string]string{name: "/home/u/x"}
				} else {
					env.Inherit = []string{name}
				}
				reg["side"] = &Profile{Name: "side", Environ: env}
				_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "lab", "side"}, testCtx(), newFakeEnv())
				wantRefusal(t, err, name+" beside identity.glab.user redirects glab off the pinned account",
					name, "side", "identity.glab.user")
			})
		}
	}
}

func TestGlabEnvIsFreeWithoutTheBlock(t *testing.T) {
	for _, name := range []string{"GLAB_CONFIG_DIR", "GITLAB_HOST", "GITLAB_TOKEN", "GITLAB_ACCESS_TOKEN", "OAUTH_TOKEN", "GITLAB_URI", "GL_HOST"} {
		reg := testRegistry()
		reg["side"] = &Profile{Name: "side", Environ: EnvGrants{Inherit: []string{name}}}
		if _, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "side"}, testCtx(), newFakeEnv()); err != nil {
			t.Errorf("inherit %s refused with no glab block: %v", name, err)
		}
	}
	p, err := resolveGlab(t, map[ProfileName]Identity{"git-only": {Git: gitBlock}})
	if err != nil {
		t.Fatal(err)
	}
	if ConditionalEnvOn(p, "GITLAB_HOST") || ConditionalEnvOn(p, "GLAB_CONFIG_DIR") {
		t.Error("glab's names read as snug's in a selection with no glab block")
	}
}

func TestGhAndGlabComposeFromTwoProfiles(t *testing.T) {
	p, err := resolveGlab(t, map[ProfileName]Identity{
		"acct-gh":   {Gh: IdentityGh{Host: "same.example", User: "gh-user"}},
		"acct-glab": {Glab: IdentityGlab{Host: "same.example", User: "glab-user"}},
	})
	if err != nil {
		t.Fatalf("a gh block and a glab block on the same host refused: %v", err)
	}
	if p.Identity.Gh.User != "gh-user" || p.Identity.Glab.User != "glab-user" {
		t.Errorf("Identity = %+v, want both blocks pinned independently", *p.Identity)
	}
	if p.IdentityOwner("gh") != "acct-gh" || p.IdentityOwner("glab") != "acct-glab" {
		t.Errorf("owners = %v", p.IdentityOwners)
	}
	if !ConditionalEnvOn(p, "GITLAB_HOST") || !ConditionalEnvOn(p, "GH_HOST") {
		t.Error("a conditional name is off beside its own pinned block")
	}
}

func TestGlabOnlyGeneratesNoGitconfig(t *testing.T) {
	p, err := resolveGlab(t, map[ProfileName]Identity{"lab": {Glab: glabBlock}})
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"/home/u/.gitconfig", "/home/u/.ssh/config"} {
		if _, ok := p.Mounts[g]; ok {
			t.Errorf("a glab-only identity generated %s", g)
		}
	}
	if _, ok := p.Env["GIT_CONFIG_GLOBAL"]; ok {
		t.Error("a glab-only identity authored GIT_CONFIG_GLOBAL")
	}
}
