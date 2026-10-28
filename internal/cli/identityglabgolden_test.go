package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestGoldenIdentityGlabArgv is the review artifact for a pinned GitLab
// account: two data descriptors (config.yml rw 0600, .netrc ro 0600), the two
// setenv rows, and no token in the argv. It runs the real stageGlabConfig with
// fake sources, so no host glab, ~/.netrc or keyring is read.
func TestGoldenIdentityGlabArgv(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	reg["lab"] = &policy.Profile{
		Name: "lab",
		Identity: &policy.Identity{
			Glab: policy.IdentityGlab{Host: "gitlab.example.com", User: "you"},
		},
	}
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "lab")
	ctx := envGoldenCtx()
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, ctx, newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}
	f := &glabFakes{acct: glabAccount{User: "you", Token: policy.Secret(fakeGlabToken)}}
	if err := stageGlabConfig(p, p.Identity, false, f.mint, f.read); err != nil {
		t.Fatalf("stageGlabConfig: %v", err)
	}
	p.InstallAnchors()
	if err := p.Validate(newEnvFakeEnv()); err != nil {
		t.Fatalf("Validate after staging: %v", err)
	}

	got := goldenFormat(p.BwrapArgs(1000, 1000))
	if strings.Contains(got, fakeGlabToken) {
		t.Fatalf("the argv carries the token:\n%s", got)
	}
	for _, want := range []string{
		ctx.Home + "/.config/glab-cli/config.yml", ctx.Home + "/.netrc",
		"GLAB_CONFIG_DIR", "GITLAB_HOST", "gitlab.example.com",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("argv lacks %q:\n%s", want, got)
		}
	}

	path := filepath.Join("testdata", "identity-glab.bwrap.txt")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/cli -run TestGoldenIdentityGlabArgv -update, then READ the diff)", err)
	}
	if got != string(want) {
		t.Errorf("argv changed — this is a change to the sandbox boundary for a profile holding a "+
			"GitLab token.\n--- got\n%s\n--- want\n%s", got, want)
	}
}
