package suggest

import (
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/ingest"
)

const home = "/home/alice"

func profile(name, host, email string, include ...string) ingest.Profile {
	return ingest.Profile{
		Name: name, File: "accounts.toml", Dir: "/home/alice/.config/snug/profiles.d", Include: include,
		Identity: ingest.ProfileIdentity{SSHHost: host, Email: email, GHUser: name},
	}
}

func repoFacts(remote string, email string) *ingest.RepoFacts {
	return &ingest.RepoFacts{
		Remotes: []ingest.Remote{ingest.ParseRemoteURL(remote)},
		Authors: []ingest.Person{{Name: "A", Email: email, Commits: 10}},
		Sampled: 10,
	}
}

func goFacts() ingest.TargetFacts {
	return ingest.TargetFacts{Languages: []ingest.Lang{{Name: "go", Marker: "go.mod", Project: "github.com/acme/app"}}}
}

func label(s Selection, id RowID) string {
	switch id {
	case Name, Desc:
		return s.Text[id]
	}
	return s.Rows[id].Choices[s.Pick[id]].Label
}

func TestSuggestClaudeImpliesNet(t *testing.T) {
	s := Suggest(ingest.Facts{Target: ingest.TargetFacts{Claude: true}}, home, "/home/alice/work/app")
	if got := label(s, Agent); got != "@claude" {
		t.Errorf("agent %q", got)
	}
	if got := label(s, Network); got != "@net" || !s.Rows[Network].Sure {
		t.Errorf("network %q sure=%v", got, s.Rows[Network].Sure)
	}
	if !strings.Contains(s.Rows[Network].Choices[0].Why, "@claude") {
		t.Errorf("why %q", s.Rows[Network].Choices[0].Why)
	}
}

func TestSuggestIdentityPrefersExistingProfile(t *testing.T) {
	f := ingest.Facts{
		Profiles: []ingest.Profile{profile("vyskocilm", "github.com", "m@example.org"), profile("plainsof", "github.com", "p@example.org")},
		Repo:     repoFacts("git@github.com:gomoni/snug.git", "m@example.org"),
	}
	s := Suggest(f, home, "/home/alice/work/snug")
	if got := label(s, Identity); got != "vyskocilm" {
		t.Fatalf("identity %q", got)
	}
	if why := s.Rows[Identity].Choices[s.Pick[Identity]].Why; why != "remote github.com:gomoni/snug" {
		t.Errorf("why %q", why)
	}
	if got := s.Text[Desc]; !strings.HasSuffix(got, ", vyskocilm") {
		t.Errorf("desc %q", got)
	}
}

func TestSuggestIdentityConflictPicksNone(t *testing.T) {
	f := ingest.Facts{
		Profiles: []ingest.Profile{profile("vyskocilm", "github.com", "m@example.org"), profile("plainsof", "github.com", "m@example.org")},
		Repo:     repoFacts("git@github.com:gomoni/snug.git", "m@example.org"),
	}
	s := Suggest(f, home, "/home/alice/work/snug")
	if got := label(s, Identity); got != "none" {
		t.Fatalf("identity %q", got)
	}
	if why := s.Rows[Identity].Choices[0].Why; why != "vyskocilm or plainsof — pick one" {
		t.Errorf("why %q", why)
	}
	if slices.ContainsFunc(s.Rows[Identity].Choices, func(c Choice) bool { return c.Label == "vyskocilm" }) == false {
		t.Errorf("both profiles must stay choosable: %+v", s.Rows[Identity].Choices)
	}
}

func TestSuggestNoRemoteSaysSo(t *testing.T) {
	s := Suggest(ingest.Facts{}, home, "/home/alice/work/app")
	if why := s.Rows[Identity].Choices[0].Why; why != "no git remote" {
		t.Errorf("why %q", why)
	}
}

func TestSuggestParentROOffUnderHome(t *testing.T) {
	s := Suggest(ingest.Facts{}, home, "/home/alice/app")
	if got := label(s, Base); got != "@sys @home @target-rw" {
		t.Errorf("base %q", got)
	}
	if why := s.Rows[Base].Choices[s.Rows[Base].Suggested].Why; why != "parent is your home" {
		t.Errorf("why %q", why)
	}
	if _, ok := s.Notes()[Base]; ok {
		t.Errorf("suggested state must not note: %v", s.Notes())
	}
	s.Pick[Base] = 0
	if got := s.Notes()[Base]; got != "parent is your home" {
		t.Errorf("turning it on must notify, got %q", got)
	}

	deep := Suggest(ingest.Facts{}, home, "/home/alice/work/app")
	if got := label(deep, Base); got != "@sys @home @target-rw @parent-ro" {
		t.Errorf("deep base %q", got)
	}
}

func TestSuggestNameSanitisedAndCollision(t *testing.T) {
	for in, want := range map[string]string{"my_proj": "my-proj", ".dotdir": "dotdir", "My Proj.v2": "my-proj-v2", "app": "app"} {
		s := Suggest(ingest.Facts{}, home, "/home/alice/work/"+in)
		if s.Text[Name] != want {
			t.Errorf("%q -> %q, want %q", in, s.Text[Name], want)
		}
	}
	s := Suggest(ingest.Facts{Profiles: []ingest.Profile{{Name: "my-proj", File: "my-proj.toml"}}}, home, "/home/alice/work/my_proj")
	if s.Text[Name] != "my-proj" {
		t.Fatalf("name %q", s.Text[Name])
	}
	if why := s.Rows[Name].Choices[0].Why; !strings.HasPrefix(why, "exists:") || !strings.Contains(why, "my-proj.toml") {
		t.Errorf("why %q", why)
	}
	if why := Suggest(ingest.Facts{}, home, "/home/alice/work/x").Rows[Name].Choices[0].Why; why != "from directory" {
		t.Errorf("why %q", why)
	}
}

func TestChangedAndRevert(t *testing.T) {
	s := Suggest(ingest.Facts{Target: ingest.TargetFacts{Claude: true}}, home, "/home/alice/work/app")
	if len(s.Notes()) != 0 {
		t.Fatalf("notes before any change: %v", s.Notes())
	}
	s.Pick[Network] = 1
	s.Text[Desc] = "mine"
	if !s.Changed(Network) || !s.Changed(Desc) || s.Changed(Agent) {
		t.Errorf("changed: net=%v desc=%v agent=%v", s.Changed(Network), s.Changed(Desc), s.Changed(Agent))
	}
	if got := s.Notes()[Network]; got != "@claude needs @net" {
		t.Errorf("note %q", got)
	}
	r := s.Revert(Network)
	if r.Changed(Network) || r.Notes()[Network] != "" {
		t.Errorf("revert left the change: %v %v", r.Changed(Network), r.Notes())
	}
	if !s.Changed(Network) || s.Pick[Network] != 1 {
		t.Errorf("Revert modified its receiver")
	}
	if !r.Changed(Desc) {
		t.Errorf("Revert(Network) reverted Desc")
	}
	all := s.RevertAll()
	if all.Changed(Desc) || all.Changed(Network) {
		t.Errorf("RevertAll left changes")
	}
	if !s.Changed(Desc) || s.Text[Desc] != "mine" {
		t.Errorf("RevertAll modified its receiver")
	}
}

func TestUnsureStartsOff(t *testing.T) {
	s := Suggest(ingest.Facts{Target: goFacts()}, home, "/home/alice/work/app")
	if got := label(s, Network); got != "—" {
		t.Errorf("network %q", got)
	}
	r := s.Rows[Network]
	if r.Sure || r.Choices[0].Label != "@net" || !strings.Contains(r.Choices[0].Why, "go mod download") {
		t.Errorf("row %+v", r)
	}
	if s.Changed(Network) {
		t.Errorf("a suggestion is not a change")
	}
}

func TestUnsureContainersNeverOn(t *testing.T) {
	s := Suggest(ingest.Facts{Target: ingest.TargetFacts{Containers: []string{"Containerfile"}}}, home, "/home/alice/work/app")
	r := s.Rows[Containers]
	if r.Sure || r.Choices[0].Label != "@podman-build" || label(s, Containers) != "—" {
		t.Errorf("row %+v pick %d", r, s.Pick[Containers])
	}
}

func TestSuggestEnvFromMarkers(t *testing.T) {
	s := Suggest(ingest.Facts{Target: goFacts()}, home, "/home/alice/work/app")
	if got := label(s, Env); got != "GOMODCACHE GOCACHE" || !s.Rows[Env].Sure {
		t.Errorf("env %q sure=%v", got, s.Rows[Env].Sure)
	}
	if why := s.Rows[Env].Choices[0].Why; why != "go.mod" {
		t.Errorf("why %q", why)
	}
}

func TestSuggestNeverInventsValues(t *testing.T) {
	f := ingest.Facts{
		Profiles: []ingest.Profile{profile("vyskocilm", "github.com", "m@example.org")},
		Repo:     repoFacts("git@github.com:evil/evil.git", "evil@example.org"),
	}
	f.Repo.Remotes = append(f.Repo.Remotes, ingest.ParseRemoteURL("git@evil.example:evil/evil.git"))
	s := Suggest(f, home, "/home/alice/work/app")
	allowed := []string{"none", "vyskocilm"}
	for _, c := range s.Rows[Identity].Choices {
		if !slices.Contains(allowed, c.Label) {
			t.Errorf("identity offered %q", c.Label)
		}
	}
}

func TestToolsFollowIdentity(t *testing.T) {
	f := ingest.Facts{
		Profiles: []ingest.Profile{
			profile("vyskocilm", "github.com", "m@example.org", "gh-cli", "@net"),
			profile("plainsof", "github.com", "p@example.org"),
		},
		Repo: repoFacts("git@github.com:gomoni/snug.git", "m@example.org"),
	}
	s := Suggest(f, home, "/home/alice/work/snug")
	if c := s.Tools(); c.Label != "gh-cli" || c.Why != "from vyskocilm" || !slices.ContainsFunc(c.Facts, func(l string) bool { return strings.Contains(l, "accounts.toml") }) {
		t.Errorf("tools %+v", c)
	}
	s.Pick[Identity] = slices.IndexFunc(s.Rows[Identity].Choices, func(c Choice) bool { return c.Label == "plainsof" })
	if c := s.Tools(); c.Label != "—" {
		t.Errorf("tools after switch %+v", c)
	}
	if s.Changed(Tools) {
		t.Errorf("Tools is never a change")
	}
}
