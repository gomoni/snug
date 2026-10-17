package suggest

import (
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/hostfacts"
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
	if !strings.Contains(s.Current(Network).Why, "@claude") {
		t.Errorf("why %q", s.Current(Network).Why)
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
	if r.Sure || r.Choices[0].Label != "@net" || !strings.Contains(s.Current(Network).Why, "go mod download") {
		t.Errorf("row %+v", r)
	}
	if s.Changed(Network) {
		t.Errorf("a suggestion is not a change")
	}
}

func TestUnsureContainersNeverOn(t *testing.T) {
	s := Suggest(ingest.Facts{Target: ingest.TargetFacts{Containers: []string{"Containerfile"}}}, home, "/home/alice/work/app")
	r := s.Rows[Containers]
	if r.Sure || r.Choices[r.Cand].Label != "@podman-build" || label(s, Containers) != "—" {
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

func fullProfile() ingest.Profile {
	return ingest.Profile{
		Name: "vyskocilm", File: "accounts.toml", Dir: "/home/alice/.config/snug/profiles.d", Include: []string{"@net", "gh-cli"},
		Identity: ingest.ProfileIdentity{
			SSHHost: "github.com", SSHKey: "{home}/.ssh/github_auth.pub", SigningKey: "{home}/.ssh/github_sign.pub",
			GitName: "Michal V", Email: "m@example.org", GHUser: "vyskocilm", GHHost: "github.com",
		},
	}
}

func TestIdentityDetailListsWhatTheProfilePins(t *testing.T) {
	f := ingest.Facts{
		Profiles: []ingest.Profile{fullProfile(), profile("plainsof", "github.com", "p@example.org")},
		SSH:      ingest.SSHFacts{Hosts: ingest.ParseSSHConfig(strings.NewReader("Host github.com\n  IdentityFile ~/.ssh/github_auth\n"))},
		Repo:     repoFacts("git@github.com:gomoni/snug.git", "m@example.org"),
	}
	s := Suggest(f, home, "/home/alice/work/snug")
	i := slices.IndexFunc(s.Rows[Identity].Choices, func(c Choice) bool { return c.Label == "vyskocilm" })
	got := strings.Join(s.IdentityDetail(i), "\n")
	want := strings.Join([]string{
		"ssh   github.com  github_auth",
		"      ~/.ssh/config  Host github.com  → github_auth",
		"sign  github_sign",
		"git   Michal V <m@example.org>",
		"gh    github.com/vyskocilm",
		"also includes: gh-cli",
	}, "\n")
	if got != want {
		t.Errorf("detail:\n%s\nwant:\n%s", got, want)
	}
	if d := s.IdentityDetail(0); len(d) != 1 || !strings.Contains(d[0], "@git") {
		t.Errorf("none: %q", d)
	}
}

func TestIdentityDetailHostTextIsCleaned(t *testing.T) {
	p := fullProfile()
	p.Identity.SSHHost = "git\x1b[2Jhub.com"
	p.Identity.Email = "m@\u202eexample.org"
	s := Suggest(ingest.Facts{Profiles: []ingest.Profile{p}}, home, "/home/alice/work/snug")
	for _, l := range s.IdentityDetail(1) {
		if strings.ContainsAny(l, "\x1b\u202e") {
			t.Errorf("forging rune in %q", l)
		}
	}
}

func TestToolsRowIsGone(t *testing.T) {
	s := Suggest(ingest.Facts{Profiles: []ingest.Profile{fullProfile()}}, home, "/home/alice/work/snug")
	if len(s.Rows) != int(Env)+1 || Env != 7 {
		t.Errorf("%d rows, Env=%d", len(s.Rows), Env)
	}
}

func TestContainersChoicesAndSuggestion(t *testing.T) {
	cases := []struct {
		name      string
		files     []string
		suggested string
		cand      string
		sure      bool
	}{
		{"containerfile", []string{"Containerfile"}, Off, "@podman-build", false},
		{"compose only", []string{"compose.yaml"}, Off, "@podman-socket", false},
		{"none", nil, Off, "", true},
	}
	for _, c := range cases {
		s := Suggest(ingest.Facts{Target: ingest.TargetFacts{Containers: c.files}}, home, "/home/alice/work/app")
		r := s.Rows[Containers]
		var labels []string
		for _, ch := range r.Choices {
			labels = append(labels, ch.Label)
		}
		if !slices.Equal(labels, []string{"@podman-socket", "@podman-build", Off}) {
			t.Errorf("%s: choices %v", c.name, labels)
		}
		if got := label(s, Containers); got != c.suggested || r.Sure != c.sure {
			t.Errorf("%s: suggested %q sure=%v", c.name, got, r.Sure)
		}
		if !c.sure && r.Choices[r.Cand].Label != c.cand {
			t.Errorf("%s: candidate %q", c.name, r.Choices[r.Cand].Label)
		}
		for i := range r.Choices {
			if s.WithPick(Containers, i).Changed(Containers) != (i != 2) {
				t.Errorf("%s: choice %d changed=%v", c.name, i, !(i != 2))
			}
		}
	}
}

func TestNetworkReasonsListOnlySourcesThatAreOn(t *testing.T) {
	f := ingest.Facts{Target: goFacts()}
	f.Target.Claude = true
	f.Target.Containers = []string{"Containerfile"}
	s := Suggest(f, home, "/home/alice/work/app")
	why := func(s Selection) string { return s.Current(Network).Why }
	if got := why(s); got != "@claude, go mod download" {
		t.Errorf("containers off: %q", got)
	}
	on := s.WithPick(Containers, 1)
	if got := why(on); got != "@claude, go mod download, container images" {
		t.Errorf("containers on: %q", got)
	}
	noAgent := on.WithPick(Agent, 1)
	if got := why(noAgent); got != "go mod download, container images" {
		t.Errorf("agent off: %q", got)
	}
	if facts := strings.Join(s.Current(Network).Facts, "|"); strings.Contains(facts, "container images") {
		t.Errorf("facts name a source that is off: %q", facts)
	}
}

func TestContainerOnlyNetReasonIsEmptyWhileContainersAreOff(t *testing.T) {
	s := Suggest(ingest.Facts{Target: ingest.TargetFacts{Containers: []string{"Containerfile"}}}, home, "/home/alice/work/app")
	if got := s.Current(Network).Why; got != "" {
		t.Errorf("reason %q with containers off", got)
	}
	if got := s.WithPick(Containers, 0).Current(Network).Why; got != "container images" {
		t.Errorf("reason %q with containers on", got)
	}
}

func TestDescFollowsIdentityUnlessEdited(t *testing.T) {
	f := claudeGoFacts()
	s := Suggest(f, home, "/home/alice/work/app")
	if s.Text[Desc] != "app, vyskocilm" {
		t.Fatalf("desc %q", s.Text[Desc])
	}
	none := s.WithPick(Identity, 0)
	if none.Text[Desc] != "app" || none.Changed(Desc) {
		t.Errorf("identity none: desc %q changed %v", none.Text[Desc], none.Changed(Desc))
	}
	if s.Text[Desc] != "app, vyskocilm" {
		t.Errorf("WithPick modified its receiver")
	}
	back := none.WithPick(Identity, s.Pick[Identity])
	if back.Text[Desc] != "app, vyskocilm" {
		t.Errorf("identity back: %q", back.Text[Desc])
	}
	mine := s.WithText(Desc, "my own words").WithPick(Identity, 0)
	if mine.Text[Desc] != "my own words" || !mine.Changed(Desc) {
		t.Errorf("an edited desc was overwritten: %q", mine.Text[Desc])
	}
	if r := mine.Revert(Desc); r.Text[Desc] != "app" || r.Changed(Desc) {
		t.Errorf("Revert(Desc) = %q", r.Text[Desc])
	}
	if r := mine.RevertAll(); r.Text[Desc] != "app, vyskocilm" || r.Changed(Desc) {
		t.Errorf("RevertAll desc = %q", r.Text[Desc])
	}
}

func TestNetworkReasonIsNotRepeatedForTwoMarkers(t *testing.T) {
	f := ingest.Facts{Target: ingest.TargetFacts{Languages: []ingest.Lang{
		{Name: "go", Marker: "go.mod"}, {Name: "go", Marker: "sub/go.mod"}}}}
	if got := Suggest(f, home, "/home/alice/work/app").Current(Network).Why; got != "go mod download" {
		t.Errorf("reason %q", got)
	}
}

func TestIdentityWarningNeedsTheSameHostAndUser(t *testing.T) {
	p := fullProfile()
	p.Identity.GHHost = "ghe.example.com"
	f := ingest.Facts{
		Profiles:    []ingest.Profile{p},
		GHInstalled: true,
		GH:          []hostfacts.GHAccount{{Host: "github.com", User: "vyskocilm"}},
	}
	s := Suggest(f, home, "/home/alice/work/snug")
	if got := s.IdentityWarning(0); got != "" {
		t.Errorf("none has no gh login: %q", got)
	}
	want := "vyskocilm: gh not logged in as vyskocilm on ghe.example.com — gh auth login --hostname ghe.example.com"
	if got := s.IdentityWarning(1); got != want {
		t.Errorf("%q", got)
	}
	s.gh = append(s.gh, hostfacts.GHAccount{Host: "GHE.example.com", User: "vyskocilm"})
	if got := s.IdentityWarning(1); got != "" {
		t.Errorf("logged in, still warned: %q", got)
	}
}
