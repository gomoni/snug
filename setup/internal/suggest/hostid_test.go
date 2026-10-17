package suggest

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/draft"
	"github.com/gomoni/snug/setup/internal/hostfacts"
	"github.com/gomoni/snug/setup/internal/ingest"
)

const hostTarget = "/home/alice/work/app"

func key(stem string) hostfacts.SSHKey {
	return hostfacts.SSHKey{Stem: stem, Path: home + "/.ssh/" + stem + ".pub", Blob: "AAAA" + stem, Comment: stem + "@laptop"}
}

// hostFacts is a host with a github.com remote, one gh login, a global git
// author, an ssh config line for the remote's host and a git signing key, and
// no profile of the person's own.
func hostFacts() ingest.Facts {
	return ingest.Facts{
		Repo:          repoFacts("git@github.com:vyskocilm/app.git", "m@example.org"),
		SSH:           ingest.SSHFacts{Hosts: ingest.ParseSSHConfig(strings.NewReader("Host github.com\n  IdentityFile ~/.ssh/github_auth\n"))},
		Keys:          []hostfacts.SSHKey{key("github_auth"), key("github_sign")},
		Authors:       []hostfacts.GitAuthor{{Name: "Michal V", Email: "m@example.org"}},
		GH:            []hostfacts.GHAccount{{Host: "github.com", User: "vyskocilm", Active: true}},
		GitSigningKey: home + "/.ssh/github_sign.pub",
		GHInstalled:   true,
	}
}

// statted makes every path exist as a regular file, so a draft stages the
// path a test names without the host having it.
func statted(t *testing.T, target string) draft.Host {
	f := filepath.Join(t.TempDir(), "gh")
	if err := os.WriteFile(f, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	h := hostFor(target)
	h.Stat = func(string) (fs.FileInfo, error) { return os.Stat(f) }
	return h
}

func labels(s Selection) []string {
	var out []string
	for _, c := range s.Rows[Identity].Choices {
		out = append(out, c.Label)
	}
	return out
}

func TestNewFromHostIsSuggestedWhenNoProfileMatches(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget)
	if got := labels(s); !slices.Equal(got, []string{"none", "new from host"}) {
		t.Fatalf("choices %q", got)
	}
	if got := label(s, Identity); got != NewFromHost {
		t.Fatalf("picked %q, want the new entry suggested", got)
	}
	if got := s.Text[Desc]; got != "app, vyskocilm" {
		t.Errorf("desc %q: DESC names the new profile, not the choice's label", got)
	}
	if got := s.IdentityProfile(); got != "vyskocilm" {
		t.Errorf("profile %q", got)
	}
}

func TestNewFromHostIsOfferedAfterProfilesButNotSuggestedOverThem(t *testing.T) {
	f := hostFacts()
	f.Profiles = []ingest.Profile{profile("work", "github.com", "m@example.org")}
	s := Suggest(f, home, hostTarget)
	if got := labels(s); !slices.Equal(got, []string{"none", "work", "new from host"}) {
		t.Fatalf("choices %q", got)
	}
	if got := label(s, Identity); got != "work" {
		t.Errorf("picked %q, the matching profile must win", got)
	}
}

func TestNewFromHostIsNotSuggestedOnATie(t *testing.T) {
	f := hostFacts()
	f.Profiles = []ingest.Profile{profile("a", "github.com", "m@example.org"), profile("b", "github.com", "m@example.org")}
	s := Suggest(f, home, hostTarget)
	if got := label(s, Identity); got != "none" {
		t.Errorf("picked %q; a tie between profiles must leave none, not the new entry", got)
	}
	if !slices.Contains(labels(s), NewFromHost) {
		t.Errorf("the entry is still offered: %q", labels(s))
	}
}

func TestNewFromHostNeedsAGitHubRemote(t *testing.T) {
	f := hostFacts()
	f.Repo = repoFacts("git@gitlab.com:vyskocilm/app.git", "m@example.org")
	if got := labels(Suggest(f, home, hostTarget)); slices.Contains(got, NewFromHost) {
		t.Errorf("offered for a gitlab.com remote: %q", got)
	}
	f = hostFacts()
	f.Repo = nil
	if got := labels(Suggest(f, home, hostTarget)); slices.Contains(got, NewFromHost) {
		t.Errorf("offered with no repository: %q", got)
	}
}

func TestNewFromHostPartsAreTheFoundFacts(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget)
	var lines []string
	for _, it := range s.IdentityItems() {
		if it.IsPart {
			if !it.On {
				t.Errorf("part %q is off by default", it.Text)
			}
			lines = append(lines, strings.SplitN(it.Text, "  ", 2)[0])
		}
	}
	want := []string{"ssh github.com github_auth", "sign github_sign", "git Michal V <m@example.org>", "gh github.com/vyskocilm"}
	if !slices.Equal(lines, want) {
		t.Errorf("parts %q, want %q", lines, want)
	}
}

func TestNewFromHostOmitsWhatHostDoesNotSay(t *testing.T) {
	f := hostFacts()
	f.GH, f.Authors, f.GitSigningKey = nil, nil, ""
	f.Repo = repoFacts("git@github.com:vyskocilm/app.git", "stranger@example.net")
	s := Suggest(f, home, hostTarget)
	var got []string
	for _, it := range s.IdentityItems() {
		if it.IsPart {
			got = append(got, strings.SplitN(it.Text, "  ", 2)[0])
		}
	}
	if !slices.Equal(got, []string{"ssh github.com github_auth"}) {
		t.Errorf("parts %q: the commits' own author is not a host fact", got)
	}
}

func TestNewFromHostNothingFoundOffersNothing(t *testing.T) {
	f := hostFacts()
	f.GH, f.Authors, f.GitSigningKey, f.Keys = nil, nil, "", nil
	f.SSH = ingest.SSHFacts{}
	f.Repo = repoFacts("git@github.com:vyskocilm/app.git", "stranger@example.net")
	if got := labels(Suggest(f, home, hostTarget)); slices.Contains(got, NewFromHost) {
		t.Errorf("offered with no part: %q", got)
	}
}

func TestNewFromHostName(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*ingest.Facts)
		want  string
		other string
	}{
		{"gh login", func(*ingest.Facts) {}, "vyskocilm", ""},
		{"email local part when gh is absent", func(f *ingest.Facts) { f.GH = nil }, "m", ""},
		{"key stem when there is no gh login and no author", func(f *ingest.Facts) {
			f.GH, f.Authors, f.GitSigningKey = nil, nil, ""
			f.Repo = repoFacts("git@github.com:vyskocilm/app.git", "stranger@example.net")
		}, "github-auth", ""},
		{"collides with a profile", func(f *ingest.Facts) {
			f.Profiles = []ingest.Profile{{Name: "vyskocilm"}, {Name: "vyskocilm-2"}}
		}, "vyskocilm-3", ""},
		{"collides with a file", func(f *ingest.Facts) {
			f.Files = []ingest.ProfileFile{{Name: "vyskocilm.toml"}}
		}, "vyskocilm-2", ""},
		{"gh login that is not a profile name", func(f *ingest.Facts) {
			f.GH = []hostfacts.GHAccount{{Host: "github.com", User: "bad_name", Active: true}}
		}, "m", ""},
	}
	for _, c := range cases {
		f := hostFacts()
		c.edit(&f)
		s := Suggest(f, home, hostTarget)
		if got := s.IdentityProfile(); got != c.want {
			t.Errorf("%s: name %q, want %q", c.name, got, c.want)
		}
	}
}

func TestNewFromHostSpacePartsToggleAndRevert(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget)
	off := s.WithPart(PartGit, false)
	if !s.PartOn(PartGit) || off.PartOn(PartGit) {
		t.Fatalf("WithPart must copy: original %v, copy %v", s.PartOn(PartGit), off.PartOn(PartGit))
	}
	if !off.Changed(Identity) {
		t.Errorf("a switched-off part must mark the row changed")
	}
	if off.Revert(Identity).Changed(Identity) || !off.Revert(Identity).PartOn(PartGit) {
		t.Errorf("revert must switch the part back on")
	}
	other := off.WithPick(Identity, 0)
	if other.Changed(Identity) != true {
		t.Errorf("picking none moves off the suggestion")
	}
	if got := s.WithPick(Identity, 0).WithPart(PartGit, false); got.Changed(Identity) != true {
		t.Errorf("changed")
	}
}

func TestBuildNewFromHostGolden(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget)
	d, refused := Build(s, hostFor(hostTarget), nil)
	id, msg := BuildIdentity(s, hostFor(hostTarget))
	if len(refused) != 0 || msg != "" || id == nil {
		t.Fatalf("refused %v msg %q id %v", refused, msg, id)
	}
	if !slices.Contains(d.Includes(), "vyskocilm") || slices.Contains(d.Includes(), "@git") {
		t.Errorf("project includes %v", d.Includes())
	}
	if strings.Contains(d.Render(), "identity") && strings.Contains(d.Render(), "[profile.app.identity") {
		t.Errorf("the project profile must not carry the identity block:\n%s", d.Render())
	}
	got := "# project\n" + d.Render() + "# identity\n" + id.Render()
	path := filepath.Join("testdata", "build-new-from-host.toml")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("differs from %s:\n%s", path, got)
	}
}

func TestBuildNewFromHostOnlyTheOnParts(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget).WithPart(PartGH, false).WithPart(PartSigning, false)
	id, msg := BuildIdentity(s, hostFor(hostTarget))
	if msg != "" {
		t.Fatalf("msg %q", msg)
	}
	out := id.Render()
	for _, bad := range []string{"identity.gh", "signing_key"} {
		if strings.Contains(out, bad) {
			t.Errorf("%s written though its part is off:\n%s", bad, out)
		}
	}
	for _, good := range []string{"identity.ssh", "identity.git", `{home}/.ssh/github_auth.pub`} {
		if !strings.Contains(out, good) {
			t.Errorf("%s missing:\n%s", good, out)
		}
	}
}

func TestBuildNewFromHostRefusesWhatItCannotWrite(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget)
	for _, c := range []struct {
		name string
		s    Selection
		want string
	}{
		{"sign without ssh", s.WithPart(PartSSH, false), "sign needs the ssh and git parts"},
		{"sign without git", s.WithPart(PartGit, false), "sign needs the ssh and git parts"},
		{"nothing on", s.WithPart(PartSSH, false).WithPart(PartSigning, false).WithPart(PartGit, false).WithPart(PartGH, false), "would pin nothing"},
	} {
		d, refused := Build(c.s, hostFor(hostTarget), nil)
		if !strings.Contains(refused[Identity], c.want) {
			t.Errorf("%s: Build refused %v", c.name, refused)
		}
		if _, msg := BuildIdentity(c.s, hostFor(hostTarget)); !strings.Contains(msg, c.want) {
			t.Errorf("%s: BuildIdentity msg %q", c.name, msg)
		}
		if d == nil {
			t.Errorf("%s: no draft", c.name)
		}
	}
}

func TestBuildIdentityIsNilForOtherChoices(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget).WithPick(Identity, 0)
	if d, msg := BuildIdentity(s, hostFor(hostTarget)); d != nil || msg != "" {
		t.Errorf("none picked: %v %q", d, msg)
	}
}

func TestNewFromHostWhyCarriesReasonAndAbuse(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget)
	for _, it := range s.IdentityItems() {
		if it.Choice != 1 || it.IsPart && it.Part == PartGHBinary {
			continue
		}
		joined := strings.Join(it.Why, "\n")
		if !strings.Contains(joined, draft.Abuse["identity"]) {
			t.Errorf("%q: the abuse sentence is missing from ?", it.Text)
		}
		if it.IsPart && (len(it.Why) < 2 || strings.HasPrefix(it.Why[0], "identity: ")) {
			t.Errorf("%q: no reason before the abuse sentence: %q", it.Text, it.Why)
		}
	}
}

func binaryLine(s Selection) (IdentItem, bool) {
	for _, it := range s.IdentityItems() {
		if it.IsPart && it.Part == PartGHBinary && it.Choice == s.Pick[Identity] {
			return it, true
		}
	}
	return IdentItem{}, false
}

func withGH(f ingest.Facts, path, resolved string) ingest.Facts {
	f.Binaries = map[string]ingest.Binary{"gh": {Path: path, Resolved: resolved}}
	return f
}

func TestGHBinaryNothingToStageUnderUsrOrAbsent(t *testing.T) {
	for name, f := range map[string]ingest.Facts{
		"under /usr":                withGH(hostFacts(), "/usr/bin/gh", "/usr/bin/gh"),
		"symlink into /usr":         withGH(hostFacts(), "/bin/gh", "/usr/bin/gh"),
		"not on PATH":               hostFacts(),
		"home path resolving /usr/": withGH(hostFacts(), home+"/bin/gh", "/usr/bin/gh"),
	} {
		s := Suggest(f, home, hostTarget)
		if it, ok := binaryLine(s); ok {
			t.Errorf("%s: staging line %q", name, it.Text)
		}
		d, _ := Build(s, hostFor(hostTarget), nil)
		if strings.Contains(d.Render(), "/snug/bin") {
			t.Errorf("%s: staged:\n%s", name, d.Render())
		}
	}
}

func TestGHBinaryOutsideUsrIsStagedByDefaultAndToggles(t *testing.T) {
	f := withGH(hostFacts(), home+"/bin/gh", home+"/bin/gh")
	s := Suggest(f, home, hostTarget)
	it, ok := binaryLine(s)
	if !ok || it.Text != "gh binary  ~/bin/gh → /snug/bin/gh (not in /usr)" || !it.On {
		t.Fatalf("line %+v ok=%v", it, ok)
	}
	if !strings.Contains(strings.Join(it.Why, " "), "the binary adds no authority of its own.") {
		t.Errorf("why %q", it.Why)
	}
	d, refused := Build(s, statted(t, hostTarget), nil)
	if !strings.Contains(d.Render(), `ro = ["{home}/bin/gh:/snug/bin/gh"]`) {
		t.Errorf("not staged in the project profile (refused %v):\n%s", refused, d.Render())
	}
	if id, _ := BuildIdentity(s, statted(t, hostTarget)); strings.Contains(id.Render(), "/snug/bin") {
		t.Errorf("the identity profile holds only the identity block:\n%s", id.Render())
	}
	d, _ = Build(s.WithPart(PartGHBinary, false), statted(t, hostTarget), nil)
	if strings.Contains(d.Render(), "/snug/bin") {
		t.Errorf("staged though switched off:\n%s", d.Render())
	}
	if !s.WithPart(PartGHBinary, false).Changed(Identity) {
		t.Errorf("switching the binary off must mark the row changed")
	}
}

func TestGHBinaryStagesWhereTheLinkPoints(t *testing.T) {
	f := withGH(hostFacts(), home+"/bin/gh", home+"/opt/gh_2.96.0/bin/gh")
	s := Suggest(f, home, hostTarget)
	if it, ok := binaryLine(s); !ok || it.Text != "gh binary  ~/opt/gh_2.96.0/bin/gh → /snug/bin/gh (not in /usr)" {
		t.Errorf("line %+v ok=%v", it, ok)
	}
	d, _ := Build(s, statted(t, hostTarget), nil)
	if !strings.Contains(d.Render(), `ro = ["{home}/opt/gh_2.96.0/bin/gh:/snug/bin/gh"]`) || strings.Contains(d.Render(), "{home}/bin/gh") {
		t.Errorf("snug refuses a grant that resolves through your own link; stage its destination:\n%s", d.Render())
	}
}

func TestGHBinaryNeedsAPinnedGH(t *testing.T) {
	f := withGH(hostFacts(), home+"/bin/gh", home+"/bin/gh")
	s := Suggest(f, home, hostTarget).WithPart(PartGH, false)
	if it, ok := binaryLine(s); ok {
		t.Errorf("line shown with the gh part off: %q", it.Text)
	}
	d, _ := Build(s, statted(t, hostTarget), nil)
	if strings.Contains(d.Render(), "/snug/bin") {
		t.Errorf("staged though nothing pins gh:\n%s", d.Render())
	}
}

func TestGHBinaryForAnExistingProfile(t *testing.T) {
	f := withGH(hostFacts(), home+"/bin/gh", home+"/bin/gh")
	f.Profiles = []ingest.Profile{profile("work", "github.com", "m@example.org")}
	s := Suggest(f, home, hostTarget)
	if got := label(s, Identity); got != "work" {
		t.Fatalf("picked %q", got)
	}
	if _, ok := binaryLine(s); !ok {
		t.Fatalf("a profile pinning gh gets the staging line")
	}
	d, _ := Build(s, statted(t, hostTarget), f.Profiles)
	if !strings.Contains(d.Render(), `"{home}/bin/gh:/snug/bin/gh"`) {
		t.Errorf("not staged:\n%s", d.Render())
	}
}

func TestGHBinaryAlreadyIncludedByTheIdentity(t *testing.T) {
	f := withGH(hostFacts(), home+"/bin/gh", home+"/bin/gh")
	work := profile("work", "github.com", "m@example.org", "gh-cli")
	cli := ingest.Profile{Name: "gh-cli", RO: []string{"{home}/bin/gh:/snug/bin/gh"}}
	f.Profiles = []ingest.Profile{work, cli}
	s := Suggest(f, home, hostTarget)
	if it, ok := binaryLine(s); ok {
		t.Errorf("staging line %q although work includes gh-cli", it.Text)
	}
	d, _ := Build(s, statted(t, hostTarget), f.Profiles)
	if strings.Contains(d.Render(), "/snug/bin") || strings.Contains(d.Render(), `"gh-cli"`) {
		t.Errorf("project profile restages or re-includes:\n%s", d.Render())
	}
	found := false
	for i := range s.Rows[Identity].Choices {
		for _, l := range s.IdentityDetail(i) {
			found = found || l == "also includes: gh-cli"
		}
	}
	if !found {
		t.Errorf("the also-includes line is gone")
	}
}

func TestGHBinaryProfileThatStagesIsSuggestedForInclusion(t *testing.T) {
	f := withGH(hostFacts(), home+"/bin/gh", home+"/bin/gh")
	cli := ingest.Profile{Name: "gh-cli", Description: "my gh", RO: []string{"{home}/bin/gh:/snug/bin/gh"}}
	f.Profiles = []ingest.Profile{profile("work", "github.com", "m@example.org"), cli}
	s := Suggest(f, home, hostTarget)
	it, ok := binaryLine(s)
	if !ok || !strings.Contains(it.Text, "include gh-cli") {
		t.Fatalf("line %+v ok=%v", it, ok)
	}
	d, _ := Build(s, statted(t, hostTarget), f.Profiles)
	if !slices.Contains(d.Includes(), "gh-cli") || strings.Contains(d.Render(), "/snug/bin") {
		t.Errorf("want an include of gh-cli and no ro of its own:\n%s", d.Render())
	}
	d, _ = Build(s.WithPart(PartGHBinary, false), statted(t, hostTarget), f.Profiles)
	if slices.Contains(d.Includes(), "gh-cli") {
		t.Errorf("included though switched off: %v", d.Includes())
	}
}

func TestToolTableIsTheOnePlace(t *testing.T) {
	if got := ToolBinaries(); !slices.Equal(got, []string{"gh"}) {
		t.Errorf("tools %q", got)
	}
}
