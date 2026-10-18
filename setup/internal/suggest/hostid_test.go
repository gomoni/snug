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

// labels is the sources of the ssh block, which has one of each kind the
// tests ask about whenever the host or a profile of yours pins ssh.
func labels(s Selection) []string {
	var out []string
	for _, c := range s.BlockChoices(BlockSSH) {
		out = append(out, c.Label)
	}
	return out
}

func allLabels(s Selection) []string {
	var out []string
	for _, b := range allBlocks {
		for _, c := range s.BlockChoices(b) {
			out = append(out, c.Label)
		}
	}
	return out
}

func TestFromHostIsSuggestedWhenNoProfileMatches(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget)
	for _, b := range allBlocks {
		if got := s.BlockChoices(b); len(got) != 2 || got[0].Label != "none" || got[1].Label != FromHost {
			t.Fatalf("%v choices %+v", b, got)
		}
		if s.Block[b] != 1 {
			t.Errorf("%v picked %d, want from host suggested", b, s.Block[b])
		}
	}
	if got := label(s, Identity); got != "vyskocilm" {
		t.Fatalf("row %q, want the new profile's name", got)
	}
	if got := s.Text[Desc]; got != "app, vyskocilm" {
		t.Errorf("desc %q: DESC names the new profile, not the choice's label", got)
	}
	if got := s.IdentityProfile(); got != "vyskocilm" {
		t.Errorf("profile %q", got)
	}
}

func TestFromHostIsOfferedAfterProfilesButNotSuggestedOverThem(t *testing.T) {
	f := hostFacts()
	f.Profiles = []ingest.Profile{profile("work", "github.com", "m@example.org")}
	s := Suggest(f, home, hostTarget)
	if got := labels(s); !slices.Equal(got, []string{"none", "work", FromHost}) {
		t.Fatalf("choices %q", got)
	}
	if got := label(s, Identity); got != "work" {
		t.Errorf("picked %q, the matching profile must win", got)
	}
}

func TestFromHostIsNotSuggestedOnATie(t *testing.T) {
	f := hostFacts()
	f.Profiles = []ingest.Profile{profile("a", "github.com", "m@example.org"), profile("b", "github.com", "m@example.org")}
	s := Suggest(f, home, hostTarget)
	if got := label(s, Identity); got != "none" {
		t.Errorf("picked %q; a tie between profiles must leave none, not the new entry", got)
	}
	if !slices.Contains(labels(s), FromHost) {
		t.Errorf("the entry is still offered: %q", labels(s))
	}
}

func TestFromHostNeedsAGitHubRemote(t *testing.T) {
	f := hostFacts()
	f.Repo = repoFacts("git@gitlab.com:vyskocilm/app.git", "m@example.org")
	if got := allLabels(Suggest(f, home, hostTarget)); slices.Contains(got, FromHost) {
		t.Errorf("offered for a gitlab.com remote: %q", got)
	}
	f = hostFacts()
	f.Repo = nil
	if got := allLabels(Suggest(f, home, hostTarget)); slices.Contains(got, FromHost) {
		t.Errorf("offered with no repository: %q", got)
	}
}

func TestFromHostBlocksAreTheFoundFacts(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget)
	for b, want := range map[Block]string{
		BlockSSH: "github.com  github_auth",
		BlockGit: "Michal V <m@example.org>",
		BlockGH:  "github.com/vyskocilm",
	} {
		if got := s.IdentityDetail(b, idx(t, s, b, FromHost)); !slices.Equal(got, []string{want}) {
			t.Errorf("%v: %q, want %q", b, got, want)
		}
	}
	var switches []string
	for _, it := range s.IdentityItems() {
		if it.IsPart {
			if !it.On {
				t.Errorf("switch %q is off by default", it.Text)
			}
			switches = append(switches, strings.SplitN(it.Text, "  ", 2)[0])
		}
	}
	if !slices.Equal(switches, []string{"sign github_sign"}) {
		t.Errorf("switches %q", switches)
	}
}

func TestFromHostOmitsWhatHostDoesNotSay(t *testing.T) {
	f := hostFacts()
	f.GH, f.Authors, f.GitSigningKey = nil, nil, ""
	f.Repo = repoFacts("git@github.com:vyskocilm/app.git", "stranger@example.net")
	s := Suggest(f, home, hostTarget)
	if got := s.BlockChoices(BlockSSH); len(got) != 2 || got[1].Label != FromHost {
		t.Errorf("ssh %+v", got)
	}
	for _, b := range []Block{BlockGit, BlockGH} {
		if got := s.BlockChoices(b); len(got) != 1 {
			t.Errorf("%v offers %+v: the commits' own author is not a host fact", b, got)
		}
	}
	for _, it := range s.IdentityItems() {
		if it.IsPart {
			t.Errorf("switch %q without a part to switch", it.Text)
		}
	}
}

func TestFromHostNothingFoundOffersNothing(t *testing.T) {
	f := hostFacts()
	f.GH, f.Authors, f.GitSigningKey, f.Keys = nil, nil, "", nil
	f.SSH = ingest.SSHFacts{}
	f.Repo = repoFacts("git@github.com:vyskocilm/app.git", "stranger@example.net")
	if got := allLabels(Suggest(f, home, hostTarget)); slices.Contains(got, FromHost) {
		t.Errorf("offered with no part: %q", got)
	}
}

func TestFromHostName(t *testing.T) {
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

func TestFromHostSwitchTogglesAndReverts(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget)
	off := s.WithPart(PartSigning, false)
	if !s.PartOn(PartSigning) || off.PartOn(PartSigning) {
		t.Fatalf("WithPart must copy: original %v, copy %v", s.PartOn(PartSigning), off.PartOn(PartSigning))
	}
	if !off.Changed(Identity) {
		t.Errorf("a switched-off part must mark the row changed")
	}
	if off.Revert(Identity).Changed(Identity) || !off.Revert(Identity).PartOn(PartSigning) {
		t.Errorf("revert must switch the part back on")
	}
	if got := s.WithBlock(BlockGit, 0); got.Changed(Identity) != true || s.Block[BlockGit] != 1 {
		t.Errorf("picking none moves off the suggestion, and WithBlock must copy")
	}
}

func TestBuildFromHostGolden(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget)
	d, refused := Build(s, hostFor(hostTarget), nil)
	id, msg := BuildIdentity(s, hostFor(hostTarget))
	if len(refused) != 0 || msg != "" || id == nil {
		t.Fatalf("refused %v msg %q id %v", refused, msg, id)
	}
	if !slices.Contains(d.Includes(), "vyskocilm") {
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

func TestBuildFromHostWritesOnlyTheBlocksPickedFromIt(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget).WithBlock(BlockGH, 0).WithPart(PartSigning, false)
	id, msg := BuildIdentity(s, hostFor(hostTarget))
	if msg != "" {
		t.Fatalf("msg %q", msg)
	}
	out := id.Render()
	for _, bad := range []string{"identity.gh", "signing_key"} {
		if strings.Contains(out, bad) {
			t.Errorf("%s written though not picked:\n%s", bad, out)
		}
	}
	for _, good := range []string{"identity.ssh", "identity.git", `{home}/.ssh/github_auth.pub`} {
		if !strings.Contains(out, good) {
			t.Errorf("%s missing:\n%s", good, out)
		}
	}
	s = s.WithBlock(BlockGit, 0)
	id, _ = BuildIdentity(s, hostFor(hostTarget))
	if out := id.Render(); strings.Contains(out, "identity.git") || !strings.Contains(out, "identity.ssh") {
		t.Errorf("only ssh was picked from the host:\n%s", out)
	}
}

func TestBuildFromHostSignNeedsSSHFromTheHost(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget).WithBlock(BlockSSH, 0)
	d, refused := Build(s, hostFor(hostTarget), nil)
	if !strings.Contains(refused[Identity], "sign needs the ssh and git parts") {
		t.Errorf("Build refused %v", refused)
	}
	if _, msg := BuildIdentity(s, hostFor(hostTarget)); !strings.Contains(msg, "sign needs the ssh and git parts") {
		t.Errorf("BuildIdentity msg %q", msg)
	}
	if d == nil {
		t.Errorf("no draft")
	}
	if got := s.BlockProblem(BlockGit, 1); !strings.Contains(got, "sign needs") {
		t.Errorf("the git section's from host line must say so: %q", got)
	}
	if _, refused := Build(s.WithPart(PartSigning, false), hostFor(hostTarget), nil); refused[Identity] != "" {
		t.Errorf("sign off, git alone from the host is writable: %v", refused)
	}
}

func TestBuildIdentityIsNilForOtherChoices(t *testing.T) {
	s := noIdentity(Suggest(hostFacts(), home, hostTarget))
	if d, msg := BuildIdentity(s, hostFor(hostTarget)); d != nil || msg != "" {
		t.Errorf("none picked: %v %q", d, msg)
	}
}

func TestFromHostWhyCarriesReasonAndAbuse(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget)
	for _, it := range s.IdentityItems() {
		if !it.IsPart && it.Text != FromHost || it.IsPart && it.Part == PartGHBinary {
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
		if it.IsPart && it.Part == PartGHBinary {
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
	s := Suggest(f, home, hostTarget).WithBlock(BlockGH, 0)
	if it, ok := binaryLine(s); ok {
		t.Errorf("line shown with no gh source: %q", it.Text)
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
	for i := range s.BlockChoices(BlockGH) {
		for _, l := range s.IdentityDetail(BlockGH, i) {
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
