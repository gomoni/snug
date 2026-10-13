package ingest

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/hostfacts"
)

func keyOf(stem string, seed byte) hostfacts.SSHKey {
	blob := BlobForTest(seed)
	fp, _ := hostfacts.FingerprintOf(blob)
	return hostfacts.SSHKey{Stem: stem, Blob: blob, Fingerprint: fp, Comment: stem + "@laptop"}
}

func snugLike() SuggestInput {
	auth, sign, other := keyOf("github_auth", 1), keyOf("github_sign", 2), keyOf("backup", 3)
	return SuggestInput{
		Repo: &RepoFacts{
			Remotes: []Remote{ParseRemoteURL("git@github.com:gomoni/snug.git")},
			Authors: []Person{{"Michal V", "m@example.org", 193}, {"Other", "o@example.org", 7}},
			Signers: []Signature{{"gpg", "", "m@example.org", 193}, {"ssh", sign.Fingerprint, "m@example.org", 7}},
			Sampled: 200,
		},
		SSH:     SSHFacts{Hosts: ParseSSHConfig(strings.NewReader("Host github.com\n  IdentityFile ~/.ssh/github_auth\n"))},
		Keys:    []hostfacts.SSHKey{other, auth, sign},
		Authors: []hostfacts.GitAuthor{{Name: "Michal V", Email: "m@example.org"}},
		GH:      []hostfacts.GHAccount{{Host: "github.com", User: "vyskocilm", Active: true}, {Host: "github.com", User: "plainsof"}},
	}
}

func TestSuggestRanksWithReasons(t *testing.T) {
	p := Suggest(snugLike())
	if p == nil {
		t.Fatal("no pick")
	}
	if p.SSH.Value != "github_auth" || !strings.Contains(p.SSH.Why, "Host github.com") {
		t.Errorf("ssh %+v", p.SSH)
	}
	if p.Signing.Value != "github_sign" || !strings.Contains(p.Signing.Why, "7 of the last 200") {
		t.Errorf("signing %+v", p.Signing)
	}
	if p.Author.Value != "m@example.org" || !strings.Contains(p.Author.Why, "193 of the last 200") {
		t.Errorf("author %+v", p.Author)
	}
	if p.GH.Value != "vyskocilm" {
		t.Errorf("gh %+v", p.GH)
	}
}

func TestSuggestPrefersAProfilePinningTheSameAuthor(t *testing.T) {
	in := snugLike()
	in.Profiles = []Profile{
		{Name: "vyskocilm", Identity: ProfileIdentity{SSHHost: "github.com", Email: "m@example.org", GHUser: "vyskocilm", SSHKey: "{home}/.ssh/github_auth.pub"}},
		{Name: "plainsof", Identity: ProfileIdentity{SSHHost: "github.com", Email: "p@example.org", GHUser: "plainsof"}},
	}
	p := Suggest(in)
	if p.Profile.Value != "vyskocilm" || len(p.Conflict) != 0 {
		t.Errorf("profile %+v conflict %v", p.Profile, p.Conflict)
	}
	in.Profiles = append(in.Profiles, Profile{Name: "twin", Identity: ProfileIdentity{SSHHost: "github.com", Email: "m@example.org"}})
	if p := Suggest(in); p.Profile.Value != "" || len(p.Conflict) != 2 {
		t.Errorf("two profiles match, so none is chosen: %+v %v", p.Profile, p.Conflict)
	}
}

// TestSuggestNeverReturnsAValueFromTheRepo: a repository naming a stranger as
// author and a key the human does not have gets no author, no signing key and
// no ssh key out of that; only the human's own are ever returned.
func TestSuggestNeverReturnsAValueFromTheRepo(t *testing.T) {
	in := snugLike()
	in.Repo.Authors = []Person{{"Evil", "evil@attacker.example", 200}}
	in.Repo.Signers = []Signature{{"ssh", "SHA256:attackerkey", "evil@attacker.example", 200}}
	in.Repo.Remotes = []Remote{ParseRemoteURL("git@evil.example:ceo/repo.git")}
	p := Suggest(in)
	if p.Author.Value != "m@example.org" || p.Author.Why != "your global git author" {
		t.Errorf("author %+v", p.Author)
	}
	if p.Signing.Value != "" || p.SSH.Value != "" || p.GH.Value != "vyskocilm" && p.GH.Value != "" {
		t.Errorf("pick %+v", p)
	}
	if p.GH.Value == "ceo" {
		t.Error("the remote's owner became a gh login the human does not have")
	}
}

// TestSuggestAuthorNameIsTheHosts: commits that use the human's email under
// another name do not get that name suggested; the host's spelling is shown.
func TestSuggestAuthorNameIsTheHosts(t *testing.T) {
	in := snugLike()
	in.Repo.Authors = []Person{{"Mallory\x1b[2J", "m@example.org", 200}}
	if p := Suggest(in); p.Author.Value != "m@example.org" || p.AuthorName != "Michal V" {
		t.Errorf("author %+v name %q", p.Author, p.AuthorName)
	}
}

func TestSuggestSigningFromGitConfigAndAllowedSigners(t *testing.T) {
	in := snugLike()
	in.Repo.Signers = nil
	in.GitSigningKey = "~/.ssh/github_sign.pub"
	if p := Suggest(in); p.Signing.Value != "github_sign" || !strings.Contains(p.Signing.Why, "user.signingkey") {
		t.Errorf("%+v", p.Signing)
	}
	in.GitSigningKey = ""
	sign := keyOf("github_sign", 2)
	in.SSH.Signers = map[string][]string{"m@example.org": {sign.Fingerprint}}
	if p := Suggest(in); p.Signing.Value != "github_sign" || !strings.Contains(p.Signing.Why, "allowed_signers") {
		t.Errorf("%+v", p.Signing)
	}
}

func TestSuggestNeedsARemote(t *testing.T) {
	in := snugLike()
	in.Repo.Remotes = nil
	if Suggest(in) != nil || Suggest(SuggestInput{}) != nil {
		t.Error("a pick without a remote")
	}
}
