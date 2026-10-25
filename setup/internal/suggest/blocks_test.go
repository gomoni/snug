package suggest

import (
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/setup/internal/ingest"
)

const blocksTarget = "/home/alice/work/app"

func prof(name string, id ingest.ProfileIdentity) ingest.Profile {
	return ingest.Profile{Name: name, File: "accounts.toml", Dir: "/home/alice/.config/snug/profiles.d", Identity: id}
}

var (
	sshA = ingest.ProfileIdentity{SSHKey: "{home}/.ssh/a.pub", SSHHost: "github.com", SSHAgent: "proxy"}
	ghA  = ingest.ProfileIdentity{GHUser: "a-user", GHHost: "github.com"}
	ghB  = ingest.ProfileIdentity{GHUser: "b-user", GHHost: "github.com"}
	gitB = ingest.ProfileIdentity{GitName: "B", Email: "b@example.org"}
)

func merge(ids ...ingest.ProfileIdentity) ingest.ProfileIdentity {
	var out ingest.ProfileIdentity
	for _, id := range ids {
		if id.SSHKey != "" || id.SSHHost != "" {
			out.SSHKey, out.SSHHost, out.SSHAgent = id.SSHKey, id.SSHHost, id.SSHAgent
		}
		if id.GitName != "" || id.Email != "" || id.SigningKey != "" {
			out.GitName, out.Email, out.SigningKey = id.GitName, id.Email, id.SigningKey
		}
		if id.GHUser != "" || id.GHHost != "" {
			out.GHUser, out.GHHost = id.GHUser, id.GHHost
		}
	}
	return out
}

// noRemote is a facts set with the given profiles and nothing suggested, so a
// test picks every block itself.
func noRemote(ps ...ingest.Profile) Selection {
	return Suggest(ingest.Facts{Profiles: ps}, home, blocksTarget)
}

func TestOneMatchedProfileComesFromEveryBlockItPins(t *testing.T) {
	f := ingest.Facts{
		Profiles: []ingest.Profile{prof("a", merge(sshA, ghA)), prof("b", merge(gitB, ghB))},
		Repo:     repoFacts("git@github.com:gomoni/snug.git", "b@example.org"),
	}
	s := Suggest(f, home, blocksTarget)
	if got := label(s, Identity); got != "b" {
		t.Fatalf("row %q, want b", got)
	}
	want := map[Block]string{BlockSSH: "none", BlockGit: "b", BlockGH: "b"}
	for b, name := range want {
		if got := s.BlockChoices(b)[s.Block[b]].Label; got != name {
			t.Errorf("%v: %q, want %q", b, got, name)
		}
	}
	if _, refused := Build(s, hostFor(blocksTarget), f.Profiles); len(refused) != 0 {
		t.Errorf("refused %v", refused)
	}
}

func TestMixedBlocksComposeWithoutRefusal(t *testing.T) {
	ps := []ingest.Profile{prof("a", sshA), prof("b", ghB)}
	s := noRemote(ps...)
	s = s.WithBlock(BlockSSH, idx(t, s, BlockSSH, "a")).WithBlock(BlockGH, idx(t, s, BlockGH, "b"))
	if got := label(s, Identity); got != "ssh a, gh b" {
		t.Errorf("row %q", got)
	}
	d, refused := Build(s, hostFor(blocksTarget), ps)
	if len(refused) != 0 {
		t.Errorf("refused %v", refused)
	}
	if inc := d.Includes(); !slices.Contains(inc, "a") || !slices.Contains(inc, "b") {
		t.Errorf("includes %v", inc)
	}
	if got := s.Text[Desc]; got != "app, a" {
		t.Errorf("desc %q follows the first pinned block", got)
	}
	if !s.Changed(Identity) {
		t.Errorf("picks off the suggestion must mark the row")
	}
}

func TestConflictingProfilesRefuseOnTheIdentityRow(t *testing.T) {
	ps := []ingest.Profile{prof("a", merge(sshA, ghA)), prof("b", ghB)}
	s := noRemote(ps...)
	s = s.WithBlock(BlockSSH, idx(t, s, BlockSSH, "a")).WithBlock(BlockGH, idx(t, s, BlockGH, "b"))
	_, refused := Build(s, hostFor(blocksTarget), ps)
	if want := `profiles "a" and "b" pin different identity.gh`; !strings.Contains(refused[Identity], want) {
		t.Fatalf("refused %q, want %q", refused[Identity], want)
	}
	if got := s.BlockProblem(BlockGH, idx(t, s, BlockGH, "b")); !strings.Contains(got, "pin different identity.gh") {
		t.Errorf("the offending line carries no problem: %q", got)
	}
	if got := s.BlockProblem(BlockGH, idx(t, s, BlockGH, "a")); got != "" {
		t.Errorf("a with a is not a conflict: %q", got)
	}
	// Order of the picks does not change which name comes first.
	r := noRemote(ps...)
	r = r.WithBlock(BlockGH, idx(t, r, BlockGH, "b")).WithBlock(BlockSSH, idx(t, r, BlockSSH, "a"))
	if _, again := Build(r, hostFor(blocksTarget), ps); again[Identity] != refused[Identity] {
		t.Errorf("refusal depends on pick order: %q vs %q", again[Identity], refused[Identity])
	}
}

func TestConflictBetweenTwoLockedPinsIsRefusedToo(t *testing.T) {
	ps := []ingest.Profile{prof("a", merge(sshA, ghA)), prof("b", merge(gitB, ghB))}
	s := noRemote(ps...)
	s = s.WithBlock(BlockSSH, idx(t, s, BlockSSH, "a")).WithBlock(BlockGit, idx(t, s, BlockGit, "b"))
	_, refused := Build(s, hostFor(blocksTarget), ps)
	if !strings.Contains(refused[Identity], "pin different identity.gh") {
		t.Errorf("a and b both pin gh and gh is picked none: %q", refused[Identity])
	}
	if _, _, _, ok := s.Locked(BlockGH); ok {
		t.Errorf("no effective gh source while the pins disagree")
	}
}

func TestNoneDoesNotRemoveAnIncludedProfilesPin(t *testing.T) {
	ps := []ingest.Profile{prof("a", merge(sshA, ghA))}
	s := noRemote(ps...)
	s = s.WithBlock(BlockSSH, idx(t, s, BlockSSH, "a"))
	name, _, _, locked := s.Locked(BlockGH)
	if name != "a" || !locked {
		t.Fatalf("effective gh %q locked %v: a is included for ssh and pins gh", name, locked)
	}
	if s.Block[BlockGH] != 0 {
		t.Errorf("another block's pick was changed: %d", s.Block[BlockGH])
	}
	if n, via, v, ok := s.Locked(BlockGH); !ok || n != "a" || via != "" || v != "github.com/a-user" {
		t.Errorf("locked %q %q %q %v", n, via, v, ok)
	}
	picked := s.WithBlock(BlockGH, 0)
	if name, _, _, _ := picked.Locked(BlockGH); name != "a" {
		t.Errorf("picking none removed the pin: %q", name)
	}
	d, _ := Build(picked, hostFor(blocksTarget), ps)
	if inc := d.Includes(); !slices.Contains(inc, "a") {
		t.Errorf("includes %v", inc)
	}
	if got := label(s, Identity); got != "a" {
		t.Errorf("row %q: every pinned block comes from a", got)
	}
}

func TestSigningFromAProfileNeedsSSHFromTheSameProfile(t *testing.T) {
	signer := prof("a", ingest.ProfileIdentity{GitName: "A", Email: "a@example.org", SigningKey: "{home}/.ssh/sign.pub"})
	other := prof("b", sshA)
	ps := []ingest.Profile{signer, other}
	s := noRemote(ps...)
	s = s.WithBlock(BlockGit, idx(t, s, BlockGit, "a")).WithBlock(BlockSSH, idx(t, s, BlockSSH, "b"))
	_, refused := Build(s, hostFor(blocksTarget), ps)
	if want := "signing_key needs identity.ssh from the same profile"; !strings.Contains(refused[Identity], want) {
		t.Errorf("refused %q, want %q", refused[Identity], want)
	}
	withSSH := ingest.Profile{Name: "a", File: "accounts.toml", Identity: merge(signer.Identity, sshA)}
	ok := noRemote(withSSH)
	ok = ok.WithBlock(BlockGit, idx(t, ok, BlockGit, "a"))
	if _, refused := Build(ok, hostFor(blocksTarget), []ingest.Profile{withSSH}); refused[Identity] != "" {
		t.Errorf("signing with ssh from the same profile: %q", refused[Identity])
	}
}

func TestFromHostBlocksGoIntoOneNewProfile(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget).WithBlock(BlockGit, 0)
	d, refused := Build(s, hostFor(hostTarget), nil)
	if refused[Identity] != "" {
		t.Fatalf("ssh and gh from the host, git none: %v", refused)
	}
	if inc := d.Includes(); !slices.Contains(inc, "vyskocilm") {
		t.Errorf("includes %v", inc)
	}
	id, msg := BuildIdentity(s, hostFor(hostTarget))
	if msg != "" || id == nil || id.Name != "vyskocilm" {
		t.Fatalf("identity %v %q", id, msg)
	}
	out := id.Render()
	if !strings.Contains(out, "identity.ssh") || !strings.Contains(out, "identity.gh") || strings.Contains(out, "identity.git") {
		t.Errorf("the new profile holds exactly the blocks picked from the host:\n%s", out)
	}
}

func TestRevertRestoresBlocksAndParts(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget)
	changed := noIdentity(s).WithPart(PartSigning, false)
	if !changed.Changed(Identity) {
		t.Fatal("not changed")
	}
	back := changed.Revert(Identity)
	if back.Changed(Identity) || !back.Parts[PartSigning] {
		t.Errorf("revert left blocks %v parts %v", back.Block, back.Parts)
	}
	if !changed.Changed(Identity) {
		t.Errorf("Revert modified its receiver")
	}
	if all := changed.RevertAll(); all.Changed(Identity) {
		t.Errorf("RevertAll left the identity changed")
	}
}

func TestSummaryNamesTheNewProfileForHostBlocks(t *testing.T) {
	s := Suggest(hostFacts(), home, hostTarget)
	if got := label(s, Identity); got != "vyskocilm" {
		t.Errorf("all blocks from host: %q", got)
	}
	if got := s.Current(Identity).Why; got != "from your host: ssh git gh" {
		t.Errorf("why %q", got)
	}
	if got := noIdentity(s).Current(Identity).Label; got != "none" {
		t.Errorf("no block: %q", got)
	}
}

func TestIncludedIsEveryPickedProfile(t *testing.T) {
	ps := []ingest.Profile{prof("a", sshA), prof("b", ghB)}
	s := noRemote(ps...)
	s = s.WithBlock(BlockGH, idx(t, s, BlockGH, "b")).WithBlock(BlockSSH, idx(t, s, BlockSSH, "a"))
	if got := s.Included(); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("included %v", got)
	}
	if got := s.IdentityProfile(); got != "a" {
		t.Errorf("first %q", got)
	}
}

func TestWithBlockCopies(t *testing.T) {
	ps := []ingest.Profile{prof("a", sshA)}
	s := noRemote(ps...)
	n := s.WithBlock(BlockSSH, 1)
	if s.Block[BlockSSH] != 0 || n.Block[BlockSSH] != 1 {
		t.Errorf("WithBlock shared its map: %v %v", s.Block, n.Block)
	}
}

func TestFromHostCountsAsAProfileInAConflict(t *testing.T) {
	f := hostFacts()
	f.Profiles = []ingest.Profile{prof("a", merge(sshA, ghA))}
	s := Suggest(f, home, hostTarget)
	s = noIdentity(s).WithBlock(BlockSSH, idx(t, s, BlockSSH, "a")).WithBlock(BlockGH, idx(t, s, BlockGH, FromHost))
	_, refused := Build(s, hostFor(hostTarget), f.Profiles)
	if want := `profiles "a" and "vyskocilm" pin different identity.gh`; !strings.Contains(refused[Identity], want) {
		t.Errorf("refused %q, want %q", refused[Identity], want)
	}
	if id, _ := BuildIdentity(s, hostFor(hostTarget)); id == nil || !strings.Contains(id.Render(), "identity.gh") || strings.Contains(id.Render(), "identity.ssh") {
		t.Errorf("the new profile holds only gh")
	}
}

func refusal(s Selection, ps []ingest.Profile) string {
	_, refused := Build(s, hostFor(blocksTarget), ps)
	return refused[Identity]
}

func TestIncludesJoinTheFold(t *testing.T) {
	ps := []ingest.Profile{
		{Name: "A", File: "a.toml", Include: []string{"B"}, Identity: ingest.ProfileIdentity{SSHKey: "{home}/.ssh/k1.pub", SSHHost: "github.com", SSHAgent: "proxy"}},
		prof("B", ghA),
		prof("C", ghB),
	}
	s := noRemote(ps...)
	s = s.WithBlock(BlockSSH, idx(t, s, BlockSSH, "A"))
	name, via, val, ok := s.Locked(BlockGH)
	if !ok || name != "B" || via != "A" || val != "github.com/a-user" {
		t.Fatalf("locked %q via %q %q %v: B is pulled in by A", name, via, val, ok)
	}
	if got := s.Included(); !slices.Equal(got, []string{"A"}) {
		t.Errorf("only the picked profile is included: %v", got)
	}
	if r := refusal(s, ps); r != "" {
		t.Errorf("refused %q", r)
	}
	c := s.WithBlock(BlockGH, idx(t, s, BlockGH, "C"))
	if want := `profiles "B" and "C" pin different identity.gh`; !strings.Contains(refusal(c, ps), want) {
		t.Errorf("refused %q, want %q", refusal(c, ps), want)
	}
	if got := s.BlockProblem(BlockGH, idx(t, s, BlockGH, "C")); got != "conflicts with B on gh" {
		t.Errorf("C's line carries no problem: %q", got)
	}
}

func TestAnSSHBlockHoldingOnlyAgentNoneIsNotOffered(t *testing.T) {
	n := prof("N", ingest.ProfileIdentity{SSHAgent: "none"})
	if got := noRemote(n).BlockChoices(BlockSSH); len(got) != 1 {
		t.Errorf("an ssh block holding only agent = none pins nothing: %+v", got)
	}
}

func TestSSHAgentDifferenceConflicts(t *testing.T) {
	k := "{home}/.ssh/k.pub"
	ps := []ingest.Profile{
		prof("A", ingest.ProfileIdentity{SSHKey: k, SSHAgent: "proxy"}),
		prof("B", ingest.ProfileIdentity{SSHKey: k, GitName: "B", Email: "b@example.org"}),
		prof("C", ingest.ProfileIdentity{SSHKey: k, GHUser: "u", GHHost: "github.com"}),
	}
	// B and C are no conflict between them, A differs from both in the agent.
	s := noRemote(ps...)
	s = s.WithBlock(BlockSSH, idx(t, s, BlockSSH, "A")).WithBlock(BlockGit, idx(t, s, BlockGit, "B"))
	if want := `profiles "A" and "B" pin different identity.ssh`; !strings.Contains(refusal(s, ps), want) {
		t.Errorf("refused %q, want %q", refusal(s, ps), want)
	}
	same := noRemote(ps[1:]...)
	same = same.WithBlock(BlockSSH, idx(t, same, BlockSSH, "B")).WithBlock(BlockGH, idx(t, same, BlockGH, "C"))
	if r := refusal(same, ps[1:]); strings.Contains(r, "different identity.ssh") {
		t.Errorf("identical blocks conflict: %q", r)
	}
}

func TestSigningNeedsAgentAndASharedOwner(t *testing.T) {
	k := "{home}/.ssh/k.pub"
	git := ingest.ProfileIdentity{GitName: "X", Email: "x@example.org", SigningKey: "{home}/.ssh/s.pub"}
	noAgent := prof("A", merge(ingest.ProfileIdentity{SSHKey: k}, git))
	s := noRemote(noAgent)
	s = s.WithBlock(BlockGit, idx(t, s, BlockGit, "A"))
	if want := `identity.ssh.agent = "proxy"`; !strings.Contains(refusal(s, []ingest.Profile{noAgent}), want) {
		t.Errorf("one profile, ssh without an agent: %q", refusal(s, []ingest.Profile{noAgent}))
	}
	work := prof("work", merge(ingest.ProfileIdentity{SSHKey: k, SSHAgent: "proxy"}, git))
	workGit := prof("work-git", ingest.ProfileIdentity{GitName: "X", Email: "x@example.org", SigningKey: "{home}/.ssh/s.pub"})
	ps := []ingest.Profile{work, workGit}
	ok := noRemote(ps...)
	ok = ok.WithBlock(BlockSSH, idx(t, ok, BlockSSH, "work")).WithBlock(BlockGit, idx(t, ok, BlockGit, "work-git"))
	if r := refusal(ok, ps); r != "" {
		t.Errorf("identical git blocks, one owner is also the ssh owner: %q", r)
	}
	other := prof("other", ingest.ProfileIdentity{SSHKey: "{home}/.ssh/o.pub", SSHAgent: "proxy"})
	ps = []ingest.Profile{other, workGit}
	bad := noRemote(ps...)
	bad = bad.WithBlock(BlockSSH, idx(t, bad, BlockSSH, "other")).WithBlock(BlockGit, idx(t, bad, BlockGit, "work-git"))
	if want := "signing_key needs identity.ssh from the same profile"; !strings.Contains(refusal(bad, ps), want) {
		t.Errorf("no shared owner: %q", refusal(bad, ps))
	}
}

func TestHostsAreComparedAsWritten(t *testing.T) {
	ps := []ingest.Profile{
		prof("A", ingest.ProfileIdentity{GHUser: "u", GHHost: "github.com"}),
		prof("B", ingest.ProfileIdentity{GHUser: "u"}),
	}
	s := noRemote(ps...)
	s = s.WithBlock(BlockGH, idx(t, s, BlockGH, "A")).WithBlock(BlockSSH, 0)
	both := ingest.Profile{Name: "AB", Include: []string{"B"}, Identity: ingest.ProfileIdentity{GitName: "G", Email: "g@example.org"}}
	ps = append(ps, both)
	s = noRemote(ps...)
	s = s.WithBlock(BlockGH, idx(t, s, BlockGH, "A")).WithBlock(BlockGit, idx(t, s, BlockGit, "AB"))
	if want := `profiles "A" and "B" pin different identity.gh`; !strings.Contains(refusal(s, ps), want) {
		t.Errorf(`"" and "github.com" are different values: %q`, refusal(s, ps))
	}
}

func TestHalfNamedHostIsRefusedAcrossBlocks(t *testing.T) {
	ps := []ingest.Profile{
		prof("A", ingest.ProfileIdentity{SSHHost: "gitlab.com", SSHKey: "{home}/.ssh/k.pub", SSHAgent: "proxy"}),
		prof("B", ingest.ProfileIdentity{GHUser: "u"}),
	}
	s := noRemote(ps...)
	s = s.WithBlock(BlockSSH, idx(t, s, BlockSSH, "A")).WithBlock(BlockGH, idx(t, s, BlockGH, "B"))
	got := refusal(s, ps)
	if !strings.Contains(got, `profiles "A" and "B": identity.ssh.host = "gitlab.com" names a host and identity.gh.host does not`) {
		t.Errorf("refused %q", got)
	}
	named := []ingest.Profile{ps[0], prof("B", ingest.ProfileIdentity{GHUser: "u", GHHost: "gitlab.com"})}
	ok := noRemote(named...)
	ok = ok.WithBlock(BlockSSH, idx(t, ok, BlockSSH, "A")).WithBlock(BlockGH, idx(t, ok, BlockGH, "B"))
	if r := refusal(ok, named); r != "" {
		t.Errorf("both blocks name the host: %q", r)
	}
}

func TestALineIsMarkedForTheConflictItWouldCause(t *testing.T) {
	ps := []ingest.Profile{
		prof("A", merge(ingest.ProfileIdentity{SSHKey: "{home}/.ssh/k1.pub", SSHHost: "github.com", SSHAgent: "proxy"}, ghA)),
		prof("B", ghB),
	}
	s := noRemote(ps...)
	s = s.WithBlock(BlockGH, idx(t, s, BlockGH, "B"))
	if got := s.BlockProblem(BlockSSH, idx(t, s, BlockSSH, "A")); got != "conflicts with B on gh" {
		t.Errorf("ssh line for A carries %q", got)
	}
	if got := s.BlockProblem(BlockSSH, 0); got != "" {
		t.Errorf("none causes nothing: %q", got)
	}
}

// accountsToml is shaped like a real accounts.toml: two accounts, each pinning
// ssh, git and gh, with the host written out in ssh and gh.
func accountsToml(name, user, email string) ingest.Profile {
	return prof(name, ingest.ProfileIdentity{
		SSHKey: "{home}/.ssh/github_auth.pub", SSHHost: "github.com", SSHAgent: "proxy",
		GitName: "Michal V", Email: email, GHUser: user, GHHost: "github.com",
	})
}

func TestFromHostIsNotOfferedForWhatAProfileCovers(t *testing.T) {
	f := hostFacts()
	f.Profiles = []ingest.Profile{accountsToml("vyskocilm", "vyskocilm", "m@example.org")}
	s := Suggest(f, home, hostTarget)
	for _, b := range allBlocks {
		if slices.ContainsFunc(s.BlockChoices(b), func(c Choice) bool { return c.Label == FromHost }) {
			t.Errorf("%v offers from host for a value vyskocilm already pins", b)
		}
	}
	if got := label(s, Identity); got != "vyskocilm" || s.UsesHost() {
		t.Errorf("row %q", got)
	}

	other := accountsToml("vyskocilm", "vyskocilm", "m@example.org")
	other.Identity.SSHKey = "{home}/.ssh/another.pub"
	f.Profiles = []ingest.Profile{other}
	s = Suggest(f, home, hostTarget)
	has := func(b Block) bool {
		return slices.ContainsFunc(s.BlockChoices(b), func(c Choice) bool { return c.Label == FromHost })
	}
	if !has(BlockSSH) || has(BlockGit) || has(BlockGH) {
		t.Errorf("from host covers only what no profile covers: ssh %v git %v gh %v", has(BlockSSH), has(BlockGit), has(BlockGH))
	}
}

func TestHypotheticalProblemIsCompact(t *testing.T) {
	f := ingest.Facts{
		Profiles: []ingest.Profile{accountsToml("vyskocilm", "vyskocilm", "m@example.org"), accountsToml("plainsof", "plainsof", "p@example.org")},
		Repo:     repoFacts("git@github.com:gomoni/snug.git", "m@example.org"),
	}
	s := Suggest(f, home, hostTarget)
	if got := s.BlockProblem(BlockSSH, idx(t, s, BlockSSH, "plainsof")); got != "conflicts with vyskocilm on git, gh" {
		t.Errorf("compact text: %q", got)
	}
	if got := s.BlockProblem(BlockSSH, s.Block[BlockSSH]); got != "" {
		t.Errorf("the picked line has no problem: %q", got)
	}
}
