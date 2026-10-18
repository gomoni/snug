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
	sshA = ingest.ProfileIdentity{SSHKey: "{home}/.ssh/a.pub", SSHHost: "github.com"}
	ghA  = ingest.ProfileIdentity{GHUser: "a-user"}
	ghB  = ingest.ProfileIdentity{GHUser: "b-user"}
	gitB = ingest.ProfileIdentity{GitName: "B", Email: "b@example.org"}
)

func merge(ids ...ingest.ProfileIdentity) ingest.ProfileIdentity {
	var out ingest.ProfileIdentity
	for _, id := range ids {
		if id.SSHKey != "" || id.SSHHost != "" {
			out.SSHKey, out.SSHHost = id.SSHKey, id.SSHHost
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
	if name, _ := s.Effective(BlockGH); name != "" {
		t.Errorf("no effective gh source while the pins disagree: %q", name)
	}
}

func TestNoneDoesNotRemoveAnIncludedProfilesPin(t *testing.T) {
	ps := []ingest.Profile{prof("a", merge(sshA, ghA))}
	s := noRemote(ps...)
	s = s.WithBlock(BlockSSH, idx(t, s, BlockSSH, "a"))
	name, locked := s.Effective(BlockGH)
	if name != "a" || !locked {
		t.Fatalf("effective gh %q locked %v: a is included for ssh and pins gh", name, locked)
	}
	if s.Block[BlockGH] != 0 {
		t.Errorf("another block's pick was changed: %d", s.Block[BlockGH])
	}
	if n, v, ok := s.Locked(BlockGH); !ok || n != "a" || v != "a-user" {
		t.Errorf("locked %q %q %v", n, v, ok)
	}
	picked := s.WithBlock(BlockGH, 0)
	if name, _ := picked.Effective(BlockGH); name != "a" {
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
	if back.Changed(Identity) || !back.PartOn(PartSigning) {
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
