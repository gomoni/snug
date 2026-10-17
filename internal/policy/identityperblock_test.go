package policy

import (
	"reflect"
	"strings"
	"testing"
)

// Identity joins one block at a time: the same block set differently by two
// profiles refuses naming both, different blocks compose. These tests hold the
// three properties that rule rests on — every block is its own pin, an absent
// block grants nothing, and a rule reading two blocks still sees both when they
// come from two profiles.

func identityProfiles(ids map[ProfileName]Identity) (map[ProfileName]*Profile, []ProfileName) {
	reg := testRegistry()
	sel := append([]ProfileName{}, testDefaults...)
	for name, id := range ids {
		id := id
		reg[name] = &Profile{Name: name, Identity: &id}
		sel = append(sel, name)
	}
	return reg, sel
}

var (
	sshBlock = IdentitySSH{Key: "/home/u/.ssh/id_auth.pub", Agent: SSHAgentProxy}
	gitBlock = IdentityGit{Name: "Base Name", Email: "base@example.com"}
	ghBlock  = IdentityGh{User: "base-user"}
)

func TestIdentityPinPerBlockRefusesNamingBothOwners(t *testing.T) {
	differ := map[string][2]Identity{
		"ssh": {{SSH: sshBlock}, {SSH: IdentitySSH{Key: "/home/u/.ssh/other.pub", Agent: SSHAgentProxy}}},
		"git": {{Git: gitBlock}, {Git: IdentityGit{Name: "Other", Email: "other@example.com"}}},
		"gh":  {{Gh: ghBlock}, {Gh: IdentityGh{User: "other-user"}}},
	}
	for _, pin := range identityPins {
		pair, ok := differ[pin.Key]
		if !ok {
			t.Errorf("identity block %q has no case here; a block added to Identity needs one", pin.Key)
			continue
		}
		for _, order := range [][2]ProfileName{{"ident-a", "ident-b"}, {"ident-b", "ident-a"}} {
			t.Run(pin.Key+"/"+string(order[0]), func(t *testing.T) {
				reg, sel := identityProfiles(map[ProfileName]Identity{order[0]: pair[0], order[1]: pair[1]})
				_, err := Resolve(reg, sel, testCtx(), newFakeEnv())
				if err == nil {
					t.Fatalf("two profiles setting identity.%s differently resolved", pin.Key)
				}
				for _, want := range []string{"ident-a", "ident-b", "identity." + pin.Key} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("refusal does not name %q: %v", want, err)
					}
				}
			})
		}
	}
}

func TestIdentityDifferentBlocksCompose(t *testing.T) {
	ids := map[ProfileName]Identity{
		"acct-ssh": {SSH: sshBlock},
		"acct-git": {Git: gitBlock},
		"acct-gh":  {Gh: ghBlock},
	}
	reg, sel := identityProfiles(ids)
	p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("three profiles setting three different blocks refused: %v", err)
	}
	want := Identity{SSH: sshBlock, Git: gitBlock, Gh: ghBlock}
	if *p.Identity != want {
		t.Errorf("Identity = %+v, want %+v", *p.Identity, want)
	}
	wantOwners := map[string]ProfileName{"ssh": "acct-ssh", "git": "acct-git", "gh": "acct-gh"}
	if !reflect.DeepEqual(p.IdentityOwners, wantOwners) {
		t.Errorf("IdentityOwners = %v, want %v", p.IdentityOwners, wantOwners)
	}
	// Order: the fold sorts the selection, so a reversed selection is the same
	// policy; resolve it explicitly reversed to hold that.
	rev := append([]ProfileName{}, sel...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	q, err := Resolve(reg, rev, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if *q.Identity != *p.Identity || !reflect.DeepEqual(q.IdentityOwners, p.IdentityOwners) {
		t.Errorf("reversed selection resolved differently: %+v %v", *q.Identity, q.IdentityOwners)
	}
}

func TestIdentityNoneOnlySSHBlockDoesNotParticipate(t *testing.T) {
	reg, sel := identityProfiles(map[ProfileName]Identity{
		"no-agent":   {SSH: IdentitySSH{Agent: "none"}},
		"with-agent": {SSH: sshBlock},
	})
	p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("an ssh block holding only agent = none refused beside a real one: %v", err)
	}
	if p.Identity.SSH != sshBlock || p.IdentityOwners["ssh"] != "with-agent" {
		t.Errorf("ssh = %+v owned by %q, want the with-agent block", p.Identity.SSH, p.IdentityOwners["ssh"])
	}
}

func TestIdentityAbsentSSHBlockIsNoAgent(t *testing.T) {
	reg, sel := identityProfiles(map[ProfileName]Identity{"git-only": {Git: gitBlock}})
	p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if p.Identity.SSH.Agent != SSHNone {
		t.Fatalf("ssh.agent = %q with no ssh block, want SSHNone", p.Identity.SSH.Agent)
	}
	cfg := string(p.Mounts["/home/u/.gitconfig"].Content)
	for _, bad := range []string{"insteadOf", "gpgsign"} {
		if strings.Contains(cfg, bad) {
			t.Errorf("~/.gitconfig of a git-only identity carries %q:\n%s", bad, cfg)
		}
	}
	for _, m := range p.Mounts {
		if strings.HasPrefix(m.Guest, "/home/u/.ssh/") {
			t.Errorf("a git-only identity generated %s", m.Guest)
		}
	}
}

func TestIdentityGhOnlyGeneratesNoGitconfig(t *testing.T) {
	reg, sel := identityProfiles(map[ProfileName]Identity{"gh-only": {Gh: ghBlock}})
	p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Mounts["/home/u/.gitconfig"]; ok {
		t.Error("a gh-only identity generated ~/.gitconfig")
	}
	if _, ok := p.Env["GIT_CONFIG_GLOBAL"]; ok {
		t.Error("a gh-only identity set GIT_CONFIG_GLOBAL")
	}
}

func TestSigningKeyNeedsAgentAcrossProfiles(t *testing.T) {
	signing := IdentityGit{Name: "Base Name", Email: "base@example.com", SigningKey: "/home/u/.ssh/id_sign.pub"}
	t.Run("no ssh block anywhere", func(t *testing.T) {
		reg, sel := identityProfiles(map[ProfileName]Identity{"signer": {Git: signing}})
		_, err := Resolve(reg, sel, testCtx(), newFakeEnv())
		if err == nil || !strings.Contains(err.Error(), `"signer"`) ||
			!strings.Contains(err.Error(), "no selected profile sets identity.ssh") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("ssh block without agent elsewhere", func(t *testing.T) {
		reg, sel := identityProfiles(map[ProfileName]Identity{
			"signer": {Git: signing},
			"keyed":  {SSH: IdentitySSH{Key: "/home/u/.ssh/id_auth.pub"}},
		})
		_, err := Resolve(reg, sel, testCtx(), newFakeEnv())
		if err == nil || !strings.Contains(err.Error(), `"signer"`) || !strings.Contains(err.Error(), `"keyed"`) {
			t.Fatalf("err = %v, want it to name both profiles", err)
		}
	})
	t.Run("agent in another profile resolves", func(t *testing.T) {
		reg, sel := identityProfiles(map[ProfileName]Identity{
			"signer": {Git: signing},
			"agent":  {SSH: sshBlock},
		})
		p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(p.Mounts["/home/u/.gitconfig"].Content), "gpgsign = true") {
			t.Error("signing key with the agent from another profile did not generate signing config")
		}
	})
}

func TestHalfNamedHostAcrossProfiles(t *testing.T) {
	reg, sel := identityProfiles(map[ProfileName]Identity{
		"ghe":   {Gh: IdentityGh{Host: "ghe.example", User: "u"}},
		"keyed": {SSH: sshBlock},
	})
	_, err := Resolve(reg, sel, testCtx(), newFakeEnv())
	if err == nil || !strings.Contains(err.Error(), `"ghe"`) || !strings.Contains(err.Error(), `"keyed"`) {
		t.Fatalf("err = %v, want a half-named-host refusal naming both profiles", err)
	}
	reg, sel = identityProfiles(map[ProfileName]Identity{
		"ghe": {Gh: IdentityGh{Host: "ghe.example", User: "u"}},
		"git": {Git: gitBlock},
	})
	if _, err := Resolve(reg, sel, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("gh on a named host beside a git-only block refused: %v", err)
	}
}

func TestIdentityProvenancePerBlock(t *testing.T) {
	reg, sel := identityProfiles(map[ProfileName]Identity{
		"acct-ssh": {SSH: sshBlock},
		"acct-git": {Git: gitBlock},
	})
	p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Mounts["/home/u/.gitconfig"].From; !reflect.DeepEqual(got, []string{"identity:acct-git+acct-ssh"}) {
		t.Errorf("~/.gitconfig From = %v, want [identity:acct-git+acct-ssh]", got)
	}
	if got := p.Mounts["/home/u/.ssh/config"].From; !reflect.DeepEqual(got, []string{"identity:acct-ssh"}) {
		t.Errorf("~/.ssh/config From = %v, want [identity:acct-ssh]", got)
	}
	if got := p.IdentityProvenance("gh"); got != "(identity)" {
		t.Errorf("provenance of an unpinned block = %q", got)
	}
}

func TestConditionalEnvByIsBlockScoped(t *testing.T) {
	gitOnly := &Profile{Identity: &Identity{Git: gitBlock}}
	noneOnly := &Profile{Identity: &Identity{SSH: IdentitySSH{Agent: "none"}}}
	for _, c := range []struct {
		prof *Profile
		key  string
		want bool
	}{
		{gitOnly, "git", true},
		{gitOnly, "ssh", false},
		{gitOnly, "gh", false},
		{noneOnly, "ssh", false},
		{&Profile{}, "git", false},
	} {
		if got := profileSetsBlock(c.prof, c.key); got != c.want {
			t.Errorf("profileSetsBlock(%+v, %q) = %v, want %v", c.prof.Identity, c.key, got, c.want)
		}
	}
}

func TestIdentityPartitionIsDerivedFromTheType(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range identityFields {
		if f.Pin == "" || !strings.HasPrefix(f.Key, f.Pin+".") {
			t.Errorf("leaf %q records pin %q", f.Key, f.Pin)
		}
		seen[f.Pin] = true
	}
	for _, p := range identityPins {
		if !seen[p.Key] {
			t.Errorf("pin %q has no leaf", p.Key)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("mustIdentityPins accepted a top-level leaf that belongs to no block")
		}
	}()
	type bad struct {
		SSH  IdentitySSH `snug:"ssh"`
		Bare string      `snug:"bare"`
	}
	mustIdentityPins(reflect.TypeOf(bad{}))
}
