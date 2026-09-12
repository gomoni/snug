package profile

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── the one refusal #454's nesting introduced (internal/profile/file.go) ──
//
// [identity] moved from seven flat keys to three per-tool blocks. The flat
// spellings and the retired agent value "agent-proxy" are simply gone — snug is
// pre-alpha and commits to no configuration compatibility, so a stale key gets
// DisallowUnknownFields' "unknown key" and a stale VALUE gets ParseSSHMode's
// refusal naming the whole accepted set. What survives as a refusal of its own
// is the one shape that PARSES and would otherwise be silently wrong: a block
// that sets nothing. It carries a POSITIVE CONTROL, the house style this file
// follows, because a refusal with no positive control could just as easily be
// banning the CAPABILITY as the spelling.

func TestEmptyIdentityBlockIsRefused(t *testing.T) {
	_, err := parse([]byte("[profile.x]\n[profile.x.identity]\n"), "mine.toml", true)
	if err == nil {
		t.Fatal("an [identity] block that sets nothing resolved; it still sets " +
			"IdentityOwner and relabels the generated ~/.gitconfig's provenance")
	}
	if !strings.Contains(err.Error(), "mine.toml") || !strings.Contains(err.Error(), `"x"`) {
		t.Errorf("error does not name the file and the profile: %v", err)
	}

	// POSITIVE CONTROL: a block that sets ANY key is not empty.
	reg, err := parse([]byte("[profile.x]\n[profile.x.identity.git]\nname = \"Some One\"\n"),
		"mine.toml", true)
	if err != nil {
		t.Fatalf("a block that sets one key must parse: %v", err)
	}
	if reg["x"].Identity == nil {
		t.Fatal("Identity is nil for a block that set identity.git.name")
	}
}

// TestIdentityFieldKeysMatchTheProfileTOMLTags is the drift check #454 needs:
// policy.IdentityFieldKeys() is derived from the policy.Identity TYPE, and
// rawIdentity's nested blocks are a SEPARATE, hand-written set of TOML decode
// structs. A leaf added to policy.Identity with no matching `toml:` tag here
// decodes nowhere — a profile author's key is silently dropped rather than
// loudly rejected — and nothing else in this repository would notice.
func TestIdentityFieldKeysMatchTheProfileTOMLTags(t *testing.T) {
	var got []string
	raw := reflect.TypeOf(rawIdentity{})
	for i := 0; i < raw.NumField(); i++ {
		f := raw.Field(i)
		switch f.Name {
		case "SSH", "Git", "Gh":
			prefix := f.Tag.Get("toml") + "."
			nested := f.Type
			for j := 0; j < nested.NumField(); j++ {
				got = append(got, prefix+nested.Field(j).Tag.Get("toml"))
			}
		default:
			t.Fatalf("rawIdentity.%s is neither ssh, git nor gh: [identity] is a container "+
				"of per-tool blocks with no keys of its own, and a field here that is not "+
				"one of the three decodes a key policy.IdentityFieldKeys() cannot name",
				f.Name)
		}
	}
	sort.Strings(got)

	want := append([]string(nil), policy.IdentityFieldKeys()...)
	sort.Strings(want)

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rawIdentity's nested toml tags = %v\npolicy.IdentityFieldKeys() = %v\n"+
			"a leaf present in one and not the other decodes nowhere or refuses nothing",
			got, want)
	}
}

// TestNestedIdentityResolvesFromATOMLFile is the only end-to-end coverage of
// the decode path: both identity goldens elsewhere in this repository build
// policy.Identity as a Go struct literal, so neither one would notice a
// rawIdentity <-> policy.Identity mapping bug (a swapped field, a block
// decoding into the wrong nested struct). This drives a real profiles.d file
// through parse(..., trusted=true) — the same call loadDir makes — and Resolve,
// then asserts every leaf field by field.
func TestNestedIdentityResolvesFromATOMLFile(t *testing.T) {
	const src = `[profile.work]
include = ["@net"]

[profile.work.identity.ssh]
host  = "ssh.example"
key   = "{home}/.ssh/id_ed25519.pub"
agent = "proxy"

[profile.work.identity.git]
name        = "Some One"
email       = "some.one@example.com"
signing_key = "{home}/.ssh/id_ed25519_signing.pub"

[profile.work.identity.gh]
host = "gh.example"
user = "some-one"
`
	extracted, err := parse([]byte(src), "profiles.d/work.toml", true)
	if err != nil {
		t.Fatalf("a real profiles.d file using the nested identity schema did not parse: %v", err)
	}

	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.merge(extracted); err != nil {
		t.Fatalf("merging the file alongside snug's own builtins failed: %v", err)
	}

	ctx := policy.Context{Target: t.TempDir(), Home: t.TempDir()}
	sel := append(append([]policy.ProfileName{}, BuiltinDefaults()...), "work")
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if p.Identity == nil {
		t.Fatal("resolved with no identity")
	}

	if p.Identity.SSH.Host != "ssh.example" {
		t.Errorf("SSH.Host = %q, want %q", p.Identity.SSH.Host, "ssh.example")
	}
	if want := ctx.Home + "/.ssh/id_ed25519.pub"; p.Identity.SSH.Key != want {
		t.Errorf("SSH.Key = %q, want %q", p.Identity.SSH.Key, want)
	}
	if p.Identity.SSH.Agent != policy.SSHAgentProxy {
		t.Errorf("SSH.Agent = %q, want %q", p.Identity.SSH.Agent, policy.SSHAgentProxy)
	}
	if p.Identity.Git.Name != "Some One" {
		t.Errorf("Git.Name = %q, want %q", p.Identity.Git.Name, "Some One")
	}
	if p.Identity.Git.Email != "some.one@example.com" {
		t.Errorf("Git.Email = %q, want %q", p.Identity.Git.Email, "some.one@example.com")
	}
	if want := ctx.Home + "/.ssh/id_ed25519_signing.pub"; p.Identity.Git.SigningKey != want {
		t.Errorf("Git.SigningKey = %q, want %q", p.Identity.Git.SigningKey, want)
	}
	if p.Identity.Gh.Host != "gh.example" {
		t.Errorf("Gh.Host = %q, want %q", p.Identity.Gh.Host, "gh.example")
	}
	if p.Identity.Gh.User != "some-one" {
		t.Errorf("Gh.User = %q, want %q", p.Identity.Gh.User, "some-one")
	}
}
