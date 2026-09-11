package profile

import (
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── the three retirals #454's nesting introduced (internal/profile/file.go) ──
//
// [identity] moved from seven flat keys to three per-tool blocks, and three
// spellings that used to mean something no longer do: the flat keys, the
// retired agent value "agent-proxy", and a block that sets nothing. Each
// carries its own POSITIVE CONTROL — the house style this file already follows
// for TestRetiredEnvKeyNamesTheFix and TestRetiredPathKeyNamesTheFix — because
// a refusal with no positive control could just as easily be banning the
// CAPABILITY as the retired spelling.

func TestRetiredFlatIdentityKeysAreRefusedNamingTheNewSpelling(t *testing.T) {
	for _, tc := range []struct {
		name        string
		flatKey     string
		val         string
		wantIn      []string
		replacement string
	}{
		{"ssh_key", "ssh_key", "/home/u/.ssh/id.pub",
			[]string{"identity.ssh.key"},
			"[profile.x.identity.ssh]\nkey = \"/home/u/.ssh/id.pub\"\n"},
		{"ssh_mode", "ssh_mode", "none",
			[]string{"identity.ssh.agent"},
			"[profile.x.identity.ssh]\nagent = \"none\"\n"},
		{"signing_key", "signing_key", "/home/u/.ssh/sign.pub",
			[]string{"identity.git.signing_key"},
			"[profile.x.identity.git]\nsigning_key = \"/home/u/.ssh/sign.pub\"\n"},
		{"git_name", "git_name", "Some One",
			[]string{"identity.git.name"},
			"[profile.x.identity.git]\nname = \"Some One\"\n"},
		{"git_email", "git_email", "some@example.com",
			[]string{"identity.git.email"},
			"[profile.x.identity.git]\nemail = \"some@example.com\"\n"},
		{"gh_user", "gh_user", "someone",
			[]string{"identity.gh.user"},
			"[profile.x.identity.gh]\nuser = \"someone\"\n"},
		// gh_host is the one key that maps to TWO new spellings, and the
		// message has to say so or a human fixes half the profile and gets a
		// silent host split (ssh pinned to the default, gh pinned to the value
		// they wrote) rather than a second refusal pointing at the other block.
		{"gh_host", "gh_host", "example.com",
			[]string{"identity.ssh.host", "identity.gh.host", "FOUR CONSUMERS"},
			"[profile.x.identity.ssh]\nhost = \"example.com\"\n[profile.x.identity.gh]\nhost = \"example.com\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "[profile.x]\n[profile.x.identity]\n" + tc.flatKey + " = " + strconv.Quote(tc.val) + "\n"
			_, err := parse([]byte(src), "mine.toml", true)
			if err == nil {
				t.Fatalf("%s = %q is retired and must be refused", tc.flatKey, tc.val)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}

			// POSITIVE CONTROL. Without it the refusal could just as well be a
			// ban on the capability rather than on the retired spelling.
			if _, err := parse([]byte("[profile.x]\n"+tc.replacement), "mine.toml", true); err != nil {
				t.Fatalf("the replacement spelling must parse: %v", err)
			}
		})
	}
}

func TestRetiredAgentProxyValueIsRefusedNamingProxy(t *testing.T) {
	_, err := parse([]byte("[profile.x]\n[profile.x.identity.ssh]\nagent = \"agent-proxy\"\n"),
		"mine.toml", true)
	if err == nil {
		t.Fatal("identity.ssh.agent = \"agent-proxy\" is retired and must be refused")
	}
	for _, want := range []string{"agent-proxy", "identity.ssh.agent", "proxy"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}

	// POSITIVE CONTROL: the replacement value parses and decodes to
	// policy.SSHAgentProxy.
	reg, err := parse([]byte("[profile.x]\n[profile.x.identity.ssh]\nagent = \"proxy\"\n"+
		"key = \"/home/u/.ssh/id.pub\"\n"), "mine.toml", true)
	if err != nil {
		t.Fatalf("the replacement value must parse: %v", err)
	}
	if reg["x"].Identity == nil || reg["x"].Identity.SSH.Agent != policy.SSHAgentProxy {
		t.Fatalf("identity.ssh.agent = %+v, want %q", reg["x"].Identity, policy.SSHAgentProxy)
	}
}

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
			// The retired flat fields (SSHKey, SigningKey, SSHMode, GitName,
			// GitEmail, GhUser, GhHost) are excluded BY NAME: their `toml:` tags
			// are exactly the spellings policy.IdentityFieldKeys() must not
			// produce, since those are the ones retiredFlatIdentity refuses.
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
