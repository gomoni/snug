package policy

import (
	"slices"
	"strings"
	"testing"
)

const testGPGFingerprint = "6732361300BBFDAE7F22972CD4381E1CE2880244"

// gpgHomeEnv is a fake host that has a ~/.gnupg, a directory elsewhere to bind
// there, and a gpg.conf inside it.
func gpgHomeEnv() *fakeEnv {
	env := newFakeEnv()
	env.dirs["/home/u/.gnupg"] = true
	env.dirs["/x/gnupg"] = true
	env.files["/home/u/.gnupg/gpg.conf"] = true
	return env
}

// resolveGPG resolves the default selection plus an identity.gpg pin with the
// given scope plus grant (if any), in the order given by grantFirst.
func resolveGPG(t *testing.T, scope string, grant *Profile, grantFirst bool, env *fakeEnv) (*Policy, error) {
	t.Helper()
	reg := testRegistry()
	reg["gpg-pin"] = &Profile{Name: "gpg-pin", Identity: &Identity{
		GPG: IdentityGPG{Fingerprint: testGPGFingerprint, Scope: scope}}}
	sel := append([]ProfileName{}, testDefaults...)
	if grant != nil {
		reg[grant.Name] = grant
		if grantFirst {
			sel = append(sel, grant.Name, "gpg-pin")
		} else {
			sel = append(sel, "gpg-pin", grant.Name)
		}
	} else {
		sel = append(sel, "gpg-pin")
	}
	return Resolve(reg, sel, testCtx(), env)
}

// TestGPGIdentityRefusesHostGnupgGrant: a profile that grants the host's
// ~/.gnupg, however spelled, cannot be selected beside identity.gpg. The
// generated ~/.gnupg is a tmpfs over that path, which would hide the grant, and
// the grant is the host keyring and possibly the unfiltered agent socket, the
// very hole identity.gpg exists to narrow. Resolve refuses rather than hide
// it, naming both sides, in either selection order. It would catch the tmpfs
// quietly replacing the grant, or the grant quietly replacing the proxy.
func TestGPGIdentityRefusesHostGnupgGrant(t *testing.T) {
	cases := []struct {
		name  string
		grant *Profile
	}{
		{"ro", &Profile{Name: "host-gnupg", RO: []string{"{home}/.gnupg"}}},
		{"rw", &Profile{Name: "host-gnupg", RW: []string{"{home}/.gnupg"}}},
		{"ro absolute", &Profile{Name: "host-gnupg", RO: []string{"/home/u/.gnupg"}}},
		{"another host dir at the guest path", &Profile{Name: "host-gnupg", RO: []string{"/x/gnupg:{home}/.gnupg"}}},
	}
	for _, tc := range cases {
		for _, first := range []bool{false, true} {
			name := tc.name + " pin-first"
			if first {
				name = tc.name + " grant-first"
			}
			t.Run(name, func(t *testing.T) {
				// Control: the grant resolves on its own, so the refusal below
				// is the interaction and not an unrelated bad profile.
				reg := testRegistry()
				reg[tc.grant.Name] = tc.grant
				if _, err := Resolve(reg, append(append([]ProfileName{}, testDefaults...), tc.grant.Name),
					testCtx(), gpgHomeEnv()); err != nil {
					t.Fatalf("control: the grant alone does not resolve: %v", err)
				}

				_, err := resolveGPG(t, "sign", tc.grant, first, gpgHomeEnv())
				if err == nil {
					t.Fatal("a ~/.gnupg grant and identity.gpg resolved together")
				}
				for _, want := range []string{"/home/u/.gnupg", "host-gnupg", "gpg-pin"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("the refusal does not name %q: %v", want, err)
					}
				}
			})
		}
	}
}

// TestGPGIdentityKeepsDeeperGrantsAndAcceptsATmpfs: a grant UNDER ~/.gnupg is
// mounted after the generated tmpfs and stays visible, and a profile's own
// tmpfs at ~/.gnupg hides nothing, so neither is refused. It would catch the
// refusal widening to every path in the subtree.
func TestGPGIdentityKeepsDeeperGrantsAndAcceptsATmpfs(t *testing.T) {
	for _, first := range []bool{false, true} {
		deeper := &Profile{Name: "gpg-conf", RO: []string{"/home/u/.gnupg/gpg.conf"}}
		p, err := resolveGPG(t, "sign", deeper, first, gpgHomeEnv())
		if err != nil {
			t.Fatalf("a grant under ~/.gnupg was refused (grant first=%v): %v", first, err)
		}
		conf, ok := p.Mounts["/home/u/.gnupg/gpg.conf"]
		if !ok {
			t.Fatal("the deeper grant is not in the policy")
		}
		if conf.Kind == KindTmpfs {
			t.Errorf("the deeper grant is a tmpfs: %+v", conf)
		}
		args := p.BwrapArgs(1000, 1000)
		tmpfs, deep := slices.Index(args, "/home/u/.gnupg"), slices.Index(args, "/home/u/.gnupg/gpg.conf")
		if tmpfs < 0 || deep < 0 || deep < tmpfs {
			t.Errorf("the deeper grant is not mounted after the generated tmpfs (tmpfs at %d, grant at %d)", tmpfs, deep)
		}
	}

	scratch := &Profile{Name: "gnupg-scratch", Tmpfs: []string{"{home}/.gnupg"}}
	for _, first := range []bool{false, true} {
		p, err := resolveGPG(t, "sign", scratch, first, gpgHomeEnv())
		if err != nil {
			t.Fatalf("a profile tmpfs at ~/.gnupg was refused (grant first=%v): %v", first, err)
		}
		m := p.Mounts["/home/u/.gnupg"]
		if m.Kind != KindTmpfs || m.Perms == nil || *m.Perms != 0o700 {
			t.Errorf("~/.gnupg = %+v, want the generated 0700 tmpfs to win", m)
		}
	}
}

// TestGPGIdentityOwnsItsHome: Resolve, not the CLI, authors ~/.gnupg as a 0700
// tmpfs and GNUPGHOME pointing at it, and only when identity.gpg is pinned.
// gpg warns "unsafe permissions on homedir" under the 0755 an anchor would give.
func TestGPGIdentityOwnsItsHome(t *testing.T) {
	p, err := resolveGPG(t, "decrypt", nil, false, gpgHomeEnv())
	if err != nil {
		t.Fatal(err)
	}
	m, ok := p.Mounts["/home/u/.gnupg"]
	if !ok || m.Kind != KindTmpfs {
		t.Fatalf("~/.gnupg = %+v (present %v), want a tmpfs", m, ok)
	}
	if m.Perms == nil || *m.Perms != 0o700 {
		t.Errorf("~/.gnupg perms = %v, want 0700", m.Perms)
	}
	if v, ok := p.EnvValue("GNUPGHOME"); !ok || v != "/home/u/.gnupg" {
		t.Errorf("GNUPGHOME = %q (set %v), want /home/u/.gnupg", v, ok)
	}

	// Control and negative in one: the same selection with no gpg pin gets
	// neither, so the assertions above are about the pin.
	q, err := Resolve(testRegistry(), testDefaults, testCtx(), gpgHomeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := q.Mounts["/home/u/.gnupg"]; ok {
		t.Error("~/.gnupg is mounted without identity.gpg")
	}
	if _, ok := q.EnvValue("GNUPGHOME"); ok {
		t.Error("GNUPGHOME is set without identity.gpg")
	}
}

// TestGPGGitconfigFollowsTheSignScope: a sign scope authors ~/.gitconfig and
// GIT_CONFIG_GLOBAL so commits are signed; a decrypt-only pin authors neither,
// because turning signing on for a key that never granted it would make a
// decryption grant a signing oracle, and would displace a user's own git config
// on behalf of a key unrelated to git.
func TestGPGGitconfigFollowsTheSignScope(t *testing.T) {
	for _, tc := range []struct {
		scope string
		want  bool
	}{{"sign", true}, {"decrypt,sign", true}, {"decrypt", false}} {
		p, err := resolveGPG(t, tc.scope, nil, false, gpgHomeEnv())
		if err != nil {
			t.Fatalf("scope %q: %v", tc.scope, err)
		}
		cfg, hasCfg := p.Mounts["/home/u/.gitconfig"]
		_, hasEnv := p.EnvValue("GIT_CONFIG_GLOBAL")
		if hasCfg != tc.want || hasEnv != tc.want {
			t.Errorf("scope %q: ~/.gitconfig present=%v GIT_CONFIG_GLOBAL set=%v, want both %v",
				tc.scope, hasCfg, hasEnv, tc.want)
		}
		if tc.want && !strings.Contains(string(cfg.Content), "gpgsign = true") {
			t.Errorf("scope %q: the generated gitconfig does not turn signing on:\n%s", tc.scope, cfg.Content)
		}
	}
}

// TestGPGScopesOfTwoProfilesConflict: two profiles pinning the same key with
// different scopes disagree about what the sandbox may do, and neither is
// widened to the other. sign against decrypt,sign is the case a union would
// quietly resolve to decrypt,sign, handing the second profile's decrypt to a
// selection that only asked for the first. Both orders are refused, naming both.
func TestGPGScopesOfTwoProfilesConflict(t *testing.T) {
	a := Identity{GPG: IdentityGPG{Fingerprint: testGPGFingerprint, Scope: "sign"}}
	b := Identity{GPG: IdentityGPG{Fingerprint: testGPGFingerprint, Scope: "decrypt,sign"}}
	for _, pair := range [][2]*Identity{{&a, &b}, {&b, &a}} {
		_, err := Resolve(conflictRegistry(pair[0], pair[1]), conflictSelection(), testCtx(), newFakeEnv())
		if err == nil {
			t.Fatalf("scopes %q and %q resolved together", pair[0].GPG.Scope, pair[1].GPG.Scope)
		}
		for _, want := range []string{"ident-a", "ident-b"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not name %q: %v", want, err)
			}
		}
	}
	// Control: identical scopes in two profiles are one identity.
	c := a
	if _, err := Resolve(conflictRegistry(&a, &c), conflictSelection(), testCtx(), newFakeEnv()); err != nil {
		t.Errorf("control: identical gpg pins were refused: %v", err)
	}
}

// TestRefuseTwoSigningKeysNamesOneProfileWhenOneOwnsBoth: a single profile
// carrying an ssh signing key and a sign-scoped gpg key is refused in the
// singular, not as `profiles "x" and "x"`.
func TestRefuseTwoSigningKeysNamesOneProfileWhenOneOwnsBoth(t *testing.T) {
	p := maximalProfile()
	p.Identity.SSH = IdentitySSH{Host: "gh.example", Key: "/home/u/.ssh/id.pub", Agent: SSHAgentProxy}
	p.Identity.GPG = IdentityGPG{Fingerprint: testGPGFingerprint, Scope: "sign"}
	reg := testRegistry()
	reg[p.Name] = p
	_, err := Resolve(reg, []ProfileName{p.Name}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("two signing keys in one profile resolved")
	}
	if strings.Contains(err.Error(), `profiles "maximal" and "maximal"`) || !strings.Contains(err.Error(), `profile "maximal"`) {
		t.Errorf("the refusal should name the one profile once: %v", err)
	}
}
