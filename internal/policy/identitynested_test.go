package policy

import (
	"strings"
	"testing"
)

// ── refuseHalfNamedHost and refuseUnpinnedGhAccount (#454's host split) ──────
//
// gh_host used to be one field four consumers read. Splitting it into
// identity.ssh.host (the generated ~/.ssh/config, known_hosts and git's
// insteadOf rule) and identity.gh.host (the gh token) means nothing is
// inherited between the two blocks, so a profile naming one and not the other
// is refused rather than silently defaulted for the artifacts it never named.

func TestHostNamedInOneBlockAndNotTheOtherIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name     string
		id       Identity
		wantHost string
	}{
		{"ssh.host named, gh.host not", Identity{
			SSH: IdentitySSH{Host: "ssh.example", Key: "/home/u/.ssh/id.pub", Agent: SSHAgentProxy},
			Gh:  IdentityGh{User: "you"},
		}, "ssh.example"},
		{"gh.host named, ssh.host not", Identity{
			SSH: IdentitySSH{Key: "/home/u/.ssh/id.pub", Agent: SSHAgentProxy},
			Gh:  IdentityGh{Host: "gh.example", User: "you"},
		}, "gh.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := tc.id
			reg := testRegistry()
			reg["pinned"] = &Profile{Name: "pinned", Identity: &id}
			sel := append(append([]ProfileName{}, testDefaults...), "pinned")

			_, err := Resolve(reg, sel, testCtx(), newFakeEnv())
			if err == nil {
				t.Fatal("a host named in one identity block and not the other resolved; " +
					"snug would generate the DEFAULT host for the artifacts the empty block feeds")
			}
			if !strings.Contains(err.Error(), tc.wantHost) {
				t.Errorf("error does not name the host that was actually set (%q): %v", tc.wantHost, err)
			}
		})
	}

	// POSITIVE CONTROL: naming NEITHER host is legal, and both default to
	// DefaultIdentityHost — the behaviour every profile that never sets a host
	// already relies on. Without this, the refusal above could be "any identity
	// with only one of the two blocks active" rather than "a host named on one
	// side and not the other".
	t.Run("neither host named resolves and defaults", func(t *testing.T) {
		id := Identity{SSH: IdentitySSH{Key: "/home/u/.ssh/id.pub", Agent: SSHAgentProxy}, Gh: IdentityGh{User: "you"}}
		reg := testRegistry()
		reg["pinned"] = &Profile{Name: "pinned", Identity: &id}
		sel := append(append([]ProfileName{}, testDefaults...), "pinned")

		p, err := Resolve(reg, sel, testCtx(), newFakeEnv())
		if err != nil {
			t.Fatalf("an identity naming neither host was refused: %v", err)
		}
		if got := p.Identity.SSHHost(); got != DefaultIdentityHost {
			t.Errorf("SSHHost() = %q, want the default %q", got, DefaultIdentityHost)
		}
		if got := p.Identity.GhHost(); got != DefaultIdentityHost {
			t.Errorf("GhHost() = %q, want the default %q", got, DefaultIdentityHost)
		}
	})
}

func TestGhHostWithoutGhUserIsRefused(t *testing.T) {
	id := Identity{Gh: IdentityGh{Host: "gh.example"}}
	reg := testRegistry()
	reg["pinned"] = &Profile{Name: "pinned", Identity: &id}
	sel := append(append([]ProfileName{}, testDefaults...), "pinned")

	_, err := Resolve(reg, sel, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("identity.gh.host with no identity.gh.user resolved; snug would stage the " +
			"token of whatever account the host's gh happens to be logged into on that host")
	}
	if !strings.Contains(err.Error(), "gh.host") {
		t.Errorf("error does not name gh.host: %v", err)
	}
	if !strings.Contains(err.Error(), "gh.user") {
		t.Errorf("error does not name gh.user, which is the fix: %v", err)
	}

	// POSITIVE CONTROL: gh.host WITH gh.user is the pinned shape and must resolve.
	id2 := Identity{Gh: IdentityGh{Host: "gh.example", User: "you"}}
	reg2 := testRegistry()
	reg2["pinned"] = &Profile{Name: "pinned", Identity: &id2}
	if _, err := Resolve(reg2, sel, testCtx(), newFakeEnv()); err != nil {
		t.Fatalf("gh.host with gh.user set was refused: %v", err)
	}
}

// TestTwoProfilesWithByteIdenticalNestedIdentitiesResolve is the canary a
// pointer field in IdentitySSH/IdentityGit/IdentityGh would trip: `b := a`
// below copies the VALUE, producing two Identity values that are byte-identical
// but occupy different memory. If any nested block were a pointer, `*p.Identity
// != id` (the conflict check in Resolve) would still compile — a pointer is
// comparable — but it would compare the POINTERS rather than what they point
// at, and two profiles agreeing on every field would refuse each other anyway.
func TestTwoProfilesWithByteIdenticalNestedIdentitiesResolve(t *testing.T) {
	a := Identity{
		SSH: IdentitySSH{Agent: SSHAgentProxy, Key: "/home/u/.ssh/id.pub"},
		Git: IdentityGit{Name: "N", Email: "n@example.com"},
		Gh:  IdentityGh{User: "you"},
	}
	b := a // a distinct value, not a shared pointer
	p, err := Resolve(conflictRegistry(&a, &b), conflictSelection(), testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("two profiles pinning byte-identical nested identity blocks refused each "+
			"other: %v — a pointer field inside Identity would degrade this comparison to "+
			"pointer identity", err)
	}
	if p.Identity == nil {
		t.Fatal("resolved with no identity")
	}
}

// TestResolveIsCommutativeOverTwoIdenticalNestedIdentities resolves the SAME
// registry twice, with the two identity-carrying profiles in each order, and
// requires the rendered ssh.key to be identical either way.
//
// This is what a pointer-shared nested block would break: Resolve's
// normalisation (`id := *prof.Identity`) writes the expanded path back through
// id, and if that copy shared a nested struct with the profile STORED in the
// registry, the first Resolve call would mutate the registry in place. The
// second call — same registry, reversed order — would then see an
// already-expanded value on one side and not the other, and resolution would
// stop being order-independent.
func TestResolveIsCommutativeOverTwoIdenticalNestedIdentities(t *testing.T) {
	id := Identity{
		SSH: IdentitySSH{Key: "{home}/.ssh/id_ed25519.pub", Agent: SSHAgentProxy},
		Gh:  IdentityGh{User: "you"},
	}
	a, b := id, id
	reg := conflictRegistry(&a, &b)

	forward := append(append([]ProfileName{}, testDefaults...), "ident-a", "ident-b")
	reverse := append(append([]ProfileName{}, testDefaults...), "ident-b", "ident-a")

	p1, err := Resolve(reg, forward, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("resolve([a,b]): %v", err)
	}
	p2, err := Resolve(reg, reverse, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("resolve([b,a]): %v", err)
	}
	if p1.Identity == nil || p2.Identity == nil {
		t.Fatal("one of the two resolutions carries no identity")
	}
	want := "/home/u/.ssh/id_ed25519.pub"
	if p1.Identity.SSH.Key != want {
		t.Fatalf("resolve([a,b]).Identity.SSH.Key = %q, want %q", p1.Identity.SSH.Key, want)
	}
	if p1.Identity.SSH.Key != p2.Identity.SSH.Key {
		t.Fatalf("resolve([a,b]).Identity.SSH.Key = %q, resolve([b,a]) = %q — the two must "+
			"agree, or the first Resolve call wrote its normalised value back into the "+
			"registry and the second saw it", p1.Identity.SSH.Key, p2.Identity.SSH.Key)
	}
}
