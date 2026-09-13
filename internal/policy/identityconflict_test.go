package policy

import (
	"reflect"
	"strings"
	"testing"
)

// The identity conflict check compares the incoming profile's identity against
// the one already accumulated. Both sides have to be NORMALISED for that
// comparison to mean what it says: p.Identity was normalised before it was
// stored — ssh.agent "" became SSHNone, ssh.key went through expandVars — so
// comparing it against the raw TOML made every spelling that needs normalising
// refuse itself, base.toml's own template among them (#559).
//
// Neither direction of the check had a test before this file: `grep -rn "pin
// different identities" --include=*_test.go .` returned nothing, and
// TestResolveIsCommutative's fixture registry defines no profile with an
// Identity, so canon's `identity %+v` line rendered `identity <nil>` for every
// permutation it compared.

func conflictRegistry(a, b *Identity) map[ProfileName]*Profile {
	reg := testRegistry()
	reg["ident-a"] = &Profile{Name: "ident-a", Identity: a}
	reg["ident-b"] = &Profile{Name: "ident-b", Identity: b}
	return reg
}

func conflictSelection() []ProfileName {
	return append(append([]ProfileName{}, testDefaults...), "ident-a", "ident-b")
}

func TestIdentityIdenticalBlocksResolveWhateverTheSpelling(t *testing.T) {
	cases := []struct {
		name string
		id   Identity
	}{
		// base.toml's own template, verbatim. Two independently sufficient
		// triggers live in it: an ssh.key holding a {…} variable, and — in the
		// shorter spellings below — an omitted ssh.agent.
		{"base.toml template", Identity{
			Gh:  IdentityGh{User: "you"},
			Git: IdentityGit{Name: "Your Name", Email: "you@example.com"},
			SSH: IdentitySSH{Key: "{home}/.ssh/id_ed25519.pub", Agent: SSHAgentProxy}}},
		{"ssh.agent omitted", Identity{Gh: IdentityGh{User: "you"}}},
		{"ssh.key with a variable, ssh.agent omitted", Identity{
			Gh: IdentityGh{User: "you"}, SSH: IdentitySSH{Key: "{home}/.ssh/id_ed25519.pub"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := tc.id, tc.id
			p, err := Resolve(conflictRegistry(&a, &b), conflictSelection(), testCtx(), newFakeEnv())
			if err != nil {
				t.Fatalf("two profiles carrying byte-identical identity blocks "+
					"refused each other: %v", err)
			}
			if p.Identity == nil {
				t.Fatal("resolved with no identity")
			}
			if p.Identity.SSH.Key != "" && strings.Contains(p.Identity.SSH.Key, "{") {
				t.Errorf("ssh.key = %q, want the expanded path: the stored value "+
					"is the normalised one", p.Identity.SSH.Key)
			}
			if p.Identity.SSH.Agent == "" {
				t.Error("ssh.agent is empty, want the parsed value: the stored " +
					"value is the normalised one")
			}
		})
	}
}

func TestIdentityDifferentBlocksStillRefuseNamingBoth(t *testing.T) {
	// The positive control for the test above. Without it, the fix "compare
	// nothing" passes — and silently picking one account would mean the agent
	// pushes as an identity the human did not choose.
	cases := []struct {
		name string
		a, b Identity
	}{
		{"different gh.user",
			Identity{Gh: IdentityGh{User: "you"}}, Identity{Gh: IdentityGh{User: "someone-else"}}},
		{"different ssh.key",
			Identity{Gh: IdentityGh{User: "you"}, SSH: IdentitySSH{Key: "{home}/.ssh/id_ed25519.pub", Agent: SSHAgentProxy}},
			Identity{Gh: IdentityGh{User: "you"}, SSH: IdentitySSH{Key: "{home}/.ssh/other.pub", Agent: SSHAgentProxy}}},
		// Normalisation must not erase a real difference: proxy and none are
		// different grants, not two spellings of one.
		{"different ssh.agent",
			Identity{Gh: IdentityGh{User: "you"}, SSH: IdentitySSH{Agent: SSHAgentProxy}},
			Identity{Gh: IdentityGh{User: "you"}, SSH: IdentitySSH{Agent: SSHNone}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := tc.a, tc.b
			_, err := Resolve(conflictRegistry(&a, &b), conflictSelection(), testCtx(), newFakeEnv())
			if err == nil {
				t.Fatal("two profiles pinning different identities resolved; " +
					"the sandbox then acts as an account the human did not pick")
			}
			for _, want := range []string{"ident-a", "ident-b"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not name %q, and naming both is how the "+
						"human knows which two to choose between: %v", want, err)
				}
			}
		})
	}
}

// baseNestedIdentity is a fully self-consistent identity: every cross-field
// constraint Resolve enforces is already satisfied — ssh.agent = "proxy" so
// git.signing_key is legal, ssh.host and gh.host are the same non-empty value so
// neither half-named-host arm fires, and gh.user is set so the unpinned-gh-account
// refusal does not fire either. TestIdentityPinRefusesTwoProfilesDifferingOnlyInEachLeaf
// mutates exactly one leaf away from this baseline per subtest, so a profile that
// resolves on its own for every reason OTHER than the one leaf under test.
func baseNestedIdentity() Identity {
	return Identity{
		SSH: IdentitySSH{Host: "fixed.example", Key: "/home/u/.ssh/id_auth.pub", Agent: SSHAgentProxy},
		Git: IdentityGit{Name: "Base Name", Email: "base@example.com", SigningKey: "/home/u/.ssh/id_sign.pub"},
		Gh:  IdentityGh{Host: "fixed.example", User: "base-user"},
	}
}

// TestIdentityPinRefusesTwoProfilesDifferingOnlyInEachLeaf generalises the
// signing_key canary this file used to carry by name: the conflict check is
// `p.Identity != nil && *p.Identity != id`, bare struct equality over every
// leaf of Identity including the ones nested a block deep, so a leaf is only
// actually compared because the struct is compared whole. Driving the table
// off identityFields — rather than hand-picking ssh.key/git.signing_key/gh.user
// the way this test used to — means a leaf ADDED to Identity gets a subtest for
// free, which is the property #454's nesting exists to keep.
//
// A version of the conflict check that compared a hand-picked subset of
// leaves (the shape a future refactor could slip into) would let exactly one
// of these subtests silently pick a side instead of refusing.
func TestIdentityPinRefusesTwoProfilesDifferingOnlyInEachLeaf(t *testing.T) {
	for _, f := range identityFields {
		t.Run(f.Key, func(t *testing.T) {
			a := baseNestedIdentity()
			b := baseNestedIdentity()
			av := reflect.ValueOf(&a).Elem().FieldByIndex(f.Index)
			bv := reflect.ValueOf(&b).Elem().FieldByIndex(f.Index)
			if f.Key == "ssh.agent" {
				// git.signing_key requires ssh.agent = "proxy" (Resolve refuses the
				// combination otherwise), so this leaf's pair drops the signing key
				// rather than inheriting the baseline's — testing the agent leaf
				// itself, not its interaction with that other refusal.
				a.Git.SigningKey = ""
				b.Git.SigningKey = ""
				av.SetString(string(SSHAgentProxy))
				bv.SetString(string(SSHNone))
			} else {
				av.SetString(av.String() + "-a")
				bv.SetString(bv.String() + "-b")
			}

			_, err := Resolve(conflictRegistry(&a, &b), conflictSelection(), testCtx(), newFakeEnv())
			if err == nil {
				t.Fatalf("two profiles differing only in identity.%s resolved; the sandbox "+
					"then acts as an identity the human did not choose", f.Key)
			}
			for _, want := range []string{"ident-a", "ident-b"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not name %q: %v", want, err)
				}
			}
		})
	}
}

// Two spellings that normalisation collapses to one value are the SAME
// identity, and refusing them would be the bug from the other side.
func TestIdentitySpellingsThatNormaliseAlikeAreOneIdentity(t *testing.T) {
	a := Identity{Gh: IdentityGh{User: "you"}}                                   // ssh.agent omitted
	b := Identity{Gh: IdentityGh{User: "you"}, SSH: IdentitySSH{Agent: SSHNone}} // written out
	p, err := Resolve(conflictRegistry(&a, &b), conflictSelection(), testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("an omitted ssh.agent and an explicit \"none\" are the same "+
			"grant; refusing them is the conflict check reading a spelling as "+
			"an account: %v", err)
	}
	if p.Identity == nil || p.Identity.SSH.Agent != SSHNone {
		t.Fatalf("identity = %+v, want ssh.agent none", p.Identity)
	}
}
