package policy

import (
	"strings"
	"testing"
)

// The identity conflict check compares the incoming profile's identity against
// the one already accumulated. Both sides have to be NORMALISED for that
// comparison to mean what it says: p.Identity was normalised before it was
// stored — ssh_mode "" became SSHNone, ssh_key went through expandVars — so
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
		// base.toml:446-453 verbatim. Two independently sufficient triggers
		// live in it: an ssh_key holding a {…} variable, and — in the shorter
		// spellings below — an omitted ssh_mode.
		{"base.toml template", Identity{
			GhUser: "you", GitName: "Your Name", GitEmail: "you@example.com",
			SSHKey: "{home}/.ssh/id_ed25519.pub", SSHMode: SSHAgentProxy}},
		{"ssh_mode omitted", Identity{GhUser: "you"}},
		{"ssh_key with a variable, ssh_mode omitted", Identity{
			GhUser: "you", SSHKey: "{home}/.ssh/id_ed25519.pub"}},
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
			if p.Identity.SSHKey != "" && strings.Contains(p.Identity.SSHKey, "{") {
				t.Errorf("ssh_key = %q, want the expanded path: the stored value "+
					"is the normalised one", p.Identity.SSHKey)
			}
			if p.Identity.SSHMode == "" {
				t.Error("ssh_mode is empty, want the parsed value: the stored " +
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
		{"different gh_user",
			Identity{GhUser: "you"}, Identity{GhUser: "someone-else"}},
		{"different ssh_key",
			Identity{GhUser: "you", SSHKey: "{home}/.ssh/id_ed25519.pub", SSHMode: SSHAgentProxy},
			Identity{GhUser: "you", SSHKey: "{home}/.ssh/other.pub", SSHMode: SSHAgentProxy}},
		// Normalisation must not erase a real difference: agent-proxy and none
		// are different grants, not two spellings of one.
		{"different ssh_mode",
			Identity{GhUser: "you", SSHMode: SSHAgentProxy},
			Identity{GhUser: "you", SSHMode: SSHNone}},
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

// The conflict check is `p.Identity != nil && *p.Identity != id` — bare struct
// equality over EVERY field of Identity — so signing_key is only actually
// compared because the struct is compared whole. This is the one test in this
// file exercising that: two profiles agreeing on ssh_key, ssh_mode and
// gh_user, differing ONLY in signing_key, must still refuse. A version of the
// conflict check that compared a hand-picked subset of fields (the shape a
// future refactor could slip into) would let this one silently pick a side.
func TestIdentityPinRefusesTwoProfilesDifferingOnlyInSigningKey(t *testing.T) {
	a := Identity{GhUser: "you", SSHMode: SSHAgentProxy,
		SSHKey: "{home}/.ssh/id_ed25519.pub", SigningKey: "{home}/.ssh/sign-a.pub"}
	b := Identity{GhUser: "you", SSHMode: SSHAgentProxy,
		SSHKey: "{home}/.ssh/id_ed25519.pub", SigningKey: "{home}/.ssh/sign-b.pub"}
	_, err := Resolve(conflictRegistry(&a, &b), conflictSelection(), testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("two profiles differing only in signing_key resolved; the sandbox then " +
			"signs with an identity the human did not choose")
	}
	for _, want := range []string{"ident-a", "ident-b"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q: %v", want, err)
		}
	}
}

// Two spellings that normalisation collapses to one value are the SAME
// identity, and refusing them would be the bug from the other side.
func TestIdentitySpellingsThatNormaliseAlikeAreOneIdentity(t *testing.T) {
	a := Identity{GhUser: "you"}                   // ssh_mode omitted
	b := Identity{GhUser: "you", SSHMode: SSHNone} // written out
	p, err := Resolve(conflictRegistry(&a, &b), conflictSelection(), testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("an omitted ssh_mode and an explicit \"none\" are the same "+
			"grant; refusing them is the conflict check reading a spelling as "+
			"an account: %v", err)
	}
	if p.Identity == nil || p.Identity.SSHMode != SSHNone {
		t.Fatalf("identity = %+v, want ssh_mode none", p.Identity)
	}
}
