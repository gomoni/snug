package profile

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// mark is the one door a profile passes through to become @-marked, and it is
// also where a builtin's `environ.declare` is refused (see mark's own doc
// comment for the argument: "@ means snug ships it" and "a profile snug ships
// writes no unrostered name" are established by the same construction). This
// is a WHITE-BOX test — mark is unexported — because Builtins() itself cannot
// exercise this path: nothing compiled into profiles/*.toml declares
// anything, by construction, so a black-box sweep over Builtins() would find
// nothing to report either way.
//
// The task note is explicit that this is exactly the shape CLAUDE.md records
// getting wrong three review rounds running for nested bind masking: "the
// rule and its test were written together, against one spelling". The
// positive control below is what tells "refused because it declared" apart
// from "the fixture never loaded at all" — an IDENTICAL fixture with only the
// declare line removed must mark cleanly, prove it published under the
// sigil, and carry the grant that was never in question.
func TestMarkRefusesABuiltinThatDeclares(t *testing.T) {
	leaky := Registry{
		"leaky": &policy.Profile{
			Name: "leaky",
			Environ: policy.EnvGrants{
				Declare: []string{"MY_TOOL_MODE"},
				Set:     map[string]string{"MY_TOOL_MODE": "fast"},
			},
		},
	}
	if _, err := mark(leaky); err == nil {
		t.Fatal("mark() accepted a profile that declares an unrostered name; a profile snug " +
			"SHIPS must have a roster row (internal/policy/envtypes.go) for every name it " +
			"writes — there is no human left to answer for an unrostered name in a compiled-in " +
			"profile")
	} else if !strings.Contains(err.Error(), "MY_TOOL_MODE") {
		t.Errorf("the refusal does not name the declared variable, which is the thing a "+
			"contributor needs to find in base.toml: %v", err)
	} else if !strings.Contains(err.Error(), "leaky") {
		t.Errorf("the refusal does not name the profile that declared it: %v", err)
	}

	// POSITIVE CONTROL: remove ONLY the declaration, keep everything else
	// about the fixture identical (same key, same struct shape, a real
	// environ grant of its own). If this is refused too, the failure above
	// proves nothing about `environ.declare` specifically — it could be an
	// unrelated defect in mark() or in the fixture's construction.
	clean := Registry{
		"leaky": &policy.Profile{
			Name:    "leaky",
			Environ: policy.EnvGrants{Set: map[string]string{"EDITOR": "vim"}},
		},
	}
	marked, err := mark(clean)
	if err != nil {
		t.Fatalf("control: an otherwise-identical builtin with no declaration was refused: %v", err)
	}
	got, ok := marked[policy.ProfileName("leaky").Marked()]
	if !ok {
		t.Fatalf("control: mark() did not publish %q under its @-marked name; got keys %v",
			"leaky", markedKeys(marked))
	}
	if got.Name != policy.ProfileName("leaky").Marked() {
		t.Errorf("control: the marked profile's own Name field reads %q, want %q",
			got.Name, policy.ProfileName("leaky").Marked())
	}
	if got.Environ.Set["EDITOR"] != "vim" {
		t.Errorf("control: the marked profile lost its own environ.set grant; got %#v", got.Environ)
	}
}

func markedKeys(r Registry) []policy.ProfileName {
	out := make([]policy.ProfileName, 0, len(r))
	for k := range r {
		out = append(out, k)
	}
	return out
}

// TestBuiltinsItselfCarriesNoDeclaration is the black-box half: the REAL,
// compiled-in profile set (profiles/*.toml) must load through Builtins()
// without tripping the refusal above. It cannot prove the refusal fires — see
// the white-box test — but it does prove nobody has since added a `declare`
// block to a shipped profile expecting it to work, which would otherwise fail
// this build the moment it happened rather than being noticed by review.
func TestBuiltinsItselfCarriesNoDeclaration(t *testing.T) {
	if _, err := Builtins(); err != nil {
		t.Fatalf("Builtins() failed: %v", err)
	}
}
