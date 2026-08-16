package profile

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// mark is the one door a profile passes through to become @-marked, and it is
// also where the roster is an ALLOWLIST for a profile snug ships (see mark's own
// doc comment for the argument: "@ means snug ships it" and "a profile snug
// ships writes no name snug has no entry for" are established by the same
// construction). This is a WHITE-BOX test — mark is unexported — because
// Builtins() itself cannot exercise this path: every name in profiles/*.toml has
// a roster row, by construction, so a black-box sweep over Builtins() would find
// nothing to report either way.
//
// This is exactly the shape CLAUDE.md records getting wrong three review rounds
// running for nested bind masking: "the rule and its test were written together,
// against one spelling". The positive control below is what tells "refused
// because the name is not on the roster" apart from "the fixture never loaded at
// all" — an IDENTICAL fixture with only the name changed to a rostered one must
// mark cleanly, prove it published under the sigil, and carry the grant that was
// never in question.
func TestMarkRefusesABuiltinThatWritesAnUnrosteredName(t *testing.T) {
	leaky := Registry{
		"leaky": &policy.Profile{
			Name: "leaky",
			Environ: policy.EnvGrants{
				Set: map[string]string{"MY_TOOL_MODE": "fast"},
			},
		},
	}
	if _, err := mark(leaky); err == nil {
		t.Fatal("mark() accepted a profile writing a name snug's roster has no entry for; a " +
			"profile snug SHIPS may not hand over a name the screen would mark `← unchecked` — " +
			"that mark says a human took responsibility, and there is no human for a " +
			"compiled-in profile")
	} else if !strings.Contains(err.Error(), "MY_TOOL_MODE") {
		t.Errorf("the refusal does not name the variable, which is the thing a "+
			"contributor needs to find in base.toml: %v", err)
	} else if !strings.Contains(err.Error(), "leaky") {
		t.Errorf("the refusal does not name the profile that wrote it: %v", err)
	}

	// The same rule at `inherit`, because a builtin taking an unrostered name
	// from the HOST is the shape @claude actually has, and a rule applied to one
	// of its two halves is this project's most-recorded defect.
	inheriting := Registry{
		"leaky": &policy.Profile{
			Name:    "leaky",
			Environ: policy.EnvGrants{Inherit: []string{"MY_TOOL_TOKEN"}},
		},
	}
	if _, err := mark(inheriting); err == nil {
		t.Error("mark() accepted a builtin that INHERITS an unrostered name; the rule is about " +
			"what a shipped profile hands over, not about which verb it used")
	}

	// POSITIVE CONTROL: change ONLY the name to one the roster carries, keep
	// everything else about the fixture identical (same key, same struct shape,
	// a real environ grant of its own). If this is refused too, the failure
	// above proves nothing about the roster specifically — it could be an
	// unrelated defect in mark() or in the fixture's construction.
	clean := Registry{
		"leaky": &policy.Profile{
			Name:    "leaky",
			Environ: policy.EnvGrants{Set: map[string]string{"EDITOR": "vim"}},
		},
	}
	marked, err := mark(clean)
	if err != nil {
		t.Fatalf("control: an otherwise-identical builtin writing a ROSTERED name was refused: %v", err)
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

// TestBuiltinsItselfWritesOnlyRosteredNames is the black-box half: the REAL,
// compiled-in profile set (profiles/*.toml) must load through Builtins() without
// tripping the refusal above. It cannot prove the refusal fires — see the
// white-box test — but it does prove nobody has since added a name to a shipped
// profile without adding the roster row that owes the abuse sentence, which
// would otherwise fail this build the moment it happened rather than being
// noticed by review.
func TestBuiltinsItselfWritesOnlyRosteredNames(t *testing.T) {
	if _, err := Builtins(); err != nil {
		t.Fatalf("Builtins() failed: %v", err)
	}
}
