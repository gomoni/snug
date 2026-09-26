package policy

import (
	"strings"
	"testing"
)

// A refused grant written with a variable names the grant as the profile
// spells it and the value each variable took, not only the expanded path.
// Issue #613: `rw = ["{target_parent}/dist"]` resolved against the deck's
// root instead of its marp/ subdirectory refused naming only
// ".../vyskocilm/dist", and read as snug expanding {target_parent} wrongly.
func TestMissingGrantNamesTheTemplateAndTheTarget(t *testing.T) {
	reg := testRegistry()
	reg["deck"] = &Profile{Name: "deck", RW: []string{"{target_parent}/dist"}}
	env := newFakeEnv()
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "deck"}, testCtx(), env)
	if err == nil {
		t.Fatal("a grant naming a path that does not exist was accepted")
	}
	for _, want := range []string{
		`grants "/home/u/proj/dist" which does not exist`,
		`the profile writes it as "{target_parent}/dist"`,
		`{target_parent} is "/home/u/proj", the parent of the target "/home/u/proj/sub"`,
		"create it, or mark it optional",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not carry %q:\n%s", want, err)
		}
	}
}

// A literal grant carries no provenance lines: its path is already what the
// author wrote, and repeating it would be noise.
func TestMissingLiteralGrantHasNoExpansionNote(t *testing.T) {
	reg := testRegistry()
	reg["lit"] = &Profile{Name: "lit", RO: []string{"/nonexistent/lit"}}
	_, err := Resolve(reg, []ProfileName{"@sys", "@target-rw", "lit"}, testCtx(), newFakeEnv())
	if err == nil {
		t.Fatal("a grant naming a path that does not exist was accepted")
	}
	if strings.Contains(err.Error(), "the profile writes it as") {
		t.Errorf("a literal grant got an expansion note:\n%s", err)
	}
}
