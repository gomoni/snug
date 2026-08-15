package profile

import (
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// Issue #45 withdrew `environ.set` for EDITOR, VISUAL and PAGER
// (internal/policy/envtypes.go's noSet) while leaving `environ.inherit` legal
// for all three — the host user's own choice, reachable only by already being
// the host user. @claude is the one shipped profile that used the old,
// symmetric grant, and the whole point of `set`/`inherit` being two separate
// verbs is that withdrawing one need not touch the other: @claude's own text
// in base.toml never used `set` for these three, so nothing about it needed to
// change.
//
// This asserts it from the REAL, compiled-in profile (profile.Builtins()),
// not from a hand-built policy.Profile literal — a literal would keep passing
// after base.toml drifted out from under it, which is exactly the "self-
// written test confirms the mechanism you had in mind" trap CLAUDE.md warns
// about. If a future edit to base.toml drops one of these three from
// @claude's `environ.inherit` block, this test is what fails.
func TestClaudeStillInheritsEditorVisualAndPager(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatalf("Builtins() failed: %v", err)
	}
	p, ok := reg[policy.ProfileName("claude").Marked()]
	if !ok {
		t.Fatalf("Builtins() carries no %q", policy.ProfileName("claude").Marked())
	}
	got := map[string]bool{}
	for _, name := range p.Environ.Inherit {
		got[name] = true
	}
	for _, name := range []string{"EDITOR", "VISUAL", "PAGER"} {
		if !got[name] {
			t.Errorf("@claude no longer inherits %s; issue #45 withdrew `set` for it, not "+
				"`inherit` — a human's editor and pager preference is meant to still survive "+
				"into the sandbox", name)
		}
		if _, isSet := p.Environ.Set[name]; isSet {
			t.Errorf("@claude sets %s directly, which issue #45 withdrew for every profile — "+
				"a builtin is not exempt from its own roster", name)
		}
	}

	// POSITIVE CONTROL: a name @claude does NOT carry must not be reported as
	// inherited, or the loop above could pass on a predicate that always
	// returns true.
	if got["GIT_EDITOR"] {
		t.Error("control: @claude appears to inherit GIT_EDITOR, which it does not grant and " +
			"which is forbidBoth regardless — the membership test itself is broken")
	}
}
