package policy

// ── rejectMasking's KindTmpfs row, for a NON-authored mount ──────────────────
//
// A red-team round on #582 caught INDEX.md saying every mount snug puts inside
// @home's tmpfs is KindData that snug authors, never a bind a profile
// expresses. False: @claude's `ro = ["{home}/.claude/skills",
// "{home}/.claude/plugins"]` is a plain profile-authored BIND, nested inside
// the tmpfs @home puts at {home}. rejectMasking's own comment (validate.go,
// the paragraph above checkNesting's KindTmpfs case) already names both
// halves correctly; this test is what makes the claim fail loudly if it ever
// stops being true, rather than being provable only by reading two files and
// noticing they disagree.
//
// Why it is not a nit: RULE 3 (validate.go, `if m.Authored { continue }`)
// already exempts every snug-authored mount unconditionally. If the tmpfs
// case were ALWAYS an authored replacement, RULE 2's KindTmpfs row (checkNesting's
// `case KindTmpfs: return nil`) would never be reached by anything RULE 3 had
// not already let through, which is the argument for deleting it as dead code.
// Deleting it makes rejectMasking refuse @claude's read-only bind of
// ~/.claude/skills nested inside tmpfs ~/.claude — @claude fails to resolve on
// the very first invocation.

import "testing"

// claudeSkillsRegistry mirrors base.toml's [profile.claude] ro/optional pair
// for skills and plugins closely enough to exercise the nesting this test is
// about, without pulling in the rest of that profile (the staged binary, the
// plugin allowlist) which nothing here reads.
func claudeSkillsRegistry() map[ProfileName]*Profile {
	reg := testRegistry()
	reg["claude"] = &Profile{
		Name: "claude",
		RO: []string{
			"{home}/.claude/skills",
			"{home}/.claude/plugins",
		},
		Optional: []string{
			"{home}/.claude/skills",
			"{home}/.claude/plugins",
		},
	}
	return reg
}

// TestClaudeSkillsIsABindNestedInsideHomesTmpfsNotAuthoredContent is the
// regression: it fails if @claude's skills/plugins grant is ever turned into
// (or replaced by) an Authored mount, which is exactly the shape that would
// make RULE 2's KindTmpfs row look redundant to a future reader. It also
// fails if that row is removed outright: measured by hand while writing this
// test, changing checkNesting's `case KindTmpfs: return nil` to return an
// error turned this test's Resolve call into that same refusal, naming
// /home/u — the row is load-bearing for this exact nesting, not merely
// plausible-sounding.
func TestClaudeSkillsIsABindNestedInsideHomesTmpfsNotAuthoredContent(t *testing.T) {
	sel := append(append([]ProfileName{}, testDefaults...), "claude")
	env := envWith("/home/u/.claude/skills", "/home/u/.claude/plugins")

	p, err := Resolve(claudeSkillsRegistry(), sel, testCtx(), env)
	if err != nil {
		t.Fatalf("Resolve(@sys+@home+@target-rw+claude): %v", err)
	}

	// POSITIVE CONTROL: @home really does cover {home} with a tmpfs, which is
	// the outer mount RULE 2's KindTmpfs row is judging. Without this, a pass
	// below would prove nothing about the nesting case at all.
	if outer, ok := p.Mounts["/home/u"]; !ok || outer.Kind != KindTmpfs {
		t.Fatalf("control: no KindTmpfs mount at /home/u; got %+v (ok=%v) — @home's own tmpfs is "+
			"missing, so this fixture cannot exercise the nesting this test is about", outer, ok)
	}

	for _, guest := range []string{"/home/u/.claude/skills", "/home/u/.claude/plugins"} {
		m, ok := p.Mounts[guest]
		if !ok {
			t.Fatalf("no mount at %s; @claude's ro grant did not resolve", guest)
		}
		if m.Kind != KindBind {
			t.Errorf("%s: Kind = %v, want KindBind — this is a profile's `ro` grant, not snug's "+
				"own generated content", guest, m.Kind)
		}
		if m.Authored {
			t.Errorf("%s: Authored = true, want false — this mount is a PROFILE's bind (@claude's "+
				"`ro`), and RULE 3 (validate.go) exempts only snug's own writes from masking; if "+
				"this is ever Authored, RULE 2's KindTmpfs row stops being the reason it survives "+
				"nested inside @home's tmpfs, and INDEX.md's inventory of what sits in that tmpfs "+
				"has to be edited alongside this test", guest)
		}
	}
}
