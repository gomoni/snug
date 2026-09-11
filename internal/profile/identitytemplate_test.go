package profile

import (
	"slices"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// ── the @identity template pasted verbatim into a user file (the broken
// spelling was introduced in ceb24ea and fixed alongside this test) ─────────
//
// base.toml's `@identity` section carries a TEMPLATE inside its comments: text
// a human is told to copy into ~/.config/snug/profiles.d/ and fill in. From
// ceb24ea until this fix, that template's `include` line read
// `["net", "git-ro"]` — the bare spelling that is correct INSIDE base.toml,
// because `mark` (builtin.go) rewrites a builtin's own includes into the
// @-namespace unconditionally. A user file gets no such rewrite (checkName
// refuses a leading '@' in a DEFINITION, but `include` is a REFERENCE and
// carries whatever the file wrote), so a human who copied the template
// verbatim and ran `snug --dry-run -p work -- true` got
// `unknown profile "net"; snug's own profiles carry a leading @, so you
// probably meant "@net"` — a template that could not be used as written.
//
// This test extracts the template out of the EMBEDDED base.toml text itself
// (the TEMPLATE-BEGIN/TEMPLATE-END fence base.toml carries around the
// block), strips the leading comment marker, and loads what is left
// through `parse` with
// trusted=true — the exact call loadDir makes for a real
// ~/.config/snug/profiles.d/*.toml file — then resolves it against the real
// builtins. Restating the template as a Go string literal here would be a
// second copy of the same text, which is exactly what let the include line
// drift from base.toml's own without either copy noticing; reading the
// embedded bytes is what makes a future edit to the template's include
// spellings, its `[profile.work.identity]` keys, or the block's indentation
// fail this test the moment base.toml is rebuilt.
func TestIdentityTemplateLoadsAsAUserProfile(t *testing.T) {
	data, err := embedded.ReadFile("profiles/base.toml")
	if err != nil {
		t.Fatal(err)
	}

	const (
		fenceStart = "# TEMPLATE-BEGIN"
		fenceEnd   = "# TEMPLATE-END"
	)
	text := string(data)
	i := strings.Index(text, fenceStart)
	j := strings.Index(text, fenceEnd)
	if i < 0 || j < 0 || j < i {
		t.Fatalf("could not find the %q / %q fence in base.toml — either the "+
			"fence was renamed or removed, or this extraction never matched "+
			"anything (see the file comment for what it looks for)", fenceStart, fenceEnd)
	}
	// i marks the start of the "# TEMPLATE-BEGIN" line itself; the block
	// begins on the NEXT line.
	beginLineEnd := strings.Index(text[i:], "\n")
	if beginLineEnd < 0 {
		t.Fatalf("%q has no following newline", fenceStart)
	}
	block := text[i+beginLineEnd+1 : j]

	var raw []string
	for line := range strings.SplitSeq(block, "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			t.Fatalf("template line %q does not start with '#' — every line between "+
				"the fences is expected to be a TOML line commented out with a leading "+
				"'#', which is what a human strips by eye when they copy the block", line)
		}
		raw = append(raw, strings.TrimPrefix(line, "#"))
	}
	rawText := strings.Join(raw, "\n")

	// NON-VACUITY CONTROL: the fence matched something a human could plausibly
	// have pasted, not an empty gap between two adjacent markers.
	if !strings.Contains(rawText, "[profile.work]") {
		t.Fatalf("the extracted template does not contain [profile.work] — the "+
			"fence matched the wrong span:\n%s", rawText)
	}

	extracted, err := parse([]byte(rawText), "template-extracted-from-base.toml", true)
	if err != nil {
		t.Fatalf("the @identity template does not parse as a user profile file: %v\n"+
			"--- extracted text ---\n%s", err, rawText)
	}
	if _, ok := extracted["work"]; !ok {
		t.Fatalf("extracted template defines no [profile.work]; got %v", extracted)
	}

	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.merge(extracted); err != nil {
		t.Fatalf("merging the extracted template alongside snug's own builtins failed: %v", err)
	}

	ctx := policy.Context{
		Target: t.TempDir(),
		Home:   t.TempDir(),
	}
	// The template's own inline comment says "the `defaults` are selected as
	// well" (base.toml, on the `include` line) — a bare `snug -p work` adds
	// `work` to BuiltinDefaults() rather than replacing it, so that is the
	// selection resolved here, not `work` alone.
	selected := append(append([]policy.ProfileName{}, BuiltinDefaults()...), "work")
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		selected, ctx, policy.OSEnviron{})
	if err != nil {
		t.Fatalf("the @identity template, loaded exactly as a file in "+
			"~/.config/snug/profiles.d/ would be, does not resolve: %v", err)
	}

	// Both includes actually took effect, not merely parsed: a future edit
	// that dropped the `include` line entirely would still parse and resolve
	// (to an empty policy), and that must not read as this test passing.
	for _, want := range []policy.ProfileName{"@net", "@git-ro"} {
		if !slices.Contains(p.Profiles, want) {
			t.Errorf("resolved policy does not carry %q; want the template's "+
				"`include` to have pulled it in. Profiles: %v", want, p.Profiles)
		}
	}
	if p.Identity == nil {
		t.Fatal("resolved policy has no Identity; want the template's " +
			"[profile.work.identity] block to have pinned one")
	}
	if p.Identity.GhUser != "you" {
		t.Errorf("Identity.GhUser = %q, want \"you\" (the template's placeholder)", p.Identity.GhUser)
	}
}
