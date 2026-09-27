package policy

import (
	"strings"
	"testing"
)

// TestExpandedListElementCannotCarryTheSeparator fails if checkExpandedElement
// (or its two call sites in collectEnv) is ever removed or bypassed: before it
// existed, a merge/prepend element written as `{target_parent}/bin` passed
// checkEnvElement (which reads the profile's raw TEXT, before {target_parent}
// is expanded) and checkAbsoluteElement (which only asks whether the EXPANDED
// value starts with '/', which it does) — and on a target whose parent
// directory is itself named with a ':' the expansion silently carried the
// list's own separator. A consumer splitting PATH on ':' then saw two
// elements, the second one relative and resolved against the payload's cwd,
// which inside snug is the target — the one directory a hostile payload
// controls. Measured, in a real sandbox: a `git` planted at that relative
// name ran.
//
// Every case below deliberately selects no @target-rw: {target} itself sits
// under the colon-bearing directory in most of them, and splitSpec's own
// host:guest split — a separate, unrelated mechanism that runs on the
// EXPANDED spec — would refuse {target} as "not absolute" before this check
// is ever reached. Granting the colon-free ANCESTOR directly is what isolates
// the one behaviour this test is about.
func TestExpandedListElementCannotCarryTheSeparator(t *testing.T) {
	cases := []struct {
		name     string
		target   string // ctx.Target; its dirname is {target_parent}
		ancestor string // a colon-free directory covering {target_parent}, granted ro
		grants   EnvGrants
	}{
		{
			name:     "merge",
			target:   "/w/pp:q/proj",
			ancestor: "/w",
			grants: EnvGrants{Merge: map[string][]string{
				"PATH": {"{target_parent}/bin"},
			}},
		},
		{
			name:     "prepend",
			target:   "/x/pp:q/proj",
			ancestor: "/x",
			grants: EnvGrants{Prepend: map[string][]string{
				"PATH": {"{target_parent}/bin"},
			}},
		},
		// The separator sits at the very END of {target_parent} rather than
		// in its middle, immediately before the "/bin" this profile appends —
		// the off-by-one a position-dependent check could get away with
		// missing.
		{
			name:     "trailing_colon_in_parent_name",
			target:   "/w2/pp:/proj",
			ancestor: "/w2",
			grants: EnvGrants{Merge: map[string][]string{
				"PATH": {"{target_parent}/bin"},
			}},
		},
		// The same hazard at a DECLARED path-list (environ.types), not only
		// at a rostered one — checkExpandedElement reads its list-ness
		// through typeWithin, which consults the profile's own declaration
		// for a name the roster does not carry.
		{
			name:     "declared_path_list",
			target:   "/g/pp:q/proj",
			ancestor: "/g",
			grants: EnvGrants{
				Types: map[string]EnvKind{"GEM_PATH": EnvKindPathList},
				Merge: map[string][]string{"GEM_PATH": {"{target_parent}/bin"}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := testRegistry()
			reg["merger"] = &Profile{Name: "merger", RO: []string{tc.ancestor}, Environ: tc.grants}
			ctx := testCtx()
			ctx.Target = tc.target
			env := newFakeEnv()
			env.dirs[tc.ancestor] = true
			env.dirs[tc.target] = true

			// No @target-rw: see the doc comment above for why.
			_, err := Resolve(reg, []ProfileName{"@sys", "@home", "merger"}, ctx, env)
			if err == nil {
				t.Fatalf("resolved cleanly; a list element whose EXPANSION carries the "+
					"separator reached the payload as several elements, one of them relative "+
					"and resolved against the target (ctx.Target=%q)", tc.target)
			}
			for _, want := range []string{"merger", "{target_parent}/bin", `":"`} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
		})
	}
}

// TestExpandedElementSurvivesOnATargetWithoutTheSeparator is the positive
// control for the case above: the identical profile, on a target whose parent
// directory carries no ':', must resolve — otherwise the refusal above would
// prove nothing about the separator specifically, only that the check refuses
// unconditionally.
func TestExpandedElementSurvivesOnATargetWithoutTheSeparator(t *testing.T) {
	reg := testRegistry()
	reg["merger"] = &Profile{Name: "merger", RO: []string{"/home/u/proj"}, Environ: EnvGrants{
		Merge: map[string][]string{"PATH": {"{target_parent}/bin"}},
	}}
	// testCtx()'s own target, /home/u/proj/sub: {target_parent} is
	// /home/u/proj, which carries no ':'. No @target-rw here either, so the
	// two cases differ only in the one fact under test.
	p, err := Resolve(reg, []ProfileName{"@sys", "@home", "merger"}, testCtx(), newFakeEnv())
	if err != nil {
		t.Fatalf("a target whose parent carries no ':' was refused: %v", err)
	}
	got := entryValues(p, "PATH")
	want := "/home/u/proj/bin"
	found := false
	for _, v := range got {
		if v == want {
			found = true
		}
	}
	if !found {
		t.Errorf("PATH = %v, does not contain %q", got, want)
	}
}
