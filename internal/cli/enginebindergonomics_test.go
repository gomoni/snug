package cli

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestErgonomicCostOfTheAnchoredSourceRule pins what `-v` a user can actually
// pass under the anchored source rule (issue #284), against the REAL builtins,
// for the target layouts people really have.
//
// # WHY THIS TEST EXISTS RATHER THAN A PARAGRAPH
//
// internal/profile/profiles/base.toml and VERIFY.md §9c-quater both carry this
// table in prose, because a user has to be able to predict the refusal — an
// outcome nobody can predict reads as a bug rather than as a boundary. A table
// in prose is a copy of state held in policy.CheckEngineBindSource, and this
// repository has a measured base rate for how those age: the ergonomics note
// this test replaces was itself wrong in BOTH directions when it was measured
// (it claimed `-v $SNUG_TARGET:/work` is "normally refused" — true only at
// depth three and beyond — and claimed a target under /tmp is refused, which
// is false when @parent-ro's own bind lands directly in the tmpfs).
//
// So the prose is checkable now. Change the rule and this test says which row
// moved; then go fix both documents, deliberately.
//
// # WHAT THE ROWS MEAN
//
// The rule: a source is forwarded only if EVERY component from it up to / is
// anchored. A name whose parent the payload can write is re-pointable; a mount
// root is not. Both columns below follow from that one sentence:
//
//   - NOTHING INSIDE THE TARGET is ever accepted, at any depth. The target is
//     a read-write bind, so every name inside it has a writable parent. This
//     is the ergonomically expensive half — `-v ./data:/data` is the commonest
//     container invocation there is, and it is a 403 on every layout.
//   - THE TARGET ROOT is accepted exactly while @parent-ro's own bind sits
//     directly inside a mount root. True two levels below $HOME and under
//     $TMPDIR/<dir>/; false at three, where the intermediate directory is a
//     plain renameable name in the home tmpfs.
//
// The way out is issue #376 — a per-bind graft under /snug/engine, handing the
// engine a mount rather than a path string it re-resolves. Until then this
// table is the boundary, and it is a refusal rather than a silent narrowing:
// nothing mounts with less than what was asked for.
func TestErgonomicCostOfTheAnchoredSourceRule(t *testing.T) {
	// Extra fixture directories for the deeper layouts. envFakeEnv's own set
	// stops at /home/u/proj/sub, and Resolve refuses a target it cannot stat.
	extraDirs := []string{
		"/home/u/src", "/home/u/src/proj",
		"/home/u/src/projects", "/home/u/src/projects/foo",
		"/home/u/x", "/home/u/x/y", "/home/u/x/y/proj", "/home/u/x/y/proj/sub",
		"/tmp/build-123", "/tmp/build-123/proj",
	}

	cases := []struct {
		name   string
		target string
		// wantRoot is whether `-v $SNUG_TARGET:/work` is accepted. wantInside
		// is not a field: a path inside the target is refused in EVERY row,
		// which is the point, and writing it per-case would let a future edit
		// quietly flip one row to true.
		wantRoot bool
		// why names the component the rule stops on, for the refusing rows —
		// so a failure says which name stopped being anchored, not merely
		// that the row moved.
		why string
	}{
		{
			name:     "two levels below $HOME: @parent-ro binds /home/u/proj, directly in the home tmpfs",
			target:   "/home/u/proj/sub",
			wantRoot: true,
		},
		{
			name:     "two levels below $HOME, different spelling",
			target:   "/home/u/src/proj",
			wantRoot: true,
		},
		{
			name:     "THREE levels below $HOME: /home/u/src is a plain name in the home tmpfs",
			target:   "/home/u/src/projects/foo",
			wantRoot: false,
			why:      "/home/u/src",
		},
		{
			name:     "four levels below $HOME",
			target:   "/home/u/x/y/proj/sub",
			wantRoot: false,
			why:      "/home/u/x",
		},
		{
			name:     "under $TMPDIR, @parent-ro's bind directly in the /tmp tmpfs",
			target:   "/tmp/build-123/proj",
			wantRoot: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg, err := profile.Builtins()
			if err != nil {
				t.Fatal(err)
			}
			env := newEnvFakeEnv()
			for _, d := range extraDirs {
				env.dirs[d] = true
			}
			ctx := policy.Context{
				Target: tc.target, Home: "/home/u",
				Shell: "/usr/bin/bash", Command: []string{"/bin/sh"},
			}
			sel := append(profile.BuiltinDefaults(), "@podman-socket")
			p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, ctx, env)
			if err != nil {
				t.Fatalf("Resolve(target=%s): %v", tc.target, err)
			}

			// The target ROOT.
			rootErr := p.CheckEngineBindSource(tc.target)
			if tc.wantRoot && rootErr != nil {
				t.Errorf("-v %s:/work is REFUSED, and this layout is one where it is supposed to "+
					"work. base.toml's abuse block and VERIFY.md 9c-quater both say so; if the rule "+
					"changed on purpose, change them too:\n%v", tc.target, rootErr)
			}
			if !tc.wantRoot {
				if rootErr == nil {
					t.Errorf("-v %s:/work is ACCEPTED, and both base.toml and VERIFY.md say this "+
						"layout refuses it. A rule that got more permissive is the direction that "+
						"reopens #284 — check what stopped being writable before updating the docs",
						tc.target)
				} else if tc.why != "" && !strings.Contains(rootErr.Error(), tc.why) {
					t.Errorf("-v %s:/work is refused, but not on %s — the documented reason for "+
						"this row is the component that moved:\n%v", tc.target, tc.why, rootErr)
				}
			}

			// INSIDE the target: refused in every row, no exceptions. This is
			// the layout-independent half and the expensive one.
			for _, inside := range []string{tc.target + "/subdir", tc.target + "/a/b"} {
				err := p.CheckEngineBindSource(inside)
				if err == nil {
					t.Errorf("-v %s:/x is ACCEPTED. Nothing inside the target may be: the target is "+
						"a read-write bind, so every name in it has a writable parent and can be "+
						"replaced with a symlink between create and start (#284)", inside)
					continue
				}
				// The refusal must not offer a fix it cannot deliver. Where
				// the target root is itself refused, there is no usable
				// substitute SOURCE and the message says so — and since issue
				// #376 landed, BOTH arms must also name the remedy that works
				// at any depth, which is a declaration rather than another
				// source.
				msg := err.Error()
				if !strings.Contains(msg, "engine_binds") {
					t.Errorf("-v %s:/x is refused without naming engine_binds, so a user at this "+
						"layout is told to give up when one line of profile would work:\n%s",
						inside, msg)
				}
				if tc.wantRoot && !strings.Contains(msg, "Fix: bind "+tc.target) {
					t.Errorf("-v %s:/x is refused without offering the substitute that DOES work "+
						"here (bind %s and address the subdirectory inside the container):\n%s",
						inside, tc.target, msg)
				}
				if !tc.wantRoot && strings.Contains(msg, "Fix: bind") {
					t.Errorf("-v %s:/x is refused with a \"Fix: bind\" line, but the target root is "+
						"refused too in this layout, so the ancestor being offered is a filesystem "+
						"snug created for this run and does not hold the caller's files. The message "+
						"must admit there is no substitute SOURCE:\n%s", inside, msg)
				}
			}

			// POSITIVE CONTROL, and it is required: a source whose every name
			// is anchored still forwards. Without it, every assertion above
			// would pass equally on a predicate that refused everything —
			// which is the shape a "fix" for #284 could most easily become.
			for _, anchored := range []string{"/usr", "/usr/bin"} {
				if err := p.CheckEngineBindSource(anchored); err != nil {
					t.Errorf("-v %s:/u:ro is refused, so this rule refuses everything and the "+
						"rows above measure nothing:\n%v", anchored, err)
				}
			}
		})
	}
}
