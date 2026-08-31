package cli

import (
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// TestErgonomicCostOfTheAnchoredSourceRule pins policy.CheckEngineBindSource's
// own rule (issue #284) against the REAL builtins, for the target layouts
// people really have.
//
// SINCE ISSUE #376, THIS RULE NO LONGER GOVERNS `-v $SNUG_TARGET:/work`. The
// container proxy's checkOne asks EngineTargetForwarded before it ever reaches
// CheckEngineBindSource, and that graft accepts the target root at any depth
// whenever the sandbox itself can see it — so the depth dependence this test
// used to pin for the ROOT is gone from the user-visible behaviour. rootErr
// below still calls CheckEngineBindSource directly and still varies by depth,
// because the RULE this file exercises is unchanged; it documents what
// happens to a source the graft's exact match does not cover, not what a
// client's `-v $SNUG_TARGET:/work` actually gets.
//
// # WHAT THE ROWS MEAN
//
// The rule: a source is forwarded only if EVERY component from it up to / is
// anchored. A name whose parent the payload can write is re-pointable; a mount
// root is not.
//
//   - NOTHING INSIDE THE TARGET is ever accepted through this rule, at any
//     depth. The target is a read-write bind, so every name inside it has a
//     writable parent. `-v ./data:/data` is still a 403 on every layout — the
//     graft is a fixed root, never a tail (issue #284 reopened through it
//     otherwise) — but the fix it now offers is uniform: bind the target
//     itself and address the subdirectory inside the container.
//   - CheckEngineBindSource, asked about the bare target directly, accepts it
//     exactly while a BIND covers the target's parent — which since issue #550
//     means exactly while @parent-ro is selected. It is not in the defaults any
//     more, so the `sel` column is the whole point of the table: the same
//     layout accepts under `defaults + @parent-ro` and refuses under
//     `defaults`. A fact about the fallback rule, superseded for the real proxy
//     path by the graft, and the reason a user forwarding a SIBLING directory
//     (which the graft does not cover) is told to select @parent-ro.
func TestErgonomicCostOfTheAnchoredSourceRule(t *testing.T) {
	// Extra fixture directories for the deeper layouts. envFakeEnv's own set
	// stops at /home/u/proj/sub, and Resolve refuses a target it cannot stat.
	extraDirs := []string{
		"/home/u/src", "/home/u/src/proj",
		"/home/u/src/projects", "/home/u/src/projects/foo",
		"/home/u/x", "/home/u/x/y", "/home/u/x/y/proj", "/home/u/x/y/proj/sub",
		"/tmp/build-123", "/tmp/build-123/proj",
	}

	withParent := append(profile.BuiltinDefaults(), "@parent-ro")
	cases := []struct {
		name   string
		target string
		// sel is the profile selection this row resolves, before
		// @podman-socket is added. nil means the shipped defaults.
		sel []policy.ProfileName
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
			name:     "two levels below $HOME, defaults: nothing binds /home/u/proj",
			target:   "/home/u/proj/sub",
			wantRoot: false,
			why:      "/home/u/proj",
		},
		{
			name:     "the same layout with -p @parent-ro: its bind anchors the parent",
			target:   "/home/u/proj/sub",
			sel:      withParent,
			wantRoot: true,
		},
		{
			name:     "two levels below $HOME, different spelling",
			target:   "/home/u/src/proj",
			wantRoot: false,
			why:      "/home/u/src",
		},
		{
			name:     "different spelling, with -p @parent-ro",
			target:   "/home/u/src/proj",
			sel:      withParent,
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
			name:     "under $TMPDIR, defaults: /tmp is snug's own tmpfs and nothing binds build-123",
			target:   "/tmp/build-123/proj",
			wantRoot: false,
			why:      "/tmp/build-123",
		},
		{
			name:     "under $TMPDIR, with -p @parent-ro",
			target:   "/tmp/build-123/proj",
			sel:      withParent,
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
			base := tc.sel
			if base == nil {
				base = profile.BuiltinDefaults()
			}
			sel := append(append([]policy.ProfileName{}, base...), "@podman-socket")
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
			// the layout-independent half and the expensive one — the graft
			// is a fixed root and never forwards a tail, so a client still
			// has to bind the target and address the subdirectory inside the
			// container. Since #376 that fix is uniform across every row: it
			// is always the target, never "there is no substitute", because
			// binding the target itself is always what actually works now.
			for _, inside := range []string{tc.target + "/subdir", tc.target + "/a/b"} {
				err := p.CheckEngineBindSource(inside)
				if err == nil {
					t.Errorf("-v %s:/x is ACCEPTED. Nothing inside the target may be: the target is "+
						"a read-write bind, so every name in it has a writable parent and can be "+
						"replaced with a symlink between create and start (#284)", inside)
					continue
				}
				msg := err.Error()
				if !strings.Contains(msg, "Fix: bind "+tc.target) {
					t.Errorf("-v %s:/x is refused without offering the substitute that DOES work "+
						"here (bind %s and address the subdirectory inside the container):\n%s",
						inside, tc.target, msg)
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
