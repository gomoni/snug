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
// below still calls CheckEngineBindSource directly and still varies with the
// mount set, because the RULE this file exercises is unchanged; it documents
// what happens to a source the graft's exact match does not cover, not what a
// client's `-v $SNUG_TARGET:/work` actually gets.
//
// SINCE ISSUE #553, EVERY ROW BELOW ACCEPTS. An ancestor whose deepest cover
// is a tmpfs is now anchored — an empty, authored tmpfs InstallAnchors mounts
// there — so it is a mount root and case 2 (enginebind.go: "the name sits in a
// directory this sandbox can write, so it can be replaced with a symlink")
// stops firing on every layout this table used to pin it for. That is a
// removal of a statement that became FALSE, not a loosening: `mv`/`ln -s` onto
// the anchor returns EBUSY (see enginebind.go's "Anchors satisfy case 3, and
// they satisfy it MORE than an ordinary bind"). `@parent-ro`'s own column is
// no longer what distinguishes a row here — every row it used to be needed for
// now accepts without it — and it stays in the table only as the CONTROL that
// this table still measures something: TestTheReadWriteBoundAncestorResidualStillRefuses
// below is the one shape that still does not accept, and @parent-ro cannot
// fix that one either (its bind IS the read-write ancestor).
//
// # WHAT THE ROWS MEAN
//
//   - NOTHING INSIDE THE TARGET is ever accepted through this rule, at any
//     depth. The target is a read-write bind, so every name inside it has a
//     writable parent. `-v ./data:/data` is still a 403 on every layout — the
//     graft is a fixed root, never a tail (issue #284 reopened through it
//     otherwise) — and the fix it offers is uniform: bind the target itself
//     and address the subdirectory inside the container.
//   - The bare target ROOT accepts on every layout below, anchored or not:
//     anchoring closed the depth-dependent gap #284's rule used to leave open
//     against a plain `~/proj/sub`-shaped target.
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
	}{
		{
			name:   "two levels below $HOME, defaults: the parent is anchored",
			target: "/home/u/proj/sub",
		},
		{
			name:   "the same layout with -p @parent-ro: its bind anchors the parent instead",
			target: "/home/u/proj/sub",
			sel:    withParent,
		},
		{
			name:   "two levels below $HOME, different spelling",
			target: "/home/u/src/proj",
		},
		{
			name:   "different spelling, with -p @parent-ro",
			target: "/home/u/src/proj",
			sel:    withParent,
		},
		{
			name:   "THREE levels below $HOME: every ancestor down to $HOME is anchored",
			target: "/home/u/src/projects/foo",
		},
		{
			name:   "four levels below $HOME",
			target: "/home/u/x/y/proj/sub",
		},
		{
			name:   "under $TMPDIR, defaults: /tmp is snug's own tmpfs and anchors build-123",
			target: "/tmp/build-123/proj",
		},
		{
			name:   "under $TMPDIR, with -p @parent-ro",
			target: "/tmp/build-123/proj",
			sel:    withParent,
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

			// The target ROOT. Every row accepts since #553 — see the file
			// comment for why the anchored-source rule no longer refuses any
			// layout in this table.
			if rootErr := p.CheckEngineBindSource(tc.target); rootErr != nil {
				t.Errorf("-v %s:/work is REFUSED, and issue #553's anchor at this layout's "+
					"parent is supposed to make every row here accept:\n%v", tc.target, rootErr)
			}

			// INSIDE the target: refused in every row, no exceptions. This is
			// the layout-independent half and the expensive one — the graft
			// is a fixed root and never forwards a tail, so a client still
			// has to bind the target and address the subdirectory inside the
			// container.
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

// TestTheReadWriteBoundAncestorResidualStillRefuses is the row #553 did NOT
// close: InstallAnchors deliberately never anchors an ancestor covered by a
// read-write bind (anchor.go, "why the cover must be a tmpfs and not merely
// payload-writable" — an empty tmpfs stacked on a real host directory would
// HIDE every entry in it, which is invariant 1's own subtraction). So a
// source one level inside an rw-granted directory is exactly as forwardable
// as it was before #553: refused by case 3 (rwBindCovers), because the rw
// grant is itself a second route to the same directory entry.
//
// No shipped builtin reaches this shape — @tmp-shared's rw of {host_tmpdir}
// looks like it should, and does not, because a target under /tmp then nests
// @cwd-rw's bind inside @tmp-shared's and rejectMasking refuses the whole
// selection (measured on this branch: "which is inside /tmp from profile
// @tmp-shared") — so this test authors its own rw-granting profile, the same
// shape a user's own profiles.d entry would take.
func TestTheReadWriteBoundAncestorResidualStillRefuses(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	reg["data"] = &policy.Profile{Name: "data", RW: []string{"/var/tmp/data"}}

	env := newEnvFakeEnv()
	for _, d := range []string{"/var/tmp/data", "/var/tmp/data/proj"} {
		env.dirs[d] = true
	}
	ctx := policy.Context{
		Target: "/var/tmp/data/proj", Home: "/home/u",
		Shell: "/usr/bin/bash", Command: []string{"/bin/sh"},
	}
	sel := append(append([]policy.ProfileName{}, profile.BuiltinDefaults()...), "data")
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, ctx, env)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	err = p.CheckEngineBindSource("/var/tmp/data/proj")
	if err == nil {
		t.Fatal("-v /var/tmp/data/proj:/work is ACCEPTED — a source one level inside a " +
			"read-write-granted directory must still refuse (case 3, rwBindCovers): the " +
			"grant itself is a second route to the same directory entry, which no anchor " +
			"can close without hiding host content invariant 1 forbids hiding")
	}
	if !strings.Contains(err.Error(), "read-write bind") {
		t.Errorf("the refusal does not read as case 3 (rwBindCovers):\n%v", err)
	}
	if !strings.Contains(err.Error(), "#284") {
		t.Errorf("the refusal does not cite issue #284:\n%v", err)
	}
}
