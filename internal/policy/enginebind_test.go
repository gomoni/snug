package policy

import (
	"strings"
	"testing"
)

// TestCheckEngineBindSource is the pure unit table for the anchored source
// rule (issue #284, §3.1 of the fix spec). Each case is named after the
// measurement row it pins — see CheckEngineBindSource's own doc comment for
// what M1-M5 mean.
func TestCheckEngineBindSource(t *testing.T) {
	cases := []struct {
		name    string
		mounts  map[string]Mount
		grafts  map[string]Graft
		guest   string
		wantErr bool
		// wantComponent, when set, must appear in the error text — the
		// refusal must name the offending COMPONENT, not merely the source.
		wantComponent string
	}{
		{
			// M-baseline: every ancestor of an ordinary @sys-style read-only
			// bind is either uncovered (root tmfs, not writable) or covered by
			// a read-only KindBind. Nothing on the path is ever writable, so
			// every component is anchored regardless of mount-root status.
			name: "ro root tmpfs chain -> anchored",
			mounts: map[string]Mount{
				"/usr": {Guest: "/usr", Kind: KindBind, Host: "/usr", Access: AccessRO},
			},
			guest:   "/usr/bin/foo",
			wantErr: false,
		},
		{
			// M5: the target lives under /tmp (a KindTmpfs, payload-writable
			// by the table in the doc comment), and nothing installs a
			// separate mount at /tmp/<dir> — it is just a name inside the
			// tmpfs. The refusal must name /tmp/<dir>, the SHALLOWEST
			// offending component, not the deeper source path.
			name: "KindTmpfs ancestor, non-mount-root leaf -> swappable, names the shallow component",
			mounts: map[string]Mount{
				"/tmp": {Guest: "/tmp", Kind: KindTmpfs, Access: AccessRW},
			},
			guest:         "/tmp/somedir/realdir",
			wantErr:       true,
			wantComponent: "/tmp/somedir",
		},
		{
			// M2: the #284 primitive itself — a read-write KindBind (the
			// sandbox's own writable target) with a plain subdirectory name
			// underneath that is not itself a mount. Renamed to a symlink
			// between create and start, per the issue's own reproduction.
			name: "rw KindBind parent, non-mount-root leaf -> swappable (#284 primitive)",
			mounts: map[string]Mount{
				"/work": {Guest: "/work", Kind: KindBind, Host: "/host/work", Access: AccessRW},
			},
			guest:         "/work/realdir",
			wantErr:       true,
			wantComponent: "realdir",
		},
		{
			// M1/M3: the target's own mount root sits directly under a
			// writable-but-unbindable ancestor ($HOME as a bare KindTmpfs, no
			// rw KindBind covering it) — the default `@parent-ro` + `@cwd-rw`
			// shape. The mount root itself is EBUSY against a rename from
			// inside this sandbox, and nothing else offers a route to the
			// same underlying entry, so it is anchored.
			name: "mount root under a writable-but-unbindable tmpfs ancestor -> anchored",
			mounts: map[string]Mount{
				"/home/u":     {Guest: "/home/u", Kind: KindTmpfs, Access: AccessRW},
				"/home/u/src": {Guest: "/home/u/src", Kind: KindBind, Host: "/home/u/src", Access: AccessRW},
			},
			guest:   "/home/u/src",
			wantErr: false,
		},
		{
			// M4: same shape as above, but now a SEPARATE read-write KindBind
			// also covers the tmpfs ancestor — an unreachable-with-shipped-
			// profiles-only configuration (no builtin grants rw over a
			// directory that also contains another mount root), but the rule
			// exists for it regardless: the engine's own namespace does not
			// contain the sandbox's mount at /home/u/src, so a rewrite
			// reachable through the OTHER rw bind still reaches what the
			// engine resolves at start.
			name: "same, but a second rw KindBind covers the ancestor -> swappable (M4 clause)",
			mounts: map[string]Mount{
				"/home/u":     {Guest: "/home/u", Kind: KindBind, Host: "/home/u", Access: AccessRW},
				"/home/u/src": {Guest: "/home/u/src", Kind: KindBind, Host: "/home/u/src", Access: AccessRW},
			},
			guest:         "/home/u/src",
			wantErr:       true,
			wantComponent: "/home/u/src",
		},
		{
			// KindData is deliberately excluded from the mount-root set (a
			// generated file overmounts an EXISTING path via --ro-bind-data,
			// issue #73 — never a renameable anchor), even when it is
			// (unusually) marked AccessRW: it must not count as a mount root,
			// so a writable parent above it still refuses the leaf.
			name: "KindData AccessRW leaf is NOT a mount root -> swappable",
			mounts: map[string]Mount{
				"/work":        {Guest: "/work", Kind: KindBind, Host: "/host/work", Access: AccessRW},
				"/work/marker": {Guest: "/work/marker", Kind: KindData, Access: AccessRW},
			},
			guest:         "/work/marker",
			wantErr:       true,
			wantComponent: "marker",
		},
		{
			// A graft installs a completely different tree in the engine's
			// derived view at its Guest — a component under one never means
			// what this sandbox's own check judged, independent of
			// writability.
			name: "an ancestor is covered by a graft's Guest -> refused",
			mounts: map[string]Mount{
				"/usr": {Guest: "/usr", Kind: KindBind, Host: "/usr", Access: AccessRO},
			},
			grafts: map[string]Graft{
				"/snug/engine/store": {
					Mount: Mount{Guest: "/snug/engine/store", Kind: KindGraft, Access: AccessRW},
				},
			},
			guest:         "/snug/engine/store/overlay-images/images.json",
			wantErr:       true,
			wantComponent: "/snug/engine/store",
		},
		{
			// POSITIVE CONTROL: the exact #284-primitive policy above, with
			// the same mount demoted from rw to ro, must return nil — proving
			// the refusal above is about writability and not merely about the
			// shape of the mount table.
			name: "positive control: #284 primitive policy demoted to ro -> anchored",
			mounts: map[string]Mount{
				"/work": {Guest: "/work", Kind: KindBind, Host: "/host/work", Access: AccessRO},
			},
			guest:   "/work/realdir",
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Policy{Mounts: tc.mounts, Grafts: tc.grafts}
			err := p.CheckEngineBindSource(tc.guest)
			if tc.wantErr && err == nil {
				t.Fatalf("CheckEngineBindSource(%q) = nil; want a refusal", tc.guest)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("CheckEngineBindSource(%q) = %v; want nil", tc.guest, err)
			}
			if tc.wantErr && tc.wantComponent != "" {
				got := err.Error()
				if !strings.Contains(got, tc.wantComponent) {
					t.Errorf("CheckEngineBindSource(%q) error does not name the offending component %q:\n%s",
						tc.guest, tc.wantComponent, got)
				}
			}
		})
	}
}
