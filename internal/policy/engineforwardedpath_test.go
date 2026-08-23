package policy

import (
	"strings"
	"testing"
)

// TestCheckEngineForwardedPathIsAskedInGuestSpace is issue #371's own table:
// CheckEngineForwardedPath asks its question purely in GUEST space — "what
// content does the engine find at this NAME" — and every row is named for
// what it pins about that.
//
// Two rows (the divergent-bind ones, "host spelling" and "guest spelling")
// share a policy carrying @claude's own shape — `{home}/.local/bin/claude:
// /snug/bin/claude` — because Host and Guest differ BY RULE there
// (splitSpec, resolve.go), not by mistake, and the whole point of this
// predicate is to survive that. A THIRD pair (@tmp-shared's
// `{host_tmpdir}:/tmp`) is included specifically because it looks identical
// in shape to @claude's but behaves differently: /tmp is itself the divergent
// bind's GUEST, so a path *underneath the host spelling* is, by coincidence,
// also underneath the bind's own guest root — and the function walks Guest
// only, so THAT coincidence is what makes the "both spellings" message fire
// for /tmp and NOT for @claude's disjoint trees. Measured, not assumed: see
// the "host spelling resolves through an unrelated cover" row below and its
// comment.
func TestCheckEngineForwardedPathIsAskedInGuestSpace(t *testing.T) {
	// The @claude shape: Host and Guest name two completely unrelated trees.
	claudeShape := map[string]Mount{
		"/snug/bin/claude": {Guest: "/snug/bin/claude", Host: "/home/u/.local/bin/claude", Kind: KindBind, Access: AccessRO},
		"/home/u":          {Guest: "/home/u", Kind: KindTmpfs, Access: AccessRW},
	}
	// The @tmp-shared shape: Host and Guest differ, but the host tmpdir
	// happens to live UNDER the bind's own Guest ("/tmp"), so a path under
	// either spelling is covered, in GUEST space, by the very same bind.
	tmpShared := map[string]Mount{
		"/tmp": {Guest: "/tmp", Host: "/tmp/snug-shared-h", Kind: KindBind, Access: AccessRW},
	}
	homeOnly := map[string]Mount{
		"/home/u": {Guest: "/home/u", Kind: KindTmpfs, Access: AccessRW},
	}
	graftCoverMounts := map[string]Mount{
		"/usr": {Guest: "/usr", Host: "/usr", Kind: KindBind, Access: AccessRO},
	}
	graftCoverGrafts := map[string]Graft{
		"/snug/engine/store": {Mount: Mount{Guest: "/snug/engine/store", Host: "/home/u/store", Kind: KindGraft, Access: AccessRW}},
	}

	cases := []struct {
		name         string
		mounts       map[string]Mount
		grafts       map[string]Graft
		path         string
		wantErr      bool
		wantInMsg    []string
		wantNotInMsg []string
	}{
		{
			// POSITIVE CONTROL: an ordinary Host==Guest bind (the @sys shape)
			// is a fixed point, and the whole table below is meaningless if
			// this is refused too.
			name:    "positive control: identical spelling under an ordinary bind is nil",
			mounts:  map[string]Mount{"/usr": {Guest: "/usr", Host: "/usr", Kind: KindBind, Access: AccessRO}},
			path:    "/usr/bin/podman",
			wantErr: false,
		},
		{
			// @claude shape, HOST spelling. This is NOT the b.Host != b.Guest
			// clause firing — the divergent bind's Guest is /snug/bin/claude,
			// which does not cover this name at all, so the deepest GUEST
			// cover of "/home/u/.local/bin/claude" is the unrelated @home
			// tmpfs. The function still refuses (a tmpfs is not KindBind),
			// but for a different reason than the guest-spelling row below —
			// and the message must NOT name /snug/bin/claude, because the
			// function never found that mount at all. This is the sharpest
			// demonstration of "asked in guest space": handing the HOST
			// string in does not even reach the bind whose Host it is.
			name:         "divergent bind, host spelling resolves through an unrelated guest-space cover, not the bind itself",
			mounts:       claudeShape,
			path:         "/home/u/.local/bin/claude",
			wantErr:      true,
			wantInMsg:    []string{"/home/u", "tmpfs", "issue #371"},
			wantNotInMsg: []string{"/snug/bin/claude"},
		},
		{
			// @claude shape, GUEST spelling. THIS is the b.Host != b.Guest
			// clause: the deepest guest cover of "/snug/bin/claude" is
			// exactly that bind (an exact match), Kind is KindBind, and
			// Host != Guest — so the message must name BOTH spellings.
			name:      "divergent bind, guest spelling names the bind directly and cites both spellings",
			mounts:    claudeShape,
			path:      "/snug/bin/claude",
			wantErr:   true,
			wantInMsg: []string{"/home/u/.local/bin/claude", "/snug/bin/claude", "issue #371"},
		},
		{
			// @tmp-shared shape, HOST spelling. Unlike @claude's, this DOES
			// hit the divergent-bind clause: /tmp/snug-shared-h/x is itself
			// under the bind's Guest ("/tmp"), so the deepest guest cover is
			// the bind, and both spellings appear.
			name:      "tmp-shared, host spelling lands on the bind's own guest root by coincidence, both spellings",
			mounts:    tmpShared,
			path:      "/tmp/snug-shared-h/x",
			wantErr:   true,
			wantInMsg: []string{"/tmp/snug-shared-h", "/tmp", "issue #371"},
		},
		{
			// @tmp-shared shape, GUEST spelling. Same clause, same message
			// shape, reached the "ordinary" way.
			name:      "tmp-shared, guest spelling, both spellings",
			mounts:    tmpShared,
			path:      "/tmp/x",
			wantErr:   true,
			wantInMsg: []string{"/tmp/snug-shared-h", "/tmp", "issue #371"},
		},
		{
			name:      "tmpfs cover names the tmpfs, not a host tree",
			mounts:    homeOnly,
			path:      "/home/u/anything",
			wantErr:   true,
			wantInMsg: []string{"/home/u", "tmpfs", "issue #371"},
		},
		{
			name:      "no cover names the read-only root",
			mounts:    map[string]Mount{},
			path:      "/var/lib/x",
			wantErr:   true,
			wantInMsg: []string{"read-only root tmpfs", "issue #371"},
		},
		{
			name:      "a graft's Guest covers the name and refuses before any mount is consulted",
			mounts:    graftCoverMounts,
			grafts:    graftCoverGrafts,
			path:      "/snug/engine/store/x",
			wantErr:   true,
			wantInMsg: []string{"/snug/engine/store", "graft", "issue #371"},
		},
		{
			// The #251 shape, named in this function's own doc comment as the
			// SECOND reason EngineGuestPath is the wrong question here: a host
			// path reachable ONLY through a graft's HOST (no bind's Guest
			// covers it at all — this is snug's own engine-owned store
			// directory, which no profile grant exposes). EngineGuestPath's
			// first arm matches by Graft.Host and answers "visible, at
			// /snug/engine/store" for exactly this path — the hole issue #251
			// closed. CheckEngineForwardedPath must NOT inherit that: no
			// mount's GUEST covers this name, so it refuses on the plain
			// "no cover" clause, same as any other unexposed path. This row
			// is what makes mutation 4 (rewriting the body in terms of
			// EngineGuestPath's bool) fail loudly rather than by accident —
			// the widening row's own nil-ness happens to survive that
			// mutation, and this one is what does not.
			name: "issue #251 shape: reachable only through a graft's Host, never through a mount's Guest -> refused",
			mounts: map[string]Mount{
				"/usr": {Guest: "/usr", Host: "/usr", Kind: KindBind, Access: AccessRO},
			},
			grafts: map[string]Graft{
				"/snug/engine/store": {Mount: Mount{
					Guest: "/snug/engine/store",
					Host:  "/home/u/.local/share/snug/engines/x/storage",
					Kind:  KindGraft, Access: AccessRW,
				}},
			},
			path:      "/home/u/.local/share/snug/engines/x/storage/overlay/l/ABC",
			wantErr:   true,
			wantInMsg: []string{"no mount of this sandbox covers", "issue #371"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Policy{Mounts: tc.mounts, Grafts: tc.grafts}
			err := p.CheckEngineForwardedPath(tc.path)
			if tc.wantErr && err == nil {
				t.Fatalf("CheckEngineForwardedPath(%q) = nil; want a refusal", tc.path)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("CheckEngineForwardedPath(%q) = %v; want nil", tc.path, err)
			}
			if err == nil {
				return
			}
			got := err.Error()
			for _, want := range tc.wantInMsg {
				if !strings.Contains(got, want) {
					t.Errorf("CheckEngineForwardedPath(%q) error does not contain %q:\n%s", tc.path, want, got)
				}
			}
			for _, unwanted := range tc.wantNotInMsg {
				if strings.Contains(got, unwanted) {
					t.Errorf("CheckEngineForwardedPath(%q) error contains %q, which it must not — "+
						"that would mean the function found the bind it never should have reached:\n%s",
						tc.path, unwanted, got)
				}
			}
		})
	}

	// THE WIDENING (issue #371's own worked example, row 8): a source under a
	// sandbox-visible directory that ALSO carries a toolchain graft whose Host
	// covers it. CheckEngineForwardedPath must accept the name — no graft's
	// GUEST covers it, and the deepest guest cover is the plain Host==Guest
	// bind — while EngineGuestPath, asked the SAME question about the SAME
	// string, answers with the graft's Guest instead, because its graft arm
	// matches by Graft.HOST and wins unconditionally over the bind arm. The
	// two functions are pinned here as disagreeing ON PURPOSE: a graft lands
	// at its Guest, never at its Host, so "where does this content appear to
	// the engine" (EngineGuestPath) and "what does this NAME mean to the
	// engine" (CheckEngineForwardedPath) are different questions with
	// different, and here divergent, right answers.
	t.Run("the widening: a graft's Host covering a bind's Host does not shadow the bind's own name", func(t *testing.T) {
		mounts := map[string]Mount{
			"/home/u/bundle": {Guest: "/home/u/bundle", Host: "/home/u/bundle", Kind: KindBind, Access: AccessRO},
		}
		grafts := map[string]Graft{
			"/snug/engine/toolchain": {Mount: Mount{Guest: "/snug/engine/toolchain", Host: "/home/u/bundle", Kind: KindGraft, Access: AccessRO}},
		}
		p := &Policy{Mounts: mounts, Grafts: grafts}

		if err := p.CheckEngineForwardedPath("/home/u/bundle/lib/x"); err != nil {
			t.Fatalf("CheckEngineForwardedPath(%q) = %v; want nil — the deepest GUEST cover is the "+
				"plain bind, Host==Guest, and no graft's GUEST covers this name", "/home/u/bundle/lib/x", err)
		}

		got, ok := p.EngineGuestPath("/home/u/bundle/lib/x")
		if !ok {
			t.Fatal("EngineGuestPath(/home/u/bundle/lib/x) = (_, false); want the graft's mapping")
		}
		if want := "/snug/engine/toolchain/lib/x"; got != want {
			t.Errorf("EngineGuestPath(%q) = %q, want %q — its graft arm matches by Graft.Host and "+
				"wins unconditionally over the bind arm, so it answers with the GRAFT's guest path "+
				"for the very same string CheckEngineForwardedPath just accepted unchanged. That is "+
				"the two functions disagreeing on purpose, not a bug in either one.",
				"/home/u/bundle/lib/x", got, want)
		}
	})
}
