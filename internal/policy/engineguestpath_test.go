package policy

import "testing"

// TestEngineGuestPathAnswersTheThreeCasesAndRefusesTheFourth is the whole rule,
// one subtest per case, with the refusal treated as a result rather than as an
// error path — because the refusal is what stops snug handing the engine a path
// it cannot resolve, and a mapper that answered "" and true would be worse than
// no mapper at all.
func TestEngineGuestPathAnswersTheThreeCasesAndRefusesTheFourth(t *testing.T) {
	env := newFakeEnv()
	p := mustResolve(t, append([]ProfileName{}, testDefaults...)...)

	// A graft of a host directory snug created for this run, which is what
	// every Tier C store/runroot/sock/conf graft is.
	if err := p.OwnEngineHostPath(env, "/home/u/secrets"); err != nil {
		t.Fatal(err)
	}
	if err := p.Graft(env, Graft{
		Mount: Mount{
			Guest: p.Target + "/store", Host: "/home/u/secrets",
			Kind: KindGraft, Access: AccessRW, From: []string{"(snug)"},
		},
		Why: "a container handed this graft writes to the image store every run of this " +
			"profile set shares, so a poisoned layer outlives the sandbox that wrote it",
	}); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	t.Run("through a graft", func(t *testing.T) {
		got, ok := p.EngineGuestPath("/home/u/secrets/overlay/l/ABC")
		if !ok {
			t.Fatal("a path under a graft's Host is not visible to the engine, but the graft is " +
				"exactly what puts it there")
		}
		if want := p.Target + "/store/overlay/l/ABC"; got != want {
			t.Errorf("got %q, want %q — the remainder below the graft's Host must survive the "+
				"mapping, or every path inside the store collapses onto the store itself", got, want)
		}
	})

	t.Run("the graft's Host itself", func(t *testing.T) {
		got, ok := p.EngineGuestPath("/home/u/secrets")
		if !ok || got != p.Target+"/store" {
			t.Errorf("got (%q, %v), want the graft's own Guest — the exact-match case is the one "+
				"every --root and --runroot argument takes", got, ok)
		}
	})

	t.Run("through the sandbox's own view", func(t *testing.T) {
		// /usr is bound by @sys, and the engine's view is DERIVED from the
		// sandbox's, so a toolchain there needs no graft and no mapping.
		got, ok := p.EngineGuestPath("/usr/bin/podman")
		if !ok {
			t.Fatal("a path inside a grant the sandbox itself has is reported invisible to the " +
				"engine — the engine's view is derived from the sandbox's, so this is the case " +
				"that needs NO graft and it must not be turned into one")
		}
		if got != "/usr/bin/podman" {
			t.Errorf("got %q, want /usr/bin/podman unchanged", got)
		}
	})

	t.Run("nothing exposes it", func(t *testing.T) {
		if got, ok := p.EngineGuestPath("/var/lib/nothing-grants-this"); ok {
			t.Errorf("got (%q, true) for a path no grant and no graft exposes; the caller would "+
				"then hand the engine a path that resolves to nothing, and podman's own error "+
				"would name a file rather than a boundary", got)
		}
	})
}

// TestEngineGuestPathRefusesAMountShadowedByAGraft is the one case where the
// honest answer is "cannot see it" even though a mount does cover the host
// path: a graft is installed ON TOP of the sandbox's view, so the guest path
// the mount would answer with now names the GRAFT's content — a different tree
// with the same name, which is worse than no answer.
func TestEngineGuestPathRefusesAMountShadowedByAGraft(t *testing.T) {
	env := newFakeEnv()
	p := mustResolve(t, append([]ProfileName{}, testDefaults...)...)

	target := p.Mounts[p.Target]
	if target.Kind != KindBind || target.Host == "" {
		t.Fatalf("fixture: the target is not a bind (%v)", target.Kind)
	}

	// CONTROL: before the graft exists, the path maps through the target's own
	// bind. Without this, the refusal below could be refusing for any reason.
	before, ok := p.EngineGuestPath(target.Host + "/sub/thing")
	if !ok || before != p.Target+"/sub/thing" {
		t.Fatalf("control: got (%q, %v) through the target's own bind, want %q",
			before, ok, p.Target+"/sub/thing")
	}

	if err := p.OwnEngineHostPath(env, "/home/u/secrets"); err != nil {
		t.Fatal(err)
	}
	if err := p.Graft(env, Graft{
		Mount: Mount{
			Guest: p.Target + "/sub", Host: "/home/u/secrets",
			Kind: KindGraft, Access: AccessRW, From: []string{"(snug)"},
		},
		Why: "a container handed this graft reaches a host directory the payload can also " +
			"write, so what it reads is what the payload last put there",
	}); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	if got, ok := p.EngineGuestPath(target.Host + "/sub/thing"); ok {
		t.Errorf("got (%q, true): the mount that answered is SHADOWED in the engine's view by a "+
			"graft at %s, so that path names the graft's content there, not this host path",
			got, p.Target+"/sub")
	}
}

// TestEngineGuestPathPrefersTheDeepestSource pins the tie-break. Two grafts, one
// inside the other's source, is not hypothetical — Tier C's own runroot and
// socket directory both sit under snug's per-run directory — and answering with
// the shallower one silently sends the caller to the wrong tree.
func TestEngineGuestPathPrefersTheDeepestSource(t *testing.T) {
	env := newFakeEnv()
	p := mustResolve(t, append([]ProfileName{}, testDefaults...)...)

	for _, h := range []string{"/home/u/secrets", "/home/u/secrets/inner"} {
		if err := p.OwnEngineHostPath(env, h); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(guest, host string) {
		t.Helper()
		if err := p.Graft(env, Graft{
			Mount: Mount{
				Guest: guest, Host: host,
				Kind: KindGraft, Access: AccessRW, From: []string{"(snug)"},
			},
			Why: "a container handed this graft writes to a host directory snug created for " +
				"this run, and what it writes outlives the container",
		}); err != nil {
			t.Fatalf("fixture %s: %v", guest, err)
		}
	}
	mk(p.Target+"/outer", "/home/u/secrets")
	mk(p.Target+"/inner", "/home/u/secrets/inner")

	got, ok := p.EngineGuestPath("/home/u/secrets/inner/file")
	if !ok {
		t.Fatal("a path under the deeper graft's Host is invisible")
	}
	if want := p.Target + "/inner/file"; got != want {
		t.Errorf("got %q, want %q — the DEEPEST matching source wins; answering with the "+
			"shallower graft sends the caller to a path that exists and holds something else",
			got, want)
	}
}
