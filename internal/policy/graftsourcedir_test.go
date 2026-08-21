package policy

import (
	"strings"
	"testing"
)

// ── G6, issue #290: a graft's SOURCE must be a DIRECTORY ────────────────────

// TestGraftSourceMustBeADirectory is G6's table: a socket, a FIFO or a
// regular file at a graft's Host is refused; a directory is accepted; and a
// source that does not exist YET is also accepted, because GraftPathsInto
// (issue #125's design pass) runs at a point where the run directory a caller
// is about to graft may not have been created — refusing here would make
// --dry-run fail on host state rather than on policy.
//
// Every row records the source's Host as OWNED first (OwnEngineHostPath), so
// the refusal each row measures is G6's — "the source is not a directory" —
// rather than G4's "no grant exposes this path". A row where G4 fired instead
// would prove nothing about G6.
func TestGraftSourceMustBeADirectory(t *testing.T) {
	const probe = "/home/u/secrets/endpoint"

	for _, tc := range []struct {
		name    string
		host    string
		setup   func(env *fakeEnv)
		refused bool
	}{
		{"socket source", probe, func(e *fakeEnv) { e.sockets = map[string]bool{probe: true} }, true},
		{"fifo source", probe, func(e *fakeEnv) { e.fifos = map[string]bool{probe: true} }, true},
		{"regular file source", probe, func(e *fakeEnv) { e.files[probe] = true }, true},
		{"directory source", "/home/u/secrets", func(e *fakeEnv) {}, false},
		{"missing source (the --dry-run path)", "/home/u/secrets/not-yet-created", func(e *fakeEnv) {}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := mustResolveDefaults(t)
			env := newFakeEnv()
			tc.setup(env)

			// OwnEngineHostPath, not a grant: G6 sits BEHIND G4 in checkGraft, so
			// a row here has to pass G4 ("the sandbox already exposes this host
			// path, or snug owns it") before it can reach G6 at all. Recording it
			// this way, rather than granting it through a profile, keeps every row
			// identical in every respect except the one under test.
			if err := p.OwnEngineHostPath(env, tc.host); err != nil {
				t.Fatalf("fixture: OwnEngineHostPath refused %s: %v", tc.host, err)
			}
			g := validGraft(p, "g6-probe")
			g.Host = tc.host

			err := p.Graft(env, g)
			switch {
			case tc.refused && err == nil:
				t.Fatalf("a graft sourced from a %s was accepted — a graft is an open_tree(2) "+
					"clone of the source moved onto the destination, and it must move a directory "+
					"TREE, never a single socket, FIFO or file", tc.name)
			case tc.refused:
				if !strings.Contains(err.Error(), "not a directory") {
					t.Errorf("the refusal for a %s does not say \"not a directory\": %v", tc.name, err)
				}
				if !strings.Contains(err.Error(), tc.host) {
					t.Errorf("the refusal for a %s does not name the source path %s: %v",
						tc.name, tc.host, err)
				}
			case !tc.refused && err != nil:
				t.Errorf("a graft sourced from a %s was refused: %v", tc.name, err)
			}
		})
	}
}

// TestG6HasNoAuthoredExemption is the negative that matters most: G6 must
// refuse an Authored graft with an endpoint source exactly as it refuses an
// unauthored one.
//
// This is the direct test that G6 was not written — and never becomes — the
// "if g.Authored { continue }" shape graft.go's own doc comment names as the
// trap: Policy.Graft sets Authored=true on EVERY graft it builds, several
// lines before checkGraft ever runs, so an Authored exemption on G6 would be
// unconditionally true for every graft this package produces and G6 would be
// documented but never actually enforced (CLAUDE.md's "a gate that is
// documented but not implemented is not a gate"). Calling checkGraft directly
// with a hand-built, explicitly Authored Graft — bypassing Policy.Graft
// entirely — is what makes this test mean something regardless of what
// Policy.Graft itself happens to set: even a caller that forged Authored
// still gets refused.
func TestG6HasNoAuthoredExemption(t *testing.T) {
	const sock = "/home/u/secrets/authored-sock"

	p := mustResolveDefaults(t)
	env := newFakeEnv()
	env.sockets = map[string]bool{sock: true}

	if err := p.OwnEngineHostPath(env, sock); err != nil {
		t.Fatalf("fixture: OwnEngineHostPath refused %s: %v", sock, err)
	}
	g := validGraft(p, "g6-authored-probe")
	g.Host = sock
	g.Authored = true // set directly, the same field Policy.Graft always sets

	if err := p.checkGraft(env, g); err == nil {
		t.Fatal("checkGraft accepted an Authored graft whose source is a SOCKET — G6 must have " +
			"no Authored exemption (issue #290)")
	} else if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("unexpected refusal: %v", err)
	}
}

// TestG6DoesNotApplyToFreshMountGrafts is G6's other boundary: KindProc,
// KindCgroup2 and KindTmpfs have no Host at all — the stage MOUNTS them fresh
// rather than cloning a host path with open_tree(2) — so G6 must not ask
// whether their (nonexistent) source is a directory. Gated on
// graftKindRules[g.Kind].hasHost, same as every other Host-shaped rule in
// checkGraft.
//
// The selection matters, and reuses graftkind_test.go's own fixture reasoning
// (TestAFreshMountGraftMayNotCarryAHost's control): with the DEFAULT
// selection, G3 alone refuses a cgroup2 or tmpfs graft, because
// /sys/fs/cgroup and /run exist in the sandbox's view only on a run that
// selects an engine (G3's fourth disjunct is conditioned on
// p.Podman != PodmanOff). @podman-socket is added so a failure here can only
// be G6's — the rule under test — never G3's.
func TestG6DoesNotApplyToFreshMountGrafts(t *testing.T) {
	for _, kind := range []Kind{KindProc, KindCgroup2, KindTmpfs} {
		t.Run(kind.String(), func(t *testing.T) {
			sel := append(append([]ProfileName{}, testDefaults...), "@podman-socket")
			p, err := Resolve(testRegistry(), sel, testCtx(), newFakeEnv())
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			if p.Podman == PodmanOff {
				t.Fatal("fixture: @podman-socket resolved to PodmanOff, so G3's fourth disjunct " +
					"is inactive and a failure below cannot be attributed to G6 specifically")
			}
			if err := p.Graft(newFakeEnv(), freshMountGraft(kind)); err != nil {
				t.Errorf("a %s graft (no Host — the stage mounts these fresh) was refused; G6 "+
					"must be gated on rules.hasHost so a Kind with no source is never asked "+
					"whether its source is a directory: %v", kind, err)
			}
		})
	}
}
