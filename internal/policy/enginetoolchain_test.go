package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEngineToolchainAdmitsExactlyItselfAndOnlyReadOnly is G4's third source
// stated as the four things it must do, each of which is a way a looser
// version would be wrong.
//
// The positive control is the FIRST assertion, not an afterthought: the same
// graft is refused before the root is recorded and accepted after, so every
// refusal below is refusing for the reason it names rather than because the
// fixture never passed G4 at all.
func TestEngineToolchainAdmitsExactlyItselfAndOnlyReadOnly(t *testing.T) {
	env := newFakeEnv()
	const root = "/home/u/secrets" // ungranted by the default selection, and resolvable

	// CONTROL: ungranted, unrecorded — refused.
	p := mustResolveDefaults(t)
	g := validGraft(p, "toolchain")
	g.Host = root
	if err := p.Graft(env, g); err == nil {
		t.Fatal("control: a graft of an ungranted host path was accepted BEFORE any toolchain " +
			"root was recorded, so the acceptance below would prove nothing")
	}

	// EXACT, READ-ONLY: accepted.
	p = mustResolveDefaults(t)
	if err := p.EngineToolchain(env, root); err != nil {
		t.Fatalf("EngineToolchain refused a hygienic absolute directory: %v", err)
	}
	g = validGraft(p, "toolchain")
	g.Host = root
	g.Access = AccessRO
	if err := p.Graft(env, g); err != nil {
		t.Fatalf("a READ-ONLY graft of the recorded toolchain root was refused: %v", err)
	}

	// WRITABLE: refused, and the refusal says which of the two mistakes it is.
	p = mustResolveDefaults(t)
	if err := p.EngineToolchain(env, root); err != nil {
		t.Fatal(err)
	}
	g = validGraft(p, "toolchain-rw")
	g.Host = root
	g.Access = AccessRW
	err := p.Graft(env, g)
	if err == nil {
		t.Fatal("a WRITABLE graft of the toolchain root was accepted — the bundle is the host " +
			"user's own installation, so this is a host-write channel out of the engine")
	}
	if !strings.Contains(err.Error(), "READ-ONLY") {
		t.Errorf("the refusal for a writable toolchain graft does not say that read-only is the "+
			"difference, so it reads as 'that path is not recorded' — which is a different "+
			"mistake with a different fix:\n%v", err)
	}

	// A SUBDIRECTORY: refused. This is the whole content of "exact membership,
	// never a prefix" — the bundle carries an image store, a home directory
	// and a configuration tree, and a prefix rule would graft any of them
	// without a line saying so.
	p = mustResolveDefaults(t)
	if err := p.EngineToolchain(env, root); err != nil {
		t.Fatal(err)
	}
	g = validGraft(p, "toolchain-sub")
	g.Host = root + "/var"
	g.Access = AccessRO
	if err := p.Graft(env, g); err == nil {
		t.Fatalf("a graft of %s/var was accepted because %s is the recorded toolchain root — "+
			"that is a prefix rule, and the field's contract is exact membership", root, root)
	}

	// A SIBLING that merely shares a string prefix: refused. Cheap, and it is
	// the classic off-by-one of a prefix rule written with strings.HasPrefix.
	p = mustResolveDefaults(t)
	if err := p.EngineToolchain(env, root); err != nil {
		t.Fatal(err)
	}
	g = validGraft(p, "toolchain-sibling")
	g.Host = root + "-other"
	g.Access = AccessRO
	if err := p.Graft(env, g); err == nil {
		t.Fatalf("a graft of %s-other was accepted against a recorded root of %s", root, root)
	}
}

// TestEngineToolchainIsWrittenOnce pins the writer's own discipline: one
// engine per run means one root, so a second DIFFERENT value is a caller bug
// and not a choice for this code to make silently. Idempotence for the same
// value is asserted too, because a rule that also refused a harmless repeat
// would push callers into tracking whether they had already called it.
func TestEngineToolchainIsWrittenOnce(t *testing.T) {
	env := newFakeEnv()
	p := mustResolveDefaults(t)

	if err := p.EngineToolchain(env, "/home/u/secrets"); err != nil {
		t.Fatalf("first write refused: %v", err)
	}
	if err := p.EngineToolchain(env, "/home/u/secrets"); err != nil {
		t.Errorf("a repeat of the SAME root was refused; idempotence is deliberate: %v", err)
	}
	err := p.EngineToolchain(env, "/opt")
	if err == nil {
		t.Fatal("a SECOND, different toolchain root was accepted — one of the two silently " +
			"decided which host directory the engine may execute out of")
	}
	if !strings.Contains(err.Error(), "/home/u/secrets") {
		t.Errorf("the refusal does not name the root already recorded, so a reader cannot tell "+
			"which of the two calls was the unexpected one:\n%v", err)
	}
	if p.EngineToolchainRoot != "/home/u/secrets" {
		t.Errorf("the refused second write changed the field to %q", p.EngineToolchainRoot)
	}

	// An empty argument is a refusal, not a clear. Otherwise the write-once
	// property would depend on the argument's value.
	if err := p.EngineToolchain(env, ""); err == nil {
		t.Fatal("an EMPTY toolchain root was accepted")
	}
	if p.EngineToolchainRoot != "/home/u/secrets" {
		t.Errorf("an empty argument cleared the recorded root (now %q)", p.EngineToolchainRoot)
	}
}

// TestEngineToolchainRunsTheSameHygieneAsTheOtherG4Source is the reason
// OwnEngineHostPath exists at all, applied to the new field on the day it is
// added rather than after a red-team round finds it: a G4 source with a doc
// comment, a reader and no hygiene check is issue #55's finding F2 exactly.
func TestEngineToolchainRunsTheSameHygieneAsTheOtherG4Source(t *testing.T) {
	env := newFakeEnv()
	for _, bad := range []string{"relative/path", "/has\x00nul", "/has\nnewline"} {
		p := mustResolveDefaults(t)
		if err := p.EngineToolchain(env, bad); err == nil {
			t.Errorf("EngineToolchain accepted %q; OwnEngineHostPath refuses the same shape, and "+
				"a G4 source that skips the check is the half-applied rule CLAUDE.md names", bad)
		}
	}
}

// engineToolchainWriteRE finds every assignment to the field, so the
// single-writer claim is checkable rather than merely documented — the same
// device TestOnlyOneWriterOfEngineOwnedHostPaths uses for G4's second source,
// and for the same reason: before OwnEngineHostPath existed, a caller could
// set that map directly and pass G4 unconditionally.
var engineToolchainWriteRE = regexp.MustCompile(`\.EngineToolchainRoot\s*=`)

func TestOnlyOneWriterOfEngineToolchainRoot(t *testing.T) {
	// moduleRoot, not filepath.Join("..", "..", "internal"): a hardcoded
	// subroot makes the walk a subdirectory of the module, so a writer in
	// cmd/snug ships green (issue #291 part 1b). visited below asserts the
	// walk really reached outside internal/.
	root := moduleRoot(t)
	visited := map[string]bool{}
	var hits []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		// A source sweep walks a tree other packages' tests are writing in. An entry
		// that vanished between its parent's ReadDir and this call is not a source
		// file and is not this sweep's business: skipping it keeps a failure in
		// THIS package from being caused by another one (issue #350).
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			// Dotted directories hold complete copies of this tree on other
			// branches (.claude/worktrees/), and walking them reports another
			// branch's writers as this one's.
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if rel, rerr := filepath.Rel(root, path); rerr == nil {
			visited[filepath.ToSlash(filepath.Dir(rel))] = true
		}
		src, rerr := os.ReadFile(path)
		// The file can vanish between the walk naming it and this read, for
		// the reason above.
		if errors.Is(rerr, fs.ErrNotExist) {
			return nil
		}
		if rerr != nil {
			return rerr
		}
		text := string(src)
		for _, loc := range engineToolchainWriteRE.FindAllStringIndex(text, -1) {
			line := 1 + strings.Count(text[:loc[0]], "\n")
			rel, _ := filepath.Rel(root, path)
			hits = append(hits, fmt.Sprintf("%s:%d", filepath.ToSlash(rel), line))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The walk really reached outside internal/, which is what a subroot
	// silently skipped. Without this, "exactly one writer" is a statement about
	// whatever subtree happened to be walked.
	for _, dir := range []string{"internal/policy", "internal/cli", "cmd/snug"} {
		if !visited[dir] {
			t.Fatalf("the sweep never visited %s, so a writer there ships green (issue #291 "+
				"part 1b). Visited %d directories under %s.", dir, len(visited), root)
		}
	}

	// Exactly one: the assignment inside EngineToolchain itself.
	if len(hits) != 1 || !strings.HasPrefix(hits[0], "internal/policy/graft.go:") {
		t.Errorf("p.EngineToolchainRoot is assigned at %v; the only legitimate writer is\n"+
			"EngineToolchain (policy/graft.go). A caller assigning it directly skips resolution\n"+
			"and hygiene and passes G4's third disjunct with nothing bounding what it names —\n"+
			"which is issue #55's finding F2, one field over.", hits)
	}
}

// TestEngineToolchainRootInsideAWritableGrantIsRefused is G4b, issue #390.
//
// G4's third disjunct admits a host path the sandbox's own grants do NOT
// expose — that is the whole point of it — and AccessRO was treated as making
// that safe. It is not, because READ-ONLY RESTRAINS THE WRONG PARTY. The graft
// being read-only stops the ENGINE writing; the PAYLOAD writes the same host
// inode through its own rw grant, and the new bytes appear under the engine's
// read-only graft on the next run. The engine resolves conmon, crun and
// netavark out of that tree as root in the sandbox's user namespace with the
// whole delegated subuid range, so a toolchain root the payload can write is
// the payload choosing what the engine executes as root.
//
// It is CLAUDE.md's socket/FIFO lesson with a third noun: `ro` says nothing
// about who else holds the path.
//
// WHY THE QUESTION IS ASKED IN HOST SPACE. An engine-view predicate is the
// wrong instrument — View.IsShadowSlot sees AccessRO and answers "safe",
// correctly and uselessly, because the write never arrives through the engine's
// view at all. So the check is HostPathVisible(host, true): "does any grant of
// this sandbox make this writable".
//
// TWO CONTROLS, and neither is decoration. A clause that refused every
// toolchain graft would pass a test that only checked the refusal, and this
// clause sits on the one disjunct whose job is to ACCEPT an ungranted path —
// so "still accepted" is the property most at risk from getting this wrong.
func TestEngineToolchainRootInsideAWritableGrantIsRefused(t *testing.T) {
	env := newFakeEnv()

	// The real spelling, not a contrivance: $SNUG_PODMAN inside the target,
	// which @cwd-rw grants writable. A podman developer sandboxing the podman
	// tree and pointing snug at ./bin/podman types exactly this.
	const writable = "/home/u/proj/sub"

	t.Run("a writable toolchain root is refused even read-only", func(t *testing.T) {
		p := mustResolveDefaults(t)
		if !p.HostPathVisible(writable, true) {
			t.Fatalf("fixture: %s is not write-visible, so this test would be asserting "+
				"nothing about the writable case", writable)
		}
		// Issue #405 gave EngineToolchain its own check (CheckEngineToolchainTree,
		// asked at record time as well as at graft time), so it now refuses to
		// record a writable root before G4b — Policy.Graft's own check, which is
		// what this test targets — is ever reached. Set directly, which is legal
		// only in _test.go: TestOnlyOneWriterOfEngineToolchainRoot's source sweep
		// excludes it, and this fixture's whole point is exercising G4b itself,
		// not the (now duplicate, and separately tested) B1 refusal at record time.
		p.EngineToolchainRoot = writable
		g := validGraft(p, "toolchain")
		g.Host = writable
		g.Access = AccessRO
		err := p.Graft(env, g)
		if err == nil {
			t.Fatal("a READ-ONLY graft of a toolchain root the payload can write was accepted; " +
				"the payload writes the host directory through its own rw grant and the engine " +
				"execs what appears there as root (issue #390)")
		}
		// The refusal must be THIS refusal, not the pre-existing "not recorded"
		// or "asked writable" one — both of which would also be non-nil.
		for _, want := range []string{"WRITABLE", "read-only"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal does not mention %q, so it may be a different clause firing: %v",
					want, err)
			}
		}
	})

	t.Run("control: an ungranted toolchain root is still accepted read-only", func(t *testing.T) {
		p := mustResolveDefaults(t)
		const ungranted = "/home/u/secrets"
		if p.HostPathVisible(ungranted, true) {
			t.Fatalf("fixture: %s is write-visible, so it is the wrong control", ungranted)
		}
		if err := p.EngineToolchain(env, ungranted); err != nil {
			t.Fatal(err)
		}
		g := validGraft(p, "toolchain")
		g.Host = ungranted
		g.Access = AccessRO
		if err := p.Graft(env, g); err != nil {
			t.Fatalf("G4b refused a toolchain root no grant makes writable — the third disjunct's "+
				"whole job is to accept an ungranted path read-only, so this is the property most "+
				"at risk from an over-broad clause: %v", err)
		}
	})

	t.Run("control: a read-only-granted root is still accepted", func(t *testing.T) {
		p := mustResolveDefaults(t)
		const readOnly = "/usr" // @sys grants it ro
		if p.HostPathVisible(readOnly, true) {
			t.Fatalf("fixture: %s is write-visible, so it is the wrong control", readOnly)
		}
		g := validGraft(p, "toolchain")
		g.Host = readOnly
		g.Access = AccessRO
		if err := p.Graft(env, g); err != nil {
			t.Fatalf("a graft of a read-only-granted path was refused; ro visibility is not the "+
				"hazard and must not be caught by G4b: %v", err)
		}
	})
}

// ── issue #369's second door: EngineToolchain judges the NAME too ──────────

// TestEngineToolchainJudgesTheNameNotOnlyTheTarget is the toolchain-root
// mirror of the measured engine-binary defect: $SNUG_PODMAN_ROOT names a
// payload-writable symlink into a CLEAN host directory (one no grant makes
// writable), so CheckEngineToolchainTree alone — which only ever sees the
// resolved bytes — would accept it. The refusal must name the SYMLINK as the
// refused object.
func TestEngineToolchainJudgesTheNameNotOnlyTheTarget(t *testing.T) {
	env := newFakeEnv()
	env.links["/home/u/proj/sub/bundle"] = "/opt/tools/bin" // clean: /opt is ro via @sys
	p := resolveDefaults(t)

	const symlink = "/home/u/proj/sub/bundle"
	err := p.EngineToolchain(env, symlink)
	if err == nil {
		t.Fatal("a toolchain root that is a payload-writable symlink to a clean host directory " +
			"was accepted")
	}
	wantPrefix := symlink + " cannot be this run's engine toolchain root"
	if !strings.HasPrefix(err.Error(), wantPrefix) {
		t.Errorf("refusal %q does not open by naming the SYMLINK as the refused object", err)
	}
}

// TestEngineToolchainEndpointArmOutranksTheSelectionArm: a PLAIN,
// non-symlinked, writable root (the target itself) must be refused with
// CheckEngineToolchainTree's own wording, never the selection arm's.
//
// THE NEGATIVE HALF IS THE ASSERTION. The first draft of EngineToolchain ran
// the selection block BEFORE resolution and therefore before
// CheckEngineToolchainTree, so this exact case — no chain involved at all —
// printed the selection message's clause "the directory at the end of that
// chain is not writable", which is FALSE for a root that is itself the
// writable directory. Without this assertion the test passes on either
// ordering.
func TestEngineToolchainEndpointArmOutranksTheSelectionArm(t *testing.T) {
	env := newFakeEnv()
	p := resolveDefaults(t)

	err := p.EngineToolchain(env, "/home/u/proj/sub") // the target itself, no symlink
	if err == nil {
		t.Fatal("a toolchain root equal to the writable target was accepted")
	}
	if !strings.Contains(err.Error(), "WRITABLE") {
		t.Errorf("refusal %q does not carry CheckEngineToolchainTree's own wording", err)
	}
	if strings.Contains(err.Error(), "CHOOSING") {
		t.Errorf("refusal %q carries the selection arm's wording for a case with no chain at "+
			"all — the endpoint arm must run first", err)
	}
}

// TestEngineToolchainRefusesAForgingRuneInTheAskedSpelling: a
// $SNUG_PODMAN_ROOT spelling containing a newline, whose RESOLVED form is
// clean, must still be refused — on the AS-GIVEN spelling, which is a sink
// (it reaches a refusal a human reads) and therefore gets the same hygiene
// check the resolved value gets.
func TestEngineToolchainRefusesAForgingRuneInTheAskedSpelling(t *testing.T) {
	env := newFakeEnv()
	env.links["/home/u/proj/sub/wei\nrd"] = "/opt/tools/bin" // resolves clean; the SPELLING carries the newline
	p := resolveDefaults(t)

	err := p.EngineToolchain(env, "/home/u/proj/sub/wei\nrd")
	if err == nil {
		t.Fatal("a $SNUG_PODMAN_ROOT spelling containing a newline was accepted because its " +
			"resolved form is clean")
	}
	if !strings.Contains(err.Error(), "engine toolchain root (asked)") {
		t.Errorf("refusal %q is not the hygiene check on the AS-GIVEN spelling", err)
	}

	// CONTROL: a trailing slash is an ordinary human spelling, not a forging
	// rune, and must still be accepted — this is what filepath.Clean on the
	// as-given value exists for.
	p2 := resolveDefaults(t)
	if err := p2.EngineToolchain(newFakeEnv(), "/srv/bin/"); err != nil {
		t.Errorf("control: a trailing slash was refused: %v", err)
	}
}

// ── issue #422: the split cannot drift ──────────────────────────────────────

// TestJudgeEngineToolchainAgreesWithEngineToolchain is the split's own
// invariant: JudgeEngineToolchain (report.go's caller, records nothing) and
// EngineToolchain (the run's writer) must reach the same verdict for the same
// root, over the same host. Compared as EQUIVALENCE — error or not, and on
// success the exact string recorded — rather than by wording, so a future
// reword of either refusal cannot fail this and a future divergence in
// verdict always will.
func TestJudgeEngineToolchainAgreesWithEngineToolchain(t *testing.T) {
	cases := []struct {
		name  string
		root  string
		setup func(*fakeEnv)
	}{
		{"clean and ungranted", "/home/u/secrets", nil},
		{"the writable target itself", "/home/u/proj/sub", nil},
		{"empty argument", "", nil},
		{"relative path", "relative/path", nil},
		{"nonexistent and ungranted", "/srv/nowhere-422", nil},
		// The selection arm's shape (TestEngineToolchainJudgesTheNameNotOnlyTheTarget's
		// fixture): a spelling inside the writable target, resolving to a clean,
		// ro-granted directory.
		{"symlink whose name is writable, resolving to clean bytes", "/home/u/proj/sub/bundle",
			func(env *fakeEnv) { env.links["/home/u/proj/sub/bundle"] = "/opt/tools/bin" }},
		// Issue #422's own shape, inside this package: a spelling OUTSIDE every
		// grant that RESOLVES into the writable target. A judge that checked the
		// spelling instead of the resolved bytes would clear this.
		{"symlink outside every grant resolving into the writable target", "/srv/bundle-422",
			func(env *fakeEnv) { env.links["/srv/bundle-422"] = "/home/u/proj/sub" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newFakeEnv()
			if tc.setup != nil {
				tc.setup(env)
			}
			p := resolveDefaults(t)

			resolved, jerr := p.JudgeEngineToolchain(env, tc.root)
			eerr := p.EngineToolchain(env, tc.root)

			if (jerr != nil) != (eerr != nil) {
				t.Fatalf("JudgeEngineToolchain err=%v, EngineToolchain err=%v for %q — the two "+
					"functions disagree about whether this root is accepted", jerr, eerr, tc.root)
			}
			if eerr == nil {
				if p.EngineToolchainRoot != resolved {
					t.Errorf("EngineToolchainRoot = %q, want JudgeEngineToolchain's own answer %q",
						p.EngineToolchainRoot, resolved)
				}
			} else if p.EngineToolchainRoot != "" {
				t.Errorf("a root EngineToolchain refused was recorded anyway: %q",
					p.EngineToolchainRoot)
			}
		})
	}
}

// TestEngineToolchainSecondDifferentWritableRootReportsWritability pins the
// deliberate behaviour change the split introduced: write-once now runs AFTER
// the judgement, so a second, different root that is ITSELF writable reports
// the writability refusal rather than "this run already recorded a different
// root". Before the split both checks ran in the other order and this case
// reported write-once's message instead.
func TestEngineToolchainSecondDifferentWritableRootReportsWritability(t *testing.T) {
	env := newFakeEnv()
	p := resolveDefaults(t)

	const first = "/home/u/secrets"   // clean, ungranted — accepted and recorded
	const second = "/home/u/proj/sub" // the writable target itself

	if err := p.EngineToolchain(env, first); err != nil {
		t.Fatalf("first write refused: %v", err)
	}
	err := p.EngineToolchain(env, second)
	if err == nil {
		t.Fatal("a second, writable toolchain root was accepted")
	}
	if !strings.Contains(err.Error(), "WRITABLE") {
		t.Errorf("the second call did not carry the writability refusal: %v", err)
	}
	if strings.Contains(err.Error(), "this run already") {
		t.Errorf("the second call carried write-once's refusal instead of the writability one "+
			"the judgement should have reached first: %v", err)
	}
	if p.EngineToolchainRoot != first {
		t.Errorf("EngineToolchainRoot changed to %q after a refused second write", p.EngineToolchainRoot)
	}
}
