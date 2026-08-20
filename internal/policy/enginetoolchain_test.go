package policy

import (
	"fmt"
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
	root := filepath.Join("..", "..", "internal")
	var hits []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
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

	// Exactly one: the assignment inside EngineToolchain itself.
	if len(hits) != 1 || !strings.HasPrefix(hits[0], "policy/graft.go:") {
		t.Errorf("p.EngineToolchainRoot is assigned at %v; the only legitimate writer is\n"+
			"EngineToolchain (policy/graft.go). A caller assigning it directly skips resolution\n"+
			"and hygiene and passes G4's third disjunct with nothing bounding what it names —\n"+
			"which is issue #55's finding F2, one field over.", hits)
	}
}
