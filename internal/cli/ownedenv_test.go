package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
	"github.com/gomoni/snug/internal/profile"
)

// ── the ownership set, checked two ways ──────────────────────────────────────
//
// Every name snug writes is in exactly one of two lists. policy.SnugOwnedEnv is
// the names no profile may write in any run, refused at parse time.
// policy.ConditionalEnvNames is the names snug fills only when a profile key
// turns a feature on — DOCKER_HOST with podman, SSH_AUTH_SOCK with the agent
// proxy — refused at resolve time as a conflict with that selection (issue
// #621). A name snug writes that is in NEITHER list is one a profile may set
// beside snug's value, and snug silently discards one of the two. An earlier
// draft of the design retyped the list by hand and missed the six writers that
// run AFTER Resolve, which is why the lists are checked against the code.
//
// Two tests, and NEITHER alone is enough. The static one below reads every
// AuthorEnv/AuthorEnvList call in the tree and asserts set equality, so a new
// writer or a stale entry fails the build. The executed one after it resolves a
// real policy and checks what actually came out — because a static check is a
// check of the code as WRITTEN, and the pasta.avx2 lesson in CLAUDE.md is what
// happens when the only check is of the thing you had in mind.
//
// internal/cli is the right home for both: it is a sibling of internal/policy
// under internal/, so it can see the writers on both sides of the Resolve
// boundary without either one importing the other. go/parser is stdlib, so
// this costs no dependency and internal/policy stays pure.

func TestSnugOwnedEnvIsExactlyWhatSnugWrites(t *testing.T) {
	// Production files only. A test that called AuthorEnv would otherwise be
	// able to widen the ownership set, which is the wrong direction entirely:
	// the set exists to constrain what profiles may write, and a test fixture is
	// not part of the sandbox's environment.
	found := map[string]bool{}
	for _, dir := range []string{filepath.Join("..", "policy"), "."} {
		for _, name := range goFilesIn(t, dir) {
			collectAuthoredNames(t, filepath.Join(dir, name), found)
		}
	}

	got := make([]string, 0, len(found))
	for n := range found {
		got = append(got, n)
	}
	sort.Strings(got)

	want := append(append([]string(nil), policy.SnugOwnedEnv...), policy.ConditionalEnvNames()...)
	sort.Strings(want)

	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("policy.SnugOwnedEnv + policy.ConditionalEnvNames() does not match the names "+
			"snug actually writes.\n  writes: %s\n  lists:  %s\n"+
			"A name snug writes but does not claim is one a profile may set beside snug's "+
			"value, and one of the two is discarded with no trace. Fix the LISTS — a "+
			"feature-conditional writer is a conditionalEnvs row with its selection "+
			"predicate — and only then ask whether the new writer should exist.",
			strings.Join(got, " "), strings.Join(want, " "))
	}

	// POSITIVE CONTROL: a static pass that silently found nothing would compare
	// two empty sets and pass. Name three writers on opposite sides of the
	// Resolve boundary, so a broken parse or a wrong directory fails loudly.
	for _, must := range []string{"HOME", "PATH", "DOCKER_HOST"} {
		if !found[must] {
			t.Errorf("the AST pass did not see the writer for %s; it is scanning the wrong "+
				"files or matching the wrong call", must)
		}
	}
}

func goFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, e.Name())
	}
	return out
}

// collectAuthoredNames records the first argument of every AuthorEnv and
// AuthorEnvList call in one file.
//
// A non-literal first argument is a HARD FAILURE rather than something to skip.
// A computed name cannot be checked by anything here, and an unchecked name is
// precisely the hole this pair of tests exists to close — so the rule is: write
// the literal.
func collectAuthoredNames(t *testing.T, path string, into map[string]bool) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "AuthorEnv" && sel.Sel.Name != "AuthorEnvList") {
			return true
		}
		if len(call.Args) == 0 {
			t.Fatalf("%s: %s call with no arguments", path, sel.Sel.Name)
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			t.Fatalf("%s: %s is called with a computed variable name; a computed name "+
				"cannot be checked against policy.SnugOwnedEnv, so write the literal",
				path, sel.Sel.Name)
		}
		name, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatalf("%s: cannot read the name in %s(%s)", path, sel.Sel.Name, lit.Value)
		}
		into[name] = true
		return true
	})
}

// TestResolvedPolicyAuthorsOnlyOwnedNames is the executed half. It resolves
// every builtin profile with a pinned identity and runs the container writer,
// then asserts that everything marked as snug's own authorship is owned, or is
// conditional with its predicate TRUE on this policy — a conditional name
// authored with its predicate false is one the resolve-time conflict does not
// guard, so a profile's line beside it would be discarded.
//
// What it does NOT reach, said plainly rather than left to be assumed:
// SSH_AUTH_SOCK (startIdentity binds a socket it has to create first) and
// GH_CONFIG_DIR/GH_HOST (stageGhConfig shells out to `gh` for a token and
// returns early without one). Those two are covered by the static test alone —
// which is exactly why the static test refuses a computed name.
func TestResolvedPolicyAuthorsOnlyOwnedNames(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	// A pinned identity, so GIT_CONFIG_GLOBAL is written — one of the names
	// only a policy carrying an Identity ever produces.
	reg["ident"] = &policy.Profile{
		Name:     "ident",
		Include:  []policy.ProfileName{"@sys", "@home", "@target-rw"},
		Identity: &policy.Identity{Git: policy.IdentityGit{Name: "A", Email: "a@example.com"}},
	}

	// Every builtin, with no exception list — see the same sweep in
	// envuncheckedsink_test.go for why a skipped name is a gap rather than a
	// tidy-up.
	var sel []policy.ProfileName
	for name := range reg {
		sel = append(sel, name)
	}
	slices.Sort(sel)

	ctx := envGoldenCtx()
	ctx.Term, ctx.Lang, ctx.TZ = "xterm", "C.UTF-8", "Europe/Prague"
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg), sel, ctx, newEnvFakeEnv())
	if err != nil {
		t.Fatalf("Resolve(%v): %v", sel, err)
	}
	p.Podman = policy.PodmanSocket
	containerEnv(p)

	owned := map[string]bool{}
	for _, n := range policy.SnugOwnedEnv {
		owned[n] = true
	}
	authored := p.AuthoredEnvNames()
	for _, n := range authored {
		if !owned[n] && !policy.ConditionalEnvOn(p, n) {
			t.Errorf("snug authored %q, which is neither in policy.SnugOwnedEnv nor a "+
				"conditional name whose predicate holds on this policy — a profile is free "+
				"to write it here, and one of the two values is silently discarded", n)
		}
	}

	// POSITIVE CONTROL: a policy where nothing was authored would pass the loop
	// above vacuously. These four span both sides of the Resolve boundary and
	// the two conditional writers.
	for _, must := range []string{"HOME", "GIT_CONFIG_GLOBAL", "TZ", "DOCKER_HOST"} {
		if !slicesHas(authored, must) {
			t.Errorf("control: %s was not authored by this fixture (authored: %v); the test "+
				"is asserting over a policy that never wrote anything", must, authored)
		}
	}
}

func slicesHas(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

// TestNoConditionalNameAuthoredWithoutItsFeature is the negative: a selection
// that turns no feature on authors none of the conditional names, so a
// profile's line on one reaches the sandbox under its own verb.
func TestNoConditionalNameAuthoredWithoutItsFeature(t *testing.T) {
	reg, err := profile.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Resolve(map[policy.ProfileName]*policy.Profile(reg),
		[]policy.ProfileName{"@sys", "@target-rw"}, envGoldenCtx(), newEnvFakeEnv())
	if err != nil {
		t.Fatal(err)
	}
	authored := p.AuthoredEnvNames()
	for _, n := range policy.ConditionalEnvNames() {
		if policy.ConditionalEnvOn(p, n) {
			t.Errorf("control: %s's feature is on in @sys @target-rw", n)
		}
		if slicesHas(authored, n) {
			t.Errorf("snug authored %s in a selection that turns its feature off", n)
		}
	}
	// POSITIVE CONTROL: the policy did author something.
	if !slicesHas(authored, "HOME") {
		t.Errorf("control: HOME not authored (authored: %v)", authored)
	}
}
