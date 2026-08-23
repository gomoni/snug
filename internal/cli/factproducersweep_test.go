package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// THE RATCHET UNDER --dry-run's TWO RENDERERS (issue #332).
//
//	For every fact-producer renderHuman calls, buildReport must call it too.
//
// report.go's header states the split between the human screen and the machine
// document as "every fact the JSON document carries / human only: the sentences
// ABOUT those facts". Issue #332 found that claim false for SEVEN producers at
// once — policy.EnvNote, grantMark/IsShadowSlot, policy.ProcfsClosuresSkipped,
// policy.ProcfsNote, p.PastaArgs, the PWD row and yieldedMark — every one of
// them written, reviewed and shipped, with the golden JSON fixture green the
// whole time. A golden pins what IS emitted; nothing pinned what was missing.
//
// So this is the assertion that would have caught all seven in one failure, and
// it is written as a SWEEP rather than as seven per-fact tests for the reason
// CLAUDE.md gives about sink sets: seven tests go stale one at a time and the
// eighth producer is added with none of them failing. It is the same shape as
// TestSnugOwnedEnvIsExactlyWhatSnugWrites (ownedenv_test.go), and it borrows
// that test's file walker.
//
// WHAT IT SEES, stated plainly because the gap matters more than the coverage:
// this pass reads CALLS, not field reads. A fact that renderHuman prints
// straight out of p.Net or p.Topology without going through a function is
// invisible here — the sweep would not have caught the network block if it had
// been written inline. What it does catch is every producer that is a function,
// which is what all seven of #332's were.
//
// The producer predicate is DERIVED, never a list:
//
//	internal/policy   any package-level policy.X(...) call, and any method
//	                  call whose name is a method on *policy.Policy returning
//	                  something other than error alone.
//	internal/cli      a package-level func that takes a *policy.Policy,
//	                  returns something other than error alone, and takes NO
//	                  io.Writer. The io.Writer clause is what separates a
//	                  producer from a renderer: describeGit(out, p) prints
//	                  prose, envGrantVerdict(p, name, value) computes a fact.
//
// Both sides are compared as CLOSURES — every producer reachable through local
// calls from renderHuman, against every one reachable from buildReport — not as
// the two files' immediate calls. That is load-bearing in both directions.
// grantMark was refactored onto envGrantVerdict so the two renderers derive one
// answer, and report.go calls the fact rather than the sentence: a
// file-versus-file comparison would report that correct arrangement as a
// failure. In the other direction, buildEnvReport reaches policy.EnvNote
// through a helper, and a shallow pass would call the fix missing.
func TestEveryFactProducerTheHumanScreenCallsIsAlsoInTheReport(t *testing.T) {
	s := newProducerSweep(t)

	human := s.closure("renderHuman")
	report := s.closure("buildReport")

	// POSITIVE CONTROL, and this test needs it more than most: every assertion
	// below is of the form "X is in both sets", so a pass that parsed nothing,
	// walked the wrong root, or matched no call would compare two empty sets
	// and report success. These six are #332's own producers, named literally.
	// The seventh, the PWD row, is deliberately absent from this list —
	// describeBwrapAuthoredEnv takes an io.Writer and is therefore not a
	// producer by the predicate above; TestTheJSONEnvironmentCarriesPWD covers
	// it, and saying so here is cheaper than a reader concluding this sweep
	// covers all seven.
	for _, must := range []string{
		"policy.EnvNote",
		"policy.ProcfsNote",
		"policy.ProcfsClosuresSkipped",
		"(*policy.Policy).PastaArgs",
		"yieldedMark",
		"envGrantVerdict",
	} {
		if !human[must] {
			t.Errorf("the sweep did not see %s in renderHuman's call graph; it is walking the "+
				"wrong root or matching the wrong call shape, and every assertion below is "+
				"passing on an empty set", must)
		}
	}

	// THE ASSERTION.
	var missing []string
	for name := range human {
		if report[name] || humanOnlyFacts[name] != "" {
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("%s is a fact-producer the human --dry-run screen calls and the JSON document "+
			"does not. --dry-run is the mechanism by which a human can trust snug at all, and "+
			"--json exists for CI gates: a fact only the human screen carries is a verdict no "+
			"gate can assert on. Add it to Report (report.go) and to the document "+
			"(dryrunjson.go), or — if leaving it out is the decision — add it to humanOnlyFacts "+
			"with the reason and the issue.", name)
	}

	// THE OTHER HALF OF THE RATCHET: an exemption that has been fixed must not
	// stay exempt. Without this, wiring a producer into the report leaves its
	// entry behind, and the next producer added under the same name inherits a
	// justification written for a different absence.
	for name, why := range humanOnlyFacts {
		switch {
		case !human[name]:
			t.Errorf("humanOnlyFacts lists %s (%q) but the human screen no longer calls it. "+
				"Delete the entry: a stale exemption is a hole with a comment over it.", name, why)
		case report[name]:
			t.Errorf("humanOnlyFacts lists %s (%q) and the report calls it now. Delete the "+
				"entry — the exemption is what the format promises NOT to carry.", name, why)
		}
	}
}

// humanOnlyFacts is the set of producers the human screen calls and the machine
// document deliberately does not, each with the reason. It is an EXEMPTION LIST
// and it is meant to be read as one: every entry is a sentence about what
// `--dry-run --json` does not tell a consumer.
//
// Three buckets, and the difference between them is the whole point —
//
//	sentence   the FACT is in the document under another name; this producer
//	           is the English wrapped around it. grantMark is the worked
//	           example: envGrantVerdict is the fact, in the report as
//	           `grant`/`grants_inside`, and grantMark is the `← not granted`
//	           mark that renders it.
//	gap        the fact is NOT in the document, by a decision, with the issue
//	           that carries it. #332 F1f (host-derived GIT/SSH/CLAUDE) and
//	           F1h (graft provenance) were judged materially larger than the
//	           seven and handed back rather than half-done — CLAUDE.md's rule
//	           that a partial answer in a machine format is worse than an
//	           absent one, because a consumer cannot tell a field empty
//	           because nothing was staged from one empty because nobody
//	           implemented it.
//	rendering  string escaping and column work. Not a fact about the policy
//	           at all; the document escapes its own strings (escapeRawForgingRunes).
//
// Adding a name here is a decision to ship a machine format without that fact.
// The test above refuses a stale entry, so the list cannot quietly outlive the
// gap it describes.
var humanOnlyFacts = map[string]string{
	// ── sentences whose fact the document already carries ────────────────
	"grantMark":               "sentence for envGrantVerdict, which the report carries as Grant/GrantsInside",
	"policy.UncheckedEnvNote": "sentence for policy.IsUncheckedEnv, which the report carries as TypeUnknown",
	"dnsHostLabel":            "sentence for p.Net.DNSHost, which the report carries as Network.DNSHost",
	"envLines":                "the human block's ROW model (marks, wrapping); reportEnvVar is the document's",
	"targetAnnotation":        "the TARGET header's `←` mark, derived from mounts[], which the document carries in full",
	"homeAnnotation":          "the HOME header's `←` mark, same derivation as targetAnnotation",
	"pathAnnotation":          "targetAnnotation/homeAnnotation's shared body",
	"mountedAt":               "pathAnnotation's deepest-covering-mount lookup over mounts[]",
	"writableBelow":           "pathAnnotation's `writable below` clause over mounts[]",

	// ── gaps, named rather than silently absent ──────────────────────────
	"policy.SortedGitKeys":             "#332 F1f: the host-derived GIT facts have no JSON representation yet",
	"policy.SSHKeySpelling":            "#332 F1f: the host-derived SSH facts have no JSON representation yet",
	"claudeStateMount":                 "#332 F1f: the CLAUDE facts have no JSON representation yet",
	"claudeSettingsMount":              "#332 F1f, same block",
	"claudeCredentialsMount":           "#332 F1f, and it is the one a gate most wants: `snug staged NOTHING at ~/.claude/.credentials.json`",
	"claudeTrustCarried":               "#332 F1f, same block",
	"projectedTargetSettings":          "#332 F1f, same block",
	"graftDestinationNote":             "#332 F1h: graft provenance beyond EngineView's own fields",
	"(*policy.Policy).SandboxView":     "#332 F1h: graftDestinationNote's covering-mount lookup",
	"(*policy.Policy).HostPathVisible": "#332 F1h: describeGrafts' G4 disjunct on the host side",

	// ── rendering ────────────────────────────────────────────────────────
	"policy.VisibleText": "escaping for a terminal; the document runs escapeRawForgingRunes over itself instead",
	"policy.JoinNames":   "joins profile names into a screen column; the document emits the array",
	"policy.IsEnvList":   "decides whether a value is quoted on screen; the document emits the string",
	"policy.FormatBytes": "renders a byte count as \"1 GiB\"/\"512 MiB\" for the FILESYSTEM block's tmpfs " +
		"rows (issue #281); the document carries the raw uint64 instead, as mounts[].size_bytes",
}

// producerSweep is the parsed corpus: every non-test file in internal/cli and
// internal/policy, plus the two derived predicates.
type producerSweep struct {
	t *testing.T
	// decls is every package-level func in internal/cli, by name. The closure
	// walk follows these and stops at anything else.
	decls map[string]*ast.FuncDecl
	// producer is the subset of decls that computes a fact rather than
	// printing one.
	producer map[string]bool
	// polMethod is every method on *policy.Policy that returns something
	// other than error alone.
	polMethod map[string]bool
}

func newProducerSweep(t *testing.T) *producerSweep {
	t.Helper()
	s := &producerSweep{
		t:         t,
		decls:     map[string]*ast.FuncDecl{},
		producer:  map[string]bool{},
		polMethod: map[string]bool{},
	}
	for _, name := range goFilesIn(t, ".") {
		for _, d := range s.parse(name).Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil {
				continue
			}
			s.decls[fd.Name.Name] = fd
		}
	}
	for name, fd := range s.decls {
		if takesPolicy(fd) && returnsAFact(fd) && !printsToAWriter(fd) {
			s.producer[name] = true
		}
	}
	for _, name := range goFilesIn(t, filepath.Join("..", "policy")) {
		for _, d := range s.parse(filepath.Join("..", "policy", name)).Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) == 0 {
				continue
			}
			star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			if id, ok := star.X.(*ast.Ident); ok && id.Name == "Policy" && returnsAFact(fd) {
				s.polMethod[fd.Name.Name] = true
			}
		}
	}
	// The corpus itself gets a positive control. goFilesIn takes a directory
	// and cannot tell an empty one from a wrong one, and every predicate below
	// is a map lookup that answers false for a corpus that was never read.
	if len(s.decls) == 0 || len(s.polMethod) == 0 {
		t.Fatalf("the sweep read no declarations (%d in internal/cli, %d methods on *policy.Policy); "+
			"it is looking at the wrong directory", len(s.decls), len(s.polMethod))
	}
	return s
}

func (s *producerSweep) parse(path string) *ast.File {
	s.t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		s.t.Fatalf("parsing %s: %v", path, err)
	}
	return f
}

// closure returns every fact-producer reachable from one package-level func by
// following calls to other package-level funcs in internal/cli.
//
// Names are qualified the way a reader would write them — "policy.EnvNote",
// "(*policy.Policy).PastaArgs", or the bare name of a local func — because
// these strings are what a failure message and humanOnlyFacts both carry.
func (s *producerSweep) closure(root string) map[string]bool {
	s.t.Helper()
	if _, ok := s.decls[root]; !ok {
		s.t.Fatalf("%s is not a package-level func in internal/cli; the sweep has no root to "+
			"walk from and would compare two empty sets", root)
	}
	found := map[string]bool{}
	walked := map[string]bool{}
	var walk func(string)
	walk = func(name string) {
		if walked[name] {
			return
		}
		walked[name] = true
		fd, ok := s.decls[name]
		if !ok {
			return
		}
		ast.Inspect(fd, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				if s.producer[fn.Name] {
					found[fn.Name] = true
				}
				walk(fn.Name)
			case *ast.SelectorExpr:
				// A qualified call into internal/policy. The receiver being
				// the package name is checked syntactically: internal/cli
				// imports it unaliased everywhere, and an aliased import would
				// show up as a producer that vanished, which the stale-entry
				// half above reports.
				if id, ok := fn.X.(*ast.Ident); ok && id.Name == "policy" {
					found["policy."+fn.Sel.Name] = true
					return true
				}
				// A method call whose name belongs to *policy.Policy. Matching
				// by NAME is the limit of a stdlib-only pass — go/types would
				// need golang.org/x/tools, and CLAUDE.md keeps go.mod minimal
				// because every dependency there runs with the authority of
				// the thing building the sandbox. A same-named method on
				// another type would add a name to both closures, so it
				// cannot hide a missing fact; it can only ask for one that is
				// already there.
				if s.polMethod[fn.Sel.Name] {
					found["(*policy.Policy)."+fn.Sel.Name] = true
				}
			}
			return true
		})
	}
	walk(root)
	return found
}

// takesPolicy reports whether fd reads the resolved policy — the thing every
// fact on either screen is derived from.
func takesPolicy(fd *ast.FuncDecl) bool {
	if fd.Type.Params == nil {
		return false
	}
	for _, p := range fd.Type.Params.List {
		star, ok := p.Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "policy" && sel.Sel.Name == "Policy" {
			return true
		}
	}
	return false
}

// printsToAWriter is the renderer/producer split. describeGit(out, p) writes
// prose and is not something the JSON document could call; envGrantVerdict(p,
// name, value) returns a fact and is.
func printsToAWriter(fd *ast.FuncDecl) bool {
	if fd.Type.Params == nil {
		return false
	}
	for _, p := range fd.Type.Params.List {
		sel, ok := p.Type.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "io" && sel.Sel.Name == "Writer" {
			return true
		}
	}
	return false
}

// returnsAFact excludes func() and func() error. A func that returns only an
// error reports whether something worked; it does not hand back a fact about
// the policy for a document to carry.
func returnsAFact(fd *ast.FuncDecl) bool {
	if fd.Type.Results == nil || len(fd.Type.Results.List) == 0 {
		return false
	}
	for _, r := range fd.Type.Results.List {
		if id, ok := r.Type.(*ast.Ident); !ok || id.Name != "error" {
			return true
		}
	}
	return false
}

// TestTheHumanOnlyExemptionsAreReadable keeps humanOnlyFacts a set of
// SENTENCES. An entry whose reason is "" or "TODO" is an exemption with no
// argument behind it, which is the shape the list exists to prevent.
func TestTheHumanOnlyExemptionsAreReadable(t *testing.T) {
	for name, why := range humanOnlyFacts {
		if len(strings.TrimSpace(why)) < 20 {
			t.Errorf("humanOnlyFacts[%q] = %q — an exemption carries the reason it exists, "+
				"and for a gap the issue that tracks it", name, why)
		}
	}
}
