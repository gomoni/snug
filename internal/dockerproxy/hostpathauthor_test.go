package dockerproxy

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gomoni/snug/test/modroot"
)

// TestHostPathVisibleHasOneAuthor is §7 item 13 of issue #55's specification:
// invariant 6 says one author of "can the sandbox see this host path", not two
// implementations that eventually disagree — the same argument that moved this
// package's OWN walk into policy.HostPathVisible in the first place, so a
// graft's G4 check and the container bind filter cannot drift apart. This test
// is what keeps that true after the move rather than only at the moment of it.
//
// Two parts. First: (*Proxy).hostPathVisible's body is nothing but a call to
// policy.HostPathVisible — no loop of its own. Second: nowhere ELSE in this
// package walks p.pol.Mounts for KindBind the way the old implementation did,
// which is the shape a "helpful" future patch could reintroduce without
// touching hostPathVisible at all (a second predicate living beside the first,
// never called by it, and asked instead of it from some new call site).
func TestHostPathVisibleHasOneAuthor(t *testing.T) {
	src, err := os.ReadFile("create.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)

	// Part 1: the function body.
	fn := funcBody(t, text, "func (p *Proxy) hostPathVisible(host string, needWrite bool) bool {")
	if !strings.Contains(fn, "p.pol.HostPathVisible(") {
		t.Errorf("hostPathVisible's body does not call p.pol.HostPathVisible — it has grown a "+
			"second implementation of \"can the sandbox see this host path\": %q", fn)
	}
	// POSITIVE CONTROL: the extraction actually found the real function and not
	// an empty string a typo in the signature above would also produce.
	if !strings.Contains(fn, "return") {
		t.Fatalf("control: funcBody extracted an empty-looking body (%q) — the signature this test "+
			"greps for has drifted from create.go's own", fn)
	}

	// Part 2: no OTHER walk of p.pol.Mounts for KindBind exists in this
	// package's shipped (non-test) source. hostPathVisible's own call site is
	// excluded by construction — mountWalkRE matches a RANGE over
	// p.pol.Mounts, and hostPathVisible no longer contains one (part 1 already
	// proved its body is one line).
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var hits []string
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		for range mountWalkRE.FindAllString(string(b), -1) {
			hits = append(hits, f.Name())
		}
	}
	if len(hits) != 0 {
		t.Errorf("found %d walk(s) of p.pol.Mounts outside policy.HostPathVisible, in: %v — "+
			"this package must have exactly one implementation of \"can the sandbox see this host "+
			"path\", and it must be policy's", len(hits), hits)
	}

	// POSITIVE CONTROL for Part 2's pattern: it must actually be ABLE to match
	// the shape the pre-issue-#55 implementation had.
	oldShape := "for _, m := range p.pol.Mounts {\n\tif m.Kind != policy.KindBind {\n"
	if !mountWalkRE.MatchString(oldShape) {
		t.Fatalf("control: mountWalkRE does not match the pre-#55 shape of hostPathVisible's own " +
			"walk — it would not catch a reintroduced copy either")
	}
}

// mountWalkRE matches a `range` over `p.pol.Mounts` — the shape a second,
// hand-rolled implementation of "what can the sandbox see" would need in order
// to walk the same data hostPathVisible now delegates on.
var mountWalkRE = regexp.MustCompile(`range\s+p\.pol\.Mounts`)

// hostPathVisibleCallRE matches a call to the EXPORTED policy.HostPathVisible
// — `<receiver>.HostPathVisible(` — wherever it appears in the tree, not just
// in this package. `func (p *Policy) HostPathVisible(...)` (the definition
// itself) does NOT match: there is a SPACE between the receiver's closing
// paren and the method name there, never a `.`.
var hostPathVisibleCallRE = regexp.MustCompile(`\.HostPathVisible\(`)

// TestHostPathVisibleCallersAreInventoried is issue #55's F6 decision, §3:
// policy.HostPathVisible's own doc comment inventories every non-test caller
// BY NAME, and says why each one owes it a resolved path (or owes nothing
// further, for a caller that only renders a value someone else already
// resolved) — because a caller that asks this about an UNRESOLVED string is
// the exact hole F6 measured and closed. This is the tripwire that keeps
// that inventory honest: it fails the moment a caller appears that the doc
// comment does not know about.
func TestHostPathVisibleCallersAreInventoried(t *testing.T) {
	// modroot.Find, not filepath.Join("..", "..", "internal"): a hardcoded
	// subroot makes the walk a subdirectory of the module, so a caller in
	// cmd/snug ships green (issue #291 part 1b). visited below asserts the
	// walk really reached outside internal/.
	root, err := modroot.Find()
	if err != nil {
		t.Fatal(err)
	}
	visited := map[string]bool{}
	hits := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
			// branch's callers as this one's.
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
		if hostPathVisibleCallRE.MatchString(string(src)) {
			rel, _ := filepath.Rel(root, path)
			hits[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The five files named in policy.HostPathVisible's own doc comment
	// (internal/policy/graft.go):
	//   - dockerproxy/create.go — checkOne, via the hostPathVisible wrapper
	//     this file's own TestHostPathVisibleHasOneAuthor already pins.
	//   - policy/graft.go — checkGraft, G4's first disjunct.
	//   - cli/dryrun.go — describeGrafts, the "owned:" provenance render.
	//   - policy/engineexec.go — CheckEngineBinary and CheckEngineToolchainTree
	//     (issue #405), one file, two callers of the ancestor arm.
	//   - policy/enginebindgrant.go — resolveEngineBinds, deciding the access a
	//     declared `engine_binds` entry is grafted at (issue #376).
	want := map[string]bool{
		"internal/dockerproxy/create.go":     true,
		"internal/policy/graft.go":           true,
		"internal/cli/dryrun.go":             true,
		"internal/policy/engineexec.go":      true,
		"internal/policy/enginebindgrant.go": true,
	}
	// The walk really reached outside internal/, which is what a subroot
	// silently skipped. Without this, the inventory is a statement about
	// whatever subtree happened to be walked.
	for _, dir := range []string{"internal/dockerproxy", "internal/policy", "internal/cli", "cmd/snug"} {
		if !visited[dir] {
			t.Fatalf("the sweep never visited %s, so a caller there ships green (issue #291 "+
				"part 1b). Visited %d directories under %s.", dir, len(visited), root)
		}
	}

	for f := range hits {
		if !want[f] {
			t.Errorf("a NEW caller of policy.HostPathVisible appeared at %s — the doc comment on "+
				"HostPathVisible (internal/policy/graft.go) inventories every caller by name; adding "+
				"one means writing its resolution obligation there too, not just calling it", f)
		}
	}
	for f := range want {
		if !hits[f] {
			t.Errorf("expected caller %s no longer calls policy.HostPathVisible — the inventory in "+
				"HostPathVisible's doc comment (internal/policy/graft.go) is now stale", f)
		}
	}

	// POSITIVE CONTROL: the pattern can actually see a violation — a
	// synthetic THIRD (well, fourth) caller written into a string literal,
	// mirroring this file's own existing control shape (line 73 above) rather
	// than planting a real call anywhere in the tree.
	fixture := "func evil(pol *policy.Policy) bool { return pol.HostPathVisible(\"/x\", false) }\n"
	if !hostPathVisibleCallRE.MatchString(fixture) {
		t.Fatal("control: the pattern does not see an ordinary call to HostPathVisible — it would " +
			"not catch a real fourth caller either")
	}
	// And it must NOT match the DEFINITION itself, or every run would report
	// a spurious fourth "caller" inside internal/policy/graft.go.
	if hostPathVisibleCallRE.MatchString("func (p *Policy) HostPathVisible(host string, needWrite bool) bool {\n") {
		t.Fatal("control: the pattern matched HostPathVisible's own DEFINITION, not just calls to it")
	}
}

// funcBody extracts the text between a function's opening `{` (found via sig,
// which must include it) and its matching closing `}`, by brace counting. Used
// instead of go/ast here because the property under test is "what literal call
// appears in this one function's source", which a brace-counted substring
// answers as directly as a parsed FuncDecl would.
func funcBody(t *testing.T, src, sig string) string {
	t.Helper()
	i := strings.Index(src, sig)
	if i < 0 {
		t.Fatalf("signature %q not found in create.go — it was renamed or reshaped, and this test "+
			"needs to be updated to match", sig)
	}
	start := i + len(sig)
	depth := 1
	j := start
	for ; j < len(src) && depth > 0; j++ {
		switch src[j] {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	return src[start:j]
}

// evalSymlinksLoopRE matches the shape resolveExisting's own loop had BEFORE
// it moved to policy.ResolveExistingHostPath (issue #55, F6) — a call to
// filepath.EvalSymlinks inside a for loop that walks the path one component
// at a time. If this shape ever reappears anywhere in this package's shipped
// source, invariant 6 ("one author of resolving a host path as far as it
// exists, not two implementations that eventually disagree") has been
// quietly reintroduced.
var evalSymlinksLoopRE = regexp.MustCompile(`for[^{]*\{[^}]*filepath\.EvalSymlinks\(`)

// TestResolveExistingHasOneAuthor is TestHostPathVisibleHasOneAuthor's twin
// for the SECOND half of "can the sandbox see this host path" (issue #55, F6
// decision §2a): resolveExisting used to be its own filepath.EvalSymlinks
// walk, duplicating what is now policy.ResolveExistingHostPath — the same
// "one author" argument that already moved HostPathVisible's own walk,
// applied to the half that was left behind and caused F6 in the first place.
func TestResolveExistingHasOneAuthor(t *testing.T) {
	src, err := os.ReadFile("create.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)

	// Part 1: the function body is a single call, not a loop of its own.
	// funcBody's own brace-counting includes the function's closing `}` in
	// what it returns (its `j` has already advanced past it when depth
	// reaches zero) — trimmed here, the same way funcBody's OTHER caller in
	// this file (TestHostPathVisibleHasOneAuthor) avoids the question by
	// using strings.Contains instead of an exact match.
	fn := strings.TrimSuffix(strings.TrimSpace(funcBody(t, text, "func resolveExisting(p string) (string, error) {")), "}")
	if got := strings.TrimSpace(fn); got != "return policy.ResolveExistingHostPath(policy.OSEnviron{}, p)" {
		t.Errorf("resolveExisting's body is not a single call to policy.ResolveExistingHostPath — "+
			"it has grown its own walk again: %q", got)
	}
	// POSITIVE CONTROL: the extraction found the real function.
	if !strings.Contains(fn, "return") {
		t.Fatalf("control: funcBody extracted an empty-looking body (%q) — the signature this test "+
			"greps for has drifted from create.go's own", fn)
	}

	// Part 2: no EvalSymlinks LOOP survives anywhere in this package's
	// shipped (non-test) source.
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var hits []string
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		if evalSymlinksLoopRE.MatchString(string(b)) {
			hits = append(hits, f.Name())
		}
	}
	if len(hits) != 0 {
		t.Errorf("found an EvalSymlinks LOOP outside policy.ResolveExistingHostPath, in: %v — this "+
			"package must have exactly one implementation of \"resolve a host path as far as it "+
			"exists\", and it must be policy's", hits)
	}

	// POSITIVE CONTROL: the pattern actually matches the PRE-#55 shape of
	// resolveExisting's own loop.
	oldShape := "func resolveExisting(p string) (string, error) {\n" +
		"\tpath := filepath.Clean(p)\n" +
		"\trest := \"\"\n" +
		"\tfor cur := path; ; {\n" +
		"\t\treal, err := filepath.EvalSymlinks(cur)\n" +
		"\t\tif err == nil {\n" +
		"\t\t\treturn filepath.Join(real, rest), nil\n" +
		"\t\t}\n" +
		"\t}\n" +
		"}\n"
	if !evalSymlinksLoopRE.MatchString(oldShape) {
		t.Fatalf("control: evalSymlinksLoopRE does not match the pre-#55 shape of resolveExisting's " +
			"own loop — it would not catch a reintroduced copy either")
	}
}
