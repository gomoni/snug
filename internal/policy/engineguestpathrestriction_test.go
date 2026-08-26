package policy

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

// engineGuestPathCallRE matches a call to the EXPORTED (*Policy).EngineGuestPath
// — `<receiver>.EngineGuestPath(` — wherever it appears in the tree. The
// definition itself, `func (p *Policy) EngineGuestPath(host string) (string,
// bool) {`, does NOT match: there is a SPACE between the receiver's closing
// paren and the method name there, never a `.`.
var engineGuestPathCallRE = regexp.MustCompile(`\.EngineGuestPath\(`)

// TestEngineGuestPathIsAskedOnlyByTheEngineWiring is a PACKAGE RESTRICTION, not
// an inventory of named call sites (contrast
// TestHostPathVisibleCallersAreInventoried in dockerproxy/hostpathauthor_test.go,
// which names every caller because HostPathVisible has several, each owing it
// a different resolution obligation). EngineGuestPath has exactly one kind of
// legitimate caller and this pins the KIND, not the list:
//
// Membership rule: only snug's OWN wiring asks where snug's own paths land in
// the engine's derived view. internal/engine writes snug-owned paths (the
// store, the runroot, sockets, generated configuration) into the engine's
// argv, environment and config files, and for THAT it needs "where does the
// engine see this host content" — EngineGuestPath's own question. Any OTHER
// package asking it is asking about someone else's string — a client-supplied
// or profile-supplied path — which is CheckEngineForwardedPath's job
// (engineforwardedpath.go's own doc comment, "What this is NOT"): asked about
// a payload-supplied string, EngineGuestPath's graft arm wins unconditionally
// over its bind arm with no depth comparison, over-answering for a graft's
// Host in exactly the shape issue #251 closed. A caller outside
// internal/engine is that mistake being made again.
//
// Modelled on the sweep skeleton in dockerproxy/hostpathauthor_test.go and
// norestriction_test.go's sweepModule (this package): modroot.Find found by
// walking UP to go.mod (issue #291 part 1b — a hardcoded subroot silently
// skips cmd/snug), dotted directories and vendor skipped, and the WALK itself
// gets a positive control — the directories it actually visited — because a
// sweep that silently walked nothing would report "one caller" for the wrong
// reason.
func TestEngineGuestPathIsAskedOnlyByTheEngineWiring(t *testing.T) {
	root, err := modroot.Find()
	if err != nil {
		t.Fatal(err)
	}
	visited := map[string]bool{}
	// hits maps a module-root-relative directory to whether it contains a
	// call. internal/engine is the one allowed to.
	hits := map[string][]string{} // dir -> files (relative) with a call

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		// A source sweep walks a tree other packages' tests may be writing
		// in concurrently. An entry that vanished between its parent's
		// ReadDir and this call is not a source file and is not this
		// sweep's business (issue #350).
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		dir := filepath.ToSlash(filepath.Dir(rel))
		visited[dir] = true

		src, rerr := os.ReadFile(path)
		if errors.Is(rerr, fs.ErrNotExist) {
			return nil
		}
		if rerr != nil {
			return rerr
		}
		if engineGuestPathCallRE.Match(src) {
			hits[dir] = append(hits[dir], rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The walk really reached outside internal/policy: without this, "the
	// only caller is internal/engine" is a statement about whatever subtree
	// happened to be walked, not about the module (issue #291 part 1b's
	// shape).
	for _, dir := range []string{"internal/engine", "internal/policy", "internal/dockerproxy", "cmd/snug"} {
		if !visited[dir] {
			t.Fatalf("the sweep never visited %s, so a caller there ships green. Visited %d "+
				"directories under %s.", dir, len(visited), root)
		}
	}

	// POSITIVE CONTROL on the DETECTOR: the sweep must actually have found
	// the one caller everyone agrees is legitimate (internal/engine), or a
	// zero-violation result below proves nothing.
	if len(hits["internal/engine"]) == 0 {
		t.Fatal("the sweep found no call to EngineGuestPath under internal/engine — either the " +
			"real caller moved (update the allowlisted directory below) or the regexp no longer " +
			"matches an ordinary call, and either way a violation elsewhere would go unreported")
	}

	// THE RESTRICTION ITSELF: any call outside internal/engine is a
	// violation.
	for dir, files := range hits {
		if dir == "internal/engine" {
			continue
		}
		t.Errorf("EngineGuestPath is called outside internal/engine, in: %v (directory %s) — only "+
			"snug's own engine wiring may ask where snug's own paths land in the engine's derived "+
			"view; a caller elsewhere is asking about someone else's string, which is "+
			"CheckEngineForwardedPath's job, not EngineGuestPath's", files, dir)
	}

	// POSITIVE CONTROL on the REGEXP ITSELF: it must be ABLE to see an
	// ordinary call, or the "any call outside internal/engine" assertion
	// above could be passing because nothing can ever match.
	fixture := "func evil(pol *Policy, host string) bool { _, ok := pol.EngineGuestPath(host); return ok }\n"
	if !engineGuestPathCallRE.MatchString(fixture) {
		t.Fatal("control: the pattern does not see an ordinary call to EngineGuestPath — it would " +
			"not catch a real violating caller either")
	}

	// NEGATIVE CONTROL: it must NOT match the DEFINITION itself, or every
	// run would report internal/policy/graft.go — where EngineGuestPath is
	// DEFINED, not called — as a violating caller.
	definition := "func (p *Policy) EngineGuestPath(host string) (string, bool) {\n"
	if engineGuestPathCallRE.MatchString(definition) {
		t.Fatal("control: the pattern matched EngineGuestPath's own DEFINITION, not just calls to it")
	}
}
