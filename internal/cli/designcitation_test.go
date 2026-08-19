package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// designDocCitation matches a SHOUTY-KEBAB design document name as it appears
// in a Go comment: ENGINE-NETNS.md, TIER-B.md, ISSUE-40-DESIGN.md. Deliberately
// narrow — lowercase .md paths, URLs and prose sentences are not citations of
// this kind, and widening it would make the allowlist below carry noise rather
// than debt.
var designDocCitation = regexp.MustCompile(`\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*\.md\b`)

// notADesignDoc are repo-root or generated files a comment may legitimately
// name. They are checked for existence like everything else, just not under
// .claude/design.
var notADesignDoc = map[string]string{
	"CLAUDE.md":  ".",
	"README.md":  ".",
	"VERIFY.md":  ".",
	"MEMORY.md":  ".",
	"AGENTS.md":  ".",
	"LICENSE.md": ".",
}

// uncommittedDesignDocs is DEBT, recorded rather than tolerated silently.
//
// An entry is a document named by a Go comment that is not in the tree: it
// lived in .claude/scratchpad/ — which is in .gitignore — and was never
// promoted by the deliberate `git mv` CLAUDE.md describes. A reader following
// such a citation gets nothing, which is issue #154 §C, found when
// TIER-B-POLICY.md turned out never to have been committed at all.
//
// IT IS EMPTY, and that is the state to keep it in. The five entries it
// shipped with — 42 citations across 19 files — were resolved by issue #156:
// ENGINE-WIRING.md and ATTACH.md were promoted into .claude/design/, and the
// three whose sources no longer existed anywhere (ISSUE-40-DESIGN.md,
// BRAINSTORM.md, RESEARCH-18-BROKER.md) had their citations repointed at the
// GitHub issues that carry the same subject — a citation a reader can follow
// beats one they cannot.
//
// THE MAP MAY ONLY SHRINK. It exists so that a promotion pass too large for
// one change can record what it did not reach, not as an allowlist for
// convenience — CLAUDE.md's warning about the command-table check is that an
// allowlist is where a rule goes to die. Adding an entry means writing down,
// in public, that you are citing something a reader cannot open.
var uncommittedDesignDocs = map[string]string{}

// TestEveryDesignDocACommentCitesExists is the regression for issue #154 §C.
//
// A citation is a promise that a reader can go and check the claim. Six code
// comments cited TIER-B-POLICY.md for settled maintainer decisions — why the
// engine gets exactly twelve capabilities, why NetworkMode="host" is allowed,
// why the `networks` endpoints carry no refusal list, why ptrace_scope=0
// refuses the run — and the file had never been committed. Two of the
// citations named SECTIONS that did not exist either (a §2.5 and a §7 of a
// document whose sections stopped at 6), which is the tell that nothing had
// ever followed one.
//
// This is the inverse of the drift #104 and #149 record. Those were documents
// that outlived the code they described; this is code citing a document that
// never landed. Both break the same property: a reader cannot check the claim.
//
// Section numbers are NOT checked. That would need a markdown parser and would
// fail on prose restructuring; the cheap half — does the file exist at all —
// is what catches the failure that actually happened.
func TestEveryDesignDocACommentCitesExists(t *testing.T) {
	root := filepath.Join("..", "..")

	type site struct{ file, doc string }
	var missing []site
	seen := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// This file names every uncommitted document in the map above, so
		// scanning it would report its own debt list as fresh findings.
		if filepath.Base(path) == "designcitation_test.go" {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		rel, _ := filepath.Rel(root, path)
		for _, doc := range designDocCitation.FindAllString(string(data), -1) {
			seen[doc] = true
			if _, ok := uncommittedDesignDocs[doc]; ok {
				continue
			}
			dir := ".claude/design"
			if d, ok := notADesignDoc[doc]; ok {
				dir = d
			}
			if _, serr := os.Stat(filepath.Join(root, dir, doc)); serr != nil {
				missing = append(missing, site{rel, doc})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, m := range missing {
		t.Errorf("%s cites %s, which is not in the tree — a citation a reader cannot follow.\n"+
			"      Promote the document into .claude/design/ (a deliberate `git mv` out of "+
			".claude/scratchpad/), or stop citing it.", m.file, m.doc)
	}

	// POSITIVE CONTROL, in both directions.
	//
	// Without the first, this test passes on a walk that read no files at all
	// — a wrong root, a SkipDir too broad, a suffix check that never matches.
	// TIER-B.md is asserted by name because promoting it is what this pass
	// did: if it is ever deleted while its six citations remain, that is the
	// exact defect returning and it must not pass as "nothing cited".
	if !seen["TIER-B.md"] {
		t.Error("the sweep found no citation of TIER-B.md, so it is not reading the files " +
			"it thinks it is — six comments cite it")
	}
	if len(seen) < 5 {
		t.Errorf("the sweep found only %d design-doc citations in the whole tree; it is "+
			"almost certainly not walking what it should", len(seen))
	}

	// Without the second, the debt map silently accumulates entries for
	// documents that have since landed — which would let a future promotion
	// go unnoticed and keep this test weaker than it looks.
	var landed []string
	for doc := range uncommittedDesignDocs {
		if _, serr := os.Stat(filepath.Join(root, ".claude", "design", doc)); serr == nil {
			landed = append(landed, doc)
		}
	}
	sort.Strings(landed)
	for _, doc := range landed {
		t.Errorf("%s is in .claude/design now — remove it from uncommittedDesignDocs, "+
			"which may only ever shrink", doc)
	}

	// And an entry nothing cites any more is dead weight that makes the debt
	// look larger than it is.
	var unused []string
	for doc := range uncommittedDesignDocs {
		if !seen[doc] {
			unused = append(unused, doc)
		}
	}
	sort.Strings(unused)
	for _, doc := range unused {
		t.Errorf("no Go comment cites %s any more — remove it from uncommittedDesignDocs", doc)
	}
}
