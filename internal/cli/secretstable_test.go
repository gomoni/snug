package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// SECRETS.md §2 is the table a reader consults to answer "what credential is
// inside the sandbox right now, and which code puts it there". Every row cites
// the code, and a citation is a promise that a reader can go and check the
// claim — the same property TestEveryDesignDocACommentCitesExists holds in the
// other direction, for a comment citing a document.
//
// A LINE NUMBER CANNOT KEEP THAT PROMISE, and this table is where it was
// measured rather than assumed. Two of its three citations were false:
// `internal/cli/identity.go:330` was offered as the `oauth_token:` write and
// landed inside the allowed_signers staging that issue #453 inserted above it,
// with the real write at :471; `internal/policy/gitextract.go:131` was offered
// as the `insteadOf` rewrite and landed on the `id.Git.Email` override, with
// the real rewrite at :176. Neither edit touched the table, nothing failed, and
// both citations read as precise.
//
// So the rule this test holds is not "the line number is right" — which no test
// can know — but that the table cites SYMBOLS, which move with the code they
// name. It checks the two halves separately: the symbol is really in the file
// the row names, and no row carries a `file.go:NNN` at all.
//
// Scope is deliberately this one table. The rest of .claude/design cites lines
// in hundreds of places; sweeping them is a change of its own, and an allowlist
// spanning the tree is where this rule would go to die.
func TestSecretsTodayTableCitesSymbolsNotLineNumbers(t *testing.T) {
	root := filepath.Join("..", "..")
	doc := filepath.Join(root, ".claude", "design", "SECRETS.md")

	b, err := os.ReadFile(doc)
	if err != nil {
		t.Fatalf("reading SECRETS.md: %v", err)
	}

	rows := secretsTodayTable(t, string(b))
	if len(rows) < 4 {
		t.Fatalf("SECRETS.md §2's table has %d body rows, want at least 4. If the section "+
			"was renamed or the table restructured, repoint this test rather than deleting "+
			"it: the citations are what it holds", len(rows))
	}

	lineCite := regexp.MustCompile("`[^`]*\\.go:[0-9]+`")
	pairCite := regexp.MustCompile("\\(`([A-Za-z_][A-Za-z0-9_.]*)`, `([^`]+\\.go)`\\)")

	symbols := 0
	for _, row := range rows {
		if m := lineCite.FindString(row); m != "" {
			t.Errorf("SECRETS.md §2 cites %s. A line number is a copy of state held in the "+
				"file it names: an insertion above it moves the code and leaves the citation "+
				"pointing at whatever took its place, and nothing in this repository fails. "+
				"Cite the symbol instead", m)
		}
		for _, m := range pairCite.FindAllStringSubmatch(row, -1) {
			symbols++
			sym, path := m[1], m[2]
			src, err := os.ReadFile(filepath.Join(root, path))
			if err != nil {
				t.Errorf("SECRETS.md §2 cites %q in %s, which cannot be read: %v", sym, path, err)
				continue
			}
			if !strings.Contains(string(src), sym) {
				t.Errorf("SECRETS.md §2 cites %q in %s and that file does not contain it. "+
					"The symbol was renamed or moved; the row now describes code that is not "+
					"where it says", sym, path)
			}
		}
	}
	if symbols == 0 {
		t.Error("no (`symbol`, `path`) citation found in SECRETS.md §2's table. Every row that " +
			"names code is supposed to carry one, so either the table lost its citations or " +
			"this test's pattern no longer matches how they are written")
	}
}

// secretsTodayTable returns the body rows of the first markdown table under
// SECRETS.md's "## 2." heading, stopping at the next heading. It matches the
// heading by NUMBER rather than by title so that rewording the section — which
// CLAUDE.md's design-document rule positively encourages — does not silently
// reduce this test to checking nothing.
func secretsTodayTable(t *testing.T, doc string) []string {
	t.Helper()

	var rows []string
	inSection, inTable := false, false
	for _, line := range strings.Split(doc, "\n") {
		switch {
		case strings.HasPrefix(line, "## 2."):
			inSection = true
			continue
		case inSection && strings.HasPrefix(line, "## "):
			return rows
		case !inSection:
			continue
		}

		if !strings.HasPrefix(line, "|") {
			if inTable {
				return rows
			}
			continue
		}
		if strings.HasPrefix(line, "|---") {
			inTable = true
			continue
		}
		if inTable {
			rows = append(rows, line)
		}
	}
	if !inSection {
		t.Fatal("SECRETS.md has no `## 2.` heading. The section this test reads was renumbered " +
			"or removed; repoint it at wherever the today-table now lives")
	}
	return rows
}
