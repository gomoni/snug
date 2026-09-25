package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// INDEX.md's "Designed, not built" line tells a reader which flags and verbs
// NOT to cite as existing. It listed `--dry-run --json` long after -j/--json
// shipped, so the one list meant to stop readers trusting unbuilt features was
// telling them a built one was missing. This fails when an entry on that line
// parses as a real invocation: a flag run parseArgs accepts, or a `snug VERB`
// that subcommands() dispatches.
//
// Entries without backticks ("shell completion") are not graded.
func TestINDEXNotBuiltLineNamesNothingThatParses(t *testing.T) {
	index := filepath.Join("..", "..", ".claude", "design", "INDEX.md")
	body, err := os.ReadFile(index)
	if err != nil {
		t.Fatalf("cannot read %s: %v", index, err)
	}
	line := regexp.MustCompile(`(?m)^\*\*Designed, not built:\*\* (.*)$`).FindSubmatch(body)
	if line == nil {
		t.Fatalf("no \"**Designed, not built:**\" line in %s; if it was renamed, update the pattern "+
			"rather than deleting the check", index)
	}
	graded := 0
	for _, m := range regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(string(line[1]), -1) {
		words := strings.Fields(m[1])
		switch {
		case words[0] == "snug" && len(words) > 1:
			graded++
			if _, ok := subcommands()[words[1]]; ok {
				t.Errorf("INDEX.md says `%s` is not built, and `%s` is a subcommand", m[1], words[1])
			}
		case strings.HasPrefix(words[0], "-"):
			graded++
			if _, err := parseArgs(append(words, ".")); err == nil {
				t.Errorf("INDEX.md says `%s` is not built, and parseArgs accepts it", m[1])
			}
		}
	}
	if graded == 0 {
		t.Fatal("the not-built line names no flag or verb; this test is grading nothing")
	}
}
