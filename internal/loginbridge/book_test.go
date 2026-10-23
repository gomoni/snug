package loginbridge

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestBookLoginOpenLimitIsTheBridges checks the open limit the `login`
// section of docs/src/claude.md states against MaxOpensPerRun.
func TestBookLoginOpenLimitIsTheBridges(t *testing.T) {
	const page = "../../docs/src/claude.md"
	data, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)\n## `login`\n(.*?)\n## ").FindSubmatch(data)
	if m == nil {
		t.Fatalf("%s has no `login` section", page)
	}
	// The prose spells small counts out; a limit past the table needs a word
	// added here before the book can state it.
	word := func(n int) string {
		words := []string{"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"}
		if n < 0 || n >= len(words) {
			t.Fatalf("no word for %d", n)
		}
		return words[n]
	}
	section := strings.Join(strings.Fields(string(m[1])), " ")
	if w := "at most " + word(MaxOpensPerRun) + " times per run"; !strings.Contains(section, w) {
		t.Errorf("%s's `login` section does not say %q", page, w)
	}
}
