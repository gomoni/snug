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

// TestTheHostModeAbuseSentenceCountsTheBridgesLimits fails if base.toml's
// host-mode ABUSE paragraph states an open or a rewrite count other than
// MaxOpensPerRun and MaxRelaysPerRun: every host rewrite spends a relay, so
// the relay limit, not the open limit, is how many times a run can replace
// the host's refresh token.
func TestTheHostModeAbuseSentenceCountsTheBridgesLimits(t *testing.T) {
	data, err := os.ReadFile("../profile/profiles/base.toml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)# ABUSE, login\.claude = "host".*?\n#\n`).Find(data)
	if m == nil {
		t.Fatal(`base.toml has no "ABUSE, login.claude = \"host\"" paragraph`)
	}
	words := []string{"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"}
	para := strings.Join(strings.Fields(strings.ReplaceAll(string(m), "#", " ")), " ")
	for _, w := range []string{
		"at most " + words[MaxOpensPerRun] + " times per run, one at a time",
		"never a different one, at most " + words[MaxRelaysPerRun] + " times per run",
	} {
		if !strings.Contains(para, w) {
			t.Errorf("the host-mode ABUSE paragraph does not say %q:\n%s", w, para)
		}
	}
}
