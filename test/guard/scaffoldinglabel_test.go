package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE LABEL IS THE DELIVERABLE, SO IT GETS A TEST.
//
// Issue #203 is a maintainer's objection that a security tool should not ship
// agent-harness hooks: snug grants and enforces in the kernel, these deny and
// match strings in an argv, and a reader who meets the second after reading the
// first reasonably concludes the project does not mean its own guiding
// principle. The decision was to KEEP the hooks and label them, rather than
// remove them — both host-damage incidents came from the main thread, which no
// other layer covers.
//
// A label nobody enforces is prose, and prose drifts away from what it
// describes; this repository has a whole rule about that. So the claims the
// label has to keep making are asserted here. Not the wording — the claims.
//
// It is deliberately NOT a test of the hooks' behaviour. That lives in
// hook_test.go and processguard_test.go.

func TestTheHooksAreLabelledAsScaffoldingAndNotAsSnug(t *testing.T) {
	path := filepath.Join("..", "..", ".claude", "hooks", "README.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s is missing (%v). Issue #203's decision was keep-and-reclassify: without "+
			"the label, a reader meets a path deny-list in a repository whose guiding principle "+
			"says there is no deny rule in snug, and concludes the project does not mean it", path, err)
	}
	// Case-insensitive: the claims matter, the capitalisation does not, and a
	// heading that opens with the phrase should count.
	text := strings.ToLower(string(body))

	for _, want := range []struct{ claim, why string }{
		{"not part of snug", "the whole point of the file — a reader has to learn this in the first line, not the fifth paragraph"},
		{"deny-list", "naming the shape honestly is what stops it being read as snug's model"},
		{"speed bump, not a boundary", "the measured record supports this reading and #202's body says it; the label must not overclaim"},
		{"argv", "the first limit: text moved off the argv is invisible whether it is a citation or a command"},
		{"bash tool alone", "the second limit, and the one people get wrong — the same operation through a file-editing tool is not graded"},
		{"main thread", "the justification. Both incidents came from the thread no agent-file rule reaches, which is why this layer exists at all"},
		{"#185", "the path-shaped incident"},
		{"#197", "the selector-shaped incident"},
		{"#203", "the open question, so a reader knows the directory's future is undecided"},
		{"blast-radius", "the structural answer, named so it can be found — it does not depend on any of this"},
		{"repository only", "the repo-local scope is a decision (#203 item 4), not an oversight, and has to read as one"},
	} {
		if !strings.Contains(text, strings.ToLower(want.claim)) {
			t.Errorf("the hooks README no longer says %q — %s", want.claim, want.why)
		}
	}

	// Every hook in the directory has to be accounted for, or the label
	// describes a set smaller than the one that ships.
	dir := filepath.Join("..", "..", ".claude", "hooks")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".py") {
			continue
		}
		found++
		if !strings.Contains(text, strings.ToLower(e.Name())) {
			t.Errorf("%s ships in .claude/hooks but the README does not mention it, so the label "+
				"describes a smaller set than the one that runs", e.Name())
		}
	}
	if found == 0 {
		t.Fatal("no .py hooks found, so this test grades an empty set and passes forever")
	}
}
