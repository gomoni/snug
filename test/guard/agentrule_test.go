package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// EVERY AGENT THAT CAN RUN A COMMAND MUST CARRY THE HOST-SHELL RULE, AND ALL
// COPIES MUST BE THE SAME BYTES.
//
// The rule itself is in .claude/agents/*.md: your Bash tool is a host shell, a
// destructive command that runs inside must be guarded in the SAME invocation,
// and PS1 is not evidence. Issue #185.
//
// This test exists because the rule is COPIED into four files and nothing else
// checks them. That is the shape issue #159 is about — a list written five times
// with one copy nobody re-reads — and it has two failure modes, both silent:
//
//   - one copy is edited and the others are not, so which agent you happen to
//     dispatch decides which rule applies;
//   - a NEW agent file is added with Bash in its tools and no rule at all, which
//     is the more likely of the two and the one no amount of care prevents.
//
// So the check is mechanical and has no allowlist: the set of files is derived
// from the `tools:` line, not from a list maintained beside it. Adding an agent
// that can run commands and forgetting the rule fails here.
//
// Markdown has no include, and the harness reads these files verbatim, so
// copying is the only way to say it four times. Then the copies have to be
// asserted equal, or "we said it everywhere" is a belief rather than a fact.
const hostShellHeading = "## Your Bash tool is a HOST shell. Always."

// The block ends at the last bullet. Anchored on its final sentence rather than
// on a blank line, so reformatting the block does not silently shorten what this
// test compares.
const hostShellLastLine = "re-read it rather than rephrasing it."

func agentFiles(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join("..", "..", ".claude", "agents")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read %s: %v", dir, err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(body)
	}
	if len(out) == 0 {
		t.Fatal("no agent files found, so this test grades an empty set and passes forever")
	}
	return out
}

// carriesBash reads the frontmatter `tools:` line. An agent with no Bash cannot
// run a command at all, so the rule would be noise in its file.
func carriesBash(body string) bool {
	// Frontmatter only: the fenced block between the first two `---` lines. An
	// earlier version scanned the whole file for a line starting with `tools:`
	// and gave up at the first `---`, which matched nothing at all — every file
	// read as "no Bash", the test found zero agents, and only the guard against
	// a vacuous comparison stopped it passing on an empty set.
	lines := strings.Split(body, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return false
	}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "---" {
			return false
		}
		if strings.HasPrefix(line, "tools:") {
			return strings.Contains(line, "Bash")
		}
	}
	return false
}

func hostShellBlock(body string) (string, bool) {
	start := strings.Index(body, hostShellHeading)
	if start == -1 {
		return "", false
	}
	end := strings.Index(body[start:], hostShellLastLine)
	if end == -1 {
		return "", false
	}
	return body[start : start+end+len(hostShellLastLine)], true
}

func TestEveryAgentWithBashCarriesTheHostShellRule(t *testing.T) {
	var blocks []struct{ file, block string }
	for name, body := range agentFiles(t) {
		if !carriesBash(body) {
			if _, ok := hostShellBlock(body); ok {
				t.Errorf("%s carries the host-shell rule but has no Bash tool. Harmless, and "+
					"worth removing: a rule in a file it cannot apply to is how a rule stops "+
					"being read where it does apply", name)
			}
			continue
		}
		block, ok := hostShellBlock(body)
		if !ok {
			t.Errorf("%s can run commands and does not carry the host-shell rule (%q).\n"+
				"That agent's Bash tool is a HOST shell like every other one, and nothing in "+
				"its file says so. Copy the block from .claude/agents/redteam.md verbatim — "+
				"this test asserts the copies are identical.", name, hostShellHeading)
			continue
		}
		blocks = append(blocks, struct{ file, block string }{name, block})
	}
	if len(blocks) < 2 {
		t.Fatalf("found %d agent files carrying the rule; with fewer than two there is nothing "+
			"to compare and the drift half of this test is vacuous", len(blocks))
	}

	// All copies must be the same bytes. Not "equivalent", not "say the same
	// thing" — the same bytes, because that is the only version of the claim a
	// test can hold.
	want := blocks[0]
	for _, got := range blocks[1:] {
		if got.block != want.block {
			t.Errorf("the host-shell rule in %s differs from the one in %s.\n"+
				"Four copies with no check is how one gets edited and three do not, and then "+
				"which agent you dispatch decides which rule applies.\n\n%s:\n%s\n\n%s:\n%s",
				got.file, want.file, want.file, want.block, got.file, got.block)
		}
	}
	t.Logf("%d agent files carry the rule, byte-identical", len(blocks))
}
