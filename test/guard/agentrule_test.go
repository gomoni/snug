package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE SANDBOX-RUN RULE BELONGS TO redteam AND TO NO OTHER AGENT.
//
// It was first written into every agent file whose tools include Bash — five of
// them — on the reasoning that they all run on the host and should all be warned
// about it. That was wrong twice over:
//
//   - Working on the host is the ORDINARY and correct mode for sandbox-tester,
//     host-bridge, go-implementer and sandbox-policy. They edit files, run
//     `go test`, drive git. A block telling them their normal mode is a hazard
//     teaches them to distrust the thing they are supposed to be doing, and
//     spends their attention where nothing is at stake.
//   - redteam is the only agent that runs snug FOR REAL, with profiles it wrote,
//     to see what escapes. It is the only one whose ordinary work can hand a
//     payload the host's key material, and the only one for which "pin HOME to a
//     scratch directory" is a rule rather than a curiosity.
//
// So the assertion is exact rather than universal: redteam carries it, nobody
// else does. Both halves matter — the second is what stops the block being
// pasted back across the tree the next time someone reads the incident report
// and reaches for breadth.
const sandboxRunHeading = "## Before any run that creates a real sandbox"

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

func TestOnlyRedteamCarriesTheSandboxRunRule(t *testing.T) {
	files := agentFiles(t)

	redteam, ok := files["redteam.md"]
	if !ok {
		t.Fatal("no .claude/agents/redteam.md; the agent that runs real sandboxes is the one " +
			"this rule exists for")
	}
	if !strings.Contains(redteam, sandboxRunHeading) {
		t.Errorf("redteam.md does not carry %q. It is the only agent that runs snug for real "+
			"with profiles it wrote, and the section is what tells it to pin HOME to a scratch "+
			"directory and to guard payloads with bin/blast-radius (issues #185, #186)",
			sandboxRunHeading)
	}
	// The three claims the section must actually make. Asserted as content
	// rather than as a heading, because a heading with the body rewritten under
	// it is exactly what a well-meaning edit produces.
	for _, want := range []struct{ text, why string }{
		{"Pin `HOME` to a scratch directory", "the mechanism that bounds every failure at once"},
		{"blast-radius", "the check, and it must be named so it can be found"},
		{"is NOT a safety property", "the lesson the previous guard was deleted for"},
	} {
		if !strings.Contains(redteam, want.text) {
			t.Errorf("redteam.md's sandbox-run section no longer says %q — %s", want.text, want.why)
		}
	}

	for name, body := range files {
		if name == "redteam.md" {
			continue
		}
		if strings.Contains(body, sandboxRunHeading) {
			t.Errorf("%s carries the sandbox-run rule, which belongs to redteam alone. Running "+
				"on the host is this agent's ordinary and correct mode; a block warning it "+
				"about that spends attention where nothing is at stake, and teaches it to "+
				"distrust its own normal way of working", name)
		}
	}
}
