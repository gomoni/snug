package guard

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The PreToolUse hook is the layer that does not depend on an agent believing
// anything, which is what makes it the one that would actually have stopped the
// #185 incident. It is also a file nothing else executes, so without this test
// a typo in it is indistinguishable from a hook that decided to allow.
//
// Both directions are asserted, and the ALLOW half carries as much weight as the
// DENY half: a hook that refuses ordinary work is a hook somebody switches off
// within the hour, and a switched-off hook protects nothing.

func hook(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", ".claude", "hooks", "deny-host-credential-paths.py"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the PreToolUse hook is missing (%v); .claude/settings.json still names it, "+
			"so every Bash call would run with no guard at all", err)
	}
	return p
}

// ask runs the hook the way Claude Code does — one JSON object on stdin — and
// reports whether it denied.
func ask(t *testing.T, command string) (denied bool, reason string) {
	t.Helper()
	in, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]string{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(hook(t))
	cmd.Stdin = strings.NewReader(string(in))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the hook failed on %q: %v", command, err)
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		return false, ""
	}
	var decision struct {
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out, &decision); err != nil {
		t.Fatalf("the hook emitted output Claude Code cannot read (%v): %s", err, out)
	}
	return decision.HookSpecificOutput.PermissionDecision == "deny",
		decision.HookSpecificOutput.PermissionDecisionReason
}

func TestTheHookRefusesDestructiveCommandsAimedAtHostCredentialPaths(t *testing.T) {
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("SKIP: no HOME to build the protected paths from")
	}
	for _, command := range []string{
		"rm -rf ~/.claude",
		"rm -rf $HOME/.ssh/",
		"rm -rf ${HOME}/.gnupg",
		// The spelling that started this: a payload string, where the verb sits
		// directly behind a quote. The first version of the matcher required
		// whitespace or a shell operator before the verb and let this through.
		`sh -c "rm -rf ~/.claude"`,
		// A snug invocation is NOT an exemption by itself. An unguarded payload
		// string is exactly the mistake, and inside a sandbox the guard costs
		// one command substitution.
		`snug /tmp/t -- sh -c "rm -rf $HOME/.ssh"`,
		"mv ~/.aws /tmp/elsewhere",
		"echo broken > $HOME/.config/snug/config.toml",
		"find $HOME/.claude -name '*.json' -delete",
		"rm -rf ~",
		// The destructive command is not the FIRST command in the line. Added
		// by mutation: disabling `&&`/`||` splitting in the shared splitter
		// changed no test, because every case above put the verb first — so the
		// segmenting the #199 fix now depends on was untested.
		"cd /tmp && rm -rf ~/.claude",
		"test -d ~/.ssh || rm -rf $HOME/.ssh",
		// The heredoc BODY is data and is stripped, but the line that opened it
		// is still a command and its redirect target is still a target. The
		// stripping must not become a way to smuggle the target past the check.
		"cat > ~/.ssh/config <<'EOF'\nharmless text\nEOF",
	} {
		denied, reason := ask(t, command)
		if !denied {
			t.Errorf("ALLOWED a destructive command aimed at a host credential path: %q\n"+
				"This is the layer that does not depend on the agent believing anything, and "+
				"it is the one that would have stopped issue #185.", command)
			continue
		}
		// The refusal has to teach, or the next agent works around it.
		for _, want := range []string{"belongs to the host", "blast-radius &&", "#185"} {
			if !strings.Contains(reason, want) {
				t.Errorf("the refusal for %q does not mention %q, so it denies without saying "+
					"what to do instead:\n%s", command, want, reason)
			}
		}
	}
}

func TestTheHookLeavesOrdinaryWorkAlone(t *testing.T) {
	for _, command := range []string{
		// Ordinary work in this repo, all of it deleting things.
		"rm -rf .claude/worktrees/issue-186-datawrite",
		"rm -f /tmp/claude-1000/scratchpad/fixture.json",
		"go test ./...",
		"git worktree remove .claude/worktrees/tmp",
		// NOT protected: an ordinary directory that merely lives under $HOME.
		// The bare-home entry guards `rm -rf ~` exactly, and deliberately not
		// its children — this repository is itself under $HOME.
		"rm -rf $HOME/projects/plainsof/cv/snug/.claude/worktrees/tmp",
		"rm -rf ${HOME}/scratch/build",
		// Reading a protected path is not destroying it.
		"cat ~/.claude/settings.json",
		"grep -r hooks ~/.claude/settings.json",
		// THE SANCTIONED FORM (redteam.md). The hook must leave it usable, or
		// the instruction and the enforcement contradict each other — and the
		// instruction is what loses.
		`snug /tmp/t -- sh -c 'blast-radius && rm -rf "$HOME/.config"'`,

		// ISSUE #199 — WRITING ABOUT DESTRUCTION IS NOT DESTRUCTION.
		//
		// Six refusals of harmless work across two sessions, zero destructive
		// commands attempted in that window. Every one was text ABOUT a
		// destructive command: this repository writes about destroying things
		// constantly, because that is what the incidents were. These are the
		// measured cases, not invented ones.
		//
		// The scratchpad path is spelled without an extension here only because
		// the design-citation sweep reads a bare `*.md` in a comment as a
		// citation it must be able to follow. The measured file was a gitignored
		// plan document; what the hook grades is unaffected by the name.
		//
		// The rule they encode: a destructive token inside a CARRIED ARGUMENT
		// was never a command. `sh -c` is a command position and is graded
		// above; a `-m` message, a `--comment` body, an `echo` string and a
		// here-document body are not.
		`git commit -m "the hook denied rm -rf ~/.claude and that was wrong"`,
		`gh issue close 185 --comment 'the report quoted rm -rf $HOME/.ssh'`,
		// The heredoc body has to be a line that WOULD be graded as a command
		// if it were one — added by mutation, because with a body starting
		// "this body quotes…" the stripping was never load-bearing and could be
		// deleted with no test noticing.
		"cat > notes.md <<'EOF'\nrm -rf ~/.claude is the command that started #185\nEOF",
		"cat > issue.md <<'EOF'\nthis body quotes rm -rf ~/.claude while documenting it\nEOF",
		"python3 - <<'PY'\nopen('.claude/scratchpad/notes','w').write('PR 200 refused rm -rf ~/.claude')\nPY",
		`echo "never run rm -rf ~/.claude" >> .claude/scratchpad/notes`,
		// The sixth: the shell function written to PROBE the hook was refused
		// by the hook, while carrying its own fixtures as arguments.
		`probe() { echo "$1"; }; probe 'rm -rf ~/.claude'`,
	} {
		if denied, reason := ask(t, command); denied {
			t.Errorf("REFUSED ordinary work: %q\nA hook that gets in the way of the work is a "+
				"hook somebody switches off, and a switched-off hook protects nothing.\n%s",
				command, reason)
		}
	}
}

// The hook is only wired in if settings.json says so, and a hook nothing invokes
// is a file with good intentions.
func TestTheHookIsWiredIntoSettings(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".claude", "settings.json"))
	if err != nil {
		t.Fatalf(".claude/settings.json is missing (%v), so the hook in .claude/hooks is never "+
			"invoked and every test above grades a file nothing runs", err)
	}
	var settings struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatalf(".claude/settings.json does not parse (%v); Claude Code would ignore it and "+
			"the guard would be silently absent", err)
	}
	for _, entry := range settings.Hooks["PreToolUse"] {
		for _, h := range entry.Hooks {
			if strings.Contains(h.Command, "deny-host-credential-paths.py") {
				if !strings.Contains(entry.Matcher, "Bash") {
					t.Errorf("the hook is registered for matcher %q rather than Bash", entry.Matcher)
				}
				return
			}
		}
	}
	t.Error("no PreToolUse entry invokes deny-host-credential-paths.py, so the hook never runs")
}
