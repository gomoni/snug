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
	} {
		denied, reason := ask(t, command)
		if !denied {
			t.Errorf("ALLOWED a destructive command aimed at a host credential path: %q\n"+
				"This is the layer that does not depend on the agent believing anything, and "+
				"it is the one that would have stopped issue #185.", command)
			continue
		}
		// The refusal has to teach, or the next agent works around it.
		for _, want := range []string{"HOST shell", "inside-snug &&", "#185"} {
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
		// THE SANCTIONED FORM. The hook must leave it usable, or the
		// instruction in the agent files and the enforcement here contradict
		// each other — and the instruction is what loses.
		`snug /tmp/t -- sh -c 'bin/inside-snug && rm -rf "$HOME/.config"'`,
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
