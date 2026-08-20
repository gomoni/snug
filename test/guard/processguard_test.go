package guard

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The second PreToolUse hook, and the one whose absence is hardest to notice.
// Its sibling needs a destructive verb AND a protected path before it refuses;
// `pkill -x bwrap` and `podman system reset` have neither, so they went through
// twice — 2026-08-13 and 2026-08-19 (issue #197).
//
// A deny-list with a broken pattern denies nothing and looks identical from the
// outside to one that works, which is the "documented but not implemented" shape
// CLAUDE.md warns about. So both directions are asserted here, and every pattern
// below was mutation-checked: break it in the hook, and the DENY case fails.

func processHook(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", ".claude", "hooks", "deny-host-process-selectors.py"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the process-selector hook is missing (%v); .claude/settings.json still names "+
			"it, so a name-matched kill would reach the host unguarded", err)
	}
	return p
}

// askProcess runs the hook the way Claude Code does — one JSON object on stdin.
func askProcess(t *testing.T, command string) (denied bool, reason string) {
	t.Helper()
	in, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]string{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(processHook(t))
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

func TestTheHookRefusesCommandsThatPickTheirTargetByMatching(t *testing.T) {
	for _, tc := range []struct{ command, why string }{
		// The two spellings that actually happened on this host.
		{"pkill -x bwrap", "exact-name matching still matches every Flatpak"},
		{"podman system reset", "destroys the distrobox this project is developed inside"},

		{"pkill -f snug", "argv matching reaches the issuing shell too"},
		{"pkill -9 -x bwrap", "the signal is not what makes this dangerous"},
		{"killall bwrap", "same selector, different program"},
		{"kill $(pgrep -f bwrap)", "the pattern search chose the pids, not the caller"},
		{"kill -9 $(pidof bwrap)", "pidof is a pattern search wearing a different name"},
		{"pgrep -f snug | xargs kill", "a kill fed from a pipe takes whatever the pipe found"},
		{"ps -eo pid,comm | grep bwrap | awk '{print $1}' | xargs -r kill -9", "the long way round to the same place"},
		{`sh -c "pkill -x bwrap"`, "a payload string is where the verb usually sits"},
		{"env -- pkill x", "the end-of-options marker is not a command"},
		{"sudo pkill -x bwrap", "a transparent wrapper changes nothing about the selector"},

		{"podman rm --all", "reaches containers this session never created"},
		{"podman stop -a", "the short spelling of the same thing"},
		{"podman rmi -a", "images the session did not build"},
		{"podman system prune -f", "unscoped by construction"},
		{"podman container prune", "every prune names no container"},
		{"docker rm --all", "docker on this host is the same engine"},
		{"podman machine stop", "operates on the engine, not on one container"},

		{"systemctl --user stop snug.service", "stops a unit this session did not start"},
		{"systemctl --user kill foo.service", "same, by signal"},
		{"loginctl terminate-user michal", "ends the login session and everything in it"},
		{"loginctl kill-session 3", "same family"},

		// The selector after a legitimate sandboxed payload. The exemption must
		// cover the payload and stop at the operator that ends it.
		{`snug /tmp/t -- sh -c 'echo hi'; pkill -x bwrap`, "the exemption must not leak past the segment"},
	} {
		denied, reason := askProcess(t, tc.command)
		if !denied {
			t.Errorf("ALLOWED a selector-matched destructive command: %q\n(%s)\n"+
				"This is the shape the path-matching hook is structurally blind to, and it is "+
				"the one that took the user's desktop down twice (issue #197).", tc.command, tc.why)
			continue
		}
		// The refusal has to name the fix, or the next agent works around it.
		for _, want := range []string{
			"descendantsOf",      // the worked example, by name so it can be found
			"P=$!",               // the shell half of "keep the pid"
			"cmd.Process.Pid",    // the Go half
			"kill <numeric-pid>", // what is NOT being refused
			"#197",
		} {
			if !strings.Contains(reason, want) {
				t.Errorf("the refusal for %q does not mention %q, so it denies without saying "+
					"what to do instead:\n%s", tc.command, want, reason)
			}
		}
	}
}

func TestTheProcessHookLeavesOrdinaryWorkAlone(t *testing.T) {
	for _, tc := range []struct{ command, why string }{
		// The sanctioned form: a pid the caller recorded.
		{"kill 12345", "a numeric pid is the correct form and must stay usable"},
		{`kill -TERM "$P"`, "P=$! is what the refusal tells people to do"},
		{"kill -9 $PID", "same, unquoted"},
		{"kill $(cat /tmp/run.pid)", "a substitution is not automatically a pattern search"},
		{"kill -- -4242", "a process group the caller started"},

		// Reads. Measuring the host is how the issue got its reproduction.
		{"pgrep -ax bwrap", "counting is not killing"},
		{"pgrep -cx bwrap", "same"},
		{"ps aux | grep bwrap", "same"},
		{"podman ps -a", "-a on a read means show me everything"},
		{"podman images -a", "same"},
		{"podman inspect cv", "reads a named container"},
		{"systemctl --user status snug.service", "status is not stop"},
		{"loginctl list-sessions", "listing is not terminating"},

		// Named container operations. A hook cannot tell which containers a
		// session created, so the honest line is to allow the scoped forms.
		{"podman rm snug-test-1", "named, so the blast radius is the name"},
		{"podman rm -f snug-test-1", "-f is force, not --all"},
		{"podman stop snug-test-1", "named"},
		{"podman run --rm alpine true", "--rm is the container it just created"},
		{"podman build -t x .", "ordinary work"},

		// The words appearing as data rather than as commands.
		{"grep -rn pkill .claude", "searching for the string is not running it"},
		{`echo "never run pkill -x bwrap"`, "quoting it in a message is not running it"},
		{"go test ./test/guard/", "this very suite"},

		// The in-sandbox payload. snug always gives the sandbox its own pid
		// namespace, so this cannot reach a host process — and it is committed
		// work (test/integration asserts exactly this probe).
		{`snug /tmp/t -- sh -c 'pkill -9 -x sleep'`, "a sandboxed payload cannot signal a host pid"},
		{`snug "$dir" -p @net -- sh -c 'podman system reset'`, "same, and the engine is the sandbox's"},

		// Ordinary destruction the sibling hook already grades.
		{"rm -rf .claude/worktrees/tmp", "not this hook's business"},
		{"git worktree remove .claude/worktrees/tmp", "same"},
	} {
		if denied, reason := askProcess(t, tc.command); denied {
			t.Errorf("REFUSED ordinary work: %q\n(%s)\nA hook that gets in the way of the work "+
				"is a hook somebody switches off, and a switched-off hook protects nothing.\n%s",
				tc.command, tc.why, reason)
		}
	}
}

// A hook nothing invokes is a file with good intentions.
func TestBothHooksAreWiredIntoSettings(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".claude", "settings.json"))
	if err != nil {
		t.Fatalf(".claude/settings.json is missing (%v), so neither hook is ever invoked", err)
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
	want := map[string]bool{
		"deny-host-credential-paths.py":  false,
		"deny-host-process-selectors.py": false,
	}
	for _, entry := range settings.Hooks["PreToolUse"] {
		for _, h := range entry.Hooks {
			for name := range want {
				if strings.Contains(h.Command, name) {
					if !strings.Contains(entry.Matcher, "Bash") {
						t.Errorf("%s is registered for matcher %q rather than Bash", name, entry.Matcher)
					}
					want[name] = true
				}
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("no PreToolUse entry invokes %s, so it never runs and every test above "+
				"grades a file nothing executes", name)
		}
	}
}

// THE KILL RULE BELONGS TO redteam, THE SAME WAY THE SANDBOX-RUN RULE DOES.
//
// It was first written into every agent file whose tools include Bash, on the
// reasoning that they all have a host shell and could all reach for `pkill`.
// That is the paste #191 already rejected once, and the reasons hold here:
//
//   - The agent files are the TEACHING layer, not the enforcement layer.
//     `.claude/hooks/deny-host-process-selectors.py` refuses the command
//     whoever is asking — every agent, and the main thread, which is where both
//     incidents actually came from. Four copies of the same 25 lines add no
//     enforcement and cost attention in every invocation of every agent.
//   - The scope was wrong in both directions when it was broad. `go-implementer`
//     supervises processes in GO — `cmd.Process.Pid`, signal forwarding — and
//     has no host-shell kill moment at all, while `sandbox-policy`, which the
//     broad version excluded, says in its own file that Bash is essential for
//     "running `make gate`, launching sandboxes".
//   - redteam is the agent that runs snug for real and then has to clean up
//     after it, which is the moment the reflex fires.
//
// So the assertion is exact rather than universal, mirroring
// TestOnlyRedteamCarriesTheSandboxRunRule. Both halves matter — the second is
// what stops the block being pasted back across the tree the next time somebody
// reads the incident report and reaches for breadth.
const killRuleHeading = "## Killing a process, and commands that pick the target for you"

func TestOnlyRedteamCarriesTheKillRule(t *testing.T) {
	files := agentFiles(t)

	body, ok := files["redteam.md"]
	if !ok {
		t.Fatal("no .claude/agents/redteam.md; the agent that runs snug for real and cleans up " +
			"after it is the one this rule exists for")
	}
	if !strings.Contains(body, killRuleHeading) {
		t.Fatalf("redteam.md does not carry %q (issue #197)", killRuleHeading)
	}
	// Asserted as content rather than as a heading, because a heading with the
	// body rewritten under it is what a well-meaning edit produces.
	for _, want := range []struct{ text, why string }{
		{"Flatpak runs every desktop application under", "the mechanism, which has to lead — 'do not pkill' without the reason reads as fussiness and gets rationalised away"},
		{"rootless-podman distrobox", "the container half of the same mechanism"},
		{"Kill only pids you started and recorded", "the rule itself"},
		{`pkill -f "<fragment>"`, "the spelling people reach for when pkill -x is refused"},
		{"2026-08-13", "the first incident, verbatim — the count was the tell and it went unnoticed"},
		{"2026-08-19", "the recurrence, verbatim — a rule with no mechanism is not a rule"},
		{"descendantsOf", "the worked example, named so it can be found"},
		{"P=$!", "how to keep the pid in a shell"},
		{"cmd.Process.Pid", "how to keep it in Go"},
	} {
		if !strings.Contains(body, want.text) {
			t.Errorf("redteam.md's kill-rule section no longer says %q — %s", want.text, want.why)
		}
	}

	for name, other := range files {
		if name == "redteam.md" {
			continue
		}
		if strings.Contains(other, killRuleHeading) {
			t.Errorf("%s carries the kill rule, which belongs to redteam alone. The hook is the "+
				"enforcement and it covers every agent and the main thread without being read; "+
				"a fourth copy of the prose adds no protection and spends attention in every "+
				"invocation. This is the paste #191 already rejected once", name)
		}
	}
}
