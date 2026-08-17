//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The harm in issue #19, measured where it actually lands.
//
// The unit tests in internal/cli assert what the policy says and what the generator
// produces. Neither can see the thing the issue is about, which is not a field
// value but a BOUNDARY CROSSING: the absolute path of every project on this
// machine arriving inside a sandbox whose whole filesystem story is that a
// sibling directory is not merely unreadable but ABSENT. @parent-ro grants the
// target's parent and nothing above it; a payload inside cannot enumerate the
// host's work. Handing it a list of seven absolute paths in its own $HOME does
// not let it READ any of them — and that is exactly why nothing caught it — but
// it tells it what is there, what the human works on, and where to aim the next
// thing it gets.
//
// So this test does two things a unit test cannot. It reads the file from
// inside a running sandbox, and it proves in the same run that those paths are
// otherwise out of reach — which is what makes the file a channel rather than a
// restatement of something the payload could already see.
func TestClaudeJSONInsideCarriesNoHostProjectInventory(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	paths := hostProjectPaths(t, proj)
	if len(paths) == 0 {
		t.Skip("this host's ~/.claude.json lists no project paths outside the fixture, so " +
			"there is no inventory to look for; TestClaudeJSONInsideIsGeneratedAndSmall " +
			"covers the host-independent half")
	}

	const begin, end = "---BEGIN-CLAUDE-JSON---", "---END-CLAUDE-JSON---"
	var script strings.Builder
	fmt.Fprintf(&script, "echo %s\ncat \"$HOME/.claude.json\"\necho\necho %s\n", begin, end)
	// The reachability probe, in the SAME run as the read. Two runs would leave
	// room for the two halves to disagree about which sandbox they measured.
	for _, p := range paths {
		fmt.Fprintf(&script, "if [ -e %s ]; then echo \"REACHABLE %s\"; else echo \"ABSENT %s\"; fi\n",
			shQuote(p), p, p)
	}
	r := run(t, []string{"-p", "@claude"}, proj, script.String()).mustRun(t)

	body := between(r.out, begin, end)
	if strings.TrimSpace(body) == "" {
		t.Fatalf("~/.claude.json is absent or empty inside the sandbox, so the sweep below "+
			"would pass on a sandbox with no Claude state at all:\n%s", r.out)
	}

	// CONTROL, and it is the half that makes the finding a finding: these paths
	// are not reachable inside. If the payload could stat them anyway, the file
	// would be telling it nothing it did not have, and the assertion below would
	// be measuring a boundary that is not there.
	var reachable []string
	for _, p := range paths {
		switch {
		case strings.Contains(r.out, "ABSENT "+p):
		case strings.Contains(r.out, "REACHABLE "+p):
			reachable = append(reachable, p)
		default:
			t.Fatalf("the probe for %q emitted neither ABSENT nor REACHABLE; the control "+
				"did not run:\n%s", p, r.out)
		}
	}
	if len(reachable) > 0 {
		t.Fatalf("control: the sandbox can stat these host project paths: %v. Either a "+
			"profile is granting far more than @parent-ro should, which is a finding in its "+
			"own right, or this fixture picked paths that overlap the target — in both cases "+
			"the inventory sweep below proves nothing", reachable)
	}

	// The sweep. A host project path inside ~/.claude.json is the finding.
	for _, p := range paths {
		if strings.Contains(body, p) {
			t.Errorf("the sandbox's ~/.claude.json names the host path %q, which the same "+
				"run just measured as ABSENT inside. ~/.claude.json must be GENERATED "+
				"(internal/cli/claude.go, claudeStateJSON), never copied: the host's is an "+
				"inventory of every project on this machine, and @parent-ro deliberately "+
				"does not grant so much as a sibling directory. See issue #19.", p)
		}
	}

	// And the positive form of the same claim. A generator that emitted nothing
	// at all would pass the sweep above by saying nothing, so the file has to be
	// checked for being the real generated one AND for the only path it may ever
	// name being the target.
	//
	// The projects key is ABSENT here rather than naming the target, and that is
	// the F1 fix rather than a weakening of this test: the target is a directory
	// created seconds ago, so no host has accepted Claude Code's trust dialog for
	// it, so snug carries no trust entry. Whether the entry appears when the host
	// HAS trusted the path is TestClaudeTrustEntryCarriesTheHostsDecision, which
	// runs both arms; what belongs here is that no OTHER path is ever named.
	var doc struct {
		Projects               map[string]json.RawMessage `json:"projects"`
		HasCompletedOnboarding bool                       `json:"hasCompletedOnboarding"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("the file inside the sandbox is not valid JSON (%v):\n%s", err, body)
	}
	// CONTROL: this is snug's generated file, not an empty document that would
	// satisfy every assertion in this test by containing nothing.
	if !doc.HasCompletedOnboarding {
		t.Fatalf("the file inside carries no hasCompletedOnboarding, so it is not the file "+
			"snug generates and the sweep above measured nothing:\n%s", body)
	}
	inside := make([]string, 0, len(doc.Projects))
	for p := range doc.Projects {
		inside = append(inside, p)
	}
	sort.Strings(inside)
	if len(inside) > 1 || (len(inside) == 1 && inside[0] != proj) {
		t.Errorf("~/.claude.json inside names projects %v, want at most the target %q. The "+
			"host's file pre-accepted Claude Code's trust prompt for every project path on "+
			"the machine, whichever of them the payload cd'd to; snug's may carry the host's "+
			"answer for the one directory given on the command line and no other.",
			inside, proj)
	}
}

// hostProjectPaths returns the absolute project paths in the REAL host's
// ~/.claude.json — the actual inventory, not a fixture. A fixture would prove
// the generator ignores a file it never reads; this proves THIS machine's list
// of projects is not inside the sandbox.
//
// Paths that overlap the sandbox's own grants are dropped rather than
// exempted: the target and its parent are legitimately visible inside (that is
// what @cwd-rw and @parent-ro are), and $HOME exists inside as a fresh tmpfs,
// so any of the three would break the reachability control for reasons that
// have nothing to do with the inventory.
func hostProjectPaths(t *testing.T, target string) []string {
	t.Helper()
	home := os.Getenv("HOME")
	b, err := os.ReadFile(filepath.Join(home, ".claude.json"))
	if err != nil {
		t.Skipf("no host ~/.claude.json (%v), so there is no inventory to look for. This "+
			"is skipped rather than failed even under SNUG_REQUIRE_SANDBOX: \"can this host "+
			"run sandboxes\" and \"has this human ever run Claude Code\" are different "+
			"questions", err)
	}
	var doc struct {
		Projects map[string]json.RawMessage `json:"projects"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Skipf("the host's ~/.claude.json did not parse (%v)", err)
	}

	parent := filepath.Dir(target)
	var out []string
	for p := range doc.Projects {
		if !filepath.IsAbs(p) || len(p) < 8 {
			continue // a relative or trivially short key would match anything
		}
		if p == home || under(p, target) || under(target, p) || under(p, parent) {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// under reports whether p is a or lies beneath it.
func under(p, a string) bool {
	return p == a || strings.HasPrefix(p, strings.TrimSuffix(a, "/")+"/")
}

// shQuote wraps s for bash. Host project paths are arbitrary filenames and one
// containing a quote would otherwise turn the probe into a different script.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
