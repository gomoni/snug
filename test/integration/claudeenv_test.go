//go:build integration

package integration

import (
	"strings"
	"testing"
)

// TestClaudeInheritsAPagerAndNeitherEditorVariable is issue #530 inside a
// real sandbox.
//
// git's exec class reaches the sandbox by fallback — GIT_EDITOR -> core.editor
// -> VISUAL -> EDITOR, and GIT_PAGER -> core.pager -> PAGER — so inheriting
// the generic name hands git the HOST's command string. @claude inherits
// PAGER and neither editor variable, on purpose: an inherited EDITOR would
// name a program this sandbox does not have (the host's editor is not bound),
// so `git commit` fails identically with the variable set and without it,
// while PAGER names `less`, which @sys's /usr does carry.
//
// internal/cli/testdata/env.claude.txt is the golden that pins the ENVIRONMENT
// block for this selection, and TestDryRunEnvironmentBlockAccountsForEveryName
// Inside proves the block and the sandbox agree on every name. Those two
// together are the design; this is the fact, and it costs one sandbox start:
// a screen and a payload measured against the SAME three host values.
//
// ALL THREE ARE SET ON THE HOST SIDE HERE, which is what makes the two
// negatives mean anything — "EDITOR is unset inside" is trivially true of a
// caller that never set it. PAGER is the control in the same breath: it
// proves the inherit mechanism is working on this very invocation, so
// EDITOR's and VISUAL's absence is @claude's choice rather than a sandbox
// that inherited nothing at all.
//
// WHETHER AN EDITOR IS REACHABLE BY NAME inside is deliberately not asserted.
// @sys binds the host's /usr wholesale, so `command -v vim` answers a
// question about this host's packages, not about @claude — which sets no
// EDITOR pointing at one either way.
func TestClaudeInheritsAPagerAndNeitherEditorVariable(t *testing.T) {
	budget(t)
	requireSandbox(t)
	proj, _ := target(t)

	env := baseEnv("EDITOR=vim", "VISUAL=vi", "PAGER=less")
	r := runEnv(t, env, []string{"-p", "@claude"}, proj, `
		echo "EDITOR=${EDITOR-unset} VISUAL=${VISUAL-unset} PAGER=${PAGER-unset}"
		command -v less >/dev/null && echo LESS-RESOLVES || echo NO-LESS`).mustRun(t)

	if !strings.Contains(r.out, "PAGER=less") {
		t.Errorf("@claude did not inherit PAGER as the host set it, so the two negatives below "+
			"would be about a sandbox that inherited nothing:\n%s", r.out)
	}
	if !strings.Contains(r.out, "EDITOR=unset") {
		t.Errorf("@claude leaked the host's EDITOR into the sandbox, where it names a program "+
			"that is not bound (issue #530):\n%s", r.out)
	}
	if !strings.Contains(r.out, "VISUAL=unset") {
		t.Errorf("@claude leaked the host's VISUAL into the sandbox (issue #530):\n%s", r.out)
	}

	// Not an assertion on @claude: a host whose /usr has no less is a host
	// where PAGER names nothing, which is worth saying out loud and is not a
	// defect in the profile.
	if strings.Contains(r.out, "NO-LESS") {
		t.Logf("PAGER=less was inherited but `less` does not resolve inside — this host's /usr " +
			"carries no less, so the inherited value names no command here")
	}
}
