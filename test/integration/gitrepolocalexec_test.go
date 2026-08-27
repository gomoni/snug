//go:build integration

package integration

import (
	"strings"
	"testing"
)

// TestGitExecutesRepoLocalConfigWithGeneratedIdentity RE-MEASURES (rather than
// assumes) that a payload-authored `.git/hooks/pre-push` AND a payload-set
// `core.fsmonitor` both run inside the sandbox, and both see the identity
// snug's own extractor generated.
//
// This is git working exactly as designed and is NOT a snug defect — the
// target directory is granted read-write by @cwd-rw, and a hook or fsmonitor
// program living inside it is no different in kind from `make` or `npm
// install` running arbitrary code there (T3/T4 in the threat model). It is
// pinned because it rules out argv/value filtering — the whitelist
// extractGitConfig applies to ~/.gitconfig — as any kind of boundary for a
// git-touching tool: the repository itself, which snug never filters at all,
// can run whatever it likes the moment `git status` or `git push` is invoked
// against it, with the same git identity every other command in the sandbox
// has.
func TestGitExecutesRepoLocalConfigWithGeneratedIdentity(t *testing.T) {
	requireSandbox(t)
	budget(t)

	// gitFixture + gitExtractEnv (gitconfig_test.go) build a global config
	// with a `gitdir:` include that fires only for `matching`, so the email
	// visible inside the sandbox is snug's GENERATED identity, not something
	// this test hardcodes into the repo.
	globalFile, matching, _ := gitFixture(t)
	env := gitExtractEnv(t, globalFile)

	script := `
mkdir -p .git/hooks
cat > .git/hooks/pre-push <<'HOOK'
#!/bin/sh
echo "PRE-PUSH-RAN email=$(git config user.email)"
exit 0
HOOK
chmod +x .git/hooks/pre-push

cat > fsmonitor.sh <<'FSM'
#!/bin/sh
echo "FSMONITOR-RAN email=$(git config user.email)" >> "$(git rev-parse --show-toplevel)/fsm-marker"
printf '\n'
FSM
chmod +x fsmonitor.sh
git config core.fsmonitor "$(pwd)/fsmonitor.sh"

git init -q --bare remote.git
echo payload-authored > file
git add file
git commit -q -m payload-authored

git status >/dev/null 2>&1
echo "FSM-MARKER: $(cat fsm-marker 2>&1)"
git push -q ./remote.git HEAD:refs/heads/main
`
	r := runEnv(t, env, []string{"-p", "gitex"}, matching, script).mustRun(t)

	// POSITIVE CONTROL: the generated identity really is what git sees inside
	// the sandbox at all — the whitelist extraction worked and the gitdir
	// condition fired. Without this, "the hook saw the generated email" would
	// be equally true of a sandbox with no git identity and an empty
	// substitution.
	if !strings.Contains(r.out, "email=included@example.invalid") {
		t.Fatalf("no generated identity (included@example.invalid) appears anywhere in the "+
			"payload's output, so this test cannot tell whether the hooks below ran under "+
			"it or under nothing at all:\n%s", r.out)
	}

	if !strings.Contains(r.out, "FSMONITOR-RAN email=included@example.invalid") {
		t.Errorf("core.fsmonitor, set from inside the repository, did NOT run under the "+
			"sandbox's generated git identity — either it did not run at all, or it ran "+
			"without the identity every other git command in the sandbox has:\n%s", r.out)
	}
	if !strings.Contains(r.out, "PRE-PUSH-RAN email=included@example.invalid") {
		t.Errorf("a repo-local .git/hooks/pre-push, authored by the payload, did NOT run "+
			"under the sandbox's generated git identity during `git push` — either the hook "+
			"did not execute, or it executed without that identity:\n%s", r.out)
	}
}
