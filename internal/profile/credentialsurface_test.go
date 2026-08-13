package profile

import (
	"strings"
	"testing"
)

// NO BUILTIN PROFILE MAY GRANT A PATH THAT CARRIES CREDENTIALS OR NAMES PROGRAMS
// TO RUN. There is no allowlist, no declared-exception table and no flag: a
// builtin that trips this test is wrong, and the fix is to generate the file
// instead of binding it.
//
// Written because `@git-ro` shipped for a milestone binding `~/.gitconfig`
// read-only, and no review caught it. The abuse comment on that profile was
// present and honest as far as it went — "any secrets you unwisely put in
// ~/.gitconfig" — and it still missed the point twice over:
//
//   - the file is a COMMAND TABLE, not a data file with secrets in it.
//     credential.helper, alias.x = !cmd, core.pager, core.sshCommand,
//     diff.*.textconv and filter.*.clean/smudge all name programs for git to
//     run. A read-only bind does not stop that; it supplies it.
//   - "unwisely put in" reads as the user's mistake. It is not: those keys are
//     what the file is FOR.
//
// The process failure is the reusable part. The abuse sentence was written once,
// at authoring time, and nothing re-read it as identity, GIT_CONFIG_GLOBAL and
// credential staging grew around it. A comment cannot fail; this test can.
//
// It governs BUILTINS ONLY, and that boundary is the design rather than a
// weakening. A human writing `ro = ["{home}/.gitconfig"]` in their own
// profiles.d is making a declaration about their own machine — invariant 3 puts
// that decision outside the sandboxed material, which is exactly where it
// belongs. What must never happen is snug SHIPPING that decision on everyone's
// behalf.
func TestNoBuiltinGrantsACredentialOrCommandTablePath(t *testing.T) {
	reg, err := Builtins()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for name, p := range reg {
		for _, g := range append(append([]string{}, p.RO...), p.RW...) {
			// A grant may be `host:guest`; the host side is what is read.
			host := g
			if i := strings.Index(g, ":"); i > 0 {
				host = g[:i]
			}
			if why := sensitiveHostPath(host); why != "" {
				found = true
				t.Errorf("builtin profile %q grants %s — %s.\n"+
					"There is no exception list for this. Generate the file from the resolved "+
					"policy and point the tool at it with its own env var (GIT_CONFIG_GLOBAL, "+
					"GH_CONFIG_DIR, NPM_CONFIG_USERCONFIG, …), the way @git-ro and the identity "+
					"band do — a bind carries every unrelated thing in the file, and for a "+
					"command table it supplies the commands rather than stopping them.",
					name, host, why)
			}
		}
	}
	if found {
		t.Log("if the grant is genuinely needed and genuinely safe, the catalogue in " +
			"sensitiveHostPath is what to argue with — in a diff, with the reason written down.")
	}
}

// sensitiveHostPath classifies a grant's host side, returning why it is refused
// or "" if it is ordinary.
//
// Two classes, deliberately not separated in the verdict because the mitigation
// is the same one: generate, do not bind.
//
//	CREDENTIAL   the file IS the secret, or points straight at it
//	COMMAND      the file names programs for a tool to execute
//
// Matching is on the path's tail, after `{home}`/`~` expansion, so it catches
// the same file wherever a profile spells it from.
func sensitiveHostPath(p string) string {
	p = strings.TrimPrefix(strings.TrimPrefix(p, "{home}"), "~")
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, "/")

	for _, c := range []struct{ path, why string }{
		// Key material and tokens.
		{".ssh", "CREDENTIAL: private keys"},
		{".gnupg", "CREDENTIAL: private keys"},
		{".aws", "CREDENTIAL: cloud keys"},
		{".config/gcloud", "CREDENTIAL: cloud tokens"},
		{".kube", "CREDENTIAL: cluster tokens"},
		{".docker", "CREDENTIAL: registry tokens"},
		{".netrc", "CREDENTIAL: passwords in plaintext"},
		{".pgpass", "CREDENTIAL: passwords in plaintext"},
		{".my.cnf", "CREDENTIAL: passwords in plaintext"},
		{".git-credentials", "CREDENTIAL: git passwords in plaintext"},
		{".config/gh", "CREDENTIAL: GitHub OAuth token"},
		{".config/hub", "CREDENTIAL: GitHub OAuth token"},
		{".cargo/credentials", "CREDENTIAL: registry token"},
		{".cargo/credentials.toml", "CREDENTIAL: registry token"},
		{".pypirc", "CREDENTIAL: registry token"},
		{".claude/.credentials.json", "CREDENTIAL: API token"},
		{".claude.json", "CREDENTIAL: carries MCP config and account state"},
		{".local/share/keyrings", "CREDENTIAL: the desktop keyring"},
		{".mozilla", "CREDENTIAL: saved passwords and cookies"},
		{".config/chromium", "CREDENTIAL: saved passwords and cookies"},
		{".config/google-chrome", "CREDENTIAL: saved passwords and cookies"},
		// Command tables: config files whose keys name programs to run.
		{".gitconfig", "COMMAND TABLE: credential.helper, alias = !cmd, core.pager, textconv"},
		{".config/git", "COMMAND TABLE: the same keys as ~/.gitconfig, in git's other global file"},
		{".npmrc", "COMMAND TABLE: registry auth tokens, and script hooks"},
		{".bashrc", "COMMAND TABLE: runs on every shell"},
		{".bash_profile", "COMMAND TABLE: runs on every login shell"},
		{".profile", "COMMAND TABLE: runs on every login shell"},
		{".zshrc", "COMMAND TABLE: runs on every shell"},
		{".config/fish", "COMMAND TABLE: runs on every shell"},
		{".config/nvim", "COMMAND TABLE: editor config executes on open"},
		{".vimrc", "COMMAND TABLE: editor config executes on open"},
		{".config/containers", "COMMAND TABLE: names the runtime binaries an engine executes"},
	} {
		if p == c.path || strings.HasPrefix(p, c.path+"/") {
			return c.why
		}
	}
	return ""
}

// The catalogue is only worth what its positive control proves: a predicate that
// silently stopped matching would leave the test above passing on a policy that
// hands over ~/.ssh.
func TestTheCredentialCatalogueActuallyMatches(t *testing.T) {
	for _, spelling := range []string{
		"{home}/.ssh", "~/.ssh", "{home}/.ssh/id_ed25519", "{home}/.gitconfig",
		"{home}/.config/gh", "{home}/.aws/credentials", "{home}/.local/share/keyrings",
	} {
		if why := sensitiveHostPath(spelling); why == "" {
			t.Errorf("the catalogue does not recognise %q; every grant would pass this "+
				"test for the wrong reason", spelling)
		}
	}
	// And it must not fire on the ordinary grants the builtins really make, or
	// the next person deletes it instead of fixing what it caught.
	for _, ordinary := range []string{
		"/usr", "/etc/passwd", "{home}/.local/bin/claude", "{home}/.claude/skills",
		"{home}/.claude/settings.json", "{home}/.local/share/claude", "{target}",
		"/etc/containers",
	} {
		if why := sensitiveHostPath(ordinary); why != "" {
			t.Errorf("the catalogue fires on %q (%s), which is an ordinary grant", ordinary, why)
		}
	}
}
