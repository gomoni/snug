package profile

import (
	"os"
	"path/filepath"
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
// The catalogue has two halves, because the matching rule differs. The
// home-rooted half below matches on the path's tail, after `{home}`/`~`
// expansion, so it catches the same file wherever a profile spells it from. The
// absolute half (systemCommandTables) matches on the whole path, because
// `/etc/passwd` must stay ordinary while `/etc/gitconfig` must not.
func sensitiveHostPath(p string) string {
	// The absolute half runs FIRST, and on the path as written. The
	// normalisation below is home-rooted by construction — it strips $HOME,
	// `{home}` and `~`, cleans, then throws the leading slash away, so
	// `/etc/gitconfig` reaches the catalogue as `etc/gitconfig` and no entry
	// there can name it. A builtin granting git's system config, or Claude
	// Code's managed settings, therefore passed this whole file (issue #170):
	// a hole in the check, not in the product.
	if why := sensitiveSystemPath(p); why != "" {
		return why
	}

	// Normalise every spelling a profile can legally write, because the first
	// version compared raw TOML text and an independent review walked straight
	// through it: `{home}//.ssh`, `{home}/./.ssh`, `{home}/.config/../.ssh` and
	// the absolute `/home/<user>/.ssh` all returned "ordinary".
	if home, err := os.UserHomeDir(); err == nil && home != "/" {
		p = strings.TrimPrefix(p, home)
	}
	p = strings.TrimPrefix(strings.TrimPrefix(p, "{home}"), "~")
	p = filepath.Clean("/" + p)
	p = strings.TrimPrefix(p, "/")
	if p == "." {
		p = ""
	}

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
		{".claude/settings.json", "COMMAND TABLE: hooks, apiKeyHelper, statusLine, env, mcpServers, enabledPlugins — keys that name programs to run or code to load"},
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
		switch {
		// The grant IS the path, or is inside it.
		case p == c.path, strings.HasPrefix(p, c.path+"/"):
			return c.why
		// The grant is an ANCESTOR of it, which is the direction the first
		// version missed entirely: a builtin granting `{home}/.claude` passed a
		// test whose `.claude/.credentials.json` entry exists precisely to stop
		// that, and `{home}` itself passed everything.
		case p == "" || strings.HasPrefix(c.path, p+"/"):
			return c.why + " (reached through an ancestor grant)"
		}
	}
	return ""
}

// systemCommandTables is the absolute-path half of the catalogue: files OUTSIDE
// $HOME that name programs for a tool to run.
//
// Every entry is a command table at its tool's MOST PRIVILEGED scope, which is
// why the list is not the home-rooted one with a prefix swapped. System scope is
// read with no flag, is read BEFORE the user's own file, and for Claude Code it
// is the one scope whose hooks still run when `allowManagedHooksOnly` is set
// (CLAUDE-SETTINGS.md §1.4). A read-only bind of any of them supplies the
// commands rather than stopping them, which is the whole lesson of `~/.gitconfig`.
//
// What is deliberately NOT here, both decisions rather than oversights:
//
//   - `/etc/containers`, which `@podman-build` really does grant read-only and
//     which the ordinary list below asserts. It names the runtime binaries an
//     engine executes, exactly as `~/.config/containers` does, so by this file's
//     own definition it belongs — and adding it would fail the build today, with
//     no generator for an engine config tree to point the fix at. Whether that
//     grant should exist is a product question, not a test's to decide: the same
//     position `{home}/.claude/plugins` is in (issue #68).
//   - `/etc/ssl`, `/etc/pki` and `/etc/crypto-policies`, which `@sys` grants and
//     without which TLS does not work at all. A weaker version of the same
//     argument reaches openssl.cnf, which can name provider and engine modules;
//     that is worth its own measurement rather than a line smuggled in here.
//
// Ordering is load-bearing in one place: the specific `/etc/claude-code/…`
// entries come BEFORE the catch-all on the directory itself, so each reports its
// own reason instead of the generic one.
var systemCommandTables = []struct{ path, why string }{
	{"/etc/gitconfig", "COMMAND TABLE: git's SYSTEM config — credential.helper, alias = !cmd, core.pager, core.sshCommand, textconv, read before ~/.gitconfig and with no flag"},

	// Claude Code's managed scope. Measured against the 2.1.235 bundle on this
	// host: `/etc/claude-code` is the managed root on every platform that is
	// not macOS or Windows, and each path below is joined onto it in the binary.
	{"/etc/claude-code/managed-settings.json", "COMMAND TABLE: managed settings — policyHelper, processWrapper, hooks, apiKeyHelper, env, mcpServers, at the one scope whose hooks still run under allowManagedHooksOnly"},
	{"/etc/claude-code/managed-settings.d", "COMMAND TABLE: the managed-settings drop-in directory, merged with the same keys"},
	{"/etc/claude-code/managed-mcp.json", "COMMAND TABLE: enterprise MCP servers, and every entry names a program to launch"},
	{"/etc/claude-code/CLAUDE.md", "COMMAND TABLE: managed-scope instructions loaded into every session inside the sandbox"},
	{"/etc/claude-code/.claude", "COMMAND TABLE: the managed customization tree — rules, skills, agents and commands are all joined onto this directory"},
	{"/etc/claude-code", "COMMAND TABLE: the managed-scope root; a grant of the directory is a grant of every managed file written into it later (issue #140)"},

	{"/etc/npmrc", "COMMAND TABLE: npm's global config — registry auth tokens, node-options, and the script keys npm executes"},
	{"/etc/ssh/ssh_config", "COMMAND TABLE: ssh's system client config — ProxyCommand, LocalCommand, Match exec, IdentityAgent"},

	// The files base.toml names as the reason `/etc` is ENUMERATED rather than
	// bound: they are EXECUTED by every shell in the sandbox, so binding one
	// injects host-controlled code into every run. The spelling varies by
	// distribution, and the list errs towards carrying all of them — an entry
	// for a path this host does not have costs nothing and fires on the host
	// that does.
	{"/etc/profile", "COMMAND TABLE: runs in every login shell in the sandbox"},
	{"/etc/profile.d", "COMMAND TABLE: every script in it runs in every login shell"},
	{"/etc/bash.bashrc", "COMMAND TABLE: runs in every bash shell (the Debian and SUSE spelling)"},
	{"/etc/bashrc", "COMMAND TABLE: runs in every bash shell (the Fedora and RHEL spelling)"},
	{"/etc/zsh", "COMMAND TABLE: zsh's system config DIRECTORY — zshenv, zshrc and zprofile all live in it on Debian and Arch"},
	{"/etc/zshrc", "COMMAND TABLE: runs in every interactive zsh (the flat spelling)"},
	{"/etc/zshenv", "COMMAND TABLE: runs in every zsh, login or not"},
}

// sensitiveSystemPath classifies an absolute grant against systemCommandTables.
//
// It does no `{home}`/`~` expansion on purpose: a grant spelled that way is the
// home-rooted half's business, and one spelled neither way is not a system path
// at all (`{target}`, and any relative spelling). `/` is not special-cased here
// — it falls through to the home-rooted half, where the empty-path case already
// fires on everything.
func sensitiveSystemPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		return ""
	}
	p = filepath.Clean(p)
	for _, c := range systemCommandTables {
		switch {
		// The grant IS the path, or is inside it.
		case p == c.path, strings.HasPrefix(p, c.path+"/"):
			return c.why
		// The ancestor direction, which the home-rooted half took two attempts
		// to get right: granting `/etc` hands over every file in it, and
		// granting `/etc/claude-code` hands over the managed scope entire.
		case strings.HasPrefix(c.path, p+"/"):
			return c.why + " (reached through an ancestor grant)"
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
		"{home}/.claude/settings.json",
		// Spellings an independent review walked straight through. The first
		// version compared raw TOML text, so every one of these read as ordinary.
		"{home}//.ssh", "{home}/./.ssh", "{home}/.config/../.ssh", "{home}/.ssh/",
		// And the ANCESTOR direction, which it missed entirely: granting the
		// parent of a catalogued path hands over the path.
		"{home}", "{home}/", "{home}/.config", "{home}/.cargo",
	} {
		if why := sensitiveHostPath(spelling); why == "" {
			t.Errorf("the catalogue does not recognise %q; every grant would pass this "+
				"test for the wrong reason", spelling)
		}
	}

	// The absolute half (issue #170). Every entry in systemCommandTables is
	// spelled out here BY HAND rather than derived from the catalogue: a control
	// generated from the thing it controls proves only that `p == c.path`
	// compares equal, which is the "test that cannot fail" this file exists to
	// avoid. The guard below then makes forgetting one an error.
	//
	// `probe` is the path actually passed to the predicate, and it differs from
	// `path` for exactly one entry: `/etc/claude-code` is an ANCESTOR of the
	// four specific entries above it, so probing the directory itself reports
	// the first of those with "(reached through an ancestor grant)" — correct
	// behaviour, and useless as proof that the catch-all line exists. The probe
	// that only the catch-all can answer is a file under it that nothing else
	// names, which is also the case the entry is FOR (issue #140).
	systemSpellings := []struct{ path, probe, want string }{
		{path: "/etc/gitconfig", want: "git's SYSTEM config"},
		{path: "/etc/claude-code/managed-settings.json", want: "policyHelper"},
		{path: "/etc/claude-code/managed-settings.d", want: "drop-in directory"},
		{path: "/etc/claude-code/managed-mcp.json", want: "enterprise MCP servers"},
		{path: "/etc/claude-code/CLAUDE.md", want: "managed-scope instructions"},
		{path: "/etc/claude-code/.claude", want: "managed customization tree"},
		{path: "/etc/claude-code", probe: "/etc/claude-code/whatever-the-next-release-adds.json", want: "the managed-scope root"},
		{path: "/etc/npmrc", want: "npm's global config"},
		{path: "/etc/ssh/ssh_config", want: "ssh's system client config"},
		{path: "/etc/profile", want: "runs in every login shell"},
		{path: "/etc/profile.d", want: "every script in it runs"},
		{path: "/etc/bash.bashrc", want: "Debian and SUSE spelling"},
		{path: "/etc/bashrc", want: "Fedora and RHEL spelling"},
		{path: "/etc/zsh", want: "system config DIRECTORY"},
		{path: "/etc/zshrc", want: "the flat spelling"},
		{path: "/etc/zshenv", want: "login or not"},
	}
	// The reason is asserted, not merely non-emptiness, and that is what makes
	// this a control per ENTRY rather than per catalogue. Four of the paths
	// above sit under `/etc/claude-code`, whose own catch-all entry would match
	// them if the specific line were deleted — so "it still fires" proves
	// nothing about the line the diff touched, while "it still fires with THIS
	// reason" does.
	for _, tc := range systemSpellings {
		probe := tc.probe
		if probe == "" {
			probe = tc.path
		}
		why := sensitiveHostPath(probe)
		if why == "" {
			t.Errorf("the catalogue does not recognise %q; a builtin granting a command "+
				"table outside $HOME would pass this test for the wrong reason", probe)
			continue
		}
		if !strings.Contains(why, tc.want) {
			t.Errorf("%q matched %q, which is not the %s entry (expected one mentioning "+
				"%q). A path covered only by a broader entry is a catalogue line nothing "+
				"proves", probe, why, tc.path, tc.want)
		}
	}
	for _, spelling := range []string{
		// Inside a catalogued directory, which is how the managed customization
		// tree is actually reached: `/etc/claude-code/.claude/rules` and
		// `.../skills` are both joined onto it in the 2.1.235 bundle.
		"/etc/claude-code/managed-settings.d/10-org.json",
		"/etc/claude-code/.claude/rules",
		"/etc/claude-code/.claude/skills",
		"/etc/profile.d/anything.sh",
		// The spellings an independent review walked through on the home half.
		"/etc/gitconfig/", "//etc/gitconfig", "/etc/./gitconfig", "/etc/ssl/../gitconfig",
		// And the ancestor direction: granting the parent hands over the path.
		// `/` is here because sensitiveSystemPath deliberately does not handle
		// it and the home-rooted half must — a refactor that broke that seam
		// would otherwise be silent.
		"/etc", "/etc/", "/etc/ssh", "/",
	} {
		if why := sensitiveHostPath(spelling); why == "" {
			t.Errorf("the catalogue does not recognise %q; a builtin granting a command "+
				"table outside $HOME would pass this test for the wrong reason", spelling)
		}
	}

	// A control on the control. An entry added to systemCommandTables without a
	// literal spelling above is a catalogue line nothing proves, and it would
	// look exactly like a covered one.
	covered := map[string]bool{}
	for _, tc := range systemSpellings {
		covered[tc.path] = true
	}
	for _, c := range systemCommandTables {
		if !covered[c.path] {
			t.Errorf("%s is in systemCommandTables with no literal positive control in "+
				"systemSpellings, so nothing proves the catalogue matches it", c.path)
		}
	}

	// And it must not fire on the ordinary grants the builtins really make, or
	// the next person deletes it instead of fixing what it caught.
	//
	// `{home}/.claude/settings.json` is now IN the catalogue above (issue #17):
	// `@claude` no longer binds it at all — the file the sandbox sees is
	// GENERATED from an allowlist of scalar preferences (policy.FilterClaudeSettings,
	// internal/cli/claude.go's stageClaudeSettings) — so the catalogue entry can never
	// fire on a real builtin grant; it stands as a permanent regression test
	// against the path ever being bound again.
	//
	// `{home}/.claude/plugins`, which `@claude` DOES still bind read-only, is
	// deliberately in NEITHER list. It is not "ordinary" — a plugin manifest
	// carries its own `hooks` block that Claude Code loads automatically
	// (CLAUDE-SETTINGS.md §4.4, measured), which is a COMMAND TABLE by this
	// file's own definition — but adding it to the catalogue above would fail
	// the build immediately, since there is no generator for a plugin tree, the
	// same situation the settings.json entry was in before this fix landed. The
	// omission is a decision, not an oversight: see
	// https://github.com/gomoni/snug/issues/68. `{home}/.claude/skills` stays
	// asserted ordinary below — a skill is model-mediated and tool-gated, a
	// plugin hook is not, and the two must not be conflated.
	//
	// The `/etc` entries below are the ones `@sys` really enumerates plus the
	// `/etc/containers` `@podman-build` grants, and they are the negative
	// control on the absolute half: a rule that fired on `/etc/passwd` or
	// `/etc/ssl` would take the whole builtin set down with it.
	for _, ordinary := range []string{
		"/usr", "/usr/bin", "/etc/passwd", "{home}/.local/bin/claude", "{home}/.claude/skills",
		"{home}/.local/share/claude", "{target}", "/etc/containers",
		"/etc/group", "/etc/nsswitch.conf", "/etc/localtime", "/etc/os-release",
		"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives",
		"/etc/ssl", "/etc/pki", "/etc/ca-certificates", "/etc/ca-certificates.conf",
		"/etc/crypto-policies", "/etc/resolv.conf",
	} {
		if why := sensitiveHostPath(ordinary); why != "" {
			t.Errorf("the catalogue fires on %q (%s), which is an ordinary grant", ordinary, why)
		}
	}
}
