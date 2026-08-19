package policy

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// InterpretedClass says WHY a path in InterpretedPaths is hazardous to hand
// over, even read-only.
type InterpretedClass uint8

const (
	// ClassCommandTable: a key in the file names a program the tool will run.
	// Read-only does not stop that — it SUPPLIES it.
	ClassCommandTable InterpretedClass = iota
	// ClassCredential: the file IS the secret, or points straight at it.
	ClassCredential
)

func (c InterpretedClass) String() string {
	switch c {
	case ClassCommandTable:
		return "COMMAND TABLE"
	case ClassCredential:
		return "CREDENTIAL"
	default:
		return "UNKNOWN"
	}
}

// InterpretedPath is one row of the catalogue below. See InterpretedPaths'
// doc comment for what the fields mean and what they may never be used for.
type InterpretedPath struct {
	// Path is either an absolute host path ("/etc/gitconfig") or a $HOME tail
	// with no leading "/", "{", or "~" (".ssh"). Scope is derived from this —
	// strings.HasPrefix(Path, "/") — deliberately not a separate field: a
	// field lets a row's two halves disagree.
	Path string
	// Class is the WORSE of the two when a file is arguably both.
	Class InterpretedClass
	// Tool is the program that interprets the file. Required on every row.
	Tool string
	// Reads is the clause completing "Tool reads this as ___". Required for a
	// SYSTEM row (Path starts with "/"); optional for a promoted home row —
	// the mark drops the clause when it is empty rather than shipping an
	// invented claim for every one of them. See homeInterpretedPaths.
	Reads string
	// Keys names the specific keys or content that make the file hazardous.
	// Required; kept to <=60 characters so one mark fits wrapMark's 3-line
	// budget (screenWidth in internal/cli/dryrun.go) — anything longer belongs
	// in Evidence instead.
	Keys string
	// Evidence is how the row was established. Required. It renders ONLY into
	// testdata/interpreted-paths.txt, never onto a screen a user runs snug to
	// see — see the package doc comment on InterpretedPaths for why a
	// catalogue like this must say what is measured and what is not.
	Evidence string
}

// InterpretedSide says which half of a grant a hit was found on: the guest
// path the sandbox will see, or the host path a bind reads from.
type InterpretedSide uint8

const (
	SideGuest InterpretedSide = iota
	SideHost
)

// InterpretedMatch says how a candidate path relates to a catalogued row.
type InterpretedMatch uint8

const (
	// MatchExact: the candidate IS the row.
	MatchExact InterpretedMatch = iota
	// MatchInside: the candidate is strictly inside the row (the row is a
	// directory and the candidate names something under it).
	MatchInside
	// MatchAncestor: the candidate is a strict ancestor of the row (the row is
	// somewhere under a directory the candidate names). Suppressed for
	// BroadHostTrees and collapsed to one mark everywhere else.
	MatchAncestor
)

// InterpretedHit is one row matched against one candidate path, tagged with
// which side of a grant produced it and how.
type InterpretedHit struct {
	Row   InterpretedPath
	Side  InterpretedSide
	Match InterpretedMatch
}

// BroadHostTrees suppresses the ancestor direction. Root-owned distribution
// package content: a different trust class, the same one
// nestedcommandtable_test.go excludes, and the trees @sys grants on EVERY
// default run. Marking them puts a COMMAND TABLE line on `ro /usr` forever,
// which is how a reader learns to skip marks.
//
// /etc is deliberately NOT here: no builtin grants it (@sys enumerates fourteen
// entries instead of binding all 109, invariant 2), and a profile granting all
// of /etc really does supply /etc/gitconfig.
var BroadHostTrees = []string{"/", "/usr", "/opt"}

// InterpretedPaths is a NAMED CATALOGUE of paths whose content a tool
// INTERPRETS: either the file IS a secret (ClassCredential) or some key in it
// names a program the tool will execute (ClassCommandTable). Read-only does not
// demote the second into the first — it stops the sandbox *editing* the file and
// supplies every command in it.
//
// IT IS NOT A FILTER AND MUST NEVER BECOME ONE. No refusal may read it: not
// Validate, not Resolve, not rejectMasking, not the sanitise filter, not the
// container proxy's bind filter. A user profile granting one of these is a human's
// declaration about their own machine — invariant 3 puts that decision outside the
// sandboxed material, and #44 settled that snug discloses rather than refuses.
// TestInterpretedPathsIsNeverConsultedByARefusal is what keeps that true; the
// comment alone has never kept anything true.
//
// It exists for three things: the mark on --dry-run's FILESYSTEM block, the
// mark on `snug profile show`, and internal/profile's builtin sweep. The first
// two fail open on incompleteness — a missing row is a missing sentence, never a
// widened sandbox. The third is a gate, and it fails open too: a builtin
// granting an uncatalogued interpreted path passes. Acceptable only because its
// input is snug's own shipped profiles, changed by a human in a reviewed diff —
// unlike ClaudeExecutingKeys, whose input is a host file plus whatever upstream
// adds next release, where one spelling (additionalMarketplaces) defeats a
// denylist with no attacker required. Never read the sweep's silence as proof
// that a builtin grants nothing hazardous.
//
// The trust-class boundary is what keeps this table finite. A row is a file
// the HOST USER or an administrator authors. Files the distribution's package
// manager owns are excluded even when they name programs, because "command
// table" applied without this boundary sweeps in half of @sys. Named
// exclusions, so nobody thinks they were missed: /etc/containers
// (containers.conf names runtime, conmon_path, helper_binaries_dir,
// network_cmd_path; storage.conf names mount_program) — root-owned, granted
// read-only by @podman-socket, unwritable from inside, and every binary it
// names is itself under the /usr grant; /etc/nsswitch.conf; /etc/ld.so.conf,
// /etc/ld.so.conf.d; /etc/alternatives; /etc/crypto-policies;
// /usr/etc/bash.bashrc. Adding any of these is a change to a builtin's
// status, not a golden update: @podman-socket and @sys grant them today, so
// the sweep would fail the build.
//
// {home}/.claude/plugins is deliberately in neither this table nor the
// ordinary list. It IS a command table by this file's definition (a plugin
// manifest carries its own hooks block) and there is no generator for a
// plugin tree, so cataloguing it would fail the build immediately. The
// omission is issue #68, not an oversight.
//
// Measured entries only. Evidence is required on every row and renders into
// testdata/interpreted-paths.txt, never onto a screen. Adding a row means
// measuring it or writing "documented, not measured on this host". A
// whitelist is a security boundary and so is a disclosure catalogue: adding a
// row is a policy change; ask what the file makes the tool DO.
var InterpretedPaths = buildInterpretedPaths()

func buildInterpretedPaths() []InterpretedPath {
	rows := []InterpretedPath{
		{
			Path:  "/etc/gitconfig",
			Class: ClassCommandTable,
			Tool:  "git",
			Reads: "its system config, read with no flag",
			Keys:  "credential.helper, alias = !cmd, core.pager, core.sshCommand",
			Evidence: "measured: literal in /usr/libexec/git/git; named in " +
				"`git config --system`'s fatal error. git 2.55.0. No /usr/etc/gitconfig.",
		},
		{
			Path:  "/etc/claude-code/managed-settings.json",
			Class: ClassCommandTable,
			Tool:  "claude",
			Reads: "managed (enterprise) settings, read with no flag",
			Keys:  "policyHelper, hooks, mcpServers, apiKeyHelper, env",
			Evidence: "measured: 2.1.235 bundle, getManagedFilePath + " +
				"/etc/claude-code; literal x34. Full key list includes processWrapper too, " +
				"dropped from Keys here to fit the mark's 60-char budget. Reads text also " +
				"trimmed to fit the mark's 3-line budget; full text was \"managed (enterprise) " +
				"settings, the highest-precedence scope, read with no flag\" — the dropped " +
				"clause said it cannot be overridden by any other settings scope.",
		},
		{
			Path:  "/etc/claude-code/managed-settings.d",
			Class: ClassCommandTable,
			Tool:  "claude",
			Reads: "a drop-in directory merged into managed settings",
			Keys:  "policyHelper, hooks, mcpServers, apiKeyHelper, env",
			Evidence: "measured: literal x16 beside getDropInDir. Full key list includes " +
				"processWrapper too, dropped from Keys here to fit the mark's 60-char budget.",
		},
		{
			Path:     "/etc/claude-code/managed-mcp.json",
			Class:    ClassCommandTable,
			Tool:     "claude",
			Reads:    "managed MCP servers, read with no flag",
			Keys:     "mcpServers - each is a program with its own argv and env",
			Evidence: "measured: literal x11",
		},
		{
			Path:  "/etc/claude-code/CLAUDE.md",
			Class: ClassCommandTable,
			Tool:  "claude",
			Reads: "a managed instruction file prepended to the prompt",
			Keys:  "prose the MODEL executes: injection into a tool-using agent",
			Evidence: "documented, not measured as a path. Full phrasing this Keys text " +
				"was trimmed from: \"prose the MODEL executes - instruction injection into " +
				"a tool-enabled agent\". Reads text also trimmed to fit the mark's 3-line " +
				"budget; full text was \"a managed instruction file prepended to the system " +
				"prompt\".",
		},
		{
			Path:  "/etc/claude-code/.claude/rules",
			Class: ClassCommandTable,
			Tool:  "claude",
			Reads: "managed rule files loaded into the instructions",
			Keys:  "prose the MODEL executes: injection into a tool-using agent",
			Evidence: "documented, not measured - MEASURE OR KEEP THE MARKER. Full phrasing " +
				"this Keys text was trimmed from: \"prose the MODEL executes - instruction " +
				"injection into a tool-enabled agent\". Reads text also trimmed to fit the " +
				"mark's 3-line budget; full text was \"managed rule files loaded into the " +
				"agent's instructions\".",
		},
		// Ported from upstream PR #181's systemCommandTables (refs #170), whose
		// reasoning is kept below: the whole managed customization tree, broader
		// than the .claude/rules row above it (that row's own text stays for an
		// exact grant of just the rules directory — deepestInterpretedHits picks
		// whichever of the two a given grant actually names).
		{
			Path:  "/etc/claude-code/.claude",
			Class: ClassCommandTable,
			Tool:  "claude",
			Reads: "the managed customization tree",
			Keys:  "rules, skills, agents, commands - loaded automatically",
			Evidence: "upstream PR #181 claims this was measured against the 2.1.235 bundle " +
				"(\"rules and skills are both joined onto it\"); not independently re-measured " +
				"here — carries the same MEASURE OR KEEP THE MARKER uncertainty as the " +
				".claude/rules row above it, which this codebase already declined to mark " +
				"measured on the same evidence. Ported reasoning, verbatim: \"the managed " +
				"customization tree - rules, skills, agents and commands are all joined onto " +
				"this directory\". Reads text trimmed to fit the mark's 3-line budget; full text " +
				"was \"the managed customization tree, joined onto the managed root\".",
		},
		// The managed-scope ROOT — upstream PR #181's reasoning, cited verbatim
		// in Evidence: a grant of the directory is a grant of every managed file
		// written into it later (issue #140). Ordered last of the claude-code
		// group so the specific rows above it are what a human reads first; the
		// catch-all's own mark only wins when a grant names nothing more
		// specific (deepestInterpretedHits).
		{
			Path:  "/etc/claude-code",
			Class: ClassCommandTable,
			Tool:  "claude",
			Reads: "the managed-scope root",
			Keys:  "hooks, mcpServers, policyHelper - everything written below",
			Evidence: "measured: this is the same /etc/claude-code literal the managed-settings.json " +
				"row above already measured (getManagedFilePath, x34; getDropInDir, x16), just as " +
				"the root rather than a specific file under it. Ported reasoning from upstream PR " +
				"#181's systemCommandTables (refs #170), verbatim: \"the managed-scope root; a " +
				"grant of the directory is a grant of every managed file written into it later " +
				"(issue #140)\". Reads text trimmed to fit the mark's 3-line budget; full text was " +
				"\"the managed-scope root; every managed file lives beneath it\".",
		},
		{
			Path:  "/etc/npmrc",
			Class: ClassCommandTable,
			Tool:  "npm",
			Reads: "its GLOBAL config when npm's prefix is /",
			Keys:  "_auth/_authToken, script-shell, node-options, ignore-scripts",
			Evidence: "documented, not measured on this host. Full key list also includes " +
				"=false on ignore-scripts, dropped from Keys here to fit the mark's 60-char budget.",
		},
	}
	rows = append(rows, sshConfigRows()...)
	// /usr/etc/npmrc — npm's global config on a host whose prefix is /usr
	// (measured here), the twin of the /etc/npmrc row above (documented, not
	// measured on this host, since npm's prefix is /usr wherever it was
	// actually run).
	rows = append(rows, InterpretedPath{
		Path:  "/usr/etc/npmrc",
		Class: ClassCommandTable,
		Tool:  "npm",
		Reads: "its GLOBAL config, read with no flag",
		Keys:  "_auth/_authToken, script-shell, node-options, ignore-scripts",
		Evidence: "measured: `npm config get globalconfig`, prefix /usr; /etc/npmrc does not " +
			"exist here. Full key list also includes =false on ignore-scripts, dropped from " +
			"Keys here to fit the mark's 60-char budget. Reads text also trimmed to fit the " +
			"mark's 3-line budget; full text was \"its GLOBAL config ($prefix/etc/npmrc), " +
			"read with no flag\".",
	})
	rows = append(rows, shellStartupRows()...)
	rows = append(rows, homeInterpretedPaths()...)
	return rows
}

// shellStartupRows: the seven system shell-startup files, ported from
// upstream PR #181's systemCommandTables (refs #170) — we had none of these,
// and CLAUDE.md's own "Facts about this environment" section already
// documents the live consequence: `@sys` binds /etc, so every one of these
// runs inside the sandbox with whatever the host's package manager put in it.
// The spelling varies by distribution, and every row is carried regardless of
// whether it exists on this host, the same reasoning @sys already applies to
// its own /etc entries — an entry for a path this host lacks costs nothing
// and fires on the host that has it.
//
// None of these is under a path @sys enumerates (verified by running
// TestNoBuiltinGrantsACredentialOrCommandTablePath, not merely inferred from
// the enumerated list), so adding them does not fail the builtin sweep.
func shellStartupRows() []InterpretedPath {
	const inherited = "documented, not measured on this host. Ported from upstream PR #181's " +
		"systemCommandTables (refs #170)"
	return []InterpretedPath{
		{
			Path:  "/etc/profile",
			Class: ClassCommandTable,
			Tool:  "sh (and bash, as a login shell)",
			Reads: "its login-shell startup script",
			Keys:  "arbitrary shell commands, every login shell",
			Evidence: inherited + ": \"runs in every login shell in the sandbox\". Reads and Keys " +
				"trimmed to fit the mark's 3-line budget (this row's Tool text is itself long); full " +
				"text was \"the system-wide login-shell startup script, read before ~/.profile\" and " +
				"\"arbitrary shell commands, run on every login shell\".",
		},
		{
			Path:  "/etc/profile.d",
			Class: ClassCommandTable,
			Tool:  "sh (and bash, as a login shell)",
			Reads: "a drop-in directory /etc/profile sources",
			Keys:  "arbitrary shell commands, every login shell",
			Evidence: inherited + ": \"every script in it runs in every login shell\". Also the " +
				"live case CLAUDE.md documents: on this box distrobox_profile.sh re-derives " +
				"XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS from here after --clearenv. Reads and " +
				"Keys trimmed to fit the mark's 3-line budget; full text was \"a drop-in directory " +
				"whose scripts /etc/profile sources\" and \"arbitrary shell commands, run on every " +
				"login shell\".",
		},
		{
			Path:     "/etc/bash.bashrc",
			Class:    ClassCommandTable,
			Tool:     "bash",
			Reads:    "the system-wide bashrc (the Debian and SUSE spelling)",
			Keys:     "arbitrary shell commands, run in every bash shell",
			Evidence: inherited + ": \"runs in every bash shell (the Debian and SUSE spelling)\".",
		},
		{
			Path:     "/etc/bashrc",
			Class:    ClassCommandTable,
			Tool:     "bash",
			Reads:    "the system-wide bashrc (the Fedora and RHEL spelling)",
			Keys:     "arbitrary shell commands, run in every bash shell",
			Evidence: inherited + ": \"runs in every bash shell (the Fedora and RHEL spelling)\".",
		},
		{
			Path:  "/etc/zsh",
			Class: ClassCommandTable,
			Tool:  "zsh",
			Reads: "zsh's system config directory: zshenv, zshrc and zprofile",
			Keys:  "arbitrary shell commands, run in every zsh shell",
			Evidence: inherited + ": \"zsh's system config DIRECTORY - zshenv, zshrc and zprofile " +
				"all live in it on Debian and Arch\".",
		},
		{
			Path:  "/etc/zshrc",
			Class: ClassCommandTable,
			Tool:  "zsh",
			Reads: "the system zshrc (flat spelling)",
			Keys:  "arbitrary shell commands, run in every zsh shell",
			Evidence: inherited + ": \"runs in every interactive zsh (the flat spelling)\". Reads " +
				"trimmed to fit the mark's 3-line budget; full text was \"the system-wide zshrc " +
				"(the flat spelling), every interactive shell\".",
		},
		{
			Path:     "/etc/zshenv",
			Class:    ClassCommandTable,
			Tool:     "zsh",
			Reads:    "the system-wide zshenv, every zsh shell, login or not",
			Keys:     "arbitrary shell commands, run in every zsh shell",
			Evidence: inherited + ": \"runs in every zsh, login or not\".",
		},
	}
}

// sshConfigRows derives the two ssh_config rows from SystemSSHConfigPaths
// (TestEverySystemSSHConfigPathIsInterpreted is the drift guard) rather than
// retyping the paths — the two lists must never name different files.
func sshConfigRows() []InterpretedPath {
	meta := []struct{ tool, reads, evidence string }{
		{
			tool:  "ssh (and git over ssh)",
			reads: "the system client config, no flag, every host",
			evidence: "measured: already policy.SystemSSHConfigPaths[0]. Reads text trimmed " +
				"to fit the mark's 3-line budget; full text was \"the system-wide client " +
				"config, read with no flag, applying to every host\".",
		},
		{
			tool:  "ssh",
			reads: "the system client config for every host, no flag, moved from /etc",
			evidence: "measured: exists here, 3148 bytes; snug replaced it in a dry run. " +
				"Reads text trimmed to fit the mark's 3-line budget; full text was \"the " +
				"system-wide client config, read with no flag, applying to every host, " +
				"where vendor config moved out of /etc\".",
		},
	}
	out := make([]InterpretedPath, 0, len(SystemSSHConfigPaths))
	for i, path := range SystemSSHConfigPaths {
		m := meta[0]
		if i < len(meta) {
			m = meta[i]
		}
		out = append(out, InterpretedPath{
			Path:  path,
			Class: ClassCommandTable,
			Tool:  m.tool,
			Reads: m.reads,
			// IdentityAgent dropped from the on-screen Keys list to fit the
			// mark's 3-line budget (m.tool "ssh (and git over ssh)" already
			// spends 22 of it); it redirects agent-forwarding, not itself an
			// RCE the way ProxyCommand/LocalCommand/Match exec are — see
			// Evidence for the full list.
			Keys: "ProxyCommand, LocalCommand, Match exec",
			Evidence: m.evidence + " Keys also dropped IdentityAgent to fit the mark's " +
				"60-char/3-line budget; ssh still honours it from this file.",
		})
	}
	return out
}

// homeInterpretedPaths is every row from internal/profile/credentialsurface_test.go's
// sensitiveHostPath catalogue, carried over verbatim except for Class, which
// splits out of the old "CREDENTIAL:"/"COMMAND TABLE:" string prefix, and the
// three reclassifications issue #169 requires: .docker,
// .config/gh and .claude.json each named a program a human could read as "just
// a credential" and are ClassCommandTable here instead.
//
// Reads is "" on every row here — none of these were measured with a specific
// "the tool reads this AS ___" clause the way the system rows above were, and
// the mark drops that clause rather than inventing 33 unverified ones.
func homeInterpretedPaths() []InterpretedPath {
	const inherited = "inherited from credentialsurface_test.go's catalogue; " +
		"class and keys reviewed, resolution order not re-measured"
	return []InterpretedPath{
		{Path: ".ssh", Class: ClassCredential, Tool: "ssh (and ssh-agent, git, scp, rsync -e ssh)",
			Keys: "private keys", Evidence: inherited},
		{Path: ".gnupg", Class: ClassCredential, Tool: "gpg",
			Keys: "private keys", Evidence: inherited},
		{Path: ".aws", Class: ClassCredential, Tool: "aws",
			Keys: "cloud keys", Evidence: inherited},
		{Path: ".config/gcloud", Class: ClassCredential, Tool: "gcloud",
			Keys: "cloud tokens", Evidence: inherited},
		{Path: ".kube", Class: ClassCredential, Tool: "kubectl",
			Keys: "cluster tokens", Evidence: inherited},
		{Path: ".docker", Class: ClassCommandTable, Tool: "docker",
			Keys: "credsStore/credHelpers name docker-credential-*",
			Evidence: inherited + "; RECLASSIFIED to ClassCommandTable per " +
				"issue #169 (was filed as CREDENTIAL: registry tokens)"},
		{Path: ".netrc", Class: ClassCredential, Tool: "curl (and anything else honouring .netrc)",
			Keys: "passwords in plaintext", Evidence: inherited},
		{Path: ".pgpass", Class: ClassCredential, Tool: "psql",
			Keys: "passwords in plaintext", Evidence: inherited},
		{Path: ".my.cnf", Class: ClassCredential, Tool: "mysql",
			Keys: "passwords in plaintext", Evidence: inherited},
		{Path: ".git-credentials", Class: ClassCredential, Tool: "git",
			Keys: "git passwords in plaintext", Evidence: inherited},
		{Path: ".config/gh", Class: ClassCommandTable, Tool: "gh",
			Keys: "gh alias set --shell stores !<cmd>",
			Evidence: inherited + "; RECLASSIFIED to ClassCommandTable per " +
				"issue #169 (was filed as CREDENTIAL: GitHub OAuth token)"},
		{Path: ".config/hub", Class: ClassCredential, Tool: "hub",
			Keys: "GitHub OAuth token", Evidence: inherited},
		{Path: ".cargo/credentials", Class: ClassCredential, Tool: "cargo",
			Keys: "registry token", Evidence: inherited},
		{Path: ".cargo/credentials.toml", Class: ClassCredential, Tool: "cargo",
			Keys: "registry token", Evidence: inherited},
		{Path: ".pypirc", Class: ClassCredential, Tool: "twine (and pip's other upload tools)",
			Keys: "registry token", Evidence: inherited},
		{Path: ".claude/.credentials.json", Class: ClassCredential, Tool: "claude",
			Keys: "API token", Evidence: inherited},
		{Path: ".claude.json", Class: ClassCommandTable, Tool: "claude",
			Keys: "mcpServers: programs with own argv and env",
			Evidence: inherited + "; RECLASSIFIED to ClassCommandTable per " +
				"issue #169 (was filed as CREDENTIAL: carries MCP config and account state)"},
		{Path: ".claude/settings.json", Class: ClassCommandTable, Tool: "claude",
			Keys: "hooks, apiKeyHelper, statusLine, env, mcpServers, plugins",
			Evidence: inherited + "; original Keys text ran long (113 chars) and is " +
				"trimmed here to fit the mark's budget: full text was " +
				"\"hooks, apiKeyHelper, statusLine, env, mcpServers, enabledPlugins " +
				"— keys that name programs to run or code to load\""},
		{Path: ".local/share/keyrings", Class: ClassCredential, Tool: "gnome-keyring (or kwallet)",
			Keys: "the desktop keyring", Evidence: inherited},
		{Path: ".mozilla", Class: ClassCredential, Tool: "firefox",
			Keys: "saved passwords and cookies", Evidence: inherited},
		{Path: ".config/chromium", Class: ClassCredential, Tool: "chromium",
			Keys: "saved passwords and cookies", Evidence: inherited},
		{Path: ".config/google-chrome", Class: ClassCredential, Tool: "google-chrome",
			Keys: "saved passwords and cookies", Evidence: inherited},
		{Path: ".gitconfig", Class: ClassCommandTable, Tool: "git",
			Keys: "credential.helper, alias = !cmd, core.pager, textconv", Evidence: inherited},
		{Path: ".config/git", Class: ClassCommandTable, Tool: "git",
			Keys: "the same keys as ~/.gitconfig, in git's other global file", Evidence: inherited},
		{Path: ".npmrc", Class: ClassCommandTable, Tool: "npm",
			Keys: "registry auth tokens, and script hooks", Evidence: inherited},
		{Path: ".bashrc", Class: ClassCommandTable, Tool: "bash",
			Keys: "runs on every shell", Evidence: inherited},
		{Path: ".bash_profile", Class: ClassCommandTable, Tool: "bash",
			Keys: "runs on every login shell", Evidence: inherited},
		{Path: ".profile", Class: ClassCommandTable, Tool: "sh (and bash, as a login shell)",
			Keys: "runs on every login shell", Evidence: inherited},
		{Path: ".zshrc", Class: ClassCommandTable, Tool: "zsh",
			Keys: "runs on every shell", Evidence: inherited},
		{Path: ".config/fish", Class: ClassCommandTable, Tool: "fish",
			Keys: "runs on every shell", Evidence: inherited},
		{Path: ".config/nvim", Class: ClassCommandTable, Tool: "nvim",
			Keys: "editor config executes on open", Evidence: inherited},
		{Path: ".vimrc", Class: ClassCommandTable, Tool: "vim",
			Keys: "editor config executes on open", Evidence: inherited},
		{Path: ".config/containers", Class: ClassCommandTable, Tool: "podman (and other containers.conf readers)",
			Keys: "names the runtime binaries an engine executes", Evidence: inherited},
	}
}

// normalizeInterpretedPath is today's sensitiveHostPath body (see
// internal/profile/credentialsurface_test.go), minus the os.UserHomeDir call —
// home is injected instead, which is what keeps this package pure. It produces
// TWO comparable forms of p: abs, a cleaned absolute path (with a leading
// "{home}" or "~" token expanded using the injected home, so an unresolved
// GRANT string compares the same way an already-resolved MOUNT path does), and
// tail, the path relative to home with no leading "/" (matching how a promoted
// home row's Path is spelled). abs is "" when it cannot be formed (a
// "{home}/…"-shaped input with no home injected) — callers must then skip
// matching it against an absolute (system) row.
func normalizeInterpretedPath(p, home string) (abs, tail string) {
	expanded := p
	switch {
	case strings.HasPrefix(expanded, "{home}"):
		expanded = home + strings.TrimPrefix(expanded, "{home}")
	case expanded == "~" || strings.HasPrefix(expanded, "~/"):
		expanded = home + strings.TrimPrefix(expanded, "~")
	}
	if strings.HasPrefix(expanded, "/") {
		abs = filepath.Clean(expanded)
	}

	t := p
	if home != "" && home != "/" {
		t = strings.TrimPrefix(t, home)
	}
	t = strings.TrimPrefix(strings.TrimPrefix(t, "{home}"), "~")
	t = filepath.Clean("/" + t)
	t = strings.TrimPrefix(t, "/")
	if t == "." {
		t = ""
	}
	tail = t
	return abs, tail
}

// matchInterpretedCandidate compares one normalised candidate (abs or tail)
// against one catalogued row's Path, in the SAME namespace (both absolute, or
// both home-relative — the caller picks which of abs/tail to pass based on
// strings.HasPrefix(row.Path, "/")).
func matchInterpretedCandidate(candidate, row string) (InterpretedMatch, bool) {
	switch {
	case candidate == row:
		return MatchExact, true
	case strings.HasPrefix(candidate, row+"/"):
		return MatchInside, true
	case isInterpretedAncestor(candidate, row):
		return MatchAncestor, true
	}
	return 0, false
}

// isInterpretedAncestor reports whether candidate is a strict ancestor of
// row. "" (home root) and "/" (filesystem root) are ancestors of everything
// in their own namespace; every other case is the ordinary path-prefix check.
func isInterpretedAncestor(candidate, row string) bool {
	if candidate == "" || candidate == "/" {
		return true
	}
	return strings.HasPrefix(row, candidate+"/")
}

// ClassifyInterpretedPath matches one path (a resolved Mount's Guest/Host, or
// an unresolved profile grant string) against InterpretedPaths. Pure: home may
// be "", in which case only matching that does not require expanding a
// "{home}"/"~" token into an absolute form is possible.
//
// It does not know which SIDE of a grant p came from — that is Side, and every
// caller (PolicyInterpretedMarks via mountInterpretedHits, GrantInterpretedMarks)
// sets it after calling this.
func ClassifyInterpretedPath(p, home string) []InterpretedHit {
	abs, tail := normalizeInterpretedPath(p, home)
	broad := abs != "" && slices.Contains(BroadHostTrees, abs)

	var hits []InterpretedHit
	for _, row := range InterpretedPaths {
		candidate := tail
		if strings.HasPrefix(row.Path, "/") {
			if abs == "" {
				continue
			}
			candidate = abs
		}
		match, ok := matchInterpretedCandidate(candidate, row.Path)
		if !ok {
			continue
		}
		if match == MatchAncestor && broad {
			continue
		}
		hits = append(hits, InterpretedHit{Row: row, Match: match})
	}
	return deepestInterpretedHits(hits)
}

// deepestInterpretedHits collapses several rows that all matched the SAME
// candidate down to the deepest one, mirroring the policy model's own rule
// that effective access at a path is that of the deepest mount covering it
// (invariant 1's one non-monotone exception). Without this, a grant of
// /etc/claude-code/managed-settings.json matches both that row (MatchExact)
// and the /etc/claude-code root row (MatchInside, since the root is a strict
// prefix) — two marks on one FILESYSTEM line, when the deeper row's Reads and
// Keys are already the more accurate of the two.
//
// Only MatchExact/MatchInside hits collapse this way. MatchAncestor hits are
// left alone — a different question (one grant sitting ABOVE many rows at
// once), and renderInterpretedAncestors already collapses those into a single
// template-D line.
//
// Every MatchExact/MatchInside hit reaching this point matched the SAME
// candidate string via matchInterpretedCandidate, whose two rules
// (candidate == row.Path, or strings.HasPrefix(candidate, row.Path+"/")) both
// require row.Path to be a PREFIX of candidate — so any two such rows are
// themselves nested, never merely overlapping, and "longest Path wins" is
// exactly "deepest wins". At most one row can be an exact match (Path is
// unique per TestEveryInterpretedRowIsWellFormed), so ties do not arise.
func deepestInterpretedHits(hits []InterpretedHit) []InterpretedHit {
	var ancestors, direct []InterpretedHit
	for _, h := range hits {
		if h.Match == MatchAncestor {
			ancestors = append(ancestors, h)
			continue
		}
		direct = append(direct, h)
	}
	if len(direct) > 1 {
		deepest := direct[0]
		for _, h := range direct[1:] {
			if len(h.Row.Path) > len(deepest.Row.Path) {
				deepest = h
			}
		}
		direct = []InterpretedHit{deepest}
	}
	return append(direct, ancestors...)
}

func tagInterpretedSide(hits []InterpretedHit, side InterpretedSide) []InterpretedHit {
	out := make([]InterpretedHit, len(hits))
	for i, h := range hits {
		h.Side = side
		out[i] = h
	}
	return out
}

// sidedInterpretedHits is the guest/host composition both mountInterpretedHits
// and GrantInterpretedMarks apply: classify the guest side, then the host side
// only if it differs, and only where it names a row the guest side did not
// already name — "emit every guest hit; emit a host hit only if no guest hit
// carries the same Row.Path" (issues #169/#170).
func sidedInterpretedHits(guest, host, home string) []InterpretedHit {
	hits := tagInterpretedSide(ClassifyInterpretedPath(guest, home), SideGuest)
	if host == guest {
		return hits
	}
	have := make(map[string]bool, len(hits))
	for _, h := range hits {
		have[h.Row.Path] = true
	}
	for _, h := range tagInterpretedSide(ClassifyInterpretedPath(host, home), SideHost) {
		if have[h.Row.Path] {
			continue
		}
		hits = append(hits, h)
	}
	return hits
}

// mountInterpretedHits is the Kind-gated hit set for one resolved Mount,
// exactly as issues #169/#170 specify — KindBind checks both guest and host,
// KindSymlink only the guest (m.Host is a link TARGET, not a host path), and
// KindTmpfs/KindData/KindProc/KindDev are never marked. Shared by
// PolicyInterpretedMarks; it does not itself know about a mount ELSEWHERE in
// the same policy having replaced a row's exact guest path with generated
// content — a single Mount cannot see its siblings, so that suppression is
// PolicyInterpretedMarks' job, against p.Mounts, not this one's.
func mountInterpretedHits(m Mount, home string) []InterpretedHit {
	switch m.Kind {
	case KindBind:
		return sidedInterpretedHits(m.Guest, m.Host, home)
	case KindSymlink:
		return tagInterpretedSide(ClassifyInterpretedPath(m.Guest, home), SideGuest)
	default:
		return nil
	}
}

// interpretedRowGuestPath is the guest path a catalogued row corresponds to,
// so it can be looked up in p.Mounts, which is keyed by real guest paths,
// while InterpretedPath.Path spells a home row without "{home}" or the host's
// actual $HOME.
func interpretedRowGuestPath(row InterpretedPath, home string) string {
	if strings.HasPrefix(row.Path, "/") {
		return row.Path
	}
	return filepath.Join(home, row.Path)
}

// PolicyInterpretedMarks is the --dry-run FILESYSTEM block's entry point: the
// marks one resolved Mount earns, computed against the WHOLE resolved policy
// rather than the mount alone, which a single Mount cannot see. It is a free
// function taking p explicitly — matching this file's existing shape
// (ClassifyInterpretedPath, sidedInterpretedHits, GrantInterpretedMarks all
// take their inputs as parameters rather than living on a receiver) — kept
// distinct in name from the InterpretedMarks renderer below it, which this
// function calls but does not replace.
//
// home is p.Home, not a parameter: every path this function classifies is
// already resolved into this same policy, so there is no caller for which
// p.Home would be the wrong home to classify against.
//
// Two things a single Mount cannot know, both supplied here from p:
//
//   - Kind gating (mountInterpretedHits) needs nothing beyond m, but lives
//     next to the thing that does need p so the two halves of "what marks does
//     m earn" stay in one function rather than split across packages.
//   - Replacement suppression (issues #169/#170) drops an ancestor hit when
//     snug itself already replaced the row's exact guest path with generated
//     content elsewhere in this same resolved set — the measured case is
//     `data /usr/etc/ssh/ssh_config (snug)+replaces:@sys`, where @sys's `ro
//     /usr` is an ancestor of the row but the one file underneath it that
//     mattered was already replaced. It does not read Mount.From — the
//     signal is a KindData mount's presence at the row's exact guest path,
//     not its provenance string, for the same reason replaceSystemSSHConfig
//     itself does not gate on ownership: refusing must not depend on the
//     host, but marking must, and reading a "replaces:" string back out of
//     prose is a second, weaker copy of a fact the mount set already states
//     structurally.
//
// It does not read m.From: only m.Kind, m.Guest and m.Host feed the hit
// computation, and only p.Mounts (keyed by Guest, never by provenance) feeds
// suppression — the mark must not depend on WHICH profile asked (spec §5,
// order-independence).
func PolicyInterpretedMarks(p *Policy, m Mount) []string {
	home := p.Home
	hits := mountInterpretedHits(m, home)
	if hits == nil {
		return nil
	}
	kept := make([]InterpretedHit, 0, len(hits))
	for _, h := range hits {
		if h.Match == MatchAncestor {
			if repl, ok := p.Mounts[interpretedRowGuestPath(h.Row, home)]; ok && repl.Kind == KindData {
				continue
			}
		}
		kept = append(kept, h)
	}
	return InterpretedMarks(kept)
}

// GrantInterpretedMarks is the `snug profile show` sink: the marks one grant
// STRING earns, before resolution. A profile's RO/RW entry may be a bare path
// (host == guest) or "host:guest"; Symlink.At is always bare. There is no Kind
// to gate on here — every RO/RW entry is bind-shaped — so the caller decides
// which fields of a Profile to run through this (never Tmpfs, which is never
// marked; Symlink.Target is a link target, not a host path, and must never be
// passed here as if it were one).
func GrantInterpretedMarks(grant, home string) []string {
	host, guest := grant, grant
	if i := strings.Index(grant, ":"); i > 0 {
		host, guest = grant[:i], grant[i+1:]
	}
	return InterpretedMarks(sidedInterpretedHits(guest, host, home))
}

// InterpretedMarks renders a slice of hits into screen lines. It is the one
// renderer both sinks above call, so wording lives in exactly one place — one
// wording, two screens, the same reasoning as policy.UncheckedEnvNote.
//
// visibleValue — CORRECTED, and the correction is stronger than the rule.
// These templates interpolate NO profile-supplied text at all: Tool, Reads,
// Keys and every Row.Path are snug's own literals from InterpretedPaths; the
// counts in the ancestor line are integers. Nothing here needs escaping
// because nothing here came from a profile.
func InterpretedMarks(hits []InterpretedHit) []string {
	var out []string
	var ancestors []InterpretedHit
	for _, h := range hits {
		if h.Match == MatchAncestor {
			ancestors = append(ancestors, h)
			continue
		}
		out = append(out, renderInterpretedHit(h))
	}
	if len(ancestors) > 0 {
		out = append(out, renderInterpretedAncestors(ancestors))
	}
	return out
}

// renderInterpretedHit is templates A/B/C from issues #169/#170: an
// exact or inside match, on whichever side produced it. Own indented line via
// wrapMark at the call site; this only builds the text, with the "  ← " prefix
// UncheckedEnvNote/EnvNote already use.
func renderInterpretedHit(h InterpretedHit) string {
	row := h.Row
	if h.Side == SideHost {
		// "exposed inside" is itself the disclosure claim — the guest sentence
		// below is about a tool RUNNING what it reads; this one never runs
		// anything, it just makes the host file's bytes visible to the sandbox.
		return fmt.Sprintf("  ← the host's %s is exposed inside - %s: %s.",
			displayInterpretedPath(row), row.Class.String(), row.Keys)
	}
	switch row.Class {
	case ClassCredential:
		if row.Reads == "" {
			return fmt.Sprintf("  ← CREDENTIAL PATH: %s reads this; "+
				"whatever is here is what it authenticates with.", row.Tool)
		}
		return fmt.Sprintf("  ← CREDENTIAL PATH: %s reads this as %s; "+
			"whatever is here is what it authenticates with.", row.Tool, row.Reads)
	default: // ClassCommandTable
		if row.Reads == "" {
			return fmt.Sprintf("  ← COMMAND TABLE: %s reads this. Read-only SUPPLIES %s.",
				row.Tool, row.Keys)
		}
		return fmt.Sprintf("  ← COMMAND TABLE: %s reads this as %s. Read-only SUPPLIES %s.",
			row.Tool, row.Reads, row.Keys)
	}
}

// renderInterpretedAncestors is template D: every ancestor hit under ONE
// grant collapses into a single line — "ro /etc is an ancestor of many rows;
// one mark per row x3 lines is the noise failure" — naming at most three row
// paths and the remainder as a count.
//
// "SUPPLIED" carries no trailing "here" — dropped when the shell-startup and
// claude-code-root rows (issues #169/#170, upstream PR #181) pushed /etc's own
// ancestor count from 8 to 17: the two extra digits in "17 paths ... (17
// command tables" ate the one word of slack this line had, tipping it from 3
// wrapped lines to 4 at TestEveryInterpretedMarkFitsTheScreen's /etc case. The
// shown paths themselves cannot shrink (they are snug's own literals) and the
// budget forbids showing fewer than three, so the boilerplate is what gave.
func renderInterpretedAncestors(hits []InterpretedHit) string {
	tables, creds := 0, 0
	paths := make([]string, 0, len(hits))
	for _, h := range hits {
		if h.Row.Class == ClassCommandTable {
			tables++
		} else {
			creds++
		}
		paths = append(paths, displayInterpretedPath(h.Row))
	}
	shown, more := paths, 0
	if len(shown) > 3 {
		more = len(shown) - 3
		shown = shown[:3]
	}
	list := strings.Join(shown, ", ")
	if more > 0 {
		list += fmt.Sprintf(", +%d more", more)
	}
	return fmt.Sprintf("  ← %d paths SUPPLIED (%s, %s): %s.",
		len(hits), interpretedCount(tables, "command table", "command tables"),
		interpretedCount(creds, "credential", "credentials"), list)
}

func interpretedCount(n int, singular, plural string) string {
	word := plural
	if n == 1 {
		word = singular
	}
	return fmt.Sprintf("%d %s", n, word)
}

// displayInterpretedPath is how a row's own Path renders on screen: a home
// tail gets its "~/" back, since InterpretedPath.Path itself never carries it
// (that is what lets strings.HasPrefix(Path, "/") double as Scope). Every
// input is snug's own catalogue literal, never a profile's text.
func displayInterpretedPath(row InterpretedPath) string {
	if strings.HasPrefix(row.Path, "/") {
		return row.Path
	}
	return "~/" + row.Path
}
