package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gomoni/snug/internal/policy"
)

// claudeFiles stages Claude Code's writable state and injects the guidance file.
//
// Read-only paths come from the `claude` profile. This handles the two things a
// profile cannot express: files that must be WRITABLE COPIES, and a file whose
// content depends on the resolved policy.
func claudeFiles(pol *policy.Policy, home string) {
	if !hasProfile(pol, "@claude") {
		return
	}

	// Staged as a copy, never bound. The sandbox writes to a private tmpfs, so a
	// token it refreshes does not reach the host and a compromised agent cannot
	// rewrite your host credentials.
	//
	// ONE file is copied, and it is the only one that is load-bearing. MEASURED
	// (claude 2.1.232): delete ~/.claude/.credentials.json inside a sandbox and
	// Claude Code says "Not logged in · Please run /login" at once; delete
	// ~/.claude.json and it connects and works. This comment used to read "both
	// files are needed" and carried that decision for a milestone (issue #19)
	// while 62 KB of the host's ~/.claude.json was copied in verbatim: every
	// project path on this machine, org, email, account and user UUIDs, machine
	// ID, MCP servers, and the host's per-project tool approvals — a
	// host-filesystem inventory @parent-ro deliberately does not grant. What
	// replaces it is claudeStateJSON below: generated, at most three keys, no
	// host bytes.
	//
	// Cost, stated plainly: a token refreshed inside the sandbox is lost when it
	// exits. Sync-back would mean writing a host file from sandbox-authored
	// bytes, which is a real channel out of the sandbox; it is deliberately not
	// implemented.
	stage := func(rel string, perm uint32) {
		data, err := os.ReadFile(filepath.Join(home, rel))
		if err != nil {
			return // absent on this host; nothing to stage
		}
		// Wrapped here rather than at the point it is stored into Mount: data is
		// 508 bytes of accessToken/refreshToken/sk-ant key the instant ReadFile
		// returns it, so the sooner it carries the guard the fewer lines can
		// render it by accident.
		//
		// Be honest about what this does NOT achieve, because the sibling case
		// does achieve it and the difference matters: ghToken's RETURN TYPE is
		// policy.Secret, so no plaintext name for the gh token exists at all.
		// Here os.ReadFile hands back a []byte and Go offers nowhere earlier to
		// intervene, so `data` stays in scope for the rest of this closure as an
		// unguarded alias. content is the second name, not the first. Anything
		// added below must use content; a fmt of `data` still leaks and no test
		// in the tree can see it.
		content := policy.Secret(data)
		guest := filepath.Join(home, rel)
		// Policy.Replace, never a raw pol.Mounts[...] = assignment: it marks the
		// mount Authored (which is what exempts it from the masking rule — it is
		// snug's own content, not a profile mounting over another profile's
		// grant) and records anything it displaced, so --dry-run still says so.
		pol.Replace(policy.Mount{
			Guest: guest, Kind: policy.KindData, Access: policy.AccessRW,
			Content: content, Perms: &perm, From: []string{"@claude"},
		})
	}
	stage(".claude/.credentials.json", 0o600)

	// The MOUNT is unconditional, unlike stage() above: a host that has never run
	// Claude Code still gets a file here, so the sandbox never opens on the theme
	// picker for a reason that is about the host rather than about this run.
	//
	// Its CONTENT is not unconditional, and the one variable part is deliberate:
	// claudeStateJSON reads the host's ~/.claude.json for a single boolean about a
	// single directory (see its doc comment). Nothing else about the host reaches
	// this file, and the read cannot fail the run.
	//
	// A nil body means json.Marshal failed, which is unreachable for a
	// map[string]any of bools and strings. It skips the mount rather than
	// substituting a literal: the degradation is then a visible prompt inside
	// the sandbox, which is the bound CLAUDE.md puts on every per-tool adapter —
	// an adapter that stops working must degrade to "that tool is unconfigured
	// in here", never to a leak or to a file snug did not author.
	if body := claudeStateJSON(pol, home); body != nil {
		perm := uint32(0o600)
		pol.Replace(policy.Mount{
			Guest: filepath.Join(home, ".claude.json"), Kind: policy.KindData,
			Access: policy.AccessRW, Content: policy.Secret(body),
			Perms: &perm, From: []string{"@claude"},
		})
	}

	guest := filepath.Join(home, ".claude", "CLAUDE.md")
	pol.Replace(policy.Mount{
		Guest: guest, Kind: policy.KindData, Access: policy.AccessRO,
		Content: claudeGuidance(pol), From: []string{"@claude"},
	})
}

func hasProfile(pol *policy.Policy, name string) bool {
	for _, n := range pol.Profiles {
		if n == name {
			return true
		}
	}
	return false
}

// claudeStateJSON is the ~/.claude.json snug GENERATES, replacing the 62 KB
// verbatim copy of the host's that @claude staged until issue #19.
//
// "Generate, don't bind" (CLAUDE.md), applied here exactly as it is applied to
// ~/.gitconfig and gh's hosts.yml. The whole file is at most three keys and it
// copies ZERO bytes of the host: two are preferences true of every snug run on
// every host, and the third is one BOOLEAN extracted from the host's file about
// the one directory the human typed on the command line.
//
// PER KEY, and each measurement is claude 2.1.232 inside a real snug sandbox:
//
//   - hasCompletedOnboarding — MEASURED: with the file absent, or present and
//     without this key, Claude Code opens on "Let's get started. Choose the text
//     style that looks best with your terminal" and BLOCKS on a seven-option
//     picker. That is the half of issue #19's report that was wrong: there is no
//     login prompt without ~/.claude.json, but there is onboarding. It blocks on
//     EVERY run, not once ever, because $HOME is a fresh tmpfs each time, and the
//     picker's answer is written to ~/.claude/settings.json, which cannot survive
//     the run either way — @claude binds that path read-only when the host has it
//     (MEASURED: EROFS) and the bind is `optional`, so on a host that has never
//     run Claude Code the same path is an ordinary file on @home's tmpfs and dies
//     with the session. Two different reasons, one outcome; do not state the bind
//     as though it were unconditional (see describeClaude, which gates on it).
//     A constant; it says nothing about this host.
//
//   - autoUpdates — the binary is a read-only bind at policy.StagedBinDir, so a
//     self-update inside can only fail. MEASURED: it prints "Auto-update failed
//     · Run claude doctor" over the prompt. A preference.
//
//   - projects.<target>.hasTrustDialogAccepted — CONDITIONAL, and the condition
//     IS the key: it is written if and only if the HOST's ~/.claude.json already
//     records hasTrustDialogAccepted = true for that exact path. snug CARRIES the
//     human's own decision about one directory across into the sandbox; it never
//     makes one on their behalf.
//
//     Written unconditionally, it removes Claude Code's trust dialog for a
//     directory nobody has ever trusted — and that dialog is not cosmetic. A/B
//     MEASURED on one hostile fixture, a target whose only content is
//     .claude/settings.json carrying a SessionStart hook:
//
//     host file copied (pre-#19)   "Quick safety check" blocks   hook NOT fired
//     key written unconditionally  no dialog, "Welcome back!"    hook FIRED
//     key omitted (this code)      "Quick safety check" blocks   hook NOT fired
//
//     Deleting the projects key inside a sandbox and relaunching restores the
//     dialog, so that key is precisely what enables repo-controlled config to
//     execute at startup. `snug -p @claude <unfamiliar-repo> -- claude` is the
//     review workflow this profile exists for, the sandbox holds the staged
//     Anthropic OAuth token, and @claude is commonly combined with @net — a
//     SessionStart hook is then one line from exfiltrating it. Omitting the key
//     makes the sandbox's trust behaviour identical to what the copied host file
//     produced (MEASURED pre-#19: an untrusted target was not in `projects`, so
//     the dialog appeared), which is what stops the disclosure fix from also
//     being a trust regression.
//
//     ABSENT OR UNPARSEABLE host file: omit the key, do not fail. A host that has
//     never run Claude Code has trusted nothing, and a run must not die on a file
//     snug only consults.
//
//     PATH MATCHING is exact, against pol.Target — the path Resolve has already
//     put through EvalSymlinks, which is the same shape Claude Code records
//     (node's cwd is resolved). Claude keys trust PER DIRECTORY, so a
//     subdirectory of a trusted target is NOT trusted (launching claude from
//     {target}/sub prompts once) and a trusted subdirectory does not trust its
//     parent. Both directions fail towards the prompt, which is the safe one; a
//     prefix match would be snug widening a decision the human did not make.
//
// WHAT THIS DISCLOSES, as the measurement rather than as a reassurance. It is NOT
// "strictly narrower than what shipped before", and saying so was this file's own
// version of the bug issue #19 fixed — a comment understating what is handed
// over. Measured: the old set was the host's SEVEN project paths, the new set is
// at most {target}, and neither contains the other. The old seven were also
// INERT — all seven are absent inside a @claude sandbox, so no entry could open
// anything — while {target} is the one directory that IS mounted, writable and
// persistent, i.e. the only live entry either version ever had. The bytes got
// smaller; the DECISION got bigger, and that is the half the old sentence hid.
// Carrying the host's answer rather than asserting one is what makes the entry
// a projection of the human's decision instead of snug's.
//
// DELIBERATELY NOT HERE, each one a stated behaviour change rather than an
// oversight: oauthAccount (email, organizationName/Uuid, accountUuid),
// machineID, userID, mcpServers, projects[*].allowedTools, and the project list
// itself. Two of those absences cost something real and both are the correct
// direction. MCP servers configured on the host are not configured in here, so
// /mcp is empty BY DESIGN. And tool approvals given in a host session no longer
// carry in, so an interactive session asks again — an approval given outside the
// sandbox is not an approval given inside it. Both are said in the injected
// guidance, in base.toml's abuse block and in --dry-run's CLAUDE block, so they
// are read rather than discovered.
//
// ADDING A KEY HERE IS A POLICY CHANGE. The question to answer first is not "is
// it convenient" but "what does this disclose about the host, and what does it
// pre-answer on the human's behalf".
//
// json.MarshalIndent plus a trailing newline, because a human who cats this file
// inside the sandbox is entitled to read it; a map[string]any marshals with
// sorted keys, so the bytes are deterministic and golden-diffable.
func claudeStateJSON(pol *policy.Policy, home string) []byte {
	state := map[string]any{
		"autoUpdates":            false,
		"hasCompletedOnboarding": true,
	}
	// No `projects` key at all when the host has not trusted this directory —
	// not an empty object and not `false`. Claude Code prompts on a missing
	// entry, which is the behaviour being restored; an explicit `false` is a
	// third state nothing has measured.
	if hostTrustsTarget(home, pol.Target) {
		state["projects"] = map[string]any{
			pol.Target: map[string]any{"hasTrustDialogAccepted": true},
		}
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil
	}
	return append(b, '\n')
}

// hostTrustsTarget answers exactly one question about the host: had the human
// already accepted Claude Code's trust dialog for THIS directory?
//
// It is the only thing the generated ~/.claude.json reads from the host, and it
// reads it as DATA in the sense .claude/design/GIT-CONFIG.md uses the word — one
// boolean is extracted, nothing is bound, and no host string leaves this
// function. The host's file is a command table's neighbour (mcpServers names
// programs, projects[*].allowedTools names approvals) and none of that is
// touched: the decoder below names two fields and json.Unmarshal drops the rest,
// so a key added by a future Claude Code release cannot arrive by accident.
//
// Every failure is the same failure — "not trusted" — because the only cost of
// being wrong in that direction is one prompt the human answers once, while the
// cost in the other direction is a repo-controlled SessionStart hook running
// without anyone being asked. Absent file, unreadable file, invalid JSON, a
// `projects` value that is not an object: all false.
//
// home is main.go's raw os.UserHomeDir() (the same value stage() reads host
// files from), while target is the canonicalised pol.Target — see
// claudeStateJSON's doc comment on why the match is exact.
func hostTrustsTarget(home, target string) bool {
	b, err := os.ReadFile(filepath.Join(home, ".claude.json"))
	if err != nil {
		return false
	}
	var doc struct {
		Projects map[string]struct {
			HasTrustDialogAccepted bool `json:"hasTrustDialogAccepted"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return false
	}
	return doc.Projects[target].HasTrustDialogAccepted
}

// claudeSettingsBound reports whether ~/.claude/settings.json is really a
// read-only bind of the host's file in THIS policy.
//
// It exists because three separate sites said "~/.claude/settings.json is
// read-only" flatly while base.toml lists that path under `optional`: a host
// that has never run Claude Code has no such file, the bind is dropped, and the
// path inside is an ordinary writable file on @home's tmpfs. The golden proved
// it — TestGoldenClaudeBlock resolves against a fake home that does not exist,
// so no bind is in that policy, and the block still claimed read-only.
//
// The lookup is exact and keyed on p.Home because the guest path comes from
// base.toml's `{home}` expansion, which Resolve fills with the SAME canonicalised
// home it puts in p.Home. If that ever stops being true the answer is false, and
// false is the safe direction here: it under-claims (the caller then says only
// that the tmpfs dies with the session, which is true of both arms) rather than
// promising a read-only file that is writable.
func claudeSettingsBound(p *policy.Policy) bool {
	m, ok := p.Mounts[filepath.Join(p.Home, ".claude", "settings.json")]
	return ok && m.Kind == policy.KindBind && m.Access == policy.AccessRO
}

// claudeGuidance is the ~/.claude/CLAUDE.md snug injects.
//
// It is generated from the ACTUAL resolved policy rather than written once, so a
// run whose network was refused truthfully says there is no network. The point
// is not politeness: every sentence here removes a class of wasted turns, and a
// class of confusing failure that an agent would otherwise try to "fix" by
// disabling something.
func claudeGuidance(pol *policy.Policy) []byte {
	var b strings.Builder
	b.WriteString("# You are running inside snug\n\n")
	b.WriteString("snug is an unprivileged sandbox. `$SNUG=1`, and the hostname is `snug`.\n")
	b.WriteString("This file was generated for THIS run and describes what is actually true.\n\n")

	b.WriteString("## Filesystem\n\n")
	fmt.Fprintf(&b, "Only `%s` is writable and persists. ", pol.Target)
	b.WriteString("`$HOME` (with its XDG directories), `/tmp`, `~/.claude` and `/dev` are writable\n")
	b.WriteString("but **ephemeral — they are gone when this session ends**. Put anything meant\n")
	b.WriteString("to survive in the project tree.\n\n")
	b.WriteString("Everything else is read-only or absent. Secrets (`~/.ssh`, `~/.gnupg`, cloud\n")
	b.WriteString("credentials), personal data, and every other project on this machine are not\n")
	b.WriteString("hidden — they were never mounted, and read as **absent**. Do not try to reach\n")
	b.WriteString("them; there is nothing there and it wastes your turns.\n\n")

	b.WriteString("## Network\n\n")
	switch pol.Net.Mode {
	case policy.NetIsolated:
		b.WriteString("**You have no network.** Not a misconfiguration — this sandbox was started\n")
		b.WriteString("offline. Do not attempt to fetch anything, install packages, or diagnose it.\n\n")
	case policy.NetEgress:
		b.WriteString("You have internet access. You **cannot** reach services on the host's\n")
		b.WriteString("`127.0.0.1`; this is intentional and is not a misconfiguration.\n")
		if len(pol.Net.Publish) > 0 {
			b.WriteString("Ports you bind ARE visible to the host on its 127.0.0.1.\n")
		} else {
			b.WriteString("Ports you bind are NOT visible to the host.\n")
		}
		b.WriteString("\n")
	case policy.NetHost:
		b.WriteString("You share the host's network namespace. Everything the host can reach, you\n")
		b.WriteString("can reach. Be correspondingly careful.\n\n")
	}

	b.WriteString("## Tooling\n\n")
	b.WriteString("Personal skills and plugins are re-exposed read-only — invoke them normally,\n")
	b.WriteString("do not try to edit them. Host `~/.claude` history and prior sessions are NOT\n")
	b.WriteString("carried in.\n\n")
	b.WriteString("`~/.claude.json` here is GENERATED by snug and holds at most three keys. The\n")
	b.WriteString("host's file was not copied in, so **there are no MCP servers configured** from\n")
	b.WriteString("the host's user config — `/mcp` shows nothing from there by design, not because\n")
	b.WriteString("it is broken. That statement is scoped to the HOST's configuration: a\n")
	b.WriteString("`.mcp.json` committed in this project lives in the target tree, snug does not\n")
	b.WriteString("remove it, and Claude Code still reads it.\n")
	b.WriteString("No host project list, session history or cost data is present. Tool permissions\n")
	b.WriteString("approved in a host session were not carried in either, so you may be asked to\n")
	b.WriteString("approve a tool the human already approved outside. None of this is a fault to\n")
	b.WriteString("diagnose.\n\n")
	// The read-only bind is OPTIONAL (base.toml), so this sentence is gated on the
	// policy rather than asserted. On a host that has never run Claude Code there
	// is no host file to bind and ~/.claude/settings.json is an ordinary file on
	// @home's tmpfs: `echo x >>` SUCCEEDS there, so "it is read-only" would be
	// false on the one artifact whose whole value is being checkable. The
	// conclusion survives either way, for two different reasons.
	if claudeSettingsBound(pol) {
		b.WriteString("Settings you change here do not persist: `~/.claude/settings.json` is a\n")
		b.WriteString("read-only bind of the host's file, and the rest of `~/.claude` is a tmpfs that\n")
		b.WriteString("dies with this session, so `/theme`, `/model` and friends will not stick.\n\n")
	} else {
		b.WriteString("Settings you change here do not persist: `~/.claude/settings.json` is NOT bound\n")
		b.WriteString("from the host (there was none to bind), so it is an ordinary file on the\n")
		b.WriteString("`~/.claude` tmpfs — writable, and gone with this session along with the rest of\n")
		b.WriteString("that directory, so `/theme`, `/model` and friends will not stick.\n\n")
	}
	// The exception, stated because "settings do not persist" is otherwise
	// absolute and the target is writable AND persistent — which is exactly where
	// Claude Code puts a project-scope permission grant.
	b.WriteString("One exception, and it is not a fault either. The PROJECT persists:\n")
	fmt.Fprintf(&b, "`%s`\n", pol.Target)
	b.WriteString("is on the host's disk, so anything Claude Code writes there — including\n")
	b.WriteString("`.claude/settings.local.json`, where a project-scope permission you accept in\n")
	b.WriteString("this session goes — is still there after the sandbox exits.\n\n")
	b.WriteString("A token you refresh here does not reach the host; it is lost when this session\n")
	b.WriteString("ends.\n\n")

	if id := pol.Identity; id != nil && id.SSHMode != policy.SSHNone {
		b.WriteString("## Identity\n\n")
		if id.GhUser != "" {
			fmt.Fprintf(&b, "git, ssh and gh are scoped to the account `%s`.\n", id.GhUser)
		}
		b.WriteString("Exactly one ssh key is available for signing. You cannot enumerate or use\n")
		b.WriteString("any other key, and no key material is present in this sandbox.\n\n")
	}

	b.WriteString("## If something is missing\n\n")
	b.WriteString("An absent path or a refused connection is almost always the sandbox doing its\n")
	b.WriteString("job, not a bug to work around. Say what you needed and why; do not try to\n")
	b.WriteString("disable, escape, or reconfigure the sandbox from inside.\n")
	return []byte(b.String())
}
