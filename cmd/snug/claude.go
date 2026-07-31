package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"snug/internal/policy"
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

	// Staged as copies, never bound. The sandbox writes to a private tmpfs, so a
	// token it refreshes does not reach the host and a compromised agent cannot
	// rewrite your host credentials.
	//
	// Both files are needed. .credentials.json is the token; ~/.claude.json is
	// account and onboarding state, and without it Claude decides it has never
	// been run and shows a login prompt.
	//
	// Cost, stated plainly: a token refreshed inside the sandbox is lost when it
	// exits. Sync-back would mean writing a host file from sandbox-authored
	// bytes, which is a real channel out of the sandbox; it is deliberately not
	// implemented yet.
	stage := func(rel string, perm uint32) {
		data, err := os.ReadFile(filepath.Join(home, rel))
		if err != nil {
			return // absent on this host; nothing to stage
		}
		guest := filepath.Join(home, rel)
		m := policy.Mount{
			Guest: guest, Kind: policy.KindData, Access: policy.AccessRW,
			Content: data, Perms: &perm, From: []string{"@claude"},
		}
		pol.Mounts[guest] = m
	}
	stage(".claude/.credentials.json", 0o600)
	stage(".claude.json", 0o600)

	guest := filepath.Join(home, ".claude", "CLAUDE.md")
	pol.Mounts[guest] = policy.Mount{
		Guest: guest, Kind: policy.KindData, Access: policy.AccessRO,
		Content: claudeGuidance(pol), From: []string{"@claude"},
	}
}

func hasProfile(pol *policy.Policy, name string) bool {
	for _, n := range pol.Profiles {
		if n == name {
			return true
		}
	}
	return false
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
	b.WriteString("`$HOME`, `/tmp` and `~/.claude` are writable but **ephemeral — they are gone\n")
	b.WriteString("when this session ends**. Put anything meant to survive in the project tree.\n\n")
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
	b.WriteString("`~/.claude.json` IS staged (Claude re-onboards without it), so any MCP server\n")
	b.WriteString("configuration it holds is visible here — but the servers themselves are not\n")
	b.WriteString("mounted and their sockets are not reachable, so host-configured MCP tools will\n")
	b.WriteString("generally not work. Do not spend turns diagnosing that.\n\n")
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
